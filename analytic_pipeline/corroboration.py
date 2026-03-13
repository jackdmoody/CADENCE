"""
Multi-Source Corroboration
============================
Validates beacon pair candidates identified by periodicity.py against
independent evidence in Zeek DNS and HTTP/SSL logs.

Architecture change from v5
-----------------------------
Corroboration now operates on (src_ip, dst_ip) pairs (identified by pair_id)
rather than DBSCAN cluster IDs. The lookup into the raw DataFrame uses
src_ip/dst_ip filters instead of cluster label filters. The hypothesis logic
(H1–H4) is unchanged.

Four hypotheses are tested per pair:
    H1 — DNS Regularity: src_ip queries the same domain at intervals
         consistent with the conn log beacon period.
    H2 — DNS Anomaly: queried domain shows DGA, fast-flux, or NXDomain.
    H3 — HTTP Consistency: uniform URI length and response body size.
    H4 — HTTP Evasion: rare UA, high-entropy URI, abnormal methods.
"""
from __future__ import annotations

import logging
import math
import re
from collections import Counter
from typing import Optional

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

from .config import BDPConfig

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Known-benign signatures
# ---------------------------------------------------------------------------

_BENIGN_UA_PATTERNS = [
    "microsoft update", "windows update", "wsus", "windows defender",
    "microsoft-cryptoapi", "mozilla/5.0 (windows nt",
    "curl/", "python-urllib", "go-http-client",
    "amazon cloudfront", "googlebot", "bingbot", "ntp", "ntpd",
]

_BENIGN_DOMAIN_SUFFIXES = (
    "windowsupdate.com", "microsoft.com", "windows.net", "azure.com",
    "office.com", "office365.com", "live.com", "msftconnecttest.com",
    "ocsp.verisign.net", "ocsp.digicert.com", "ctldl.windowsupdate.com",
    "googleapis.com", "gstatic.com", "amazon.com", "amazonaws.com",
    "cloudfront.net", "akamaiedge.net",
    # NTP and time services — periodic by design, not beacons
    "time.google.com", "time.windows.com", "pool.ntp.org", "ntp.org",
    "time.apple.com", "time.cloudflare.com", "time.nist.gov",
    "google.com", "github.com",
)


# ---------------------------------------------------------------------------
# DNS log loading
# ---------------------------------------------------------------------------

def load_dns_logs(path: str, cfg: BDPConfig) -> pd.DataFrame:
    """Load and normalise a Zeek dns.log CSV export."""
    df = pd.read_csv(path, low_memory=False)

    rename = {
        "ts": "ts", "id.orig_h": "src_ip", "query": "query",
        "rcode_name": "rcode_name", "answers": "answers", "TTLs": "ttls",
    }
    for src, dst in rename.items():
        if src in df.columns and dst not in df.columns:
            df = df.rename(columns={src: dst})

    for col in ("ts", "src_ip", "query"):
        if col not in df.columns:
            raise ValueError(f"DNS log missing required column '{col}'. Available: {list(df.columns)[:20]}")

    df["ts"] = pd.to_datetime(df["ts"], unit="s", utc=True, errors="coerce")

    if cfg.io.query_start:
        df = df[df["ts"] >= pd.to_datetime(cfg.io.query_start, utc=True)]
    if cfg.io.query_end:
        df = df[df["ts"] <= pd.to_datetime(cfg.io.query_end, utc=True)]

    df = df.dropna(subset=["ts", "src_ip", "query"]).copy()
    log.info("DNS log loaded: %d records, %d unique src_ips", len(df), df["src_ip"].nunique())
    return df


def load_http_logs(path: str, cfg: BDPConfig) -> pd.DataFrame:
    """Load and normalise a Zeek http.log CSV export."""
    df = pd.read_csv(path, low_memory=False)

    rename = {
        "id.orig_h": "src_ip", "id.resp_h": "dst_ip",
        "user_agent": "user_agent",
        "request_body_len": "request_body_len",
        "response_body_len": "response_body_len",
    }
    for src, dst in rename.items():
        if src in df.columns and dst not in df.columns:
            df = df.rename(columns={src: dst})

    df["ts"] = pd.to_datetime(
        df.get("ts", pd.Series(dtype="float64")), unit="s", utc=True, errors="coerce"
    )

    if cfg.io.query_start:
        df = df[df["ts"] >= pd.to_datetime(cfg.io.query_start, utc=True)]
    if cfg.io.query_end:
        df = df[df["ts"] <= pd.to_datetime(cfg.io.query_end, utc=True)]

    df = df.dropna(subset=["src_ip"]).copy()
    log.info("HTTP log loaded: %d records, %d unique src_ips", len(df), df["src_ip"].nunique())
    return df


# ---------------------------------------------------------------------------
# DNS helpers (H1 + H2)
# ---------------------------------------------------------------------------

def _string_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s.lower())
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _is_likely_dga(domain: str, cfg: BDPConfig) -> bool:
    cc    = cfg.corroboration
    parts = domain.lower().rstrip(".").split(".")
    if len(parts) < 2:
        return False
    label = parts[0]
    if len(label) < cc.dga_min_label_len:
        return False
    entropy   = _string_entropy(label)
    no_vowels = not re.search(r"[aeiou]", label)
    long_runs = bool(re.search(r"[^aeiou]{6,}", label))
    return entropy >= cc.dga_entropy_threshold and (no_vowels or long_runs)


def _is_benign_domain(domain: str) -> bool:
    d = domain.lower().rstrip(".")
    return any(d == s or d.endswith("." + s) for s in _BENIGN_DOMAIN_SUFFIXES)


def score_dns_hypothesis(
    src_ips:       set[str],
    dst_ips:       set[str],
    dns_df:        pd.DataFrame,
    beacon_period: float,
    cfg:           BDPConfig,
) -> dict:
    """Test H1 (DNS regularity) and H2 (DNS anomaly indicators)."""
    cc = cfg.corroboration

    null_result = {
        "h1_dns_regularity": False,
        "h1_dns_period_s":   0.0,
        "h1_dns_period_delta": 1.0,
        "h2_dns_anomaly":    False,
        "h2_dga_domains":    [],
        "h2_nxdomain_count": 0,
        "h2_short_ttl_count": 0,
        "dns_score":         0.0,
        "matched_domains":   [],
    }

    if dns_df.empty or "src_ip" not in dns_df.columns:
        return null_result

    src_dns = dns_df[dns_df["src_ip"].isin(src_ips)].copy()
    if src_dns.empty:
        return null_result

    # --- H1: DNS regularity ---
    h1_pass       = False
    h1_period_s   = 0.0
    h1_delta      = 1.0
    matched_domains: list[str] = []

    if beacon_period > 0:
        for domain, dom_df in src_dns.groupby("query"):
            if _is_benign_domain(str(domain)):
                continue
            if len(dom_df) < 3:
                continue
            dom_ts  = dom_df["ts"].sort_values()
            dns_iat = np.diff(dom_ts.astype(np.int64) / 1e9)
            if len(dns_iat) < 2:
                continue
            mean_iat = float(np.mean(dns_iat))
            delta    = abs(mean_iat - beacon_period) / (beacon_period + 1e-9)
            if delta <= cc.period_tolerance_pct:
                h1_pass     = True
                h1_period_s = mean_iat
                h1_delta    = delta
                matched_domains.append(str(domain))

    # --- H2: DNS anomaly indicators ---
    dga_domains:   list[str] = []
    nxdomain_count = 0
    short_ttl_count = 0

    for _, dns_row in src_dns.iterrows():
        domain = str(dns_row.get("query", ""))
        if _is_benign_domain(domain):
            continue

        if _is_likely_dga(domain, cfg):
            dga_domains.append(domain)

        rcode = str(dns_row.get("rcode_name", "")).upper()
        if "NXDOMAIN" in rcode:
            nxdomain_count += 1

        ttls_raw = dns_row.get("ttls", "")
        if isinstance(ttls_raw, str) and ttls_raw:
            try:
                ttls = [float(t) for t in ttls_raw.strip("[]").split(",") if t.strip()]
                if any(t < cc.short_ttl_threshold_s for t in ttls):
                    short_ttl_count += 1
            except ValueError:
                pass

    h2_pass = bool(dga_domains) or nxdomain_count > 0 or short_ttl_count > 0

    dns_score = float(np.clip(
        0.35 * float(h1_pass)
        + 0.40 * float(h2_pass)
        + 0.15 * float(bool(dga_domains))
        + 0.10 * float(nxdomain_count > 0),
        0.0, 1.0,
    ))

    return {
        "h1_dns_regularity":  h1_pass,
        "h1_dns_period_s":    round(h1_period_s, 1),
        "h1_dns_period_delta": round(h1_delta, 4),
        "h2_dns_anomaly":     h2_pass,
        "h2_dga_domains":     list(set(dga_domains))[:10],
        "h2_nxdomain_count":  nxdomain_count,
        "h2_short_ttl_count": short_ttl_count,
        "dns_score":          round(dns_score, 4),
        "matched_domains":    matched_domains[:10],
    }


# ---------------------------------------------------------------------------
# HTTP helpers (H3 + H4)
# ---------------------------------------------------------------------------

def _is_benign_ua(ua: str) -> bool:
    if not isinstance(ua, str):
        return False
    ua_lower = ua.lower()
    return any(pattern in ua_lower for pattern in _BENIGN_UA_PATTERNS)


def score_http_hypothesis(
    src_ips:  set[str],
    dst_ips:  set[str],
    http_df:  pd.DataFrame,
    cfg:      BDPConfig,
) -> dict:
    """Test H3 (HTTP behavioral consistency) and H4 (HTTP evasion indicators)."""
    cc = cfg.corroboration

    null_result = {
        "h3_http_consistency":   False,
        "h3_response_body_cv":   np.nan,
        "h3_uri_len_cv":         np.nan,
        "h4_rare_ua":            False,
        "h4_high_uri_entropy":   False,
        "h4_abnormal_methods":   [],
        "h4_evasion_indicators": False,
        "http_score":            0.0,
        "http_flow_count":       0,
        "unique_user_agents":    [],
        "benign_ua_filtered":    0,
    }

    if http_df.empty or "src_ip" not in http_df.columns:
        return null_result

    cluster_http = http_df[
        http_df["src_ip"].isin(src_ips)
        & (http_df["dst_ip"].isin(dst_ips) if "dst_ip" in http_df.columns else True)
    ].copy()

    if cluster_http.empty:
        return null_result

    benign_ua_count = 0
    if "user_agent" in cluster_http.columns:
        benign_mask     = cluster_http["user_agent"].apply(_is_benign_ua)
        benign_ua_count = int(benign_mask.sum())
        cluster_http    = cluster_http[~benign_mask]

    if cluster_http.empty:
        return {**null_result, "benign_ua_filtered": benign_ua_count}

    n_flows = len(cluster_http)

    body_cv = np.nan
    uri_cv  = np.nan

    if "response_body_len" in cluster_http.columns:
        body_vals = pd.to_numeric(cluster_http["response_body_len"], errors="coerce").dropna()
        if len(body_vals) > 1 and body_vals.mean() > 0:
            body_cv = float(body_vals.std() / body_vals.mean())

    if "uri" in cluster_http.columns:
        uri_lens = cluster_http["uri"].dropna().apply(len)
        if len(uri_lens) > 1 and uri_lens.mean() > 0:
            uri_cv = float(uri_lens.std() / uri_lens.mean())

    h3_pass = (
        (not np.isnan(body_cv) and body_cv < cc.http_body_cv_threshold)
        or (not np.isnan(uri_cv) and uri_cv < cc.http_uri_cv_threshold)
    )

    rare_ua = False
    if "user_agent" in cluster_http.columns:
        ua_counts = cluster_http["user_agent"].fillna("").value_counts()
        if len(ua_counts) > 0:
            rare_ua = float(ua_counts.iloc[0] / n_flows) < cc.rare_ua_threshold

    high_entropy_uri = False
    if "uri" in cluster_http.columns:
        uri_entropies    = cluster_http["uri"].fillna("").apply(lambda s: _string_entropy(s))
        high_entropy_uri = float(uri_entropies.mean()) > cc.uri_entropy_threshold

    abnormal_methods: list[str] = []
    if "method" in cluster_http.columns:
        normal_methods   = {"GET", "POST", "HEAD", "OPTIONS"}
        observed_methods = set(cluster_http["method"].dropna().str.upper().unique())
        abnormal_methods = sorted(observed_methods - normal_methods)

    h4_pass = rare_ua or high_entropy_uri or bool(abnormal_methods)

    http_score = float(np.clip(
        0.35 * float(h3_pass)
        + 0.30 * float(rare_ua)
        + 0.20 * float(high_entropy_uri)
        + 0.15 * float(bool(abnormal_methods)),
        0.0, 1.0,
    ))

    unique_uas = cluster_http["user_agent"].dropna().unique().tolist() \
        if "user_agent" in cluster_http.columns else []

    return {
        "h3_http_consistency":   h3_pass,
        "h3_response_body_cv":   round(body_cv, 4) if not np.isnan(body_cv) else np.nan,
        "h3_uri_len_cv":         round(uri_cv, 4)  if not np.isnan(uri_cv)  else np.nan,
        "h4_rare_ua":            rare_ua,
        "h4_high_uri_entropy":   high_entropy_uri,
        "h4_abnormal_methods":   abnormal_methods,
        "h4_evasion_indicators": h4_pass,
        "http_score":            round(http_score, 4),
        "http_flow_count":       n_flows,
        "unique_user_agents":    unique_uas[:10],
        "benign_ua_filtered":    benign_ua_count,
    }


# ---------------------------------------------------------------------------
# Corroboration score
# ---------------------------------------------------------------------------

def _corroboration_score(
    dns_score:       float,
    http_score:      float,
    h1_pass:         bool,
    h2_pass:         bool,
    h3_pass:         bool,
    h4_pass:         bool,
    http_flow_count: int = 0,
) -> float:
    """
    Compute corroboration score in [0, 1].

    When no HTTP flows are present (e.g. HTTPS/DNS-only beacons), the HTTP
    weight is redistributed to DNS so the pair isn't penalised for using an
    encrypted transport. This is the correct behaviour: absence of HTTP
    evidence is neutral, not negative.
    """
    if http_flow_count == 0:
        # No HTTP log entries (e.g. HTTPS/DNS-only beacons).
        # Redistribute HTTP weight to DNS. H2 (anomaly indicators) is weighted
        # more heavily than H1 (regularity) since periodic legitimate services
        # also pass H1. When only H1 passes (slow fixed-C2, no DGA), the
        # dns_score still carries signal from the matched domain regularity.
        boolean_score = (
            0.35 * float(h1_pass)
            + 0.65 * float(h2_pass)
        )
        return round(0.55 * boolean_score + 0.45 * dns_score, 4)
    else:
        boolean_score = (
            0.25 * float(h1_pass)
            + 0.35 * float(h2_pass)
            + 0.20 * float(h3_pass)
            + 0.20 * float(h4_pass)
        )
        return round(0.60 * boolean_score + 0.20 * dns_score + 0.20 * http_score, 4)


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def corroborate_beacon_candidates(
    periodicity_df: pd.DataFrame,
    df_anomalies:   pd.DataFrame,
    dns_df:         pd.DataFrame,
    http_df:        pd.DataFrame,
    cfg:            BDPConfig,
) -> pd.DataFrame:
    """
    Cross-validate every beacon-candidate pair against DNS and HTTP evidence.

    Parameters
    ----------
    periodicity_df : Output of periodicity.score_all_pairs().
    df_anomalies   : Raw anomaly DataFrame with src_ip, dst_ip columns.
    dns_df         : Normalised DNS log DataFrame from load_dns_logs().
    http_df        : Normalised HTTP log DataFrame from load_http_logs().
    cfg            : Pipeline configuration.

    Returns
    -------
    pd.DataFrame — one row per beacon candidate pair with all hypothesis
    results and a final corroborated boolean. Sorted by corroboration_score.
    """
    candidates = periodicity_df[periodicity_df["is_beacon_pair"]].copy()

    if candidates.empty:
        log.warning("No beacon candidates to corroborate — periodicity stage found none.")
        return pd.DataFrame()

    log.info("Corroborating %d beacon candidate pairs.", len(candidates))
    results = []

    for _, row in candidates.iterrows():
        src = row["src_ip"]
        dst = row["dst_ip"]
        pair_df = df_anomalies[
            (df_anomalies["src_ip"] == src) & (df_anomalies["dst_ip"] == dst)
        ]

        src_ips       = {src}
        dst_ips       = {dst}
        beacon_period = float(row.get("dominant_period_s", 0.0))

        dns_result  = score_dns_hypothesis(src_ips, dst_ips, dns_df, beacon_period, cfg)
        http_result = score_http_hypothesis(src_ips, dst_ips, http_df, cfg)

        corr_score = _corroboration_score(
            dns_score        = dns_result["dns_score"],
            http_score       = http_result["http_score"],
            h1_pass          = dns_result["h1_dns_regularity"],
            h2_pass          = dns_result["h2_dns_anomaly"],
            h3_pass          = http_result["h3_http_consistency"],
            h4_pass          = http_result["h4_evasion_indicators"],
            http_flow_count  = http_result["http_flow_count"],
        )

        results.append({
            # Identity
            "pair_id":              row["pair_id"],
            "src_ip":               src,
            "dst_ip":               dst,
            "flow_count":           len(pair_df),
            # Periodicity (carried forward)
            "beacon_confidence":    row["beacon_confidence"],
            "dominant_period_s":    row["dominant_period_s"],
            "is_periodic":          row["is_periodic"],
            # H1
            "h1_dns_regularity":    dns_result["h1_dns_regularity"],
            "h1_dns_period_s":      dns_result["h1_dns_period_s"],
            "h1_period_delta_pct":  dns_result["h1_dns_period_delta"],
            # H2
            "h2_dns_anomaly":       dns_result["h2_dns_anomaly"],
            "h2_dga_domain_count":  len(dns_result["h2_dga_domains"]),
            "h2_nxdomain_count":    dns_result["h2_nxdomain_count"],
            "h2_short_ttl_count":   dns_result["h2_short_ttl_count"],
            "h2_dga_domains":       dns_result["h2_dga_domains"],
            # H3
            "h3_http_consistency":  http_result["h3_http_consistency"],
            "h3_response_body_cv":  http_result["h3_response_body_cv"],
            "h3_uri_len_cv":        http_result["h3_uri_len_cv"],
            # H4
            "h4_evasion_indicators": http_result["h4_evasion_indicators"],
            "h4_rare_ua":           http_result["h4_rare_ua"],
            "h4_high_uri_entropy":  http_result["h4_high_uri_entropy"],
            "h4_abnormal_methods":  http_result["h4_abnormal_methods"],
            # Composite
            "dns_score":            dns_result["dns_score"],
            "http_score":           http_result["http_score"],
            "corroboration_score":  corr_score,
            "corroborated":         corr_score >= cfg.corroboration.min_score,
            # Analyst context
            "matched_domains":      dns_result["matched_domains"][:5],
            "unique_user_agents":   http_result["unique_user_agents"],
        })

    result_df = (
        pd.DataFrame(results)
        .sort_values("corroboration_score", ascending=False)
        .reset_index(drop=True)
    )

    n_corroborated = int(result_df["corroborated"].sum())
    log.info(
        "Corroboration complete: %d / %d candidates confirmed (score >= %.2f)",
        n_corroborated, len(result_df), cfg.corroboration.min_score,
    )
    return result_df


# ---------------------------------------------------------------------------
# Visualisation
# ---------------------------------------------------------------------------

def plot_corroboration_summary(corroboration_df: pd.DataFrame) -> None:
    """Four-panel summary of corroboration results."""
    if corroboration_df.empty:
        log.warning("No data to plot — corroboration_df is empty.")
        return

    df     = corroboration_df.copy()
    colors = ["#d62728" if v else "#1f77b4" for v in df["corroborated"]]

    fig, axes = plt.subplots(2, 2, figsize=(16, 10))

    axes[0, 0].bar(range(len(df)), df["corroboration_score"], color=colors)
    axes[0, 0].set_xticks(range(len(df)))
    axes[0, 0].set_xticklabels(df["pair_id"].astype(str), rotation=90, fontsize=6)
    axes[0, 0].set_xlabel("Pair (src→dst)")
    axes[0, 0].set_ylabel("Corroboration Score")
    axes[0, 0].set_title("Corroboration Score by Pair\n(red = corroborated)")
    axes[0, 0].grid(axis="y", alpha=0.3)
    from matplotlib.patches import Patch
    axes[0, 0].legend(handles=[
        Patch(color="#d62728", label="Corroborated"),
        Patch(color="#1f77b4", label="Not corroborated"),
    ])

    hyp_labels = ["H1\nDNS Regularity", "H2\nDNS Anomaly",
                  "H3\nHTTP Consistency", "H4\nHTTP Evasion"]
    hyp_cols   = ["h1_dns_regularity", "h2_dns_anomaly",
                  "h3_http_consistency", "h4_evasion_indicators"]
    hyp_rates  = [df[c].mean() if c in df.columns else 0.0 for c in hyp_cols]
    bar_colors = ["#2ca02c" if r >= 0.5 else "#ff7f0e" for r in hyp_rates]
    axes[0, 1].bar(hyp_labels, hyp_rates, color=bar_colors)
    axes[0, 1].set_ylim(0, 1.05)
    axes[0, 1].set_ylabel("Fraction of Candidates Passing")
    axes[0, 1].set_title("Hypothesis Pass Rates")
    axes[0, 1].grid(axis="y", alpha=0.3)
    for i, r in enumerate(hyp_rates):
        axes[0, 1].text(i, r + 0.02, f"{r:.0%}", ha="center", fontsize=9)

    scatter_colors = ["#d62728" if v else "#1f77b4" for v in df["corroborated"]]
    axes[1, 0].scatter(df["beacon_confidence"], df["dns_score"],
                       c=scatter_colors, s=80, alpha=0.8, edgecolors="white")
    axes[1, 0].set_xlabel("Beacon Confidence (periodicity)")
    axes[1, 0].set_ylabel("DNS Corroboration Score")
    axes[1, 0].set_title("DNS Evidence vs. Periodicity Confidence")
    axes[1, 0].grid(True, alpha=0.3)

    axes[1, 1].scatter(df["beacon_confidence"], df["http_score"],
                       c=scatter_colors, s=80, alpha=0.8, edgecolors="white")
    axes[1, 1].set_xlabel("Beacon Confidence (periodicity)")
    axes[1, 1].set_ylabel("HTTP Corroboration Score")
    axes[1, 1].set_title("HTTP Evidence vs. Periodicity Confidence")
    axes[1, 1].grid(True, alpha=0.3)

    plt.suptitle("Multi-Source Corroboration Summary", fontsize=13, fontweight="bold")
    plt.tight_layout()
    plt.show()


def print_analyst_brief(
    corroboration_df: pd.DataFrame,
    top_n: int = 5,
) -> None:
    """Print a structured analyst brief for the top-N corroborated pairs."""
    corroborated = corroboration_df[corroboration_df["corroborated"]].head(top_n)

    if corroborated.empty:
        print("No corroborated beacon pairs found.")
        return

    print("=" * 70)
    print(f"  BEACON ANALYTIC — TOP {len(corroborated)} CORROBORATED CANDIDATES")
    print("=" * 70)

    for rank, (_, row) in enumerate(corroborated.iterrows(), start=1):
        period_min = row["dominant_period_s"] / 60 if row["dominant_period_s"] > 0 else 0
        print(f"\n  #{rank}  {row['src_ip']} → {row['dst_ip']}  ({int(row['flow_count'])} flows)")
        print(f"  {'─' * 60}")
        print(f"  Beacon period     : {row['dominant_period_s']:.0f}s  ({period_min:.1f} min)")
        print(f"  Beacon confidence : {row['beacon_confidence']:.3f}  "
              f"Corroboration score: {row['corroboration_score']:.3f}")
        print()
        print(f"  DNS evidence:")
        print(f"    H1 Regularity  {'✓' if row['h1_dns_regularity'] else '✗'}  "
              f"DNS period={row['h1_dns_period_s']:.0f}s  "
              f"(Δ={row['h1_period_delta_pct']:.1%} vs conn period)")
        print(f"    H2 Anomaly     {'✓' if row['h2_dns_anomaly'] else '✗'}  "
              f"DGA={row['h2_dga_domain_count']}  "
              f"NXD={row['h2_nxdomain_count']}  "
              f"ShortTTL={row['h2_short_ttl_count']}")
        if row["h2_dga_domains"]:
            for d in row["h2_dga_domains"][:3]:
                print(f"             DGA candidate: {d}")
        if row["matched_domains"]:
            for d in row["matched_domains"][:3]:
                print(f"             Domain: {d}")
        print()
        print(f"  HTTP evidence:")
        print(f"    H3 Consistency {'✓' if row['h3_http_consistency'] else '✗'}  "
              f"body_CV={row['h3_response_body_cv']:.3f}  "
              f"uri_CV={row['h3_uri_len_cv']:.3f}")
        print(f"    H4 Evasion     {'✓' if row['h4_evasion_indicators'] else '✗'}  "
              f"rare_UA={row['h4_rare_ua']}  "
              f"high_entropy_URI={row['h4_high_uri_entropy']}")
        if row["h4_abnormal_methods"]:
            print(f"             Abnormal methods: {row['h4_abnormal_methods']}")
        if row["unique_user_agents"]:
            for ua in row["unique_user_agents"][:2]:
                print(f"             UA: {str(ua)[:60]}")

    print("\n" + "=" * 70)
    print(f"  {len(corroborated)} pairs warrant analyst investigation.")
    print(f"  Investigate in order of corroboration_score descending.")
    print("=" * 70)
