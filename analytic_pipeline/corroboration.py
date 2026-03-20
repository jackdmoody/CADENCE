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

Robustness improvements (v8)
-----------------------------
Fix  #1  H1 uses median IAT + CV gate instead of mean IAT (burst-resistant).
Fix  #2  H1 selects the domain with the minimum period delta, not first-match.
Fix  #3  H1 minimum DNS observation gate scales with expected firing count.
Fix  #4  DGA detection now also checks digit-run density (numeric DGA).
Fix  #5  NXDomain evidence is rate-normalised against total queries.
Fix  #6  Fast-flux detection via high unique-answer IP count per domain.
Fix  #7  H3 uses a combined weighted score instead of OR-logic boolean.
Fix  #8  Response body CV computed on trimmed distribution (5th-95th pct).
Fix  #9  URI consistency checks path component separate from query string.
Fix #10  UA rarity measured against global HTTP traffic, not pair-local.
Fix #11  UA monotony (always same UA) surfaced as a distinct boolean signal.
Fix #12  H4 URI entropy: fraction of high-entropy URIs, not mean entropy.
Fix #13  H1 validates resolved IP in DNS answers matches dst_ip.
Fix #14  Combined H1+H2 bonus when the same domain passes both hypotheses.
Fix #15  Benign domain list is configurable via CorroborationConfig.
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
# Known-benign signatures (hardcoded baseline — extended via config fix #15)
# ---------------------------------------------------------------------------

_BENIGN_UA_PATTERNS = [
    "microsoft update", "windows update", "wsus", "windows defender",
    "microsoft-cryptoapi", "mozilla/5.0 (windows nt",
    "curl/", "python-urllib", "go-http-client",
    "amazon cloudfront", "googlebot", "bingbot", "ntp", "ntpd",
]

_BASE_BENIGN_DOMAIN_SUFFIXES = (
    "windowsupdate.com", "microsoft.com", "windows.net", "azure.com",
    "office.com", "office365.com", "live.com", "msftconnecttest.com",
    "ocsp.verisign.net", "ocsp.digicert.com", "ctldl.windowsupdate.com",
    "googleapis.com", "gstatic.com", "amazon.com", "amazonaws.com",
    "cloudfront.net", "akamaiedge.net",
    # NTP and time services -- periodic by design, not beacons
    "time.google.com", "time.windows.com", "pool.ntp.org", "ntp.org",
    "time.apple.com", "time.cloudflare.com", "time.nist.gov",
    "google.com", "github.com",
)

# Backward-compat alias for any external imports
_BENIGN_DOMAIN_SUFFIXES = _BASE_BENIGN_DOMAIN_SUFFIXES


def _get_benign_suffixes(cfg: BDPConfig) -> tuple:
    """Fix #15: Merge hardcoded list with operator-supplied extras from config."""
    extra = tuple(cfg.corroboration.extra_benign_domain_suffixes or ())
    return _BASE_BENIGN_DOMAIN_SUFFIXES + extra


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


def _digit_run_density(label: str) -> float:
    """Fraction of the label covered by consecutive digit runs of length >= 3.

    Fix #4: Numeric-heavy DGA labels (e.g. 'a4k19x83m2z7') can pass the
    vowel/consonant-run checks but exhibit long digit runs uncommon in natural
    language domain labels.
    """
    runs = re.findall(r"\d{3,}", label)
    return sum(len(r) for r in runs) / max(len(label), 1)


def _is_likely_dga(domain: str, cfg: BDPConfig) -> bool:
    """Fix #4: Extended DGA heuristic includes digit-run density."""
    cc    = cfg.corroboration
    parts = domain.lower().rstrip(".").split(".")
    if len(parts) < 2:
        return False
    label = parts[0]
    if len(label) < cc.dga_min_label_len:
        return False
    entropy     = _string_entropy(label)
    no_vowels   = not re.search(r"[aeiou]", label)
    long_runs   = bool(re.search(r"[^aeiou]{6,}", label))
    digit_dense = _digit_run_density(label) > 0.30
    return entropy >= cc.dga_entropy_threshold and (no_vowels or long_runs or digit_dense)


def _is_benign_domain(domain: str, benign_suffixes: tuple) -> bool:
    """Fix #15: Accept benign_suffixes tuple so callers can pass config-merged list."""
    d = domain.lower().rstrip(".")
    return any(d == s or d.endswith("." + s) for s in benign_suffixes)


def _extract_answer_ips(answers_raw) -> list:
    """Parse the Zeek dns.log 'answers' field into a flat list of IP strings."""
    if not isinstance(answers_raw, str) or not answers_raw.strip():
        return []
    raw = answers_raw.strip("[]").replace('"', "")
    candidates = [a.strip() for a in raw.split(",") if a.strip()]
    ip_pattern = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$|^[0-9a-fA-F:]{3,}$")
    return [c for c in candidates if ip_pattern.match(c)]


def score_dns_hypothesis(
    src_ips:        set,
    dst_ips:        set,
    dns_df:         pd.DataFrame,
    beacon_period:  float,
    cfg:            BDPConfig,
    window_seconds: float = 0.0,
) -> dict:
    """Test H1 (DNS regularity) and H2 (DNS anomaly indicators).

    Parameters
    ----------
    window_seconds : Total observation window in seconds. Used by Fix #3 to
        compute the expected DNS query count and scale the minimum observation
        gate by the configured duty-cycle fraction.
    """
    cc         = cfg.corroboration
    benign_sfx = _get_benign_suffixes(cfg)

    null_result = {
        "h1_dns_regularity":    False,
        "h1_dns_period_s":      0.0,
        "h1_dns_period_delta":  1.0,
        "h2_dns_anomaly":       False,
        "h2_dga_domains":       [],
        "h2_nxdomain_count":    0,
        "h2_nxdomain_rate":     0.0,
        "h2_short_ttl_count":   0,
        "h2_fast_flux_domains": [],
        "dns_score":            0.0,
        "matched_domains":      [],
    }

    if dns_df.empty or "src_ip" not in dns_df.columns:
        return null_result

    src_dns = dns_df[dns_df["src_ip"].isin(src_ips)].copy()
    if src_dns.empty:
        return null_result

    # ------------------------------------------------------------------ #
    # Fix #3: Scale minimum observation count by expected firing count.  #
    # For beacon_period P over window W, expect W/P DNS queries.         #
    # Require at least dns_min_obs_duty_cycle * (W/P), floored at 3.    #
    # ------------------------------------------------------------------ #
    if beacon_period > 0 and window_seconds > 0:
        expected_firings = window_seconds / beacon_period
        min_dns_obs = max(3, int(expected_firings * cc.dns_min_obs_duty_cycle))
    else:
        min_dns_obs = 3

    # --- H1: DNS regularity ---
    h1_pass        = False
    h1_period_s    = 0.0
    h1_delta       = 1.0
    matched_domains: list = []

    # Fix #2: Track best (minimum delta) match rather than first-match.
    best_delta  = 1.0
    best_domain = ""
    best_period = 0.0

    if beacon_period > 0:
        for domain, dom_df in src_dns.groupby("query"):
            if _is_benign_domain(str(domain), benign_sfx):
                continue

            # Fix #3: duty-cycle-scaled minimum observation gate
            if len(dom_df) < min_dns_obs:
                continue

            dom_ts  = dom_df["ts"].sort_values()
            dns_iat = np.diff(dom_ts.values.astype("datetime64[ns]").astype(np.float64) / 1e9)
            if len(dns_iat) < 2:
                continue

            # Fix #1: median IAT (burst-resistant) + CV gate (periodicity check)
            median_iat = float(np.median(dns_iat))
            iat_cv     = float(dns_iat.std() / (median_iat + 1e-9))

            # Only treat as periodic DNS if the IAT sequence is itself regular
            if iat_cv > 0.60:
                continue

            delta = abs(median_iat - beacon_period) / (beacon_period + 1e-9)

            if delta <= cc.period_tolerance_pct:
                matched_domains.append(str(domain))

                # Fix #13: small penalty when resolved IPs don't include dst_ip
                if "answers" in dom_df.columns and dst_ips:
                    answer_ips: set = set()
                    for ans_raw in dom_df["answers"].dropna():
                        answer_ips.update(_extract_answer_ips(ans_raw))
                    if answer_ips and not answer_ips.intersection(dst_ips):
                        delta = min(delta + 0.05, 1.0)

                # Fix #2: keep the domain with the lowest delta
                if delta < best_delta:
                    best_delta  = delta
                    best_domain = str(domain)
                    best_period = median_iat

        if best_domain:
            h1_pass     = True
            h1_period_s = best_period
            h1_delta    = best_delta

    # --- H2: DNS anomaly indicators ---
    dga_domains:       list = []
    nxdomain_count:    int  = 0
    short_ttl_count:   int  = 0
    fast_flux_domains: list = []
    total_queries:     int  = len(src_dns)

    for domain, dom_df in src_dns.groupby("query"):
        domain_str = str(domain)
        if _is_benign_domain(domain_str, benign_sfx):
            continue

        # Fix #4: extended DGA check
        if _is_likely_dga(domain_str, cfg):
            dga_domains.append(domain_str)

        for _, dns_row in dom_df.iterrows():
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

        # Fix #6: fast-flux detection via unique resolved IPs per domain
        if "answers" in dom_df.columns:
            all_ips: set = set()
            for ans_raw in dom_df["answers"].dropna():
                all_ips.update(_extract_answer_ips(ans_raw))
            if len(all_ips) >= cc.fast_flux_unique_ip_threshold:
                fast_flux_domains.append(domain_str)

    # Fix #5: rate-normalise NXDomain
    nxdomain_rate        = nxdomain_count / max(total_queries, 1)
    nxdomain_significant = nxdomain_rate >= cc.nxdomain_rate_threshold or nxdomain_count > 0

    h2_pass = (
        bool(dga_domains)
        or nxdomain_significant
        or short_ttl_count > 0
        or bool(fast_flux_domains)
    )

    # Fix #14: bonus when the same domain drives both H1 (periodic) and H2 (anomalous)
    h1_h2_overlap = bool(matched_domains) and bool(
        set(matched_domains) & (set(dga_domains) | set(fast_flux_domains))
    )
    overlap_bonus = 0.10 if h1_h2_overlap else 0.0

    dns_score = float(np.clip(
        0.35 * float(h1_pass)
        + 0.40 * float(h2_pass)
        + 0.15 * float(bool(dga_domains))
        + 0.10 * float(nxdomain_significant)
        + overlap_bonus,
        0.0, 1.0,
    ))

    return {
        "h1_dns_regularity":    h1_pass,
        "h1_dns_period_s":      round(h1_period_s, 1),
        "h1_dns_period_delta":  round(h1_delta, 4),
        "h2_dns_anomaly":       h2_pass,
        "h2_dga_domains":       list(set(dga_domains))[:10],
        "h2_nxdomain_count":    nxdomain_count,
        "h2_nxdomain_rate":     round(nxdomain_rate, 4),
        "h2_short_ttl_count":   short_ttl_count,
        "h2_fast_flux_domains": fast_flux_domains[:10],
        "dns_score":            round(dns_score, 4),
        "matched_domains":      matched_domains[:10],
    }


# ---------------------------------------------------------------------------
# HTTP helpers (H3 + H4)
# ---------------------------------------------------------------------------

def _is_benign_ua(ua: str) -> bool:
    if not isinstance(ua, str):
        return False
    ua_lower = ua.lower()
    return any(pattern in ua_lower for pattern in _BENIGN_UA_PATTERNS)


def _uri_path(uri: str) -> str:
    """Return the path component of a URI, stripping the query string."""
    return uri.split("?")[0] if isinstance(uri, str) else ""


def score_http_hypothesis(
    src_ips:        set,
    dst_ips:        set,
    http_df:        pd.DataFrame,
    cfg:            BDPConfig,
    global_ua_freq: Optional[pd.Series] = None,
) -> dict:
    """Test H3 (HTTP behavioral consistency) and H4 (HTTP evasion indicators).

    Parameters
    ----------
    global_ua_freq : Pre-computed normalised value_counts of user_agent across
        the full HTTP log. Used by Fix #10 for global UA rarity detection.
        If None, falls back to pair-local UA frequency (original behaviour).
    """
    cc = cfg.corroboration

    null_result = {
        "h3_http_consistency":   False,
        "h3_response_body_cv":   np.nan,
        "h3_uri_len_cv":         np.nan,
        "h3_path_cv":            np.nan,
        "h3_consistency_score":  0.0,
        "h4_rare_ua":            False,
        "h4_ua_monotony":        False,
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

    # ------------------------------------------------------------------ #
    # H3: HTTP Behavioral Consistency                                     #
    # Fix #7: weighted combination score instead of OR-logic boolean.    #
    # Fix #8: trim top/bottom body_cv_trim_pct before computing CV.      #
    # Fix #9: compute CV on URI path component separately.               #
    # ------------------------------------------------------------------ #
    body_cv = np.nan
    uri_cv  = np.nan
    path_cv = np.nan
    trim_p  = cc.body_cv_trim_pct

    if "response_body_len" in cluster_http.columns:
        body_vals = pd.to_numeric(cluster_http["response_body_len"], errors="coerce").dropna()
        if len(body_vals) > 1 and body_vals.mean() > 0:
            # Fix #8: trimmed distribution — drop top/bottom percentile
            lo, hi = body_vals.quantile([trim_p, 1.0 - trim_p])
            trimmed = body_vals[(body_vals >= lo) & (body_vals <= hi)]
            if len(trimmed) > 1 and trimmed.mean() > 0:
                body_cv = float(trimmed.std() / trimmed.mean())

    if "uri" in cluster_http.columns:
        uris = cluster_http["uri"].dropna()

        # Fix #9a: full URI length CV
        uri_lens = uris.apply(len)
        if len(uri_lens) > 1 and uri_lens.mean() > 0:
            uri_cv = float(uri_lens.std() / uri_lens.mean())

        # Fix #9b: path-only CV
        path_lens = uris.apply(_uri_path).apply(len)
        if len(path_lens) > 1 and path_lens.mean() > 0:
            path_cv = float(path_lens.std() / path_lens.mean())

    # Fix #7: weighted H3 score; normalise by the weight of available signals
    h3_components    = []
    available_weight = 0.0
    if not np.isnan(body_cv):
        w = 0.4
        h3_components.append(w * float(body_cv < cc.http_body_cv_threshold))
        available_weight += w
    if not np.isnan(uri_cv):
        w = 0.3
        h3_components.append(w * float(uri_cv < cc.http_uri_cv_threshold))
        available_weight += w
    if not np.isnan(path_cv):
        w = 0.3
        h3_components.append(w * float(path_cv < cc.http_uri_cv_threshold))
        available_weight += w

    h3_consistency_score = (sum(h3_components) / available_weight) if available_weight > 0 else 0.0
    h3_pass = h3_consistency_score >= 0.50

    # ------------------------------------------------------------------ #
    # H4: HTTP Evasion Indicators                                        #
    # Fix #10: UA rarity vs. global distribution.                        #
    # Fix #11: UA monotony (always the same UA) as a distinct signal.    #
    # Fix #12: fraction of high-entropy URIs instead of mean entropy.    #
    # ------------------------------------------------------------------ #
    rare_ua_global = False
    ua_monotony    = False

    if "user_agent" in cluster_http.columns:
        ua_counts  = cluster_http["user_agent"].fillna("").value_counts()
        if len(ua_counts) > 0:
            top_ua_str = str(ua_counts.index[0])

            # Fix #11: monotony — pair always (or nearly always) uses one UA
            ua_monotony = float(ua_counts.iloc[0] / n_flows) >= (1.0 - cc.rare_ua_threshold)

            # Fix #10: rarity against global distribution
            if global_ua_freq is not None and top_ua_str:
                rare_ua_global = float(global_ua_freq.get(top_ua_str, 0.0)) < cc.global_ua_rare_threshold
            else:
                # Fallback to pair-local frequency (original behaviour)
                rare_ua_global = float(ua_counts.iloc[0] / n_flows) < cc.rare_ua_threshold

    # Fix #12: fraction-based high-entropy URI detection
    high_entropy_uri = False
    if "uri" in cluster_http.columns:
        uri_entropies    = cluster_http["uri"].fillna("").apply(_string_entropy)
        frac_high        = float((uri_entropies > cc.uri_entropy_threshold).mean())
        high_entropy_uri = frac_high >= cc.high_entropy_uri_frac

    abnormal_methods: list = []
    if "method" in cluster_http.columns:
        normal_methods   = {"GET", "POST", "HEAD", "OPTIONS"}
        observed_methods = set(cluster_http["method"].dropna().str.upper().unique())
        abnormal_methods = sorted(observed_methods - normal_methods)

    h4_pass = rare_ua_global or ua_monotony or high_entropy_uri or bool(abnormal_methods)

    http_score = float(np.clip(
        0.30 * float(h3_pass)
        + 0.25 * float(rare_ua_global)
        + 0.15 * float(ua_monotony)
        + 0.20 * float(high_entropy_uri)
        + 0.10 * float(bool(abnormal_methods)),
        0.0, 1.0,
    ))

    unique_uas = cluster_http["user_agent"].dropna().unique().tolist() \
        if "user_agent" in cluster_http.columns else []

    return {
        "h3_http_consistency":   h3_pass,
        "h3_response_body_cv":   round(body_cv, 4)  if not np.isnan(body_cv)  else np.nan,
        "h3_uri_len_cv":         round(uri_cv, 4)   if not np.isnan(uri_cv)   else np.nan,
        "h3_path_cv":            round(path_cv, 4)  if not np.isnan(path_cv)  else np.nan,
        "h3_consistency_score":  round(h3_consistency_score, 4),
        "h4_rare_ua":            rare_ua_global,
        "h4_ua_monotony":        ua_monotony,
        "h4_high_uri_entropy":   high_entropy_uri,
        "h4_abnormal_methods":   abnormal_methods,
        "h4_evasion_indicators": h4_pass,
        "http_score":            round(http_score, 4),
        "http_flow_count":       n_flows,
        "unique_user_agents":    unique_uas[:10],
        "benign_ua_filtered":    benign_ua_count,
    }


# ---------------------------------------------------------------------------
# TLS/SSL log loading and helpers (H5 + H6)  — Point 7
# ---------------------------------------------------------------------------

def load_ssl_logs(path: str, cfg: BDPConfig) -> pd.DataFrame:
    """Load and normalise a Zeek ssl.log CSV export.

    Expected Zeek ssl.log columns used:
        ts, id.orig_h (src_ip), id.resp_h (dst_ip),
        server_name (SNI), ja3, ja3s,
        cert_chain_fuids, validation_status,
        resumed, established
    """
    df = pd.read_csv(path, low_memory=False)

    rename = {
        "ts":             "ts",
        "id.orig_h":      "src_ip",
        "id.resp_h":      "dst_ip",
        "server_name":    "server_name",
        "ja3":            "ja3",
        "ja3s":           "ja3s",
        "cert_chain_fuids": "cert_chain_fuids",
        "validation_status": "validation_status",
        "resumed":        "resumed",
        "established":    "established",
        "cert_chain":     "cert_chain_fuids",   # alternate name
    }
    for src, dst in rename.items():
        if src in df.columns and dst not in df.columns:
            df = df.rename(columns={src: dst})

    if "ts" not in df.columns:
        raise ValueError(f"SSL log missing 'ts' column. Available: {list(df.columns)[:20]}")

    df["ts"] = pd.to_datetime(df["ts"], unit="s", utc=True, errors="coerce")

    if cfg.io.query_start:
        df = df[df["ts"] >= pd.to_datetime(cfg.io.query_start, utc=True)]
    if cfg.io.query_end:
        df = df[df["ts"] <= pd.to_datetime(cfg.io.query_end, utc=True)]

    df = df.dropna(subset=["ts"]).copy()
    log.info("SSL log loaded: %d records", len(df))
    return df


def score_tls_hypothesis(
    src_ips: set,
    dst_ips: set,
    ssl_df:  pd.DataFrame,
    cfg:     BDPConfig,
) -> dict:
    """Test H5 (TLS behavioral consistency) and H6 (TLS evasion indicators).

    H5 — TLS Consistency
        SNI stable (low entropy across sessions), JA3 fingerprint monotonic
        (same client hello every time), certificate reused across sessions.
        These properties distinguish automated C2 from human browsing.

    H6 — TLS Evasion
        Self-signed or validation-failing certificate, newly issued cert
        (< N days old), known C2 JA3 fingerprint, absent SNI (raw IP C2),
        high session resumption rate (beacon maintaining persistent session).

    Parameters
    ----------
    src_ips : Source IPs for this channel.
    dst_ips : Destination IPs for this channel.
    ssl_df  : Normalised SSL log DataFrame from load_ssl_logs().
    cfg     : Pipeline configuration.
    """
    tc = cfg.corroboration.tls

    null_result = {
        "h5_tls_consistency":    False,
        "h5_sni_stable":         False,
        "h5_ja3_monotonic":      False,
        "h5_cert_reused":        False,
        "h6_tls_evasion":        False,
        "h6_self_signed":        False,
        "h6_new_cert":           False,
        "h6_known_c2_ja3":       False,
        "h6_absent_sni":         False,
        "h6_high_resumption":    False,
        "tls_score":             0.0,
        "ssl_flow_count":        0,
        "observed_snis":         [],
        "observed_ja3s":         [],
    }

    if ssl_df.empty or "src_ip" not in ssl_df.columns:
        return null_result

    pair_ssl = ssl_df[
        ssl_df["src_ip"].isin(src_ips)
        & (ssl_df["dst_ip"].isin(dst_ips) if "dst_ip" in ssl_df.columns else True)
    ].copy()

    if pair_ssl.empty:
        return null_result

    n = len(pair_ssl)

    # ------------------------------------------------------------------ #
    # H5: TLS Behavioral Consistency                                      #
    # ------------------------------------------------------------------ #

    # SNI stability: entropy of the server_name distribution
    sni_stable = False
    observed_snis: list = []
    if "server_name" in pair_ssl.columns:
        snis = pair_ssl["server_name"].dropna().astype(str)
        snis = snis[snis != "-"]
        observed_snis = snis.unique().tolist()[:10]
        if len(snis) > 0:
            sni_entropy = _string_entropy(" ".join(snis))   # reuse existing helper
            # Low entropy = consistently the same SNI = automation signal
            sni_stable = sni_entropy < tc.sni_entropy_threshold or snis.nunique() == 1

    # JA3 monotony: fraction of sessions using the same JA3 fingerprint
    ja3_monotonic = False
    observed_ja3s: list = []
    if "ja3" in pair_ssl.columns:
        ja3s = pair_ssl["ja3"].dropna().astype(str)
        ja3s = ja3s[ja3s.str.len() == 32]   # valid MD5
        observed_ja3s = ja3s.unique().tolist()[:5]
        if len(ja3s) > 0:
            top_frac = float(ja3s.value_counts().iloc[0] / len(ja3s))
            ja3_monotonic = top_frac >= tc.ja3_monotony_threshold

    # Certificate reuse: same cert chain across >= N sessions
    cert_reused = False
    if "cert_chain_fuids" in pair_ssl.columns:
        certs = pair_ssl["cert_chain_fuids"].dropna().astype(str)
        certs = certs[certs.str.len() > 0]
        if len(certs) >= tc.cert_reuse_min_sessions:
            top_count = int(certs.value_counts().iloc[0])
            cert_reused = top_count >= tc.cert_reuse_min_sessions

    h5_pass = (sni_stable and ja3_monotonic) or (ja3_monotonic and cert_reused) or (sni_stable and cert_reused)

    # ------------------------------------------------------------------ #
    # H6: TLS Evasion Indicators                                          #
    # ------------------------------------------------------------------ #

    # Self-signed / validation failure
    self_signed = False
    if "validation_status" in pair_ssl.columns:
        statuses = pair_ssl["validation_status"].fillna("").astype(str).str.lower()
        fail_keywords = ("self signed", "unable to get", "certificate verify failed",
                         "unknown ca", "self-signed")
        self_signed = bool(statuses.apply(
            lambda s: any(kw in s for kw in fail_keywords)
        ).any())

    # Known C2 JA3 fingerprint
    known_c2_ja3 = False
    if observed_ja3s and tc.ja3_known_c2:
        known_c2_ja3 = bool(set(observed_ja3s) & set(tc.ja3_known_c2))

    # Absent SNI (raw IP contact — no hostname in ClientHello)
    absent_sni = False
    if "server_name" in pair_ssl.columns:
        sni_present = pair_ssl["server_name"].dropna()
        sni_present = sni_present[
            (sni_present.astype(str) != "-") & (sni_present.astype(str).str.strip() != "")
        ]
        absent_sni = len(sni_present) == 0

    # High session resumption rate (beacon reusing TLS session to reduce overhead)
    high_resumption = False
    if "resumed" in pair_ssl.columns:
        resumed_vals = pair_ssl["resumed"].astype(str).str.lower()
        resumption_rate = float((resumed_vals == "true").mean())
        high_resumption = resumption_rate > 0.80

    # New cert heuristic: if we have cert timestamps or serial patterns,
    # we could compute age — but Zeek ssl.log doesn't expose cert_not_before
    # directly. We flag this as False unless a future enrichment step adds it.
    new_cert = False

    h6_pass = self_signed or known_c2_ja3 or absent_sni or high_resumption or new_cert

    # TLS score: weighted combination of component signals
    tls_score = float(np.clip(
        tc.h5_weight * (
            0.40 * float(sni_stable)
            + 0.40 * float(ja3_monotonic)
            + 0.20 * float(cert_reused)
        )
        + tc.h6_weight * (
            0.30 * float(self_signed)
            + 0.25 * float(known_c2_ja3)
            + 0.25 * float(absent_sni)
            + 0.20 * float(high_resumption)
        ),
        0.0, 1.0,
    ))

    return {
        "h5_tls_consistency":    h5_pass,
        "h5_sni_stable":         sni_stable,
        "h5_ja3_monotonic":      ja3_monotonic,
        "h5_cert_reused":        cert_reused,
        "h6_tls_evasion":        h6_pass,
        "h6_self_signed":        self_signed,
        "h6_new_cert":           new_cert,
        "h6_known_c2_ja3":       known_c2_ja3,
        "h6_absent_sni":         absent_sni,
        "h6_high_resumption":    high_resumption,
        "tls_score":             round(tls_score, 4),
        "ssl_flow_count":        n,
        "observed_snis":         observed_snis,
        "observed_ja3s":         observed_ja3s,
    }


# ---------------------------------------------------------------------------
# Corroboration score
# ---------------------------------------------------------------------------

def _corroboration_score(
    dns_score:       float,
    http_score:      float,
    tls_score:       float,
    h1_pass:         bool,
    h2_pass:         bool,
    h3_pass:         bool,
    h4_pass:         bool,
    h5_pass:         bool,
    h6_pass:         bool,
    http_flow_count: int = 0,
    ssl_flow_count:  int = 0,
) -> float:
    """
    Compute corroboration score in [0, 1].

    Evidence tiers (adaptive weight redistribution):
    - HTTP present:  DNS(0.30) + HTTP(0.30) + TLS(0.20) + booleans(0.20)
    - TLS only:      DNS(0.40) + TLS(0.40) + booleans(0.20)
    - DNS only:      DNS(0.60) + booleans(0.40)

    Absence of a log type is neutral (weight redistributes), not negative.
    """
    has_http = http_flow_count > 0
    has_tls  = ssl_flow_count  > 0

    if has_http and has_tls:
        # Full cross-layer evidence
        bool_score = (
            0.20 * float(h1_pass)
            + 0.25 * float(h2_pass)
            + 0.15 * float(h3_pass)
            + 0.15 * float(h4_pass)
            + 0.13 * float(h5_pass)
            + 0.12 * float(h6_pass)
        )
        return round(
            0.30 * dns_score + 0.30 * http_score + 0.20 * tls_score + 0.20 * bool_score,
            4,
        )
    elif has_http and not has_tls:
        # DNS + HTTP (original path)
        bool_score = (
            0.25 * float(h1_pass)
            + 0.35 * float(h2_pass)
            + 0.20 * float(h3_pass)
            + 0.20 * float(h4_pass)
        )
        return round(0.60 * bool_score + 0.20 * dns_score + 0.20 * http_score, 4)
    elif has_tls and not has_http:
        # DNS + TLS (HTTPS/encrypted beacons)
        bool_score = (
            0.25 * float(h1_pass)
            + 0.35 * float(h2_pass)
            + 0.20 * float(h5_pass)
            + 0.20 * float(h6_pass)
        )
        return round(0.40 * dns_score + 0.40 * tls_score + 0.20 * bool_score, 4)
    else:
        # DNS only (no HTTP or TLS log)
        bool_score = (
            0.35 * float(h1_pass)
            + 0.65 * float(h2_pass)
        )
        return round(0.55 * bool_score + 0.45 * dns_score, 4)


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def corroborate_beacon_candidates(
    periodicity_df: pd.DataFrame,
    df_anomalies:   pd.DataFrame,
    dns_df:         pd.DataFrame,
    http_df:        pd.DataFrame,
    cfg:            BDPConfig,
    ssl_df:         Optional[pd.DataFrame] = None,   # Point 7
) -> pd.DataFrame:
    """
    Cross-validate every beacon-candidate channel against DNS, HTTP, and TLS evidence.

    Parameters
    ----------
    periodicity_df : Output of periodicity.score_all_pairs().
    df_anomalies   : Raw anomaly DataFrame with src_ip, dst_ip, channel_id columns.
    dns_df         : Normalised DNS log DataFrame from load_dns_logs().
    http_df        : Normalised HTTP log DataFrame from load_http_logs().
    cfg            : Pipeline configuration.
    ssl_df         : Optional normalised SSL log from load_ssl_logs() (Point 7).

    Returns
    -------
    pd.DataFrame -- one row per beacon candidate with H1-H6 results and
    final corroborated boolean. Sorted by corroboration_score descending.
    """
    candidates = periodicity_df[periodicity_df["is_beacon_pair"]].copy()

    if candidates.empty:
        log.warning("No beacon candidates to corroborate -- periodicity stage found none.")
        return pd.DataFrame()

    # Pre-compute global UA frequency once across all HTTP traffic.
    global_ua_freq: Optional[pd.Series] = None
    if not http_df.empty and "user_agent" in http_df.columns:
        global_ua_freq = http_df["user_agent"].dropna().value_counts(normalize=True)

    # Determine observation window length for DNS duty-cycle gate.
    window_seconds = 0.0
    if not dns_df.empty and "ts" in dns_df.columns:
        ts_range = dns_df["ts"].agg(["min", "max"])
        if pd.notna(ts_range["min"]) and pd.notna(ts_range["max"]):
            window_seconds = (ts_range["max"] - ts_range["min"]).total_seconds()
    if window_seconds == 0.0 and cfg.io.query_start and cfg.io.query_end:
        try:
            t0 = pd.to_datetime(cfg.io.query_start, utc=True)
            t1 = pd.to_datetime(cfg.io.query_end, utc=True)
            window_seconds = (t1 - t0).total_seconds()
        except Exception:
            pass

    ssl_available = ssl_df is not None and not ssl_df.empty
    log.info(
        "Corroborating %d beacon candidate channels (ssl=%s).",
        len(candidates), ssl_available,
    )
    results = []

    for _, row in candidates.iterrows():
        src = row["src_ip"]
        dst = row["dst_ip"]
        channel_id = str(row.get("channel_id", f"{src}→{dst}"))

        # Retrieve flows using channel_id if available for precision (Point 1)
        if "channel_id" in df_anomalies.columns:
            pair_df = df_anomalies[df_anomalies["channel_id"] == channel_id]
        else:
            pair_df = df_anomalies[
                (df_anomalies["src_ip"] == src) & (df_anomalies["dst_ip"] == dst)
            ]

        src_ips       = {src}
        dst_ips       = {dst}
        beacon_period = float(row.get("dominant_period_s", 0.0))

        dns_result  = score_dns_hypothesis(
            src_ips, dst_ips, dns_df, beacon_period, cfg,
            window_seconds=window_seconds,
        )
        http_result = score_http_hypothesis(
            src_ips, dst_ips, http_df, cfg,
            global_ua_freq=global_ua_freq,
        )
        # Point 7: TLS corroboration (null result if no ssl_df)
        tls_result = score_tls_hypothesis(
            src_ips, dst_ips,
            ssl_df if ssl_available else pd.DataFrame(),
            cfg,
        )

        corr_score = _corroboration_score(
            dns_score        = dns_result["dns_score"],
            http_score       = http_result["http_score"],
            tls_score        = tls_result["tls_score"],
            h1_pass          = dns_result["h1_dns_regularity"],
            h2_pass          = dns_result["h2_dns_anomaly"],
            h3_pass          = http_result["h3_http_consistency"],
            h4_pass          = http_result["h4_evasion_indicators"],
            h5_pass          = tls_result["h5_tls_consistency"],
            h6_pass          = tls_result["h6_tls_evasion"],
            http_flow_count  = http_result["http_flow_count"],
            ssl_flow_count   = tls_result["ssl_flow_count"],
        )

        results.append({
            # Identity
            "channel_id":            channel_id,
            "pair_id":               row["pair_id"],
            "src_ip":                src,
            "dst_ip":                dst,
            "flow_count":            len(pair_df),
            # Periodicity (carried forward)
            "beacon_confidence":     row["beacon_confidence"],
            "dominant_period_s":     row["dominant_period_s"],
            "is_periodic":           row["is_periodic"],
            # H1
            "h1_dns_regularity":     dns_result["h1_dns_regularity"],
            "h1_dns_period_s":       dns_result["h1_dns_period_s"],
            "h1_period_delta_pct":   dns_result["h1_dns_period_delta"],
            # H2
            "h2_dns_anomaly":        dns_result["h2_dns_anomaly"],
            "h2_dga_domain_count":   len(dns_result["h2_dga_domains"]),
            "h2_nxdomain_count":     dns_result["h2_nxdomain_count"],
            "h2_nxdomain_rate":      dns_result["h2_nxdomain_rate"],
            "h2_short_ttl_count":    dns_result["h2_short_ttl_count"],
            "h2_fast_flux_count":    len(dns_result["h2_fast_flux_domains"]),
            "h2_dga_domains":        dns_result["h2_dga_domains"],
            "h2_fast_flux_domains":  dns_result["h2_fast_flux_domains"],
            # H3
            "h3_http_consistency":   http_result["h3_http_consistency"],
            "h3_response_body_cv":   http_result["h3_response_body_cv"],
            "h3_uri_len_cv":         http_result["h3_uri_len_cv"],
            "h3_path_cv":            http_result["h3_path_cv"],
            "h3_consistency_score":  http_result["h3_consistency_score"],
            # H4
            "h4_evasion_indicators": http_result["h4_evasion_indicators"],
            "h4_rare_ua":            http_result["h4_rare_ua"],
            "h4_ua_monotony":        http_result["h4_ua_monotony"],
            "h4_high_uri_entropy":   http_result["h4_high_uri_entropy"],
            "h4_abnormal_methods":   http_result["h4_abnormal_methods"],
            # H5 (TLS consistency)
            "h5_tls_consistency":    tls_result["h5_tls_consistency"],
            "h5_sni_stable":         tls_result["h5_sni_stable"],
            "h5_ja3_monotonic":      tls_result["h5_ja3_monotonic"],
            "h5_cert_reused":        tls_result["h5_cert_reused"],
            # H6 (TLS evasion)
            "h6_tls_evasion":        tls_result["h6_tls_evasion"],
            "h6_self_signed":        tls_result["h6_self_signed"],
            "h6_known_c2_ja3":       tls_result["h6_known_c2_ja3"],
            "h6_absent_sni":         tls_result["h6_absent_sni"],
            "h6_high_resumption":    tls_result["h6_high_resumption"],
            # Composite
            "dns_score":             dns_result["dns_score"],
            "http_score":            http_result["http_score"],
            "tls_score":             tls_result["tls_score"],
            "corroboration_score":   corr_score,
            "corroborated":          corr_score >= cfg.corroboration.min_score,
            # Analyst context
            "matched_domains":       dns_result["matched_domains"][:5],
            "unique_user_agents":    http_result["unique_user_agents"],
            "observed_snis":         tls_result["observed_snis"],
            "observed_ja3s":         tls_result["observed_ja3s"],
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
        log.warning("No data to plot -- corroboration_df is empty.")
        return

    df     = corroboration_df.copy()
    colors = ["#d62728" if v else "#1f77b4" for v in df["corroborated"]]

    fig, axes = plt.subplots(2, 2, figsize=(16, 10))

    axes[0, 0].bar(range(len(df)), df["corroboration_score"], color=colors)
    axes[0, 0].set_xticks(range(len(df)))
    axes[0, 0].set_xticklabels(df["pair_id"].astype(str), rotation=90, fontsize=6)
    axes[0, 0].set_xlabel("Pair (src->dst)")
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
    print(f"  BEACON ANALYTIC -- TOP {len(corroborated)} CORROBORATED CANDIDATES")
    print("=" * 70)

    for rank, (_, row) in enumerate(corroborated.iterrows(), start=1):
        period_min = row["dominant_period_s"] / 60 if row["dominant_period_s"] > 0 else 0
        print(f"\n  #{rank}  {row['src_ip']} -> {row['dst_ip']}  ({int(row['flow_count'])} flows)")
        print(f"  {'─' * 60}")
        print(f"  Beacon period     : {row['dominant_period_s']:.0f}s  ({period_min:.1f} min)")
        print(f"  Beacon confidence : {row['beacon_confidence']:.3f}  "
              f"Corroboration score: {row['corroboration_score']:.3f}")
        print()
        print(f"  DNS evidence:")
        print(f"    H1 Regularity  {'✓' if row['h1_dns_regularity'] else '✗'}  "
              f"DNS period={row['h1_dns_period_s']:.0f}s  "
              f"(Delta={row['h1_period_delta_pct']:.1%} vs conn period)")
        print(f"    H2 Anomaly     {'✓' if row['h2_dns_anomaly'] else '✗'}  "
              f"DGA={row['h2_dga_domain_count']}  "
              f"NXD={row['h2_nxdomain_count']} ({row.get('h2_nxdomain_rate', 0):.1%})  "
              f"ShortTTL={row['h2_short_ttl_count']}  "
              f"FastFlux={row.get('h2_fast_flux_count', 0)}")
        if row["h2_dga_domains"]:
            for d in row["h2_dga_domains"][:3]:
                print(f"             DGA candidate: {d}")
        if row.get("h2_fast_flux_domains"):
            for d in row["h2_fast_flux_domains"][:2]:
                print(f"             Fast-flux domain: {d}")
        if row["matched_domains"]:
            for d in row["matched_domains"][:3]:
                print(f"             Domain: {d}")
        print()
        print(f"  HTTP evidence:")
        print(f"    H3 Consistency {'✓' if row['h3_http_consistency'] else '✗'}  "
              f"body_CV={row['h3_response_body_cv']:.3f}  "
              f"uri_CV={row['h3_uri_len_cv']:.3f}  "
              f"path_CV={row.get('h3_path_cv', float('nan')):.3f}  "
              f"score={row.get('h3_consistency_score', 0):.2f}")
        print(f"    H4 Evasion     {'✓' if row['h4_evasion_indicators'] else '✗'}  "
              f"rare_UA={row['h4_rare_ua']}  "
              f"ua_monotony={row.get('h4_ua_monotony', False)}  "
              f"high_entropy_URI={row['h4_high_uri_entropy']}")
        if row["h4_abnormal_methods"]:
            print(f"             Abnormal methods: {row['h4_abnormal_methods']}")
        if row["unique_user_agents"]:
            for ua in row["unique_user_agents"][:2]:
                print(f"             UA: {str(ua)[:60]}")
        print()
        print(f"  TLS evidence:")
        print(f"    H5 Consistency {'✓' if row.get('h5_tls_consistency') else '✗'}  "
              f"sni_stable={row.get('h5_sni_stable', False)}  "
              f"ja3_monotonic={row.get('h5_ja3_monotonic', False)}  "
              f"cert_reused={row.get('h5_cert_reused', False)}")
        print(f"    H6 Evasion     {'✓' if row.get('h6_tls_evasion') else '✗'}  "
              f"self_signed={row.get('h6_self_signed', False)}  "
              f"known_ja3={row.get('h6_known_c2_ja3', False)}  "
              f"absent_sni={row.get('h6_absent_sni', False)}  "
              f"high_resume={row.get('h6_high_resumption', False)}")
        if row.get("observed_snis"):
            for s in row["observed_snis"][:2]:
                print(f"             SNI: {str(s)[:60]}")
        if row.get("observed_ja3s"):
            for j in row["observed_ja3s"][:2]:
                print(f"             JA3: {str(j)[:36]}")

    print("\n" + "=" * 70)
    print(f"  {len(corroborated)} pairs warrant analyst investigation.")
    print(f"  Investigate in order of corroboration_score descending.")
    print("=" * 70)
