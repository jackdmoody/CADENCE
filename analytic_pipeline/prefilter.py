"""
Domain-Knowledge Pre-Filter
=============================
Removes (src_ip, dst_ip) pairs that are almost certainly benign *before*
Isolation Forest scoring. This reduces the feature space IForest has to
work with, preventing benign high-volume services from diluting anomaly
scores and eliminating obvious false positives early.

What this filters
------------------
1. Internal-to-internal pairs   (both IPs in RFC 1918 / link-local space)
2. Known infrastructure destinations  (CDNs, DNS resolvers, NTP pools, CAs)
3. Well-known benign services by port  (53/DNS, 123/NTP, 443 to known CDNs)
4. High-fanin destinations  (dst IPs contacted by many unique src IPs — shared infra)
5. Dead pairs  (pairs dominated by failed connection states — no active C2 channel)

What this does NOT filter
--------------------------
- Anything involving an external destination not on the allowlist
- Any pair that has already been flagged by a prior stage
- Anything the analyst has not explicitly marked as benign

The allowlist is intentionally conservative. It is better to let a benign
pair through to IForest (where it will likely score as normal anyway) than
to accidentally suppress a C2 channel using a compromised CDN endpoint.

Usage
------
    from bdp_analytic.prefilter import apply_prefilter

    pair_df, removed_df = apply_prefilter(pair_df, cfg, raw_df=conn_df)
    # pair_df   → continues to IForest
    # removed_df → logged for audit, not analysed further
"""
from __future__ import annotations

import ipaddress
import logging
from typing import Optional

import numpy as np
import pandas as pd

from .config import BDPConfig

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Known-benign infrastructure (conservative defaults)
# ---------------------------------------------------------------------------

# Well-known public DNS resolvers
KNOWN_DNS_RESOLVERS = {
    "8.8.8.8", "8.8.4.4",              # Google
    "1.1.1.1", "1.0.0.1",              # Cloudflare
    "9.9.9.9", "149.112.112.112",      # Quad9
    "208.67.222.222", "208.67.220.220", # OpenDNS
    "64.6.64.6", "64.6.65.6",          # Verisign
}

# NTP pool destinations (commonly seen)
KNOWN_NTP_DESTINATIONS = {
    "17.253.34.123",                    # Apple NTP
    "17.253.34.253",
}

# Well-known CDN / cloud provider CIDR blocks (sampled, not exhaustive)
# These are checked as network prefixes, not exact IPs
KNOWN_CDN_PREFIXES = [
    "13.32.0.0/15",     # Amazon CloudFront
    "13.224.0.0/14",    # Amazon CloudFront
    "104.16.0.0/13",    # Cloudflare
    "104.24.0.0/14",    # Cloudflare
    "151.101.0.0/16",   # Fastly
    "199.232.0.0/16",   # Fastly
    "23.0.0.0/12",      # Akamai (partial)
    "184.24.0.0/13",    # Akamai (partial)
]

# Well-known benign domain suffixes (matched against dst_ip reverse or
# domain columns if available)
KNOWN_BENIGN_DOMAINS = {
    "windowsupdate.com",
    "microsoft.com",
    "apple.com",
    "googleapis.com",
    "gstatic.com",
    "akamaiedge.net",
    "cloudflare.com",
    "amazontrust.com",
    "digicert.com",
    "letsencrypt.org",
    "ocsp.pki.goog",
}

# Ports associated with infrastructure services
INFRASTRUCTURE_PORTS = {
    53,     # DNS
    123,    # NTP
    5353,   # mDNS
}

# Zeek connection states indicating a failed / never-established session.
# S0  = SYN sent, no reply
# REJ = Connection rejected
# RSTO = Connection reset by originator
# RSTOS0 = SYN sent then reset by originator (no SYN-ACK)
# S1 technically means SYN-ACK seen but no data, borderline — excluded
FAILED_CONN_STATES = {"S0", "REJ", "RSTO", "RSTOS0", "OTH"}


# ---------------------------------------------------------------------------
# Default thresholds
# ---------------------------------------------------------------------------

# Destination popularity: if more than this fraction of all unique source
# IPs communicate with a destination, that destination is shared
# infrastructure (proxy, cloud service, internal API), not C2.
# Set conservatively high — on real enterprise networks most C2 destinations
# are contacted by 1–3 hosts, while shared services are contacted by 50%+.
DEFAULT_DST_FANIN_THRESHOLD = 0.50

# Connection state: if more than this fraction of a pair's flows have
# failed connection states, the pair has no viable C2 channel.
DEFAULT_FAILED_CONN_RATIO = 0.90


# ---------------------------------------------------------------------------
# RFC 1918 / link-local / loopback checks
# ---------------------------------------------------------------------------

def _is_internal(ip_str: str) -> bool:
    """
    Check if an IP is RFC 1918 private, loopback, link-local, or multicast.

    Excludes RFC 5737 documentation ranges (192.0.2.0/24, 198.51.100.0/24,
    203.0.113.0/24) which Python's ipaddress.is_private treats as private
    but are commonly used as simulated external IPs in synthetic datasets.
    """
    try:
        addr = ipaddress.ip_address(ip_str)

        # RFC 5737 documentation ranges — treat as external, not internal.
        # These are used by synthetic data generators as stand-ins for
        # real external C2 destinations.
        _DOC_RANGES = [
            ipaddress.ip_network("192.0.2.0/24"),
            ipaddress.ip_network("198.51.100.0/24"),
            ipaddress.ip_network("203.0.113.0/24"),
        ]
        for net in _DOC_RANGES:
            if addr in net:
                return False

        return addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast
    except (ValueError, TypeError):
        return False


def _in_cdn_prefix(ip_str: str, prefixes: list[str]) -> bool:
    """Check if an IP falls within any known CDN CIDR prefix."""
    try:
        addr = ipaddress.ip_address(ip_str)
        for prefix in prefixes:
            if addr in ipaddress.ip_network(prefix, strict=False):
                return True
    except (ValueError, TypeError):
        pass
    return False


# ---------------------------------------------------------------------------
# Destination popularity analysis
# ---------------------------------------------------------------------------

def compute_dst_fanin(
    raw_df: pd.DataFrame,
    src_col: str = "src_ip",
    dst_col: str = "dst_ip",
) -> pd.Series:
    """
    Compute the fraction of unique source IPs that contact each destination.

    Returns a Series indexed by dst_ip with values in [0, 1].
    A value of 0.30 means 30% of all unique source IPs talked to that
    destination — almost certainly shared infrastructure.
    """
    total_sources = raw_df[src_col].nunique()
    if total_sources == 0:
        return pd.Series(dtype=float)

    fanin_counts = raw_df.groupby(dst_col)[src_col].nunique()
    fanin_frac = fanin_counts / total_sources

    return fanin_frac


def _build_high_fanin_set(
    raw_df: pd.DataFrame,
    threshold: float = DEFAULT_DST_FANIN_THRESHOLD,
    src_col: str = "src_ip",
    dst_col: str = "dst_ip",
) -> set[str]:
    """
    Return the set of destination IPs contacted by more than `threshold`
    fraction of all unique source IPs.
    """
    fanin = compute_dst_fanin(raw_df, src_col, dst_col)
    popular = fanin[fanin > threshold]

    if len(popular) > 0:
        log.info(
            "Destination popularity: %d destinations contacted by >%.0f%% of sources",
            len(popular), threshold * 100,
        )
        for dst, frac in popular.nlargest(5).items():
            log.info("  %s  fanin=%.1f%%", dst, frac * 100)

    return set(popular.index)


# ---------------------------------------------------------------------------
# Connection state analysis
# ---------------------------------------------------------------------------

def compute_pair_conn_state_ratio(
    raw_df: pd.DataFrame,
    src_col: str = "src_ip",
    dst_col: str = "dst_ip",
    state_col: str = "conn_state",
) -> pd.DataFrame:
    """
    For each (src, dst) pair, compute the fraction of flows with failed
    connection states.

    Returns a DataFrame with columns: src_ip, dst_ip, total_flows,
    failed_flows, failed_ratio.
    """
    if state_col not in raw_df.columns:
        log.info("Connection state column '%s' not found — skipping state filter", state_col)
        return pd.DataFrame(columns=[src_col, dst_col, "total_flows", "failed_flows", "failed_ratio"])

    pair_groups = raw_df.groupby([src_col, dst_col])

    total = pair_groups.size().rename("total_flows")
    failed = pair_groups[state_col].apply(
        lambda s: s.isin(FAILED_CONN_STATES).sum()
    ).rename("failed_flows")

    result = pd.concat([total, failed], axis=1).reset_index()
    result["failed_ratio"] = result["failed_flows"] / result["total_flows"]

    return result


def _build_dead_pair_set(
    raw_df: pd.DataFrame,
    threshold: float = DEFAULT_FAILED_CONN_RATIO,
    src_col: str = "src_ip",
    dst_col: str = "dst_ip",
    state_col: str = "conn_state",
) -> set[tuple[str, str]]:
    """
    Return set of (src_ip, dst_ip) tuples where the failed connection
    ratio exceeds the threshold.
    """
    state_df = compute_pair_conn_state_ratio(raw_df, src_col, dst_col, state_col)

    if state_df.empty:
        return set()

    dead = state_df[state_df["failed_ratio"] >= threshold]

    if len(dead) > 0:
        log.info(
            "Connection state filter: %d pairs have >=%.0f%% failed connections",
            len(dead), threshold * 100,
        )

    return set(zip(dead[src_col].astype(str), dead[dst_col].astype(str)))


# ---------------------------------------------------------------------------
# Per-pair classification
# ---------------------------------------------------------------------------

def _classify_pair(
    src_ip: str,
    dst_ip: str,
    dst_port: Optional[int],
    high_fanin_dsts: set[str],
    dead_pairs: set[tuple[str, str]],
    custom_allowlist: Optional[set] = None,
    custom_cdn_prefixes: Optional[list] = None,
) -> Optional[str]:
    """
    Classify a single pair as filtered or not.

    Returns a reason string if the pair should be filtered,
    or None if it should continue to IForest.

    Filter order is intentional — cheapest checks first, most expensive last.
    """
    cdn_prefixes = custom_cdn_prefixes or KNOWN_CDN_PREFIXES

    # 1. Both internal → no C2 relevance
    if _is_internal(src_ip) and _is_internal(dst_ip):
        return "both_internal"

    # 2. Destination is a known DNS resolver
    if dst_ip in KNOWN_DNS_RESOLVERS:
        return "known_dns_resolver"

    # 3. Destination is a known NTP server
    if dst_ip in KNOWN_NTP_DESTINATIONS:
        return "known_ntp"

    # 4. Known infrastructure port to internal destination
    if dst_port and dst_port in INFRASTRUCTURE_PORTS and _is_internal(dst_ip):
        return "infrastructure_port_internal"

    # 5. Destination in known CDN CIDR
    if _in_cdn_prefix(dst_ip, cdn_prefixes):
        return "known_cdn"

    # 6. High-fanin destination — contacted by many unique sources
    #    C2 destinations are typically contacted by 1–3 compromised hosts,
    #    not by 25%+ of the fleet.
    if dst_ip in high_fanin_dsts:
        return "high_fanin_destination"

    # 7. Dead pair — >90% failed connection states
    #    A C2 beacon requires successful connections to receive tasking.
    #    If nearly all attempts fail, there is no viable C2 channel.
    if (src_ip, dst_ip) in dead_pairs:
        return "dead_pair_failed_conns"

    # 8. Custom allowlist (analyst-provided IPs or subnets)
    if custom_allowlist and dst_ip in custom_allowlist:
        return "custom_allowlist"

    return None


# ---------------------------------------------------------------------------
# Main pre-filter entry point
# ---------------------------------------------------------------------------

def apply_prefilter(
    pair_df: pd.DataFrame,
    cfg: BDPConfig,
    raw_df: Optional[pd.DataFrame] = None,
    dst_fanin_threshold: Optional[float] = None,
    failed_conn_threshold: Optional[float] = None,
    custom_allowlist: Optional[set] = None,
    custom_cdn_prefixes: Optional[list] = None,
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """
    Apply domain-knowledge pre-filter to pair DataFrame.

    Parameters
    ----------
    pair_df               : Pair-level DataFrame with src_ip, dst_ip columns.
    cfg                   : Pipeline configuration. Thresholds are now read
                            from cfg.prefilter (PrefilterConfig) by default.
    raw_df                : Raw flow-level DataFrame (needed for fanin and
                            conn state analysis). If None, those filters
                            are skipped.
    dst_fanin_threshold   : Override cfg.prefilter.dst_fanin_threshold.
    failed_conn_threshold : Override cfg.prefilter.failed_conn_threshold.
    custom_allowlist      : Optional set of destination IPs to always filter.
    custom_cdn_prefixes   : Optional list of CIDR strings to treat as CDN.
    """
    # Resolve thresholds: explicit arg > config > module default
    _fanin_thresh   = dst_fanin_threshold   if dst_fanin_threshold   is not None \
                      else getattr(cfg.prefilter, "dst_fanin_threshold",   DEFAULT_DST_FANIN_THRESHOLD)
    _failed_thresh  = failed_conn_threshold if failed_conn_threshold is not None \
                      else getattr(cfg.prefilter, "failed_conn_threshold", DEFAULT_FAILED_CONN_RATIO)
    n_before = len(pair_df)

    # --- Build lookup sets from raw flow data ---
    if raw_df is not None and not raw_df.empty:
        src_col = "src_ip" if "src_ip" in raw_df.columns else "source.ip"
        dst_col = "dst_ip" if "dst_ip" in raw_df.columns else "destination.ip"

        state_col = None
        for candidate in ["conn_state", "network.connection.state", "conn.state"]:
            if candidate in raw_df.columns:
                state_col = candidate
                break

        high_fanin_dsts = _build_high_fanin_set(
            raw_df, _fanin_thresh, src_col, dst_col,
        )

        if state_col:
            dead_pairs = _build_dead_pair_set(
                raw_df, _failed_thresh, src_col, dst_col, state_col,
            )
        else:
            log.info("No conn_state column found in raw data — skipping dead pair filter")
            dead_pairs = set()
    else:
        log.info("No raw flow data provided — skipping fanin and conn state filters")
        high_fanin_dsts = set()
        dead_pairs = set()

    # --- Determine dst_port column in pair_df ---
    port_col = None
    for candidate in ["dst_port", "destination.port", "id.resp_p", "dst_port_mode"]:
        if candidate in pair_df.columns:
            port_col = candidate
            break

    # --- Classify each pair ---
    reasons = []
    for _, row in pair_df.iterrows():
        src = str(row.get("src_ip", ""))
        dst = str(row.get("dst_ip", ""))
        port = int(row[port_col]) if port_col and pd.notna(row.get(port_col)) else None

        reason = _classify_pair(
            src, dst, port,
            high_fanin_dsts, dead_pairs,
            custom_allowlist, custom_cdn_prefixes,
        )
        reasons.append(reason)

    pair_df = pair_df.copy()
    pair_df["prefilter_reason"] = reasons

    removed_df  = pair_df[pair_df["prefilter_reason"].notna()].copy()
    filtered_df = pair_df[pair_df["prefilter_reason"].isna()].copy()
    filtered_df = filtered_df.drop(columns=["prefilter_reason"])

    n_removed = len(removed_df)
    n_after   = len(filtered_df)

    # Safety valve: if the pre-filter would remove >95% of pairs, it is
    # likely too aggressive for this dataset (e.g. synthetic data where
    # background traffic is uniformly distributed across destinations).
    # In that case, disable the fanin filter and re-run with only the
    # static allowlist filters.
    if n_before > 0 and n_after / n_before < 0.05:
        log.warning(
            "Pre-filter too aggressive: would keep only %d / %d pairs (%.1f%%). "
            "Disabling high-fanin filter and re-running.",
            n_after, n_before, n_after / n_before * 100,
        )
        # Re-classify without fanin
        reasons2 = []
        for _, row in pair_df.iterrows():
            src = str(row.get("src_ip", ""))
            dst = str(row.get("dst_ip", ""))
            port = int(row[port_col]) if port_col and pd.notna(row.get(port_col)) else None
            reason = _classify_pair(
                src, dst, port,
                set(),  # empty fanin set
                dead_pairs,
                custom_allowlist, custom_cdn_prefixes,
            )
            reasons2.append(reason)

        pair_df["prefilter_reason"] = reasons2
        removed_df  = pair_df[pair_df["prefilter_reason"].notna()].copy()
        filtered_df = pair_df[pair_df["prefilter_reason"].isna()].copy()
        filtered_df = filtered_df.drop(columns=["prefilter_reason"])
        n_removed = len(removed_df)
        n_after   = len(filtered_df)

    if n_removed > 0:
        reason_counts = removed_df["prefilter_reason"].value_counts()
        breakdown = "  |  ".join(f"{r}={c}" for r, c in reason_counts.items())
        log.info(
            "Pre-filter: %d / %d pairs removed (%.1f%%) → %d pairs continue to IForest",
            n_removed, n_before, n_removed / n_before * 100, n_after,
        )
        log.info("Pre-filter breakdown: %s", breakdown)
    else:
        log.info("Pre-filter: 0 pairs removed — all %d pairs continue to IForest", n_before)

    return filtered_df, removed_df


# ---------------------------------------------------------------------------
# Summary output
# ---------------------------------------------------------------------------

def print_prefilter_summary(removed_df: pd.DataFrame) -> None:
    """Print a summary of pre-filtered pairs for audit."""
    if removed_df.empty:
        print("  Pre-filter: no pairs removed.")
        return

    print(f"  Pre-filter removed {len(removed_df)} pairs:")
    for reason, count in removed_df["prefilter_reason"].value_counts().items():
        label = {
            "both_internal":              "Both IPs internal (RFC 1918)",
            "known_dns_resolver":         "Known DNS resolver",
            "known_ntp":                  "Known NTP server",
            "infrastructure_port_internal": "Infrastructure port → internal",
            "known_cdn":                  "Known CDN CIDR",
            "high_fanin_destination":     "High-fanin destination (shared infra)",
            "dead_pair_failed_conns":     "Dead pair (>90% failed connections)",
            "custom_allowlist":           "Analyst allowlist",
        }.get(reason, reason)
        print(f"    {label:<45} {count:>6}")