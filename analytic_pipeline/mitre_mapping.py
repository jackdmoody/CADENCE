"""
MITRE ATT&CK Mapping for CADENCE
==================================
Maps pipeline detection signals to MITRE ATT&CK techniques, producing
structured annotations on each corroborated lead.

Every mapping is derived from evidence the pipeline has already collected —
no external lookups or threat intel feeds required.

Usage
------
    from bdp_analytic.mitre_mapping import annotate_leads

    # art.corroboration is the corroboration DataFrame
    annotated = annotate_leads(art.corroboration)

    # Each row now has a 'mitre_techniques' column: list of dicts
    # [{"technique_id": "T1071.001", "name": "...", "tactic": "...", "evidence": "..."}]

References
-----------
    MITRE ATT&CK Enterprise v15  —  https://attack.mitre.org/
"""
from __future__ import annotations

import logging
from typing import Optional

import pandas as pd

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# ATT&CK technique catalogue (relevant to C2 beacon detection)
# ---------------------------------------------------------------------------

TECHNIQUE_DB = {
    # -- Command and Control --------------------------------------------------
    "T1071.001": {
        "name": "Application Layer Protocol: Web Protocols",
        "tactic": "Command and Control",
        "url": "https://attack.mitre.org/techniques/T1071/001/",
        "description": "C2 communication over HTTP/HTTPS to blend with normal web traffic.",
    },
    "T1071.004": {
        "name": "Application Layer Protocol: DNS",
        "tactic": "Command and Control",
        "url": "https://attack.mitre.org/techniques/T1071/004/",
        "description": "C2 communication tunneled over DNS queries and responses.",
    },
    "T1568.002": {
        "name": "Dynamic Resolution: Domain Generation Algorithms",
        "tactic": "Command and Control",
        "url": "https://attack.mitre.org/techniques/T1568/002/",
        "description": "Algorithmically generated domains for C2 rendezvous.",
    },
    "T1568.001": {
        "name": "Dynamic Resolution: Fast Flux DNS",
        "tactic": "Command and Control",
        "url": "https://attack.mitre.org/techniques/T1568/001/",
        "description": "Rapidly changing DNS records to evade IP-based blocking.",
    },
    "T1573": {
        "name": "Encrypted Channel",
        "tactic": "Command and Control",
        "url": "https://attack.mitre.org/techniques/T1573/",
        "description": "C2 traffic encrypted to prevent content inspection.",
    },
    "T1095": {
        "name": "Non-Application Layer Protocol",
        "tactic": "Command and Control",
        "url": "https://attack.mitre.org/techniques/T1095/",
        "description": "C2 over raw network protocols outside standard application layers.",
    },
    "T1571": {
        "name": "Non-Standard Port",
        "tactic": "Command and Control",
        "url": "https://attack.mitre.org/techniques/T1571/",
        "description": "C2 communication over ports not typically associated with the protocol.",
    },
    "T1029": {
        "name": "Scheduled Transfer",
        "tactic": "Exfiltration",
        "url": "https://attack.mitre.org/techniques/T1029/",
        "description": "Data exfiltration at scheduled intervals matching beacon timing.",
    },
    "T1041": {
        "name": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration",
        "url": "https://attack.mitre.org/techniques/T1041/",
        "description": "Data exfiltrated over the same channel used for C2.",
    },

    # -- Defense Evasion / Discovery ------------------------------------------
    "T1036": {
        "name": "Masquerading",
        "tactic": "Defense Evasion",
        "url": "https://attack.mitre.org/techniques/T1036/",
        "description": "Beacon traffic disguised as legitimate service communication.",
    },
    "T1001": {
        "name": "Data Obfuscation",
        "tactic": "Command and Control",
        "url": "https://attack.mitre.org/techniques/T1001/",
        "description": "C2 data encoded or obfuscated within protocol payloads.",
    },
    "T1132": {
        "name": "Data Encoding",
        "tactic": "Command and Control",
        "url": "https://attack.mitre.org/techniques/T1132/",
        "description": "Standard or custom encoding of C2 data (e.g., base64 in URI).",
    },
}


# ---------------------------------------------------------------------------
# Signal-to-technique mapping rules
# ---------------------------------------------------------------------------

def _map_single_lead(row: pd.Series) -> list[dict]:
    """
    Given a single corroborated lead (one row from corroboration DataFrame),
    return a list of matched ATT&CK techniques with evidence strings.
    """
    techniques = []

    def _add(tid: str, evidence: str) -> None:
        entry = TECHNIQUE_DB[tid].copy()
        entry["technique_id"] = tid
        entry["evidence"] = evidence
        techniques.append(entry)

    # --- Beacon periodicity (always present for corroborated leads) --------
    period_s = float(row.get("dominant_period_s", 0))
    conf     = float(row.get("beacon_confidence", 0))

    if period_s > 0:
        _add("T1029", f"Scheduled beacon interval: {period_s:.0f}s "
                       f"(confidence: {conf:.3f})")

    # --- H1: DNS regularity -----------------------------------------------
    h1 = bool(row.get("h1_dns_regularity", False))
    if h1:
        _add("T1071.004", "DNS query period matches conn-log beacon period, "
                          "indicating DNS-layer C2 communication")

    # --- H2: DNS anomaly indicators ----------------------------------------
    h2 = bool(row.get("h2_dns_anomaly", False))

    dga_domains   = row.get("h2_dga_domains", []) or []
    nxd_count     = int(row.get("h2_nxdomain_count", 0))
    short_ttl     = int(row.get("h2_short_ttl_count", 0))

    if dga_domains:
        examples = ", ".join(str(d) for d in list(dga_domains)[:3])
        _add("T1568.002", f"DGA-generated domains detected: {examples}")

    if short_ttl > 0:
        _add("T1568.001", f"Short DNS TTLs ({short_ttl} records) "
                          "suggest fast-flux infrastructure")

    if nxd_count > 0 and not dga_domains:
        _add("T1071.004", f"NXDomain responses ({nxd_count}) suggest "
                          "sinkholed or rotating C2 infrastructure")

    # --- H3: HTTP behavioral consistency -----------------------------------
    h3 = bool(row.get("h3_http_consistency", False))
    if h3:
        body_cv = row.get("h3_response_body_cv")
        uri_cv  = row.get("h3_uri_len_cv")
        detail = []
        if body_cv is not None:
            detail.append(f"body_CV={float(body_cv):.3f}")
        if uri_cv is not None:
            detail.append(f"uri_CV={float(uri_cv):.3f}")
        _add("T1071.001", f"Stereotyped HTTP patterns ({', '.join(detail) or 'uniform payloads'}) "
                          "consistent with automated C2 polling")

    # --- H4: HTTP evasion indicators ---------------------------------------
    h4 = bool(row.get("h4_evasion_indicators", False))

    rare_ua     = bool(row.get("h4_rare_ua", False))
    high_ent    = bool(row.get("h4_high_uri_entropy", False))
    abn_methods = row.get("h4_abnormal_methods", []) or []

    if rare_ua:
        _add("T1036", "Rare or absent User-Agent string — "
                       "beacon masquerading as legitimate traffic")

    if high_ent:
        _add("T1132", "High-entropy URI indicates encoded C2 payload data")
        _add("T1001", "Obfuscated data in HTTP URI suggests "
                       "C2 command/response encoding")

    if abn_methods:
        methods_str = ", ".join(str(m) for m in abn_methods)
        _add("T1071.001", f"Non-standard HTTP methods ({methods_str}) "
                          "outside normal browsing behavior")

    # --- Encrypted beacon (no HTTP evidence but confirmed periodic) --------
    if not h3 and not h4 and conf >= 0.50:
        _add("T1573", "Beacon confirmed periodic with no HTTP payload visibility — "
                       "likely encrypted C2 channel (HTTPS/TLS)")

    # --- Changepoint / operator interaction --------------------------------
    has_shift = bool(row.get("has_interval_shift", False))
    if has_shift:
        _add("T1571", "Beacon interval shift detected — human operator "
                       "reconfigured the implant mid-campaign")

    # --- Exfiltration indicators -------------------------------------------
    flow_count = int(row.get("flow_count", 0))
    if flow_count > 500 and period_s > 0:
        _add("T1041", f"Sustained periodic communication ({flow_count:,} flows) "
                       "over beacon channel may indicate data exfiltration")

    return techniques


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def annotate_leads(corroboration: pd.DataFrame) -> pd.DataFrame:
    """
    Add a 'mitre_techniques' column to the corroboration DataFrame.

    Each entry is a list of dicts:
        [{"technique_id": "T1568.002", "name": "...", "tactic": "...",
          "evidence": "...", "url": "..."}]

    Only corroborated leads are annotated; non-corroborated rows get
    an empty list.
    """
    if corroboration.empty:
        corroboration["mitre_techniques"] = []
        return corroboration

    df = corroboration.copy()

    def _annotate_row(row):
        if not bool(row.get("corroborated", False)):
            return []
        return _map_single_lead(row)

    df["mitre_techniques"] = df.apply(_annotate_row, axis=1)

    n_annotated = sum(1 for t in df["mitre_techniques"] if len(t) > 0)
    n_techniques = sum(len(t) for t in df["mitre_techniques"])
    log.info("MITRE ATT&CK: %d leads annotated with %d total technique mappings",
             n_annotated, n_techniques)

    return df


def format_mitre_text(techniques: list[dict]) -> str:
    """
    Format a list of technique dicts into a readable text block
    for terminal output or report inclusion.
    """
    if not techniques:
        return "  No MITRE ATT&CK mappings."

    lines = []
    # Group by tactic
    by_tactic: dict[str, list[dict]] = {}
    for t in techniques:
        tactic = t.get("tactic", "Unknown")
        by_tactic.setdefault(tactic, []).append(t)

    for tactic, techs in by_tactic.items():
        lines.append(f"  {tactic}:")
        for t in techs:
            lines.append(f"    {t['technique_id']}  {t['name']}")
            lines.append(f"      └─ {t['evidence']}")
        lines.append("")

    return "\n".join(lines)


def print_mitre_summary(corroboration: pd.DataFrame) -> None:
    """
    Print a MITRE ATT&CK summary to the terminal for all corroborated leads.
    """
    if "mitre_techniques" not in corroboration.columns:
        corroboration = annotate_leads(corroboration)

    confirmed = corroboration[corroboration.get("corroborated", False) == True]
    if confirmed.empty:
        print("\n  No corroborated leads to map to ATT&CK.")
        return

    width = 68
    print(f"\n{'=' * width}")
    print(f"  MITRE ATT&CK Mapping")
    print(f"{'=' * width}")

    for _, row in confirmed.iterrows():
        src = row.get("src_ip", "?")
        dst = row.get("dst_ip", "?")
        techniques = row.get("mitre_techniques", [])

        print(f"\n  {src} → {dst}")
        print(f"  {'─' * 60}")
        print(format_mitre_text(techniques))

    # Deduplicated technique summary
    all_tids = set()
    for _, row in confirmed.iterrows():
        for t in row.get("mitre_techniques", []):
            all_tids.add(t["technique_id"])

    print(f"  {'─' * 60}")
    print(f"  Unique techniques observed: {len(all_tids)}")
    print(f"  {', '.join(sorted(all_tids))}")
    print()
