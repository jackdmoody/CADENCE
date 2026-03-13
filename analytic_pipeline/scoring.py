"""
Pair Prioritization and Triage
================================
Assigns each (src_ip, dst_ip) pair a weighted priority score using
threat-informed heuristics. Replaces the previous cluster-based scoring
now that DBSCAN has been removed from the pipeline.

Scoring Logic
-------------
Each heuristic contributes an additive integer weight. When periodicity
scores are available, beacon_confidence is the dominant component.

    Heuristic                   Description                          Max Weight
    ──────────────────────────  ───────────────────────────────────  ──────────
    Beacon Confidence           Periodicity composite score (× 4)    4
    Beaconing Pattern           Low std-dev in duration               1
    Uncommon Ports              Any flows to non-standard ports       1
    Data Volume                 Avg bytes > 95th-pct of all flows     1
    Temporal Anomalies          Connections outside normal hours      1
                                                           Maximum:   8

Output columns
--------------
    pair_id, src_ip, dst_ip, flow_count, beacon_confidence,
    duration_std, uncommon_port_hits, avg_total_bytes,
    off_hour_connections, priority_score
"""
from __future__ import annotations

import logging
from typing import Optional

import numpy as np
import pandas as pd

from .config import BDPConfig

log = logging.getLogger(__name__)


def prioritize_pairs(
    df: pd.DataFrame,
    cfg: BDPConfig,
    periodicity_df: Optional[pd.DataFrame] = None,
) -> pd.DataFrame:
    """
    Score each (src_ip, dst_ip) pair using threat-informed heuristics,
    optionally incorporating periodicity beacon_confidence scores.

    Parameters
    ----------
    df             : Raw (unscaled) DataFrame with src_ip, dst_ip columns.
    cfg            : Pipeline configuration (uses triage sub-config).
    periodicity_df : Optional output of periodicity.score_all_pairs().
                     If provided, beacon_confidence is merged and weighted.

    Returns
    -------
    pd.DataFrame sorted by priority_score descending, one row per pair.
    """
    tc           = cfg.triage
    common_ports = set(tc.common_ports)
    off_start, off_end = tc.off_hour_range

    # Build periodicity lookup {pair_id: beacon_confidence}
    periodicity_lookup: dict[str, float] = {}
    if periodicity_df is not None and "pair_id" in periodicity_df.columns:
        periodicity_lookup = dict(
            zip(
                periodicity_df["pair_id"].astype(str),
                periodicity_df["beacon_confidence"].astype(float),
            )
        )

    # Column name helpers — handle both _raw-suffixed and plain names
    def _col(*candidates):
        for c in candidates:
            if c in df.columns:
                return c
        raise KeyError(f"None of {candidates} found. Available: {list(df.columns)}")

    dur_col   = _col("duration_raw",    "duration")
    port_col  = _col("dst_p_raw",       "dst_p")
    bytes_col = _col("total_bytes_raw", "total_bytes")
    global_95th = df[bytes_col].quantile(0.95)

    rows = []
    for (src, dst), pair_df in df.groupby(["src_ip", "dst_ip"]):
        pair_id = f"{src}→{dst}"
        flow_count = len(pair_df)

        # A. Beacon confidence (dominant component)
        beacon_confidence = periodicity_lookup.get(pair_id, 0.0)
        beacon_score = int(round(beacon_confidence * 4))

        # B. Beaconing pattern — low duration std suggests fixed-interval traffic
        beaconing_score = int(pair_df[dur_col].std() < tc.beaconing_std_thresh)

        # C. Uncommon ports — non-standard ports indicate covert channels
        uncommon_hits  = int(pair_df[port_col].apply(lambda p: int(p) not in common_ports).sum())
        uncommon_score = int(uncommon_hits > 0)

        # D. Data volume — average transfer above 95th-pct may indicate exfiltration
        volume_score = int((pair_df[bytes_col] > global_95th).mean() > tc.high_volume_pct)

        # E. Temporal anomalies — connections outside normal operating hours
        off_hours      = int(pair_df["hour"].apply(lambda h: h < off_start or h >= off_end).sum())
        temporal_score = int(off_hours > 0)

        priority_score = (
            beacon_score + beaconing_score + uncommon_score
            + volume_score + temporal_score
        )

        rows.append({
            "pair_id":               pair_id,
            "src_ip":                src,
            "dst_ip":                dst,
            "flow_count":            flow_count,
            "beacon_confidence":     round(beacon_confidence, 4),
            "duration_std":          round(float(pair_df[dur_col].std()), 4),
            "uncommon_port_hits":    uncommon_hits,
            "avg_total_bytes":       round(float(pair_df[bytes_col].mean()), 2),
            "off_hour_connections":  off_hours,
            "priority_score":        priority_score,
        })

    result = pd.DataFrame(rows).sort_values("priority_score", ascending=False).reset_index(drop=True)
    log.info(
        "prioritize_pairs(): scored %d pairs; max score=%d",
        len(result),
        result["priority_score"].max() if not result.empty else 0,
    )
    return result


def recover_raw_features(df_scaled: pd.DataFrame) -> pd.DataFrame:
    """
    Strip scaled columns from the DataFrame, retaining only raw features.

    Parameters
    ----------
    df_scaled : Scaled DataFrame (contains *_stdz columns from process_features).

    Returns
    -------
    pd.DataFrame with *_stdz and *log_stdz columns removed.
    """
    raw_cols = [
        col for col in df_scaled.columns
        if not col.endswith("_stdz") and not col.endswith("log_stdz")
    ]
    df_raw = df_scaled[raw_cols].copy()
    log.info("recover_raw_features(): %d columns retained", len(raw_cols))
    return df_raw
