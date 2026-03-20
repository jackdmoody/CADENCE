"""
Channel Prioritization and Triage
====================================
Assigns each channel a weighted priority score using beacon-informed
heuristics. Works with any channel key (src_ip, dst_ip, dst_port, proto)
as long as the DataFrame contains src_ip and dst_ip columns.

Point 6: Reweighted triage toward beacon-native signals
---------------------------------------------------------
The original triage weighted uncommon ports and high data volume equally
with beacon confidence. Those are weak signals for modern C2 (which
intentionally uses 443 and tiny payloads). The updated weights prioritise:

    Beacon Confidence   Periodicity composite score.            (× 4)  max 4
    Payload Stability   Low bytes CV across all pair flows.     (× 2)  max 2
    Persistence         Multi-day activity ratio.               (× 2)  max 2
    Period Agreement    Conn-period vs DNS/HTTP cadence match.  (× 1)  max 1
    Off-hour Activity   Connections outside normal hours.       (× 1)  max 1
                                                    Maximum:          10

Uncommon ports and high volume are retained as metadata columns for analyst
context but NO LONGER contribute to the priority score. High-volume exfil
is better captured by req_resp_asymmetry in the IForest feature set.

Output columns
--------------
    channel_id, pair_id, src_ip, dst_ip, flow_count,
    beacon_confidence, duration_std, avg_total_bytes,
    bytes_cv, persistence_ratio, off_hour_connections,
    priority_score
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
    Score each channel using beacon-informed heuristics.

    Parameters
    ----------
    df             : Raw (unscaled) flow-level DataFrame with src_ip, dst_ip.
    cfg            : Pipeline configuration.
    periodicity_df : Optional output of periodicity.score_all_pairs().
                     If provided, beacon_confidence is merged by channel_id.

    Returns
    -------
    pd.DataFrame sorted by priority_score descending, one row per channel.
    """
    tc           = cfg.triage
    off_start, off_end = tc.off_hour_range

    # Build periodicity lookup keyed by channel_id (preferred) or pair_id
    periodicity_lookup: dict[str, float]  = {}
    period_s_lookup:    dict[str, float]  = {}
    if periodicity_df is not None and not periodicity_df.empty:
        id_col = "channel_id" if "channel_id" in periodicity_df.columns else "pair_id"
        for _, prow in periodicity_df.iterrows():
            key = str(prow[id_col])
            periodicity_lookup[key] = float(prow.get("beacon_confidence", 0.0))
            period_s_lookup[key]    = float(prow.get("dominant_period_s", 0.0))

    # Column name helpers — handle _raw-suffixed and plain names
    def _col(*candidates):
        for c in candidates:
            if c in df.columns:
                return c
        return None

    dur_col   = _col("duration_raw",    "duration",    "event.duration")
    bytes_col = _col("total_bytes_raw", "total_bytes", "destination.bytes")

    # Determine grouping key
    group_col = "channel_id" if "channel_id" in df.columns else None

    rows = []

    if group_col:
        group_iter = df.groupby(group_col, sort=False)
    else:
        group_iter = df.groupby(["src_ip", "dst_ip"], sort=False)

    for group_key, pair_df in group_iter:
        if group_col:
            channel_id = str(group_key)
            src = str(pair_df["src_ip"].iloc[0])
            dst = str(pair_df["dst_ip"].iloc[0])
        else:
            src, dst   = group_key
            channel_id = f"{src}→{dst}"

        pair_id    = f"{src}→{dst}"
        flow_count = len(pair_df)
        lookup_key = channel_id

        # --- A. Beacon confidence (dominant component, max 4) ---
        beacon_confidence = periodicity_lookup.get(lookup_key,
                            periodicity_lookup.get(pair_id, 0.0))
        beacon_score = int(round(beacon_confidence * 4))

        # --- B. Payload stability: low bytes CV = uniform beacon payload (max 2) ---
        bytes_cv = np.nan
        avg_bytes = 0.0
        if bytes_col:
            b = pd.to_numeric(pair_df[bytes_col], errors="coerce").dropna()
            if len(b) > 1 and b.mean() > 0:
                bytes_cv  = float(b.std() / b.mean())
                avg_bytes = float(b.mean())
        # Scale: CV < 0.10 → 2pts, CV < 0.30 → 1pt, else 0
        if not np.isnan(bytes_cv):
            payload_score = 2 if bytes_cv < 0.10 else (1 if bytes_cv < 0.30 else 0)
        else:
            payload_score = 0

        # --- C. Persistence: fraction of window days with activity (max 2) ---
        persistence_ratio = np.nan
        if "timestamp" in pair_df.columns:
            ts = pd.to_numeric(pair_df["timestamp"], errors="coerce").dropna()
            if len(ts) > 0:
                first_ts    = float(ts.min())
                last_ts     = float(ts.max())
                window_days = max((last_ts - first_ts) / 86400.0, 1.0)
                active_days = ts.apply(lambda t: int(t // 86400)).nunique()
                persistence_ratio = float(active_days / window_days)
        # Scale: >90% days active → 2pts, >50% → 1pt, else 0
        if not np.isnan(persistence_ratio):
            persistence_score = 2 if persistence_ratio > 0.90 else (1 if persistence_ratio > 0.50 else 0)
        else:
            persistence_score = 0

        # --- D. Period agreement with corroborating DNS/HTTP cadence (max 1) ---
        # Proxy: if the channel has a strong beacon_confidence AND a valid period,
        # the ACF and FFT period estimates agree → treat as confirmed period agreement.
        dominant_period = period_s_lookup.get(lookup_key, period_s_lookup.get(pair_id, 0.0))
        period_agreement_score = int(
            beacon_confidence >= 0.70 and dominant_period >= cfg.periodicity.min_period_s
        )

        # --- E. Temporal anomalies: connections outside normal hours (max 1) ---
        off_hours = 0
        if "hour" in pair_df.columns:
            off_hours = int(
                pair_df["hour"].apply(lambda h: h < off_start or h >= off_end).sum()
            )
        temporal_score = int(off_hours > 0)

        # --- Metadata (analyst context, not scored) ---
        dur_std = float(pair_df[dur_col].std()) if dur_col else np.nan

        priority_score = (
            beacon_score
            + payload_score
            + persistence_score
            + period_agreement_score
            + temporal_score
        )

        rows.append({
            "channel_id":           channel_id,
            "pair_id":              pair_id,
            "src_ip":               src,
            "dst_ip":               dst,
            "flow_count":           flow_count,
            "beacon_confidence":    round(beacon_confidence, 4),
            "dominant_period_s":    round(dominant_period, 1),
            "bytes_cv":             round(bytes_cv, 4) if not np.isnan(bytes_cv) else np.nan,
            "avg_total_bytes":      round(avg_bytes, 2),
            "persistence_ratio":    round(persistence_ratio, 4) if not np.isnan(persistence_ratio) else np.nan,
            "duration_std":         round(dur_std, 4) if not np.isnan(dur_std) else np.nan,
            "off_hour_connections": off_hours,
            # Score components (analyst transparency)
            "score_beacon":         beacon_score,
            "score_payload":        payload_score,
            "score_persistence":    persistence_score,
            "score_period_agree":   period_agreement_score,
            "score_temporal":       temporal_score,
            "priority_score":       priority_score,
        })

    result = (
        pd.DataFrame(rows)
        .sort_values("priority_score", ascending=False)
        .reset_index(drop=True)
    )
    log.info(
        "prioritize_pairs(): scored %d channels; max score=%d",
        len(result),
        result["priority_score"].max() if not result.empty else 0,
    )
    return result


def recover_raw_features(df_scaled: pd.DataFrame) -> pd.DataFrame:
    """Strip scaled columns from the DataFrame, retaining only raw features."""
    raw_cols = [
        col for col in df_scaled.columns
        if not col.endswith("_stdz") and not col.endswith("log_stdz")
    ]
    df_raw = df_scaled[raw_cols].copy()
    log.info("recover_raw_features(): %d columns retained", len(raw_cols))
    return df_raw
