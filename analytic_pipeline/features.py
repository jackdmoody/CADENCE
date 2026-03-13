"""
Feature Engineering — Pair Aggregation
=========================================
Transforms a flow-level Zeek conn log DataFrame into a pair-level
behavioral summary DataFrame, one row per (src_ip, dst_ip) pair.

Architecture note
-----------------
Earlier versions of this module applied variance filtering, log transforms,
and StandardScaler to individual flow rows. This caused a fundamental
detection gap: beacon flows are volumetrically *normal* — small bytes, short
duration, standard ports — so IForest scored them as inliers and they were
dropped before periodicity analysis could run.

The fix is to shift the unit of analysis from flow to pair at this stage.
Per-pair features (IAT CV, flow count, byte uniformity) directly encode the
behavioral regularity that defines a beacon. A pair with 1400 identical flows
at 5-minute intervals is obviously anomalous at the pair level even though each
individual flow looks unremarkable.

Output
------
aggregate_pairs() returns one row per (src_ip, dst_ip) pair with:

    Identity
        src_ip, dst_ip

    Volume
        n_flows             Total flow count.
        log_n_flows         log1p(n_flows); heavy-tail compression.

    Scheduling regularity  (primary beacon signal)
        iat_mean_s          Mean inter-arrival time in seconds.
        iat_cv              Coefficient of variation of IAT sequence.
                            Low CV = regular schedule = beacon signal.
        iat_log_mean        log1p(iat_mean_s); compresses long periods.

    Payload uniformity
        bytes_mean          Mean destination bytes per flow.
        bytes_cv            CV of destination bytes.
                            Low CV = uniform payload = beacon signal.

    Connection consistency
        duration_cv         CV of flow duration.
        conn_state_entropy  Shannon entropy of connection state distribution.
                            Zero = all flows have the same outcome.

    Temporal concentration
        sin_time_mean       Mean sin(time-of-day); encodes time clustering.
        cos_time_mean       Mean cos(time-of-day).

    Metadata (preserved for downstream stages, not used in IForest)
        first_seen          Earliest timestamp in pair.
        last_seen           Latest timestamp in pair.
        scenario            Scenario label if present (synthetic data only).
"""
from __future__ import annotations

import logging
from typing import Optional

import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler

from .config import BDPConfig

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Pair aggregation
# ---------------------------------------------------------------------------

def _shannon_entropy(series: pd.Series) -> float:
    """Shannon entropy of a categorical series."""
    probs = series.value_counts(normalize=True).values
    return float(-np.sum(probs * np.log2(probs + 1e-12)))


def aggregate_pairs(
    df: pd.DataFrame,
    cfg: BDPConfig,
) -> pd.DataFrame:
    """
    Aggregate flow-level DataFrame to one row per (src_ip, dst_ip) pair.

    Pairs with fewer than cfg.pair.min_pair_flows flows are dropped —
    they cannot support reliable IAT statistics.

    Parameters
    ----------
    df  : Output of loaders.load_and_prepare() — one row per flow.
    cfg : Pipeline configuration.

    Returns
    -------
    DataFrame with one row per (src_ip, dst_ip) pair and the columns
    described in the module docstring.
    """
    min_flows = cfg.pair.min_pair_flows

    records = []
    grouped = df.groupby(["src_ip", "dst_ip"], sort=False)

    for (src, dst), grp in grouped:
        n = len(grp)
        if n < min_flows:
            continue

        grp = grp.sort_values("timestamp")

        # --- IAT sequence ---
        ts = grp["timestamp"]
        # timestamp may be datetime or numeric; convert to float seconds
        if pd.api.types.is_datetime64_any_dtype(ts):
            ts_num = ts.astype(np.int64) / 1e9
        else:
            ts_num = ts.astype(float)

        iat = ts_num.diff().dropna().values
        iat = iat[iat > 0]  # drop zero-gap duplicates

        if len(iat) >= 2:
            iat_mean = float(np.mean(iat))
            iat_cv   = float(np.std(iat) / iat_mean) if iat_mean > 0 else np.nan
        else:
            iat_mean = np.nan
            iat_cv   = np.nan

        # --- Bytes ---
        b = grp["destination.bytes"] if "destination.bytes" in grp.columns else grp.get("total_bytes", pd.Series([0]*n))
        bytes_mean = float(b.mean())
        bytes_cv   = float(b.std() / bytes_mean) if bytes_mean > 0 else 0.0

        # --- Duration ---
        dur_col = "duration" if "duration" in grp.columns else "event.duration"
        if dur_col in grp.columns:
            dur_mean = float(grp[dur_col].mean())
            dur_cv   = float(grp[dur_col].std() / dur_mean) if dur_mean > 0 else 0.0
        else:
            dur_cv = np.nan

        # --- Connection state entropy ---
        state_col = "conn_state" if "conn_state" in grp.columns else "network.connection.state"
        conn_entropy = _shannon_entropy(grp[state_col]) if state_col in grp.columns else 0.0

        # --- Time-of-day encoding ---
        sin_mean = float(grp["sin_time"].mean()) if "sin_time" in grp.columns else 0.0
        cos_mean = float(grp["cos_time"].mean()) if "cos_time" in grp.columns else 1.0

        rec = {
            "src_ip":             src,
            "dst_ip":             dst,
            "n_flows":            n,
            "log_n_flows":        float(np.log1p(n)),
            "iat_mean_s":         iat_mean,
            "iat_log_mean":       float(np.log1p(iat_mean)) if not np.isnan(iat_mean) else np.nan,
            "iat_cv":             iat_cv,
            "bytes_mean":         bytes_mean,
            "bytes_cv":           bytes_cv,
            "duration_cv":        dur_cv,
            "conn_state_entropy": conn_entropy,
            "sin_time_mean":      sin_mean,
            "cos_time_mean":      cos_mean,
            "first_seen":         float(ts_num.iloc[0]),
            "last_seen":          float(ts_num.iloc[-1]),
        }

        # Preserve scenario label if present (synthetic data)
        if "scenario" in grp.columns:
            rec["scenario"] = grp["scenario"].iloc[0]

        records.append(rec)

    pair_df = pd.DataFrame(records)
    log.info(
        "aggregate_pairs(): %d flows → %d pairs (min_flows=%d)",
        len(df), len(pair_df), min_flows,
    )
    return pair_df.reset_index(drop=True)


# ---------------------------------------------------------------------------
# Scaling for IForest
# ---------------------------------------------------------------------------

IFOREST_FEATURES = [
    "log_n_flows",
    "iat_cv",
    "iat_log_mean",
    "bytes_cv",
    "duration_cv",
    "conn_state_entropy",
    "sin_time_mean",
    "cos_time_mean",
]


def scale_pair_features(
    pair_df: pd.DataFrame,
    cfg: BDPConfig,
    scaler: Optional[StandardScaler] = None,
) -> tuple[pd.DataFrame, StandardScaler]:
    """
    Z-score standardise pair-level IForest features.

    NaN values (e.g. iat_cv for pairs with only 1 IAT observation) are
    filled with 0 before scaling — equivalent to assuming average behavior
    for under-observed pairs.

    Parameters
    ----------
    pair_df : Output of aggregate_pairs().
    cfg     : Pipeline configuration.
    scaler  : Pre-fitted scaler for inference; if None, fit on pair_df.

    Returns
    -------
    pair_df_scaled : pair_df with additional *_stdz columns appended.
    scaler         : Fitted StandardScaler.
    """
    features = [f for f in IFOREST_FEATURES if f in pair_df.columns]
    X = pair_df[features].fillna(0).astype(float)

    if scaler is None:
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)
    else:
        X_scaled = scaler.transform(X)

    scaled_cols = {f"{f}_stdz": X_scaled[:, i] for i, f in enumerate(features)}
    out = pair_df.copy()
    for col, vals in scaled_cols.items():
        out[col] = vals

    log.info(
        "scale_pair_features(): %d pairs, %d features scaled.",
        len(out), len(features),
    )
    return out, scaler


# ---------------------------------------------------------------------------
# Legacy flow-level helpers (kept for loaders.py compatibility)
# ---------------------------------------------------------------------------

def process_features(
    df: pd.DataFrame,
    cfg: BDPConfig,
    heavy_tailed=None,
) -> tuple[pd.DataFrame, None, list, list]:
    """
    Compatibility shim: aggregate flows to pairs and scale.

    Returns a tuple matching the old (df_scaled, scaler, stdz_cols, heavy_tailed)
    signature so that pipeline.py's scale() method needs no changes.

    The returned df_scaled is a pair-level DataFrame (not flow-level).
    The scaler is stored on the BDPPipeline artifact; stdz_cols and
    heavy_tailed are returned as empty lists since they no longer apply.
    """
    pair_df = aggregate_pairs(df, cfg)
    pair_df_scaled, scaler = scale_pair_features(pair_df, cfg)
    return pair_df_scaled, scaler, [], []
