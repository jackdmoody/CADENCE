"""
Feature Engineering — Channel Aggregation
==========================================
Transforms a flow-level Zeek conn log DataFrame into a channel-level
behavioral summary DataFrame, one row per channel.

Point 1: Channel key
--------------------
The grouping unit is now configurable via cfg.pair.channel_key. The default
is (src_ip, dst_ip, dst_port, proto), which separates services on the same
destination host. All downstream stages (SAX, periodicity, corroboration,
triage) receive a 'channel_id' string key that encodes all key components.

Legacy (src_ip, dst_ip) behaviour is available by setting:
    cfg.pair.channel_key = ("src_ip", "dst_ip")

Point 4: New beacon-discriminating features
-------------------------------------------
In addition to the original 8 IForest features, the following are computed:

    iat_mad_s           Median absolute deviation of IAT (robust jitter measure).
    iat_ratio           Median / mean IAT; near 1.0 = symmetric, low = skewed.
    missing_beat_rate   Fraction of expected beacon slots with no connection.
                        Requires enough observations to estimate period.
    persistence_ratio   Fraction of observation days with at least one flow.
                        Beacons are active every day; sporadic traffic is not.
    req_resp_asymmetry  |src_bytes - dst_bytes| / (src_bytes + dst_bytes + 1).
                        C2 polling: tiny request, small response → near 0.
                        Exfiltration: large src → near 1.
    zero_payload_frac   Fraction of flows with zero destination bytes.
                        High in keepalive/heartbeat channels.

Output columns (all existing + new)
-------------------------------------
    Identity
        src_ip, dst_ip, dst_port, proto, channel_id

    Volume
        n_flows, log_n_flows

    Scheduling regularity  (primary beacon signal)
        iat_mean_s, iat_cv, iat_log_mean
        iat_mad_s (new), iat_ratio (new), missing_beat_rate (new)

    Payload uniformity
        bytes_mean, bytes_cv

    Temporal / persistence
        persistence_ratio (new)
        sin_time_mean, cos_time_mean

    Payload character
        req_resp_asymmetry (new), zero_payload_frac (new)

    Connection consistency
        duration_cv, conn_state_entropy

    Metadata
        first_seen, last_seen, scenario
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
# Helpers
# ---------------------------------------------------------------------------

def _shannon_entropy(series: pd.Series) -> float:
    """Shannon entropy of a categorical series."""
    probs = series.value_counts(normalize=True).values
    return float(-np.sum(probs * np.log2(probs + 1e-12)))


def _ts_to_float(ts: pd.Series) -> pd.Series:
    """Convert timestamp series to float Unix seconds, handling both dtypes."""
    if pd.api.types.is_datetime64_any_dtype(ts):
        return ts.values.astype("datetime64[ns]").astype(np.float64) / 1e9
    return ts.astype(float)


def _channel_id(row_keys: tuple, key_names: tuple) -> str:
    """Build a human-readable channel ID string from key component values."""
    return "→".join(str(v) for v in row_keys)


# ---------------------------------------------------------------------------
# Channel aggregation
# ---------------------------------------------------------------------------

def aggregate_pairs(
    df: pd.DataFrame,
    cfg: BDPConfig,
) -> pd.DataFrame:
    """
    Aggregate flow-level DataFrame to one row per channel.

    Point 1: Groups by cfg.pair.channel_key (default: src_ip, dst_ip,
    dst_port, proto) rather than just (src_ip, dst_ip).

    Point 4: Computes persistence_ratio, iat_mad_s, iat_ratio,
    missing_beat_rate, req_resp_asymmetry, and zero_payload_frac
    in addition to the original 8 IForest features.

    Parameters
    ----------
    df  : Output of loaders.load_and_prepare() — one row per flow.
    cfg : Pipeline configuration.

    Returns
    -------
    DataFrame with one row per channel.
    """
    min_flows   = cfg.pair.min_pair_flows
    channel_key = list(cfg.pair.channel_key)

    # Resolve which key columns are actually present in df.
    # dst_port may appear as 'dst_p' and proto as 'service' depending on schema.
    col_aliases = {
        "dst_port": ["dst_port", "dst_p", "id.resp_p", "destination.port"],
        "proto":    ["proto", "service", "network.protocol", "network.transport"],
    }
    resolved_key: list[str] = []
    for k in channel_key:
        if k in df.columns:
            resolved_key.append(k)
        elif k in col_aliases:
            for alias in col_aliases[k]:
                if alias in df.columns:
                    resolved_key.append(alias)
                    break
            else:
                log.debug("channel_key component '%s' not found in df — omitting", k)
        else:
            log.debug("channel_key component '%s' not found in df — omitting", k)

    # Ensure src_ip and dst_ip are always in the key
    for required in ("src_ip", "dst_ip"):
        if required not in resolved_key:
            resolved_key.insert(0, required)

    # Deduplicate while preserving order
    seen: set = set()
    resolved_key = [k for k in resolved_key if not (k in seen or seen.add(k))]  # type: ignore[func-returns-value]

    log.info("aggregate_pairs(): channel key = %s", resolved_key)

    records = []
    grouped = df.groupby(resolved_key, sort=False)

    for key_vals, grp in grouped:
        n = len(grp)
        if n < min_flows:
            continue

        grp = grp.sort_values("timestamp")

        # --- Channel identity ---
        if isinstance(key_vals, tuple):
            kv = key_vals
        else:
            kv = (key_vals,)

        rec: dict = {}
        for col, val in zip(resolved_key, kv):
            rec[col] = val

        # Ensure src_ip and dst_ip are always present for downstream
        rec.setdefault("src_ip", kv[0])
        rec.setdefault("dst_ip", kv[1] if len(kv) > 1 else "")

        # Channel ID encodes all key components
        rec["channel_id"] = _channel_id(kv, tuple(resolved_key))
        # Legacy pair_id alias (src→dst) kept for backward compat
        rec["pair_id"]    = f"{rec['src_ip']}→{rec['dst_ip']}"

        # --- IAT sequence ---
        ts_num = _ts_to_float(grp["timestamp"])
        iat    = np.diff(np.sort(ts_num.values))
        iat    = iat[iat > 0]

        if len(iat) >= 2:
            iat_mean = float(np.mean(iat))
            iat_med  = float(np.median(iat))
            iat_cv   = float(np.std(iat) / iat_mean) if iat_mean > 0 else np.nan
            # Point 4: MAD and ratio
            iat_mad  = float(np.median(np.abs(iat - iat_med)))
            iat_ratio = float(iat_med / iat_mean) if iat_mean > 0 else np.nan
        else:
            iat_mean = iat_med = iat_cv = iat_mad = iat_ratio = np.nan

        # --- Point 4: persistence ratio (fraction of window days with activity) ---
        first_ts = float(ts_num.iloc[0])
        last_ts  = float(ts_num.iloc[-1])
        window_days = max((last_ts - first_ts) / 86400.0, 1.0)
        active_days = ts_num.apply(lambda t: int(t // 86400)).nunique()
        persistence_ratio = float(active_days / window_days)

        # --- Point 4: missing beat rate ---
        # Estimate using period ≈ median IAT; count beacon slots with no firing.
        if iat_med and iat_med > 0 and len(iat) >= 4:
            expected_beats = max(int(round((last_ts - first_ts) / iat_med)), 1)
            actual_beats   = len(grp)
            missing_beat_rate = float(max(0, expected_beats - actual_beats) / expected_beats)
        else:
            missing_beat_rate = np.nan

        # --- Bytes ---
        b = (grp["destination.bytes"] if "destination.bytes" in grp.columns
             else grp.get("total_bytes", pd.Series([0] * n, index=grp.index)))
        bytes_mean = float(b.mean())
        bytes_cv   = float(b.std() / bytes_mean) if bytes_mean > 0 else 0.0

        # --- Point 4: request/response asymmetry ---
        src_bytes_col = next(
            (c for c in ("source.bytes", "src_bytes") if c in grp.columns), None
        )
        if src_bytes_col and bytes_mean > 0:
            src_b  = grp[src_bytes_col].fillna(0).values.astype(float)
            dst_b  = b.fillna(0).values.astype(float)
            asym   = np.abs(src_b - dst_b) / (src_b + dst_b + 1.0)
            req_resp_asymmetry = float(np.median(asym))
        else:
            req_resp_asymmetry = np.nan

        # --- Point 4: zero-payload fraction ---
        zero_payload_frac = float((b == 0).mean()) if len(b) > 0 else 0.0

        # --- Duration ---
        dur_col = next(
            (c for c in ("duration", "event.duration") if c in grp.columns), None
        )
        if dur_col:
            dur_vals = grp[dur_col].dropna()
            dur_mean = float(dur_vals.mean()) if len(dur_vals) > 0 else 0.0
            dur_cv   = float(dur_vals.std() / dur_mean) if dur_mean > 0 else 0.0
        else:
            dur_cv = np.nan

        # --- Connection state entropy ---
        state_col = next(
            (c for c in ("conn_state", "network.connection.state") if c in grp.columns), None
        )
        conn_entropy = _shannon_entropy(grp[state_col]) if state_col else 0.0

        # --- Time-of-day encoding ---
        sin_mean = float(grp["sin_time"].mean()) if "sin_time" in grp.columns else 0.0
        cos_mean = float(grp["cos_time"].mean()) if "cos_time" in grp.columns else 1.0

        rec.update({
            "n_flows":             n,
            "log_n_flows":         float(np.log1p(n)),
            "iat_mean_s":          iat_mean,
            "iat_log_mean":        float(np.log1p(iat_mean)) if not np.isnan(iat_mean) else np.nan,
            "iat_cv":              iat_cv,
            "iat_mad_s":           iat_mad,           # Point 4
            "iat_ratio":           iat_ratio,          # Point 4
            "missing_beat_rate":   missing_beat_rate,  # Point 4
            "persistence_ratio":   persistence_ratio,  # Point 4
            "bytes_mean":          bytes_mean,
            "bytes_cv":            bytes_cv,
            "req_resp_asymmetry":  req_resp_asymmetry, # Point 4
            "zero_payload_frac":   zero_payload_frac,  # Point 4
            "duration_cv":         dur_cv,
            "conn_state_entropy":  conn_entropy,
            "sin_time_mean":       sin_mean,
            "cos_time_mean":       cos_mean,
            "first_seen":          first_ts,
            "last_seen":           last_ts,
        })

        if "scenario" in grp.columns:
            rec["scenario"] = grp["scenario"].iloc[0]

        records.append(rec)

    pair_df = pd.DataFrame(records)
    log.info(
        "aggregate_pairs(): %d flows → %d channels (key=%s, min_flows=%d)",
        len(df), len(pair_df), resolved_key, min_flows,
    )
    return pair_df.reset_index(drop=True)


# ---------------------------------------------------------------------------
# Scaling for IForest
# ---------------------------------------------------------------------------

IFOREST_FEATURES = [
    "log_n_flows",
    "iat_cv",
    "iat_log_mean",
    "iat_mad_s",           # Point 4
    "iat_ratio",           # Point 4
    "missing_beat_rate",   # Point 4
    "persistence_ratio",   # Point 4
    "bytes_cv",
    "req_resp_asymmetry",  # Point 4
    "zero_payload_frac",   # Point 4
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
    Z-score standardise channel-level IForest features.

    NaN values are filled with 0 before scaling (assumes average behaviour
    for under-observed channels).
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
        "scale_pair_features(): %d channels, %d features scaled.",
        len(out), len(features),
    )
    return out, scaler


# ---------------------------------------------------------------------------
# Legacy shim
# ---------------------------------------------------------------------------

def process_features(
    df: pd.DataFrame,
    cfg: BDPConfig,
    heavy_tailed=None,
) -> tuple[pd.DataFrame, None, list, list]:
    """Compatibility shim: aggregate flows to channels and scale."""
    pair_df = aggregate_pairs(df, cfg)
    pair_df_scaled, scaler = scale_pair_features(pair_df, cfg)
    return pair_df_scaled, scaler, [], []
