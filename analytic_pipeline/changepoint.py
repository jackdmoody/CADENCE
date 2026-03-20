"""
Changepoint Detection via PELT
================================
Identifies when a beacon *started* and whether its interval *changed*
during the observation window, using the Pruned Exact Linear Time (PELT)
algorithm.

Architecture change from v5
-----------------------------
Changepoint detection now operates directly on (src_ip, dst_ip) pairs
(identified by pair_id) rather than iterating within DBSCAN clusters.
The cluster_id / dbscan_cluster references have been replaced with pair_id.

Timestamp computation uses the raw `timestamp` column (Unix float seconds)
throughout, consistent with the rest of the refactored pipeline.
"""
from __future__ import annotations

import logging
from typing import Optional

import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import numpy as np
import pandas as pd

from .config import BDPConfig

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# PELT implementation (L2 cost, no external dependency)
# ---------------------------------------------------------------------------

def _l2_cost(series: np.ndarray, start: int, end: int) -> float:
    segment = series[start:end]
    n = len(segment)
    if n <= 1:
        return 0.0
    mean = np.mean(segment)
    return float(np.sum((segment - mean) ** 2))


def _pelt(
    series:   np.ndarray,
    penalty:  float,
    min_size: int = 2,
) -> list[int]:
    """PELT algorithm with L2 cost. Returns list of changepoint indices."""
    n = len(series)
    if n < 2 * min_size:
        return []

    F    = np.full(n + 1, np.inf)
    prev = np.full(n + 1, -1, dtype=int)
    F[0] = -penalty

    candidates = [0]

    for t in range(min_size, n + 1):
        best_cost = np.inf
        best_prev = -1

        for s in candidates:
            if t - s < min_size:
                continue
            cost = F[s] + penalty + _l2_cost(series, s, t)
            if cost < best_cost:
                best_cost = cost
                best_prev = s

        F[t]    = best_cost
        prev[t] = best_prev

        candidates = [s for s in candidates if F[s] + penalty <= F[t]]
        candidates.append(t)

    changepoints = []
    t = n
    while prev[t] > 0:
        changepoints.append(prev[t])
        t = prev[t]

    return sorted(changepoints)


def _bic_penalty(series: np.ndarray) -> float:
    n     = len(series)
    sigma = float(np.std(series))
    return max(2.0 * np.log(max(n, 2)) * (sigma ** 2), 1.0)


# ---------------------------------------------------------------------------
# Changepoint classification
# ---------------------------------------------------------------------------

def _classify_changepoints(
    series:          np.ndarray,
    changepoints:    list[int],
    timestamps:      np.ndarray,
    cv_threshold:    float,
) -> dict:
    """Classify each changepoint as a beacon start or an interval shift."""
    boundaries = [0] + changepoints + [len(series)]
    segments   = []
    for i in range(len(boundaries) - 1):
        s   = boundaries[i]
        e   = boundaries[i + 1]
        seg = series[s:e]
        if len(seg) == 0:
            continue
        mean = float(np.mean(seg))
        std  = float(np.std(seg))
        cv   = std / (mean + 1e-9)
        ts   = float(timestamps[s]) if s < len(timestamps) else float(timestamps[-1])
        segments.append({
            "start_idx":   s,
            "end_idx":     e,
            "mean_iat":    mean,
            "std_iat":     std,
            "cv":          cv,
            "is_periodic": cv < cv_threshold,
            "start_ts":    ts,
        })

    beacon_start_ts = None
    interval_shifts = []

    for i, seg in enumerate(segments):
        if i == 0:
            continue
        prev = segments[i - 1]
        if not prev["is_periodic"] and seg["is_periodic"]:
            if beacon_start_ts is None:
                beacon_start_ts = seg["start_ts"]
        if prev["is_periodic"] and seg["is_periodic"]:
            delta = abs(seg["mean_iat"] - prev["mean_iat"]) / (prev["mean_iat"] + 1e-9)
            if delta > 0.10:
                interval_shifts.append({
                    "timestamp":    seg["start_ts"],
                    "old_period_s": round(prev["mean_iat"], 1),
                    "new_period_s": round(seg["mean_iat"], 1),
                    "delta_pct":    round(delta * 100, 1),
                })

    return {
        "beacon_start_ts": beacon_start_ts,
        "interval_shifts": interval_shifts,
        "segments":        segments,
    }


# ---------------------------------------------------------------------------
# Per-pair changepoint analysis
# ---------------------------------------------------------------------------

def analyze_pair_changepoints(
    timestamps: pd.Series,
    cfg:        BDPConfig,
) -> dict:
    """
    Run PELT changepoint detection on a single (src_ip, dst_ip) IAT sequence.

    Uses the raw numeric timestamp column (Unix seconds float).
    """
    pc = cfg.pelt
    n  = len(timestamps)

    null = {
        "n_changepoints":      0,
        "changepoint_times":   [],
        "beacon_start_ts":     None,
        "beacon_start_dt":     None,
        "pre_start_iat_mean":  np.nan,
        "post_start_iat_mean": np.nan,
        "interval_shifts":     [],
        "has_interval_shift":  False,
        "pelt_cost":           np.nan,
    }

    if n < pc.min_observations:
        return null

    ts_vals = pd.to_numeric(timestamps, errors="coerce").dropna().sort_values().to_numpy(dtype=float)
    iat     = np.diff(ts_vals)

    if len(iat) < pc.min_segment_length * 2:
        return null

    penalty      = _bic_penalty(iat) if pc.penalty == "bic" else float(pc.penalty)
    changepoints = _pelt(iat, penalty, min_size=pc.min_segment_length)

    if not changepoints:
        return {**null, "n_changepoints": 0}

    cp_times       = [float(ts_vals[k]) for k in changepoints]
    classification = _classify_changepoints(iat, changepoints, ts_vals, cfg.periodicity.cv_threshold)

    beacon_start_ts = classification["beacon_start_ts"]
    beacon_start_dt = (
        pd.Timestamp(beacon_start_ts, unit="s", tz="UTC").strftime("%Y-%m-%d %H:%M:%S UTC")
        if beacon_start_ts is not None else None
    )

    pre_mean  = np.nan
    post_mean = np.nan
    if beacon_start_ts is not None:
        pre_mask  = ts_vals[:-1] < beacon_start_ts
        post_mask = ts_vals[:-1] >= beacon_start_ts
        if pre_mask.any():
            pre_mean  = float(np.mean(iat[pre_mask]))
        if post_mask.any():
            post_mean = float(np.mean(iat[post_mask]))

    boundaries = [0] + changepoints + [len(iat)]
    total_cost = sum(
        _l2_cost(iat, boundaries[i], boundaries[i + 1])
        for i in range(len(boundaries) - 1)
    )

    return {
        "n_changepoints":      len(changepoints),
        "changepoint_times":   cp_times,
        "beacon_start_ts":     beacon_start_ts,
        "beacon_start_dt":     beacon_start_dt,
        "pre_start_iat_mean":  round(pre_mean, 2) if not np.isnan(pre_mean) else np.nan,
        "post_start_iat_mean": round(post_mean, 2) if not np.isnan(post_mean) else np.nan,
        "interval_shifts":     classification["interval_shifts"],
        "has_interval_shift":  len(classification["interval_shifts"]) > 0,
        "pelt_cost":           round(total_cost, 2),
        "_segments":           classification["segments"],
    }


# ---------------------------------------------------------------------------
# All-pairs changepoint analysis
# ---------------------------------------------------------------------------

def analyze_beacon_changepoints(
    periodicity_df: pd.DataFrame,
    df_anomalies:   pd.DataFrame,
    cfg:            BDPConfig,
) -> pd.DataFrame:
    """
    Apply PELT changepoint detection to all confirmed beacon pairs.

    Filters periodicity_df to is_beacon_pair=True before running,
    so PELT is only applied where periodicity has confirmed beaconing.

    Parameters
    ----------
    periodicity_df : Output of periodicity.score_all_pairs().
    df_anomalies   : Raw anomaly DataFrame with src_ip, dst_ip, timestamp.
    cfg            : Pipeline configuration.

    Returns
    -------
    pd.DataFrame — one row per beacon pair with changepoint results.
    """
    beacon_pairs = periodicity_df[periodicity_df["is_beacon_pair"]]

    if beacon_pairs.empty:
        log.warning("No beacon pairs to analyze — periodicity stage found none.")
        return pd.DataFrame()

    log.info("Running PELT on %d confirmed beacon pairs.", len(beacon_pairs))
    results = []

    for _, row in beacon_pairs.iterrows():
        src = row["src_ip"]
        dst = row["dst_ip"]
        # Point 1: use channel_id for precise flow retrieval if available
        if "channel_id" in row and "channel_id" in df_anomalies.columns:
            pair_df = df_anomalies[df_anomalies["channel_id"] == row["channel_id"]]
        else:
            pair_df = df_anomalies[
                (df_anomalies["src_ip"] == src) & (df_anomalies["dst_ip"] == dst)
            ]

        result = analyze_pair_changepoints(pair_df["timestamp"], cfg)
        result["pair_id"]          = row["pair_id"]
        result["src_ip"]           = src
        result["dst_ip"]           = dst
        result["dominant_period_s"] = row.get("dominant_period_s", np.nan)
        results.append(result)

    changepoint_df = (
        pd.DataFrame(results)
        .sort_values("beacon_start_ts", na_position="last")
        .reset_index(drop=True)
    )

    n_with_start = int(changepoint_df["beacon_start_ts"].notna().sum())
    n_operator   = int(changepoint_df["has_interval_shift"].sum())
    log.info(
        "PELT complete: %d/%d pairs have estimated start times, %d show operator interaction",
        n_with_start, len(changepoint_df), n_operator,
    )
    return changepoint_df


# ---------------------------------------------------------------------------
# Visualisation
# ---------------------------------------------------------------------------

def plot_campaign_timeline(changepoint_df: pd.DataFrame) -> None:
    """Gantt-style timeline showing estimated beacon start times across all pairs."""
    df = changepoint_df.dropna(subset=["beacon_start_ts"]).copy()
    if df.empty:
        log.warning("No pairs with estimated start times to plot.")
        return

    df     = df.sort_values("beacon_start_ts")
    starts = pd.to_datetime(df["beacon_start_ts"], unit="s", utc=True)
    labels = [
        f"{r['src_ip']} → {r['dst_ip']}  (T={r['dominant_period_s']:.0f}s)"
        for _, r in df.iterrows()
    ]
    colors = ["#d62728" if v else "#1f77b4" for v in df["has_interval_shift"]]

    fig, ax = plt.subplots(figsize=(14, max(4, len(df) * 0.6)))

    for i, (start, label, color) in enumerate(zip(starts, labels, colors)):
        ax.scatter(start, i, s=120, color=color, zorder=5)
        ax.axhline(i, color="gray", linestyle=":", alpha=0.3, linewidth=0.7)

    ax.set_yticks(range(len(labels)))
    ax.set_yticklabels(labels, fontsize=9)
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%Y-%m-%d"))
    plt.setp(ax.xaxis.get_majorticklabels(), rotation=30, ha="right")
    ax.set_xlabel("Estimated Beacon Start Date/Time")
    ax.set_title("Campaign Timeline — Estimated Beacon Start by Pair\n"
                 "(red = operator interaction detected)")
    ax.grid(axis="x", alpha=0.3)

    from matplotlib.lines import Line2D
    ax.legend(handles=[
        Line2D([0], [0], marker="o", color="w", markerfacecolor="#d62728",
               markersize=10, label="Operator interaction detected"),
        Line2D([0], [0], marker="o", color="w", markerfacecolor="#1f77b4",
               markersize=10, label="No interval shift"),
    ], loc="lower right", fontsize=9)

    plt.tight_layout()
    plt.show()


def print_changepoint_brief(changepoint_df: pd.DataFrame) -> None:
    """Print structured PELT results for all beacon pairs."""
    if changepoint_df.empty:
        print("No changepoint results to display.")
        return

    print("\n" + "=" * 70)
    print("  CHANGEPOINT ANALYSIS — BEACON TIMELINE RECONSTRUCTION")
    print("=" * 70)

    for _, row in changepoint_df.iterrows():
        period = row.get("dominant_period_s", 0)
        print(f"\n  {row['src_ip']} → {row['dst_ip']}  "
              f"(beacon period ≈ {period:.0f}s / {period/60:.1f} min)")
        print(f"  {'─' * 55}")

        if row["beacon_start_dt"]:
            print(f"  Estimated start : {row['beacon_start_dt']}")
        else:
            print(f"  Estimated start : Could not determine")

        if row["has_interval_shift"]:
            print(f"  ⚠  Operator interaction: interval shift detected")
            for shift in row["interval_shifts"]:
                print(f"     {shift['old_period_s']:.0f}s → {shift['new_period_s']:.0f}s "
                      f"(Δ={shift['delta_pct']:.1f}%)")
        else:
            print(f"  No interval shifts detected (consistent automated behavior)")

    print("\n" + "=" * 70)
    print("  Correlate earliest start times with security events to identify")
    print("  the initial access vector.")
    print("=" * 70)
