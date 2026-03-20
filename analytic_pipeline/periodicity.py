"""
Periodicity Analysis
======================
Tests each (src_ip, dst_ip) pair for statistically significant inter-arrival
time regularity — the defining behavioral property of C2 beaconing.

Architecture change from v5
-----------------------------
Periodicity scoring now operates directly on (src_ip, dst_ip) pairs from the
IForest anomaly set. The previous version scored at the DBSCAN cluster level,
which caused beacon signals to be diluted by unrelated flows that happened to
land in the same cluster. Working at the pair level is cleaner, simpler, and
makes the noise-pair workaround unnecessary.

Key change: all timestamp computation now uses the raw `timestamp` column
(Unix float seconds) rather than the `datetime` column, eliminating all dtype
ambiguity issues from timezone-aware Timestamps stored as object dtype after
pandas concat operations.

Output columns per (src_ip, dst_ip) pair
------------------------------------------
    pair_id             "src→dst" string key.
    src_ip, dst_ip      Endpoint addresses.
    n_observations      Number of connections in this pair.
    dominant_period_s   Estimated beacon interval in seconds.
    acf_peak            Height of the dominant ACF peak (0–1).
    acf_peak_lag        Lag index of the dominant peak.
    iat_cv              Coefficient of variation of the IAT sequence.
    fft_period_s        Period from the dominant FFT frequency.
    fft_power_ratio     Fraction of total spectral power at dominant freq.
    is_periodic         Boolean: passes all periodicity thresholds.
    beacon_confidence   Composite score in [0, 1].
    is_beacon_pair      Boolean: beacon_confidence >= threshold.
"""
from __future__ import annotations

import logging
from typing import Optional

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from scipy import signal
from statsmodels.tsa.stattools import acf

from .config import BDPConfig

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# IAT computation
# ---------------------------------------------------------------------------

def _compute_iat_sequence(timestamps: pd.Series) -> np.ndarray:
    """
    Convert a series of timestamps to inter-arrival times in seconds.

    Expects numeric Unix seconds (float or int). This is always the case
    when using the `timestamp` column from the pipeline.

    Returns an empty array if fewer than 3 observations are present.
    """
    if len(timestamps) < 3:
        return np.array([])

    if pd.api.types.is_numeric_dtype(timestamps):
        ts = timestamps.sort_values().to_numpy(dtype=float)
        return np.diff(ts)

    # datetime64 (including timezone-aware from load_and_prepare)
    if pd.api.types.is_datetime64_any_dtype(timestamps):
        ts = timestamps.sort_values()
        return np.diff(ts.values.astype("datetime64[ns]").astype(np.float64) / 1e9)

    # Last resort: try numeric coercion
    vals = pd.to_numeric(timestamps, errors="coerce").dropna()
    if len(vals) < 3:
        return np.array([])
    median_val = float(vals.median())
    ts_sec = vals / 1e9 if median_val > 1e12 else vals
    return np.diff(ts_sec.sort_values().to_numpy()).astype(float)


# ---------------------------------------------------------------------------
# ACF and FFT analysis
# ---------------------------------------------------------------------------

def _binned_count_acf(
    timestamps: np.ndarray,
    nlags: int,
    significance_threshold: float,
) -> tuple[float, int]:
    """
    Compute ACF on a binned flow-count time series rather than raw IAT.

    Rationale: ACF on raw IAT sequences fails for jittered beacons because
    consecutive intervals are not correlated with each other — they are
    independent draws from a distribution centered on the beacon period.
    Binning flows into half-period-width buckets and computing ACF on the
    resulting count series is robust to jitter: a periodic beacon produces
    a count series with a strong autocorrelation peak at lag 1 regardless
    of per-interval jitter.

    Parameters
    ----------
    timestamps  : Sorted array of Unix-second timestamps.
    nlags       : Maximum ACF lags to compute.
    significance_threshold : Minimum peak height to report.

    Returns
    -------
    (peak_height, peak_lag) of the dominant ACF peak above threshold.
    """
    if len(timestamps) < 8:
        return 0.0, 0

    iat = np.diff(timestamps)
    iat = iat[iat > 0]
    if len(iat) < 4:
        return 0.0, 0

    # Bin size = half the median IAT so each beacon firing lands in its own bin
    bin_size = max(float(np.median(iat)) / 2.0, 1.0)
    t_min, t_max = timestamps[0], timestamps[-1]
    bins = np.arange(t_min, t_max + bin_size, bin_size)
    counts, _ = np.histogram(timestamps, bins=bins)

    if len(counts) < nlags + 2:
        nlags = max(1, len(counts) - 2)

    # Numpy-based normalized autocorrelation (avoids statsmodels dependency path)
    x = counts.astype(float) - counts.mean()
    n = len(x)
    if n < 4:
        return 0.0, 0

    full = np.correlate(x, x, mode="full")
    acf_vals = full[n - 1:] / (full[n - 1] + 1e-9)

    acf_search = acf_vals[1:nlags + 1]
    noise_floor = 1.96 / np.sqrt(n)
    threshold = max(significance_threshold, noise_floor)

    above = np.where(acf_search > threshold)[0]
    if len(above) == 0:
        return 0.0, 0

    best_lag = int(above[np.argmax(acf_search[above])])
    return float(acf_search[best_lag]), best_lag + 1


def _acf_dominant_peak(
    iat: np.ndarray,
    nlags: int,
    significance_threshold: float,
) -> tuple[float, int]:
    """Return (peak_height, peak_lag) of the dominant ACF peak above threshold."""
    n = len(iat)
    if n < nlags + 2:
        nlags = max(1, n - 2)

    acf_vals    = acf(iat, nlags=nlags, fft=True, missing="conservative")
    acf_search  = acf_vals[1:]   # skip lag 0 (always 1.0)
    noise_floor = 1.96 / np.sqrt(n)
    threshold   = max(significance_threshold, noise_floor)

    above = np.where(acf_search > threshold)[0]
    if len(above) == 0:
        return 0.0, 0

    best_lag = int(above[np.argmax(acf_search[above])])
    return float(acf_search[best_lag]), best_lag + 1   # +1 to restore lag index


def _fft_dominant_period(
    iat: np.ndarray,
    min_period_s: float,
) -> tuple[float, float]:
    """Return (dominant_period_s, power_ratio) from Welch PSD of IAT sequence."""
    n = len(iat)
    if n < 8:
        return 0.0, 0.0

    nperseg    = min(n, 64)
    freqs, psd = signal.welch(iat, fs=1.0, nperseg=nperseg)

    with np.errstate(divide="ignore", invalid="ignore"):
        periods = np.where(freqs > 0, 1.0 / freqs, 0.0)

    valid = (freqs > 0) & (periods >= min_period_s)
    if not valid.any():
        return 0.0, 0.0

    psd_valid     = psd[valid]
    periods_valid = periods[valid]
    dominant_idx  = int(np.argmax(psd_valid))
    power_ratio   = float(psd_valid[dominant_idx] / (psd[valid].sum() + 1e-12))
    return float(periods_valid[dominant_idx]), power_ratio


# ---------------------------------------------------------------------------
# Per-pair scoring
# ---------------------------------------------------------------------------

def score_pair_periodicity(
    timestamps: pd.Series,
    cfg: BDPConfig,
) -> dict:
    """
    Compute all periodicity metrics for a single (src_ip, dst_ip) pair.

    Parameters
    ----------
    timestamps : Series of Unix-second timestamps for this pair.
    cfg        : Pipeline configuration.

    Returns
    -------
    Dict of periodicity metrics; is_periodic=False if too few observations.
    """
    pc  = cfg.periodicity
    iat = _compute_iat_sequence(timestamps)
    n   = len(timestamps)

    null_result = {
        "dominant_period_s":  0.0,
        "acf_peak":           0.0,
        "acf_peak_lag":       0,
        "iat_cv":             np.nan,
        "fft_period_s":       0.0,
        "fft_power_ratio":    0.0,
        "n_observations":     n,
        "is_periodic":        False,
    }

    if len(iat) < pc.min_observations - 1:
        return null_result

    iat_mean = float(np.mean(iat))
    iat_std  = float(np.std(iat))
    iat_cv   = iat_std / (iat_mean + 1e-9)

    # Use binned-count ACF rather than raw IAT ACF.
    # Raw IAT ACF fails for jittered beacons (consecutive intervals are
    # independent draws, not autocorrelated). Binned count ACF is robust
    # to jitter and gives strong peaks for all tested beacon scenarios.
    ts_sorted = np.sort(pd.to_numeric(timestamps, errors="coerce").dropna().to_numpy(dtype=float))
    acf_peak, acf_lag = _binned_count_acf(ts_sorted, pc.acf_nlags, pc.acf_significance_threshold)

    # Period estimate from binned ACF.
    # bin_size = median_iat / 2; the count series peaks at lag=2 when one
    # full beacon period elapses (each firing lands in a distinct bin, so
    # two consecutive firings span 2 bins = 1 full period).
    #   period = acf_lag * bin_size = acf_lag * (median_iat / 2)
    # For the common lag=2 case: 2 * (median_iat/2) = median_iat. Correct.
    iat_median   = float(np.median(iat))
    acf_period_s = float(acf_lag * iat_median / 2.0) if acf_lag > 0 else 0.0

    fft_period_s, fft_power_ratio = _fft_dominant_period(iat, pc.min_period_s)

    # Prefer ACF period when available; FFT on raw IAT is unreliable for jittered beacons
    dominant_period_s = acf_period_s if acf_period_s >= pc.min_period_s else fft_period_s

    # FFT is not required when binned-ACF already provides strong evidence.
    # Requiring all three gates would reject jittered beacons where FFT spreads
    # power across many frequencies instead of concentrating at the beacon period.
    acf_passes  = acf_peak  > pc.acf_significance_threshold and acf_period_s >= pc.min_period_s
    fft_passes  = fft_power_ratio > pc.fft_power_ratio_threshold and fft_period_s >= pc.min_period_s
    is_periodic = (
        iat_cv < pc.cv_threshold
        and dominant_period_s >= pc.min_period_s
        and (acf_passes or fft_passes)
    )

    return {
        "dominant_period_s":  round(dominant_period_s, 1),
        "acf_peak":           round(acf_peak, 4),
        "acf_peak_lag":       acf_lag,
        "iat_cv":             round(iat_cv, 4),
        "fft_period_s":       round(fft_period_s, 1),
        "fft_power_ratio":    round(fft_power_ratio, 4),
        "n_observations":     n,
        "is_periodic":        is_periodic,
    }


# ---------------------------------------------------------------------------
# Beacon confidence
# ---------------------------------------------------------------------------

def _beacon_confidence(
    is_periodic:      bool,
    acf_peak:         float,
    iat_cv:           float,
    fft_power_ratio:  float,
    cfg:              BDPConfig,
) -> float:
    """
    Compute a composite beacon confidence score in [0, 1] for a single pair.

    Uses continuous signal strengths rather than the hard is_periodic boolean
    so that short observation windows (where FFT may be unreliable) still
    surface genuine beacons. The boolean is included as a bonus weight rather
    than as a gating condition.

        acf_peak     (0.40)  ACF peak height — primary periodicity evidence.
        iat_cv       (0.30)  Inverted IAT CV — interval regularity.
        fft_power    (0.20)  Spectral concentration — independent confirmation.
        is_periodic  (0.10)  Bonus for passing all hard thresholds simultaneously.

    Parameters
    ----------
    is_periodic     : Whether the pair passed all hard periodicity thresholds.
    acf_peak        : Height of the dominant ACF peak.
    iat_cv          : Coefficient of variation of the IAT sequence.
    fft_power_ratio : Fraction of spectral power at the dominant frequency.
    cfg             : Pipeline configuration.

    Returns
    -------
    Float in [0, 1].
    """
    pc = cfg.periodicity

    acf_score = float(np.clip(acf_peak / (pc.acf_significance_threshold + 1e-9), 0, 1))
    cv_score  = float(np.clip(1.0 - (iat_cv / pc.cv_threshold), 0, 1)) if not np.isnan(iat_cv) else 0.0
    fft_score = float(np.clip(fft_power_ratio / (pc.fft_power_ratio_threshold + 1e-9), 0, 1))

    return round(
        0.40 * acf_score
        + 0.30 * cv_score
        + 0.20 * fft_score
        + 0.10 * float(is_periodic),
        4,
    )


# ---------------------------------------------------------------------------
# All-pairs scoring
# ---------------------------------------------------------------------------

def score_all_pairs(
    df_anomalies:  pd.DataFrame,
    cfg:           BDPConfig,
    sax_df:        Optional[pd.DataFrame] = None,
) -> pd.DataFrame:
    """
    Apply periodicity scoring to every (src_ip, dst_ip) pair in the
    anomaly set, optionally restricted to SAX-passing pairs.

    Parameters
    ----------
    df_anomalies : IForest-filtered DataFrame with src_ip, dst_ip, timestamp.
    cfg          : Pipeline configuration.
    sax_df       : Optional output of screen_pairs(). If provided, only pairs
                   with sax_prescreen_pass=True are evaluated with ACF+FFT.
                   All other pairs receive beacon_confidence=0.

    Returns
    -------
    pd.DataFrame with one row per pair, sorted by beacon_confidence descending.
    """
    pc = cfg.periodicity

    # Build set of channel_ids that passed SAX (prefer channel_id, fall back to pair_id)
    sax_pass_ids: Optional[set] = None
    if sax_df is not None and "sax_prescreen_pass" in sax_df.columns:
        id_col = "channel_id" if "channel_id" in sax_df.columns else "pair_id"
        sax_pass_ids = set(
            sax_df[sax_df["sax_prescreen_pass"]][id_col].astype(str).tolist()
        )
        log.info("ACF analysis restricted to %d SAX-passing channels", len(sax_pass_ids))

    results = []

    # Point 1: group by channel_id if available, else fall back to (src_ip, dst_ip)
    if "channel_id" in df_anomalies.columns:
        group_iter = df_anomalies.groupby("channel_id", sort=False)
        use_channel_id = True
    else:
        group_iter = df_anomalies.groupby(["src_ip", "dst_ip"])
        use_channel_id = False

    for group_key, pair_df in group_iter:
        if use_channel_id:
            channel_id = str(group_key)
            src = str(pair_df["src_ip"].iloc[0])
            dst = str(pair_df["dst_ip"].iloc[0])
        else:
            src, dst = group_key
            channel_id = f"{src}→{dst}"

        pair_id = f"{src}→{dst}"

        # Skip if SAX filter active and this channel didn't pass
        sax_lookup_key = channel_id if sax_pass_ids is not None and channel_id in (sax_pass_ids or set()) else pair_id
        if sax_pass_ids is not None and channel_id not in sax_pass_ids and pair_id not in sax_pass_ids:
            results.append({
                "channel_id":         channel_id,
                "pair_id":            pair_id,
                "src_ip":             src,
                "dst_ip":             dst,
                "n_observations":     len(pair_df),
                "dominant_period_s":  0.0,
                "acf_peak":           0.0,
                "acf_peak_lag":       0,
                "iat_cv":             np.nan,
                "fft_period_s":       0.0,
                "fft_power_ratio":    0.0,
                "is_periodic":        False,
                "beacon_confidence":  0.0,
                "is_beacon_pair":     False,
            })
            continue

        # Skip channels below minimum observation count
        if len(pair_df) < pc.min_observations:
            results.append({
                "channel_id":         channel_id,
                "pair_id":            pair_id,
                "src_ip":             src,
                "dst_ip":             dst,
                "n_observations":     len(pair_df),
                "dominant_period_s":  0.0,
                "acf_peak":           0.0,
                "acf_peak_lag":       0,
                "iat_cv":             np.nan,
                "fft_period_s":       0.0,
                "fft_power_ratio":    0.0,
                "is_periodic":        False,
                "beacon_confidence":  0.0,
                "is_beacon_pair":     False,
            })
            continue

        metrics = score_pair_periodicity(pair_df["timestamp"], cfg)
        confidence = _beacon_confidence(
            metrics["is_periodic"],
            metrics["acf_peak"],
            metrics["iat_cv"],
            metrics["fft_power_ratio"],
            cfg,
        )

        results.append({
            "channel_id":         channel_id,
            "pair_id":            pair_id,
            "src_ip":             src,
            "dst_ip":             dst,
            **metrics,
            "beacon_confidence":  confidence,
            "is_beacon_pair":     confidence >= pc.confidence_threshold,
        })

    periodicity_df = (
        pd.DataFrame(results)
        .sort_values("beacon_confidence", ascending=False)
        .reset_index(drop=True)
    )

    n_beacon = int(periodicity_df["is_beacon_pair"].sum()) if not periodicity_df.empty else 0
    log.info(
        "score_all_pairs(): %d beacon pairs identified out of %d total pairs",
        n_beacon, len(periodicity_df),
    )
    return periodicity_df


# ---------------------------------------------------------------------------
# Visualisation
# ---------------------------------------------------------------------------

def plot_iat_distribution(
    pair_df: pd.DataFrame,
    src_ip:  str,
    dst_ip:  str,
    cfg:     BDPConfig,
) -> None:
    """Plot IAT histogram, ACF, and PSD for a single (src_ip, dst_ip) pair."""
    if len(pair_df) < 3:
        log.warning("Too few observations for %s → %s to plot IAT.", src_ip, dst_ip)
        return

    iat = _compute_iat_sequence(pair_df["timestamp"])
    if len(iat) == 0:
        return

    result = score_pair_periodicity(pair_df["timestamp"], cfg)
    nlags   = min(cfg.periodicity.acf_nlags, len(iat) - 2)
    acf_vals = acf(iat, nlags=nlags, fft=True, missing="conservative")

    fig, axes = plt.subplots(1, 3, figsize=(16, 4))

    axes[0].hist(iat, bins=40, color="steelblue", edgecolor="black", alpha=0.8)
    axes[0].axvline(float(np.mean(iat)), color="red", linestyle="--",
                    label=f"Mean IAT = {np.mean(iat):.0f}s")
    axes[0].set_title(f"IAT Distribution\n{src_ip} → {dst_ip}")
    axes[0].set_xlabel("Inter-Arrival Time (seconds)")
    axes[0].set_ylabel("Count")
    axes[0].legend(fontsize=8)
    axes[0].grid(True, alpha=0.3)

    noise_floor = 1.96 / np.sqrt(len(iat))
    axes[1].bar(range(len(acf_vals)), acf_vals, color="steelblue", alpha=0.7)
    axes[1].axhline(noise_floor,  color="red", linestyle="--",
                    label=f"95% CI (±{noise_floor:.3f})")
    axes[1].axhline(-noise_floor, color="red", linestyle="--")
    if result["acf_peak_lag"] > 0:
        axes[1].axvline(result["acf_peak_lag"], color="orange", linestyle=":",
                        linewidth=2, label=f"Peak lag={result['acf_peak_lag']}")
    axes[1].set_title(f"Autocorrelation Function\nCV={result['iat_cv']:.3f}  "
                      f"ACF peak={result['acf_peak']:.3f}")
    axes[1].set_xlabel("Lag")
    axes[1].set_ylabel("ACF")
    axes[1].legend(fontsize=8)
    axes[1].grid(True, alpha=0.3)

    n = len(iat)
    nperseg = min(n, 64)
    freqs, psd = signal.welch(iat, fs=1.0, nperseg=nperseg)
    with np.errstate(divide="ignore", invalid="ignore"):
        periods = np.where(freqs > 0, 1.0 / freqs, np.nan)
    valid = ~np.isnan(periods)
    axes[2].semilogy(periods[valid], psd[valid], color="steelblue")
    if result["fft_period_s"] > 0:
        axes[2].axvline(result["fft_period_s"], color="red", linestyle="--",
                        label=f"Dominant period={result['fft_period_s']:.0f}s")
    axes[2].set_title(f"Power Spectral Density\nPower ratio={result['fft_power_ratio']:.3f}")
    axes[2].set_xlabel("Period (seconds)")
    axes[2].set_ylabel("Power (log scale)")
    axes[2].legend(fontsize=8)
    axes[2].grid(True, alpha=0.3)

    verdict = "✓ PERIODIC" if result["is_periodic"] else "✗ NOT PERIODIC"
    fig.suptitle(
        f"{verdict}  |  Dominant period: {result['dominant_period_s']:.0f}s  "
        f"({result['dominant_period_s']/60:.1f} min)",
        fontsize=11, fontweight="bold",
    )
    plt.tight_layout()
    plt.show()


def plot_pair_periodicity_summary(periodicity_df: pd.DataFrame) -> None:
    """Bar chart of beacon_confidence across all evaluated pairs."""
    if periodicity_df.empty:
        return

    df     = periodicity_df.sort_values("beacon_confidence", ascending=False).head(50)
    colors = ["#d62728" if v else "#1f77b4" for v in df["is_beacon_pair"]]

    fig, axes = plt.subplots(1, 2, figsize=(16, 5))

    axes[0].bar(range(len(df)), df["beacon_confidence"], color=colors)
    axes[0].set_xticks(range(len(df)))
    axes[0].set_xticklabels(df["pair_id"].astype(str), rotation=90, fontsize=6)
    axes[0].set_xlabel("Pair (src→dst)")
    axes[0].set_ylabel("Beacon Confidence Score")
    axes[0].set_title("Beacon Confidence by Pair (top 50)\n(red = is_beacon_pair)")
    axes[0].grid(axis="y", alpha=0.3)
    from matplotlib.patches import Patch
    axes[0].legend(handles=[
        Patch(color="#d62728", label="Beacon pair"),
        Patch(color="#1f77b4", label="Non-beacon pair"),
    ])

    beacon_pairs = periodicity_df[
        periodicity_df["is_beacon_pair"] & (periodicity_df["dominant_period_s"] > 0)
    ]
    if len(beacon_pairs) > 0:
        periods_min = beacon_pairs["dominant_period_s"] / 60
        axes[1].hist(periods_min, bins=20, color="#d62728", edgecolor="black", alpha=0.8)
        axes[1].set_xlabel("Dominant Beacon Period (minutes)")
        axes[1].set_ylabel("Number of Pairs")
        axes[1].set_title("Distribution of Beacon Periods\n(beacon pairs only)")
        axes[1].grid(True, alpha=0.3)
        for period_min, label in [(5, "5m"), (15, "15m"), (30, "30m"),
                                   (60, "1h"), (360, "6h"), (1440, "24h")]:
            if periods_min.min() <= period_min <= periods_min.max():
                axes[1].axvline(period_min, color="gray", linestyle=":", alpha=0.7, linewidth=1)
                axes[1].text(period_min, axes[1].get_ylim()[1] * 0.9,
                             label, fontsize=7, color="gray", ha="center")
    else:
        axes[1].text(0.5, 0.5, "No beacon pairs identified",
                     ha="center", va="center", transform=axes[1].transAxes)
        axes[1].set_title("Distribution of Beacon Periods")

    plt.tight_layout()
    plt.show()


# ---------------------------------------------------------------------------
# Backward-compat alias (used by changepoint.py and corroboration.py)
# ---------------------------------------------------------------------------

def plot_cluster_periodicity_summary(periodicity_df: pd.DataFrame) -> None:
    """Alias for plot_pair_periodicity_summary (backward compatibility)."""
    plot_pair_periodicity_summary(periodicity_df)
