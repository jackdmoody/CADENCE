"""
SAX Periodicity Pre-Screening
================================
Fast symbolic pre-filter that eliminates clearly non-periodic (src, dst) pairs
before the computationally expensive ACF + FFT analysis in periodicity.py.

This module is unchanged in its core SAX math. The only structural change is
that screen_pairs() now operates directly on all (src_ip, dst_ip) pairs from
the IForest anomaly set rather than iterating within DBSCAN clusters.

How SAX works
--------------
1. Divide the IAT sequence into w equal-length segments (word length).
2. Compute the mean of each segment (PAA) to reduce dimensionality.
3. Map each PAA value to a symbol from an alphabet of size a.
4. The result is a string of w symbols, e.g. "aabccbbaabccbb".

A periodic IAT sequence produces a repeating motif in the SAX string.
Three tests are applied:
    1. Symbol CV: low CV indicates tightly clustered PAA values.
    2. SAX ACF: peak autocorrelation of the symbol sequence at lag > 0.
    3. Motif fraction: fraction of the word covered by the longest repeat.

A pair passes if at least cfg.sax.min_tests_passing tests fire.

Output columns per (src_ip, dst_ip) pair
------------------------------------------
    pair_id             "src→dst" key.
    src_ip, dst_ip      Endpoint addresses.
    sax_word            Encoded SAX string.
    sax_symbol_cv       CV of the integer symbol sequence.
    sax_acf_peak        Peak ACF value of the symbol sequence at lag > 0.
    sax_motif_fraction  Fraction of SAX word explained by longest repeat.
    sax_passes          Boolean: passes SAX screening.
    n_observations      Number of connections in this pair.
"""
from __future__ import annotations

import logging
from typing import Optional

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

from .config import BDPConfig

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# SAX encoding
# ---------------------------------------------------------------------------

_SAX_BREAKPOINTS: dict[int, list[float]] = {
    2: [0.0],
    3: [-0.4307, 0.4307],
    4: [-0.6745, 0.0, 0.6745],
    5: [-0.8416, -0.2533, 0.2533, 0.8416],
    6: [-0.9674, -0.4307, 0.0, 0.4307, 0.9674],
    7: [-1.0676, -0.5659, -0.1800, 0.1800, 0.5659, 1.0676],
    8: [-1.1503, -0.6745, -0.3186, 0.0, 0.3186, 0.6745, 1.1503],
}

_ALPHABET = "abcdefgh"


def _paa(series: np.ndarray, n_segments: int) -> np.ndarray:
    """Piecewise Aggregate Approximation: reduce series to n_segments means."""
    n = len(series)
    if n_segments >= n:
        return np.array([series[min(i, n - 1)] for i in range(n_segments)], dtype=float)

    segment_size = n / n_segments
    paa_values   = np.zeros(n_segments)
    for i in range(n_segments):
        start   = i * segment_size
        end     = start + segment_size
        i_start = int(np.ceil(start))
        i_end   = int(np.floor(end))

        total = 0.0
        weight = 0.0
        if i_start > 0 and start < i_start:
            frac    = i_start - start
            total  += series[i_start - 1] * frac
            weight += frac
        for j in range(i_start, min(i_end, n)):
            total  += series[j]
            weight += 1.0
        if i_end < n and end > i_end:
            frac    = end - i_end
            total  += series[i_end] * frac
            weight += frac

        paa_values[i] = total / weight if weight > 0 else 0.0
    return paa_values


def _znorm(series: np.ndarray, eps: float = 1e-8) -> np.ndarray:
    """Z-normalise a series to mean 0, std 1."""
    std = np.std(series)
    if std < eps:
        return np.zeros_like(series, dtype=float)
    return (series - np.mean(series)) / std


def encode_sax(
    iat:          np.ndarray,
    word_length:  int,
    alphabet_size: int,
) -> tuple[str, np.ndarray]:
    """Encode a raw IAT sequence as a SAX string."""
    if alphabet_size not in _SAX_BREAKPOINTS:
        raise ValueError(f"alphabet_size must be in {list(_SAX_BREAKPOINTS)}; got {alphabet_size}")

    znorm_iat   = _znorm(iat.astype(float))
    paa_values  = _paa(znorm_iat, word_length)
    breakpoints = _SAX_BREAKPOINTS[alphabet_size]

    symbols     = []
    symbol_ints = []
    for val in paa_values:
        idx = int(np.searchsorted(breakpoints, val))
        symbols.append(_ALPHABET[idx])
        symbol_ints.append(idx)

    return "".join(symbols), np.array(symbol_ints, dtype=int)


# ---------------------------------------------------------------------------
# SAX periodicity tests
# ---------------------------------------------------------------------------

def _sax_symbol_cv(symbol_ints: np.ndarray) -> float:
    if len(symbol_ints) < 2:
        return np.nan
    mean = float(np.mean(symbol_ints))
    std  = float(np.std(symbol_ints))
    return std / (mean + 1e-9)


def _sax_acf_peak(symbol_ints: np.ndarray, max_lag: int = 10) -> float:
    n = len(symbol_ints)
    if n < max_lag + 2:
        return 0.0
    x     = symbol_ints.astype(float)
    x_std = np.std(x)
    if x_std < 1e-9:
        return 0.0
    x_norm = (x - np.mean(x)) / x_std
    peaks  = []
    for lag in range(1, min(max_lag + 1, n)):
        corr = float(np.mean(x_norm[:n - lag] * x_norm[lag:]))
        peaks.append(abs(corr))
    return float(max(peaks)) if peaks else 0.0


def _sax_motif_fraction(sax_word: str) -> float:
    n = len(sax_word)
    if n < 4:
        return 0.0
    best_fraction = 0.0
    for motif_len in range(2, n // 2 + 1):
        motif = sax_word[:motif_len]
        count = 0
        pos   = 0
        while pos <= n - motif_len:
            if sax_word[pos:pos + motif_len] == motif:
                count += 1
                pos   += motif_len
            else:
                pos   += 1
        fraction = (count * motif_len) / n
        if fraction > best_fraction:
            best_fraction = fraction
    return round(best_fraction, 4)


# ---------------------------------------------------------------------------
# Per-pair screening
# ---------------------------------------------------------------------------

def screen_pair_sax(timestamps: pd.Series, cfg: BDPConfig) -> dict:
    """
    Apply SAX screening to a single (src_ip, dst_ip) pair.

    Uses the raw numeric timestamp column (Unix seconds float) for IAT
    computation — unambiguous and dtype-safe.

    Parameters
    ----------
    timestamps : Series of Unix-second timestamps for this pair.
    cfg        : Pipeline configuration.

    Returns
    -------
    Dict of SAX screening metrics and sax_passes boolean.
    """
    sc = cfg.sax
    n  = len(timestamps)

    null = {
        "sax_word":           "",
        "sax_symbol_cv":      np.nan,
        "sax_acf_peak":       0.0,
        "sax_motif_fraction": 0.0,
        "sax_passes":         False,
        "n_observations":     n,
    }

    if n < sc.min_observations:
        return null

    # Use numeric Unix seconds directly — no datetime parsing needed
    ts  = pd.to_numeric(timestamps, errors="coerce").dropna().sort_values()
    iat = np.diff(ts.to_numpy(dtype=float))

    if len(iat) < 3:
        return null

    word_length = min(sc.word_length, len(iat) - 1)
    if word_length < 4:
        return null

    try:
        sax_word, symbol_ints = encode_sax(iat, word_length, sc.alphabet_size)
    except Exception as e:
        log.debug("SAX encoding failed for pair: %s", e)
        return null

    symbol_cv      = _sax_symbol_cv(symbol_ints)
    acf_peak       = _sax_acf_peak(symbol_ints, max_lag=min(sc.max_acf_lag, word_length // 2))
    motif_fraction = _sax_motif_fraction(sax_word)

    tests_passing = (
        (not np.isnan(symbol_cv) and symbol_cv < sc.cv_threshold)
        + (acf_peak > sc.acf_threshold)
        + (motif_fraction > sc.motif_threshold)
    )
    sax_passes = tests_passing >= sc.min_tests_passing

    return {
        "sax_word":           sax_word,
        "sax_symbol_cv":      round(float(symbol_cv), 4) if not np.isnan(symbol_cv) else np.nan,
        "sax_acf_peak":       round(float(acf_peak), 4),
        "sax_motif_fraction": float(motif_fraction),
        "sax_passes":         sax_passes,
        "n_observations":     n,
    }


# ---------------------------------------------------------------------------
# All-pairs screening
# ---------------------------------------------------------------------------

def screen_pairs(
    df_anomalies: pd.DataFrame,
    cfg:          BDPConfig,
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """
    Apply SAX screening to every (src_ip, dst_ip) pair in the anomaly set.

    Pairs are sorted by flow count descending before evaluation so the
    richest pairs (most likely to show a real signal) are always evaluated
    even when max_pairs is hit.

    Parameters
    ----------
    df_anomalies : IForest-filtered DataFrame with src_ip, dst_ip, timestamp.
    cfg          : Pipeline configuration.

    Returns
    -------
    (sax_df, pairs_df)
        sax_df   — one row per pair with sax_prescreen_pass column.
        pairs_df — same, but as a flat list for visualisation.
                   (identical to sax_df in the pair-first architecture,
                    kept for API symmetry with the old screen_clusters)
    """
    pc = cfg.pair
    sc = cfg.sax

    # Group by channel_id if available (Point 1), else fall back to (src_ip, dst_ip)
    group_col = "channel_id" if "channel_id" in df_anomalies.columns else None

    if group_col:
        pair_counts = (
            df_anomalies.groupby(group_col)
            .size()
            .reset_index(name="n_flows")
            .sort_values("n_flows", ascending=False)
        )
    else:
        pair_counts = (
            df_anomalies.groupby(["src_ip", "dst_ip"])
            .size()
            .reset_index(name="n_flows")
            .sort_values("n_flows", ascending=False)
        )

    pair_counts = pair_counts[pair_counts["n_flows"] >= pc.min_pair_flows]

    if len(pair_counts) > pc.max_pairs:
        log.info(
            "screen_pairs(): capping at %d channels (of %d total unique channels)",
            pc.max_pairs, len(pair_counts),
        )
        pair_counts = pair_counts.head(pc.max_pairs)

    log.info("screen_pairs(): evaluating %d channels", len(pair_counts))

    results = []
    for _, row in pair_counts.iterrows():
        if group_col:
            channel_id = row[group_col]
            pair_df    = df_anomalies[df_anomalies[group_col] == channel_id]
            src = str(pair_df["src_ip"].iloc[0])
            dst = str(pair_df["dst_ip"].iloc[0])
        else:
            src, dst   = row["src_ip"], row["dst_ip"]
            channel_id = f"{src}→{dst}"
            pair_df    = df_anomalies[
                (df_anomalies["src_ip"] == src) & (df_anomalies["dst_ip"] == dst)
            ]

        result = screen_pair_sax(pair_df["timestamp"], cfg)
        result["channel_id"]         = channel_id
        result["pair_id"]            = f"{src}→{dst}"
        result["src_ip"]             = src
        result["dst_ip"]             = dst
        result["sax_prescreen_pass"] = result["sax_passes"]
        results.append(result)

        log.debug(
            "Channel %s  SAX: passes=%s  n=%d",
            channel_id, result["sax_passes"], result["n_observations"],
        )

    sax_df   = pd.DataFrame(results)
    pairs_df = sax_df.copy()  # same data, kept for API symmetry

    n_pass = int(sax_df["sax_prescreen_pass"].sum()) if not sax_df.empty else 0
    n_skip = len(sax_df) - n_pass
    log.info(
        "SAX pre-screening: %d pairs pass → full ACF analysis  |  %d pairs eliminated",
        n_pass, n_skip,
    )
    return sax_df, pairs_df


# ---------------------------------------------------------------------------
# Visualisation
# ---------------------------------------------------------------------------

def plot_sax_screening_summary(
    sax_df:   pd.DataFrame,
    pairs_df: pd.DataFrame,
) -> None:
    """Scatter summary of SAX screening results for all evaluated pairs."""
    if sax_df.empty:
        log.warning("plot_sax_screening_summary: no data to plot")
        return

    fig, axes = plt.subplots(1, 2, figsize=(15, 5))

    # Panel 1: n_observations vs sax_acf_peak, coloured by pass/fail
    passes = sax_df[sax_df["sax_prescreen_pass"] == True]
    fails  = sax_df[sax_df["sax_prescreen_pass"] == False]

    axes[0].scatter(
        fails["n_observations"], fails["sax_acf_peak"],
        c="#aec7e8", s=15, alpha=0.4, label="SAX fail", edgecolors="none"
    )
    axes[0].scatter(
        passes["n_observations"], passes["sax_acf_peak"],
        c="#d62728", s=25, alpha=0.8, label="SAX pass", edgecolors="none"
    )
    axes[0].set_xlabel("Observations per Pair")
    axes[0].set_ylabel("SAX ACF Peak")
    axes[0].set_title(
        f"SAX Pre-Screening: Observations vs ACF Peak\n"
        f"{len(passes)} pass / {len(fails)} fail"
    )
    axes[0].legend()
    axes[0].grid(True, alpha=0.3)

    # Panel 2: ACF peak vs motif fraction
    axes[1].scatter(
        fails["sax_acf_peak"], fails["sax_motif_fraction"],
        c="#aec7e8", s=15, alpha=0.4, label="SAX fail", edgecolors="none"
    )
    axes[1].scatter(
        passes["sax_acf_peak"], passes["sax_motif_fraction"],
        c="#d62728", s=25, alpha=0.8, label="SAX pass", edgecolors="none"
    )
    axes[1].set_xlabel("SAX ACF Peak")
    axes[1].set_ylabel("SAX Motif Fraction")
    axes[1].set_title("SAX Decision Space: ACF Peak vs Motif Fraction")
    axes[1].legend()
    axes[1].grid(True, alpha=0.3)

    plt.suptitle("SAX Periodicity Pre-Screening Summary", fontsize=12, fontweight="bold")
    plt.tight_layout()
    plt.show()
