"""
Isolation Forest Anomaly Pre-Filter — Pair Level
==================================================
Scores (src_ip, dst_ip) pairs rather than individual flows.

Architecture note
-----------------
Flow-level IForest (prior to v6) consistently scored beacon flows as *normal*
because individual beacon connections are volumetrically unremarkable — small
bytes, short duration, standard ports. The anomaly signal only becomes visible
when flows are aggregated to the pair level: a pair with 1400 identical flows
at 5-minute intervals has a very low IAT CV and bytes CV, which is anomalous
relative to background pairs.

By shifting IForest input from flows to pairs, the contamination parameter
controls the fraction of *pairs* flagged rather than flows, which is both
more meaningful and more stable across different data volumes.

Output columns added to pair_df:
    iforest_score   decision_function value (lower = more anomalous)
    iforest_label   1 = normal, -1 = anomaly
"""
from __future__ import annotations

import logging

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split

from .config import BDPConfig
from .features import IFOREST_FEATURES

log = logging.getLogger(__name__)


def run_isolation_forest(
    pair_df: pd.DataFrame,
    cfg: BDPConfig,
    feature_suffix: str = "_stdz",
) -> tuple[pd.DataFrame, pd.DataFrame, IsolationForest, float]:
    """
    Fit Isolation Forest on scaled pair features and annotate pair_df.

    Parameters
    ----------
    pair_df        : Scaled pair DataFrame (output of features.process_features).
                     Must contain *_stdz columns for each IForest feature.
    cfg            : Pipeline configuration.
    feature_suffix : Column suffix identifying scaled modelling features.

    Returns
    -------
    df_annotated : Full pair DataFrame with iforest_score and iforest_label.
    anomalies_df : Subset of df_annotated where iforest_label == -1.
    model        : Fitted IsolationForest object.
    stability    : Float in [0, 1]; train/test score-quantile agreement.
    """
    iso_cfg = cfg.isolation

    features = [c for c in pair_df.columns if c.endswith(feature_suffix)]
    if not features:
        # Fallback: use raw IFOREST_FEATURES if stdz cols absent
        features = [f for f in IFOREST_FEATURES if f in pair_df.columns]

    log.info("IsolationForest: %d pair-level features, %d pairs.", len(features), len(pair_df))

    df_model = pair_df[features].fillna(0).astype(float)

    model = IsolationForest(
        n_estimators=iso_cfg.n_estimators,
        max_samples=min(iso_cfg.max_samples, len(df_model)),
        contamination=iso_cfg.contamination,
        random_state=iso_cfg.random_state,
    ).fit(df_model)

    df_out = pair_df.copy()
    df_out["iforest_score"] = model.decision_function(df_model)

    # Hard percentile cut on the full pair set.
    # IsolationForest.predict() sets its threshold on the training sample
    # (max_samples rows). When max_samples < n_pairs the effective anomaly
    # rate on the full dataset can differ substantially from contamination.
    # Cutting at the contamination percentile of all pair scores guarantees
    # exactly contamination * n_pairs anomalous pairs regardless of max_samples.
    score_threshold = np.percentile(df_out["iforest_score"], iso_cfg.contamination * 100)
    df_out["iforest_label"] = np.where(
        df_out["iforest_score"] <= score_threshold, -1, 1
    ).astype(int)

    # --- Stability check ---
    if len(df_model) >= 10:
        X_train, X_test = train_test_split(
            df_model, test_size=iso_cfg.test_size, random_state=iso_cfg.random_state
        )
        train_scores = -model.decision_function(X_train)
        test_scores  = -model.decision_function(X_test)
        qs = np.linspace(0, 1, 11)
        stability = float(
            1.0 - np.mean(
                np.abs(np.quantile(train_scores, qs) - np.quantile(test_scores, qs))
                / (np.std(train_scores) + 1e-8)
            )
        )
    else:
        stability = 1.0

    n_anom = int((df_out["iforest_label"] == -1).sum())
    log.info(
        "Pair-level IForest: %d / %d pairs anomalous (%.1f%%)  stability=%.3f%s",
        n_anom, len(df_out), n_anom / len(df_out) * 100, stability,
        "  ⚠ below threshold" if stability < iso_cfg.stability_threshold else "",
    )

    return df_out, df_out[df_out["iforest_label"] == -1].copy(), model, stability


# ---------------------------------------------------------------------------
# Concentration analysis
# ---------------------------------------------------------------------------

def concentration_report(
    df: pd.DataFrame,
    key_col,
    topk: tuple[int, ...] = (1, 5, 10, 20),
) -> pd.Series:
    """HHI and top-k share percentages for anomalous pairs grouped by key_col."""
    if isinstance(key_col, (list, tuple)):
        key_series = df[key_col].astype(str).agg("→".join, axis=1)
        key_name   = " → ".join(key_col)
    else:
        key_series = df[key_col].astype(str)
        key_name   = key_col

    counts = key_series.value_counts(dropna=False)
    total  = counts.sum()
    shares = (counts / total).values

    topk_shares = {
        f"top_{k}_share_pct": round(float(shares[:k].sum()) * 100, 2)
        if len(shares) >= k else round(float(shares.sum()) * 100, 2)
        for k in topk
    }
    hhi = float(np.sum(shares ** 2))

    return pd.Series({
        "key":              key_name,
        "unique_keys":      int(len(counts)),
        "total_anomalies":  int(total),
        "hhi":              round(hhi, 4),
        "hhi_interpretation": (
            "unconcentrated"          if hhi < 0.15 else
            "moderately concentrated" if hhi < 0.25 else
            "highly concentrated"
        ),
        **topk_shares,
    })


def print_concentration_summary(
    df: pd.DataFrame,
    label_col: str = "iforest_label",
) -> None:
    """Print HHI / top-k concentration report for anomalous pairs."""
    anomalies_df = df[df[label_col] == -1]

    src_s  = concentration_report(anomalies_df, "src_ip")
    dst_s  = concentration_report(anomalies_df, "dst_ip")

    anomaly_rate = len(anomalies_df) / len(df)
    s_top5 = float(src_s.get("top_5_share_pct", 0))
    d_top5 = float(dst_s.get("top_5_share_pct", 0))
    s_hhi  = float(src_s.get("hhi", 0))
    d_hhi  = float(dst_s.get("hhi", 0))

    verdicts = []
    if s_hhi < 0.15 and d_hhi < 0.15:
        verdicts.append("Anomalies spread across many pairs (HHI < 0.15) — broadly representative.")
    if s_top5 > 80:
        verdicts.append("Anomalies highly concentrated in src IPs (top-5 > 80%).")
    if d_top5 > 80:
        verdicts.append("Anomalies highly concentrated in dst IPs (top-5 > 80%).")
    if not verdicts:
        verdicts.append("No strong concentration signals.")

    print("=== Anomaly Rate Diagnosis ===")
    print(f"  Rate: {anomaly_rate:.2%}  |  src top-5={s_top5}%  HHI={s_hhi}"
          f"  |  dst top-5={d_top5}%  HHI={d_hhi}")
    for v in verdicts:
        print(f"  → {v}")


# ---------------------------------------------------------------------------
# Visualisation stubs (kept for pipeline.py compatibility)
# ---------------------------------------------------------------------------

def plot_iforest_score_distribution(df, *args, **kwargs):
    """Plot IForest score distribution for pair-level scores."""
    try:
        import matplotlib.pyplot as plt
        scores = df["iforest_score"].astype(float)
        threshold = np.percentile(scores, 5)
        plt.figure(figsize=(9, 5))
        plt.hist(scores, bins=60, color="steelblue", edgecolor="black", alpha=0.7)
        plt.axvline(threshold, color="red", linestyle="--", linewidth=2,
                    label=f"5th pct cutoff ({threshold:.4f})")
        plt.title("Isolation Forest Score Distribution — Pair Level")
        plt.xlabel("Anomaly Score (lower = more anomalous)")
        plt.ylabel("Pair count")
        plt.grid(True, alpha=0.3)
        plt.legend()
        plt.tight_layout()
        plt.show()
    except Exception:
        pass


def plot_iforest_analysis(df, *args, **kwargs):
    """Stub — pair-level IForest has no per-flow polar clock."""
    plot_iforest_score_distribution(df)
