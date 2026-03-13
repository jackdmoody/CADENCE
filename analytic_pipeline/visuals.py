"""
Visualisation Utilities
=========================
Static matplotlib outputs for batch analysis and interactive Plotly outputs
for notebook-based threat hunting. All functions are side-effect only
(render in-place or to file); none modify input DataFrames.

Matplotlib outputs:
    plot_dbscan_clusters          2D PCA scatter coloured by cluster.
    plot_cluster_size_distribution Bar chart with Pareto 80% overlay.

Plotly outputs:
    plot_dbscan_3d                Interactive 3D PCA scatter.
    plot_cluster_investigation    Full per-cluster analyst view (7 charts).
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
from matplotlib.patches import Patch
from sklearn.decomposition import PCA

try:
    import plotly.express as px
    PLOTLY_AVAILABLE = True
except ImportError:
    PLOTLY_AVAILABLE = False

from .clustering import select_cluster_features

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# DBSCAN cluster visualisation
# ---------------------------------------------------------------------------

def plot_dbscan_clusters(
    df: pd.DataFrame,
    with_pca: int = 2,
    cluster_col: str = "dbscan_cluster",
) -> None:
    """
    Scatter plot of DBSCAN clusters projected into 2D PCA space.

    Parameters
    ----------
    df          : Clustered DataFrame (output of clustering.apply_dbscan).
    with_pca    : Number of PCA components to reduce to (must be 2).
    cluster_col : Column containing DBSCAN cluster labels.
    """
    feats   = select_cluster_features(df)
    X_pca   = PCA(n_components=with_pca).fit_transform(df[feats].values)
    plot_df = df.assign(pca1=X_pca[:, 0], pca2=X_pca[:, 1])

    plt.figure(figsize=(10, 8))
    sns.scatterplot(
        data=plot_df, x="pca1", y="pca2",
        hue=cluster_col, palette="tab20",
        legend="full", alpha=0.6,
    )
    plt.title("DBSCAN Clusters (PCA-reduced 2D)")
    plt.legend(bbox_to_anchor=(1.05, 1), loc="upper left")
    plt.tight_layout()
    plt.show()


def plot_dbscan_3d(
    df: pd.DataFrame,
    features: Optional[list[str]] = None,
    cluster_col: str = "dbscan_cluster",
    with_pca: int = 3,
) -> None:
    """
    Interactive 3D scatter of DBSCAN clusters via Plotly + PCA reduction.

    Parameters
    ----------
    df          : Clustered DataFrame.
    features    : Feature columns; defaults to select_cluster_features(df).
    cluster_col : Column containing DBSCAN cluster labels.
    with_pca    : Number of PCA components (must be 3).
    """
    if not PLOTLY_AVAILABLE:
        log.warning("plotly not installed — skipping 3D plot.")
        return

    if features is None:
        features = select_cluster_features(df)

    X_pca   = PCA(n_components=with_pca).fit_transform(df[features].values)
    plot_df = df.assign(pca1=X_pca[:, 0], pca2=X_pca[:, 1], pca3=X_pca[:, 2])

    px.scatter_3d(
        plot_df, x="pca1", y="pca2", z="pca3",
        color=cluster_col,
        title="DBSCAN Clusters (3D PCA)",
        opacity=0.7,
    ).update_traces(
        marker=dict(size=4)
    ).update_layout(
        legend_title_text="Cluster"
    ).show()


def plot_cluster_size_distribution(
    df_clustered: pd.DataFrame,
    cluster_col: str = "dbscan_cluster",
    top_k: Optional[int] = None,
    log_scale: bool = True,
    figsize: tuple = (18, 6),
    save_path: Optional[str] = None,
    table_top_n: int = 10,
) -> None:
    """
    Bar chart of cluster sizes with a Pareto cumulative-% overlay.

    Clusters that collectively cover the first 80% of anomalies are
    highlighted in orange — these should be triaged first to determine
    whether they represent benign high-volume services or widespread
    malicious patterns.

    Parameters
    ----------
    df_clustered : Clustered DataFrame.
    cluster_col  : Column containing DBSCAN cluster labels.
    top_k        : If set, show only the top_k largest clusters.
    log_scale    : Use log scale on the y-axis.
    figsize      : Figure dimensions.
    save_path    : If provided, save the figure to this path.
    table_top_n  : Number of rows to print in the top-N summary table.
    """
    counts  = df_clustered[cluster_col].value_counts().sort_values(ascending=False)
    total   = counts.sum()
    cum_pct = counts.cumsum() / total * 100

    k80_pos           = int(np.argmax(cum_pct.values >= 80))
    clusters_80       = counts.index[:k80_pos + 1]
    coverage_80_exact = float(cum_pct.iloc[k80_pos])

    log.info("%d clusters account for %.2f%% of anomalies (≥80%%).",
             len(clusters_80), coverage_80_exact)

    top_table = (
        counts.head(table_top_n)
              .rename_axis("Cluster ID").reset_index(name="Count")
              .assign(
                  Percent=lambda d: (100 * d["Count"] / total).round(2),
                  CumulativePct=lambda d: d["Count"].cumsum() / total * 100,
              )
    )
    try:
        display(top_table)   # type: ignore[name-defined]  # noqa: F821
    except NameError:
        print(top_table.to_string())

    counts_plot = counts.head(top_k) if top_k else counts
    cum_plot    = counts_plot.cumsum() / total * 100
    bar_colors  = np.where(counts_plot.index.isin(clusters_80), "tab:orange", "tab:blue")

    fig, ax1 = plt.subplots(figsize=figsize)
    ax1.bar(counts_plot.index.astype(str), counts_plot.values, color=bar_colors)
    if log_scale:
        ax1.set_yscale("log")
        ax1.set_ylabel("Number of anomalies (log scale)")
    else:
        ax1.set_ylabel("Number of anomalies")
    ax1.set_xlabel("Cluster ID")
    ax1.set_title("DBSCAN Cluster Size Distribution with Pareto Line (80% Highlight)")
    ax1.grid(axis="y", linestyle="--", alpha=0.4)
    plt.setp(ax1.get_xticklabels(), rotation=90, ha="center")
    ax1.legend(handles=[
        Patch(color="tab:orange", label="Clusters within first 80%"),
        Patch(color="tab:blue",   label="Other clusters"),
    ], loc="center right")

    ax2 = ax1.twinx()
    ax2.plot(counts_plot.index.astype(str), cum_plot, marker="o", linewidth=2, color="darkred")
    ax2.set_ylabel("Cumulative % of anomalies")
    ax2.set_ylim(0, 105)
    ax2.axhline(80, linestyle="--", linewidth=1, color="gray")
    ax2.text(0.5, 82, "80% threshold", fontsize=9, color="gray")

    plt.tight_layout()
    if save_path:
        plt.savefig(save_path, dpi=140, bbox_inches="tight")
        log.info("Saved cluster size distribution to %s", save_path)
    plt.show()


# ---------------------------------------------------------------------------
# Per-cluster analyst investigation
# ---------------------------------------------------------------------------

def plot_cluster_investigation(
    cluster_id: int,
    df: pd.DataFrame,
    common_ports: set[int],
) -> None:
    """
    Full analyst view for a single DBSCAN cluster.

    Renders 7 visualisations:
        1. Minute-of-hour activity by IP pair (interactive Plotly bar).
        2. Time gaps between consecutive connections (beaconing detection).
        3. Total bytes per flow with KDE.
        4. Flow duration vs total bytes scatter.
        5. Minute × destination-port heatmap.
        6. Hourly connection frequency (interactive Plotly).
        7. Connections-over-time series (interactive Plotly).

    Also prints:
        - Top src_ip → dst_ip pairs.
        - Internal / external IP classification.
        - Top destination ports and uncommon port count.
        - Compact summary statistics.

    Parameters
    ----------
    cluster_id   : DBSCAN cluster ID to investigate.
    df           : Raw (unscaled) DataFrame with dbscan_cluster column.
    common_ports : Set of well-known port numbers used for uncommon-port flagging.
    """
    cdf = df[df["dbscan_cluster"] == cluster_id].copy()
    if cdf.empty:
        log.warning("No data for cluster %d.", cluster_id)
        return

    log.info("--- Cluster %d (%d connections) ---", cluster_id, len(cdf))

    # --- IP pair summary ---
    print(f"\nTop src_ip → dst_ip pairs (cluster {cluster_id}):")
    top_pairs = (
        cdf.groupby(["src_ip", "dst_ip"]).size()
           .sort_values(ascending=False).head(5)
    )
    try:    display(top_pairs)          # type: ignore[name-defined]  # noqa: F821
    except NameError: print(top_pairs.to_string())

    # Internal / external classification
    def _is_internal(ip: str) -> bool:
        return ip.startswith(("10.", "192.168.", "172.16."))

    cdf["internal_src"] = cdf["src_ip"].apply(_is_internal)
    cdf["internal_dst"] = cdf["dst_ip"].apply(_is_internal)
    in_ext = cdf.groupby(["internal_src", "internal_dst"]).size()
    print("\nInternal vs External:")
    try:    display(in_ext)             # type: ignore[name-defined]  # noqa: F821
    except NameError: print(in_ext.to_string())

    # Port analysis
    top_dports = cdf["dst_p_raw"].value_counts().head(5)
    print("\nTop Destination Ports:")
    try:    display(top_dports)         # type: ignore[name-defined]  # noqa: F821
    except NameError: print(top_dports.to_string())
    print(f"Uncommon port flows: {cdf[~cdf['dst_p_raw'].isin(common_ports)]['dst_p_raw'].nunique()}")

    # --- 1. Minute activity (interactive) ---
    if PLOTLY_AVAILABLE:
        cdf["minute"]  = cdf["datetime"].dt.minute.astype(int)
        cdf["ip_pair"] = cdf["src_ip"] + " → " + cdf["dst_ip"]
        min_counts = cdf.groupby(["minute", "ip_pair"]).size().reset_index(name="count")
        px.bar(min_counts, x="minute", y="count", color="ip_pair", barmode="stack",
               title=f"Cluster {cluster_id} — Minute-of-Hour Activity",
               labels={"minute": "Minute", "count": "Connections"},
               color_discrete_sequence=px.colors.qualitative.Set2,
        ).update_layout(showlegend=False).show()

    # --- 2. Time gaps ---
    cdf_s = cdf.sort_values("datetime").copy()
    cdf_s["time_diff_sec"] = cdf_s["datetime"].diff().dt.total_seconds()
    plt.figure(figsize=(12, 4))
    plt.plot(cdf_s["datetime"], cdf_s["time_diff_sec"], marker="o", linewidth=1)
    plt.title("Time Gaps Between Connections — low std suggests beaconing")
    plt.ylabel("Seconds"); plt.xlabel("Time")
    plt.grid(True); plt.tight_layout(); plt.show()

    # --- 3. Bytes histogram ---
    plt.figure(figsize=(12, 4))
    sns.histplot(cdf["total_bytes_raw"], bins=30, kde=True,
                 color="skyblue", edgecolor="black")
    plt.title("Total Bytes per Flow")
    plt.xlabel("Bytes"); plt.ylabel("Count")
    plt.grid(True); plt.tight_layout(); plt.show()

    # --- 4. Duration vs bytes ---
    plt.figure(figsize=(12, 5))
    plt.scatter(cdf["duration_raw"], cdf["total_bytes_raw"], alpha=0.6, edgecolors="w")
    plt.title("Flow Duration vs Total Bytes")
    plt.xlabel("Duration (s)"); plt.ylabel("Total Bytes")
    plt.grid(True); plt.tight_layout(); plt.show()

    # --- 5. Minute × port heatmap ---
    cdf["minute"] = cdf["datetime"].dt.minute.astype(int)
    hm = cdf.groupby(["minute", "dst_p_raw"]).size().unstack(fill_value=0).sort_index()
    plt.figure(figsize=(12, 6))
    sns.heatmap(hm, cmap="YlGnBu", linewidths=0.5)
    plt.title("Heatmap — Minute vs Destination Port")
    plt.xlabel("Destination Port"); plt.ylabel("Minute of Hour")
    plt.tight_layout(); plt.show()

    # --- 6. Hourly frequency (interactive) ---
    if PLOTLY_AVAILABLE:
        px.histogram(cdf, x="hour", nbins=24,
                     title=f"Cluster {cluster_id} — Connection Frequency by Hour",
                     labels={"hour": "Hour"},
                     color_discrete_sequence=["salmon"],
        ).update_layout(showlegend=False).show()

    # --- 7. Connections over time (interactive) ---
    if PLOTLY_AVAILABLE:
        ts = cdf.copy()
        ts["ts_min"]  = ts["datetime"].dt.floor("T")
        ts_counts     = ts.groupby("ts_min").size().reset_index(name="connections")
        px.line(ts_counts, x="ts_min", y="connections",
                title=f"Cluster {cluster_id} — Connections Over Time",
                labels={"ts_min": "Time", "connections": "Connections"},
                markers=True,
        ).update_traces(line_color="mediumseagreen").update_layout(showlegend=False).show()

    # --- Summary stats ---
    off_hours = cdf["hour"].apply(lambda h: h < 6 or h >= 22)
    print(f"\n--- Summary: Cluster {cluster_id} ---")
    print(f"  Unique src_ip         : {cdf['src_ip'].nunique()}")
    print(f"  Unique dst_ip         : {cdf['dst_ip'].nunique()}")
    print(f"  Avg Duration          : {cdf['duration_raw'].mean():.2f} s")
    print(f"  Avg Total Bytes       : {cdf['total_bytes_raw'].mean():.2f}")
    print(f"  Off-hour Connections  : {off_hours.sum()} / {len(cdf)}")
    print(f"  Beaconing STD (dur)   : {cdf['duration_raw'].std():.2f}")
    print(f"  Beaconing STD (min)   : {cdf['minute'].std():.2f}")
