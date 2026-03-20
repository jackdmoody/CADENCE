"""
CADENCE Pipeline Orchestrator
================================
Combines all pipeline stages into a single orchestrator. DBSCAN clustering
has been removed; the pipeline now works directly on (src_ip, dst_ip) pairs
after IForest pre-filtering.

Stage sequence:
    1.  load()          Ingest and feature-engineer conn log
    2.  scale()         Pair-level aggregation, StandardScaler
    3.  prefilter()     Domain-knowledge pre-filter (infra, fanin, conn state)
    4.  filter()        Isolation Forest anomaly pre-filter
    5.  sax_screen()    SAX symbolic pre-filter per (src,dst) pair
    6.  periodicity()   ACF + FFT on SAX-passing pairs
    7.  score()         Heuristic priority scoring per pair
    8.  changepoints()  PELT on confirmed beacon pairs
    9.  corroborate()   DNS + HTTP cross-source validation
    10. mitre_map()     ATT&CK technique annotation on confirmed leads

Typical usage:
    from bdp_analytic import BDPPipeline, BDPConfig
    from pathlib import Path

    cfg = BDPConfig()
    cfg.io.input_csv = Path("data/conn_logs.csv")

    pipe = BDPPipeline(cfg)
    art  = pipe.run(dns_log_path="data/dns.csv", http_log_path="data/http.csv")
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from .config import BDPConfig
from .loaders import load_and_prepare
from .features import process_features
from .isolation import (
    run_isolation_forest,
    print_concentration_summary,
    plot_iforest_score_distribution,
    plot_iforest_analysis,
)
from .scoring import prioritize_pairs, recover_raw_features
from .sax_screening import screen_pairs, plot_sax_screening_summary
from .periodicity import (
    score_all_pairs,
    plot_pair_periodicity_summary,
)
from .corroboration import (
    load_dns_logs,
    load_http_logs,
    load_ssl_logs,
    corroborate_beacon_candidates,
    plot_corroboration_summary,
    print_analyst_brief,
)
from .changepoint import (
    analyze_beacon_changepoints,
    plot_campaign_timeline,
    print_changepoint_brief,
)
from .prefilter import (
    apply_prefilter,
    print_prefilter_summary,
)
from .mitre_mapping import (
    annotate_leads,
    print_mitre_summary,
)

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Artifacts dataclass
# ---------------------------------------------------------------------------

@dataclass
class BDPArtifacts:
    """All outputs from a full pipeline run. None/empty = stage was skipped."""
    raw:           pd.DataFrame              = field(default_factory=pd.DataFrame)
    scaled:        pd.DataFrame              = field(default_factory=pd.DataFrame)
    prefiltered:   pd.DataFrame              = field(default_factory=pd.DataFrame)
    anomalies:     pd.DataFrame              = field(default_factory=pd.DataFrame)
    sax:           pd.DataFrame              = field(default_factory=pd.DataFrame)
    periodicity:   pd.DataFrame              = field(default_factory=pd.DataFrame)
    priority:      pd.DataFrame              = field(default_factory=pd.DataFrame)
    changepoints:  pd.DataFrame              = field(default_factory=pd.DataFrame)
    corroboration: pd.DataFrame              = field(default_factory=pd.DataFrame)
    scaler:        Optional[StandardScaler]  = None
    iforest_model: Optional[IsolationForest] = None
    iforest_stability: float                 = 0.0


# ---------------------------------------------------------------------------
# Main pipeline class
# ---------------------------------------------------------------------------

class BDPPipeline:
    """
    End-to-end orchestrator for the CADENCE behavioral anomaly detection analytic.

    Stages
    ------
    1.  load         — Ingest from CSV; engineer all features.
    2.  scale        — Pair-level aggregation, StandardScaler.
    3.  prefilter    — Domain-knowledge pre-filter (infra, fanin, conn state).
    4.  filter       — Isolation Forest pre-filter.
    5.  sax_screen   — SAX symbolic pre-filter per (src,dst) pair.
    6.  periodicity  — Per-pair ACF + FFT beacon scoring.
    7.  score        — Heuristic priority scoring per pair.
    8.  changepoints — PELT beacon start / interval shift detection.
    9.  corroborate  — DNS + HTTP cross-source validation.
    10. mitre_map    — ATT&CK technique annotation on confirmed leads.
    """

    def __init__(self, cfg: Optional[BDPConfig] = None) -> None:
        self.cfg = cfg or BDPConfig()

    # ------------------------------------------------------------------
    # Stage 1: Load
    # ------------------------------------------------------------------

    def load(self) -> pd.DataFrame:
        """Ingest Zeek conn log and engineer all features."""
        log.info("Stage 1: load()")
        return load_and_prepare(self.cfg)

    # ------------------------------------------------------------------
    # Stage 2: Scale
    # ------------------------------------------------------------------

    def scale(
        self,
        df: pd.DataFrame,
    ) -> tuple[pd.DataFrame, Optional[StandardScaler]]:
        """Aggregate flows to (src,dst) pairs and scale pair-level features."""
        log.info("Stage 2: scale() — aggregating %d flows to pair-level features", len(df))
        df_scaled, scaler, _, _ = process_features(df, self.cfg)
        return df_scaled, scaler

    # ------------------------------------------------------------------
    # Stage 3: Pre-filter (domain knowledge)
    # ------------------------------------------------------------------

    def prefilter(
        self,
        pair_df: pd.DataFrame,
        raw_df: pd.DataFrame,
    ) -> tuple[pd.DataFrame, pd.DataFrame]:
        """
        Domain-knowledge pre-filter: remove known-benign pairs before IForest.

        Filters include: internal-to-internal, known infrastructure, CDN CIDRs,
        high-fanin destinations (shared services), and dead pairs (failed conns).
        """
        log.info("Stage 3: prefilter()")
        filtered_df, removed_df = apply_prefilter(pair_df, self.cfg, raw_df=raw_df)
        print_prefilter_summary(removed_df)
        return filtered_df, removed_df

    # ------------------------------------------------------------------
    # Stage 4: Filter (IForest)
    # ------------------------------------------------------------------

    def filter(
        self,
        df_scaled: pd.DataFrame,
        visualize: bool = True,
    ) -> tuple[pd.DataFrame, pd.DataFrame, IsolationForest, float]:
        """Isolation Forest anomaly pre-filter."""
        log.info("Stage 4: filter()")
        df_annotated, anomalies_df, model, stability = run_isolation_forest(
            df_scaled, self.cfg
        )
        print_concentration_summary(df_annotated)
        if visualize:
            plot_iforest_score_distribution(df_annotated)
            plot_iforest_analysis(df_annotated)
        return df_annotated, anomalies_df, model, stability

    # ------------------------------------------------------------------
    # Stage 5: SAX pre-screening
    # ------------------------------------------------------------------

    def sax_screen(
        self,
        anomalies: pd.DataFrame,
        visualize: bool = True,
    ) -> tuple[pd.DataFrame, pd.DataFrame]:
        """
        SAX symbolic pre-screening of all (src,dst) pairs in the anomaly set.

        Operates directly on pairs — no cluster intermediary. Pairs are sorted
        by flow count descending and capped at cfg.pair.max_pairs before
        SAX evaluation to keep the stage tractable.

        Returns
        -------
        (sax_df, pairs_df) — same DataFrame in both slots for API compatibility.
        """
        log.info("Stage 5: sax_screen()")
        sax_df, pairs_df = screen_pairs(anomalies, self.cfg)
        if visualize and not sax_df.empty:
            plot_sax_screening_summary(sax_df, pairs_df)
        n_pass = int(sax_df["sax_prescreen_pass"].sum()) if not sax_df.empty else 0
        log.info("SAX: %d/%d pairs pass → proceed to ACF", n_pass, len(sax_df))
        return sax_df, pairs_df

    # ------------------------------------------------------------------
    # Stage 6: Periodicity (ACF + FFT)
    # ------------------------------------------------------------------

    def periodicity(
        self,
        anomalies: pd.DataFrame,
        sax_df:    Optional[pd.DataFrame] = None,
        visualize: bool = True,
    ) -> pd.DataFrame:
        """
        Per-pair inter-arrival time periodicity analysis via ACF + FFT.

        When sax_df is provided, only pairs with sax_prescreen_pass=True
        are submitted to full ACF + FFT analysis. All other pairs receive
        beacon_confidence=0 and is_beacon_pair=False.
        """
        log.info("Stage 6: periodicity()")
        periodicity_df = score_all_pairs(anomalies, self.cfg, sax_df=sax_df)
        if visualize and not periodicity_df.empty:
            plot_pair_periodicity_summary(periodicity_df)
        n_beacon = int(periodicity_df["is_beacon_pair"].sum()) if not periodicity_df.empty else 0
        log.info("Periodicity: %d beacon pairs identified.", n_beacon)
        return periodicity_df

    # ------------------------------------------------------------------
    # Stage 7: Score / triage
    # ------------------------------------------------------------------

    def score(
        self,
        anomalies:      pd.DataFrame,
        periodicity_df: Optional[pd.DataFrame] = None,
    ) -> pd.DataFrame:
        """
        Recover raw features and compute per-pair priority scores.

        When periodicity_df is supplied, beacon_confidence is incorporated
        as the dominant scoring component.
        """
        log.info("Stage 7: score()")
        raw = recover_raw_features(anomalies)
        return prioritize_pairs(raw, self.cfg, periodicity_df=periodicity_df)

    # ------------------------------------------------------------------
    # Stage 8: PELT changepoint detection
    # ------------------------------------------------------------------

    def detect_changepoints(
        self,
        periodicity_df: pd.DataFrame,
        anomalies:      pd.DataFrame,
        visualize:      bool = True,
    ) -> pd.DataFrame:
        """PELT changepoint detection on confirmed beacon pairs."""
        log.info("Stage 8: detect_changepoints()")
        changepoint_df = analyze_beacon_changepoints(periodicity_df, anomalies, self.cfg)
        if visualize and not changepoint_df.empty:
            plot_campaign_timeline(changepoint_df)
            print_changepoint_brief(changepoint_df)
        return changepoint_df

    # ------------------------------------------------------------------
    # Stage 9: Corroborate
    # ------------------------------------------------------------------

    def corroborate(
        self,
        periodicity_df: pd.DataFrame,
        anomalies:      pd.DataFrame,
        dns_log_path:   Optional[str] = None,
        http_log_path:  Optional[str] = None,
        ssl_log_path:   Optional[str] = None,   # Point 7
        visualize:      bool = True,
    ) -> pd.DataFrame:
        """Cross-validate beacon candidates against DNS, HTTP, and TLS evidence."""
        log.info("Stage 9: corroborate()")

        if dns_log_path is None and http_log_path is None and ssl_log_path is None:
            log.warning("No DNS, HTTP, or SSL logs provided — skipping corroboration.")
            return pd.DataFrame()

        dns_df  = load_dns_logs(dns_log_path, self.cfg)   if dns_log_path   else pd.DataFrame()
        http_df = load_http_logs(http_log_path, self.cfg) if http_log_path  else pd.DataFrame()
        ssl_df  = load_ssl_logs(ssl_log_path, self.cfg)   if ssl_log_path   else None

        corroboration_df = corroborate_beacon_candidates(
            periodicity_df, anomalies, dns_df, http_df, self.cfg,
            ssl_df=ssl_df,
        )

        if visualize and not corroboration_df.empty:
            plot_corroboration_summary(corroboration_df)
            print_analyst_brief(corroboration_df)

        return corroboration_df

    # ------------------------------------------------------------------
    # Stage 10: MITRE ATT&CK annotation
    # ------------------------------------------------------------------

    def mitre_map(
        self,
        corroboration_df: pd.DataFrame,
    ) -> pd.DataFrame:
        """Annotate corroborated leads with MITRE ATT&CK technique mappings."""
        log.info("Stage 10: mitre_map()")
        annotated = annotate_leads(corroboration_df)
        print_mitre_summary(annotated)
        return annotated

    # ------------------------------------------------------------------
    # Convenience: run all stages end-to-end
    # ------------------------------------------------------------------

    def run(
        self,
        dns_log_path:  Optional[str] = None,
        http_log_path: Optional[str] = None,
        ssl_log_path:  Optional[str] = None,   # Point 7
        visualize:     bool = True,
    ) -> BDPArtifacts:
        """
        Execute all pipeline stages in sequence.

        Stage sequence
        --------------
        1.  load()              Ingest and feature-engineer conn log
        2.  scale()             Pair-level aggregation, StandardScaler
        3.  prefilter()         Domain-knowledge pre-filter
        4.  filter()            Isolation Forest anomaly pre-filter
        5.  sax_screen()        SAX symbolic pre-filter per (src,dst) pair
        6.  periodicity()       ACF + FFT on SAX-passing pairs
        7.  score()             Heuristic priority scoring per pair
        8.  detect_changepoints() PELT on confirmed beacon pairs
        9.  corroborate()       DNS + HTTP cross-source validation
        10. mitre_map()         ATT&CK technique annotation

        Returns
        -------
        BDPArtifacts with all intermediate and final outputs.
        """
        art = BDPArtifacts()

        # Stages 1–2: load, scale
        art.raw                                          = self.load()
        art.scaled, art.scaler                           = self.scale(art.raw)

        # Stage 3: domain-knowledge pre-filter
        art.scaled, art.prefiltered                      = self.prefilter(art.scaled, art.raw)

        # Stage 4: Isolation Forest
        art.scaled, art.anomalies, \
            art.iforest_model, art.iforest_stability     = self.filter(art.scaled, visualize)

        # art.scaled    = pair-level summary (one row per pair, IForest scored)
        # art.anomalies = anomalous pairs only (pair-level)
        # SAX/ACF/periodicity need raw flows — join anomalous pair identities
        # back to art.raw to recover the full IAT sequence per pair.
        _anomalous_pairs = art.anomalies[["src_ip", "dst_ip"]].drop_duplicates()
        art.anomalies = art.raw.merge(
            _anomalous_pairs, on=["src_ip", "dst_ip"], how="inner"
        )
        log.info(
            "Flow join: %d anomalous pairs → %d raw flows passed to SAX/ACF",
            len(_anomalous_pairs), len(art.anomalies),
        )

        # Stage 5: SAX pre-screen all (src,dst) pairs
        art.sax, _                                       = self.sax_screen(art.anomalies, visualize)

        # Stage 6: Periodicity (ACF + FFT), gated by SAX
        art.periodicity                                  = self.periodicity(
                                                               art.anomalies,
                                                               sax_df=art.sax,
                                                               visualize=visualize,
                                                           )

        # Stage 7: Priority scoring with beacon_confidence
        art.priority                                     = self.score(
                                                               art.anomalies,
                                                               periodicity_df=art.periodicity,
                                                           )

        # Stage 8: PELT changepoint detection on beacon pairs
        art.changepoints                                 = self.detect_changepoints(
                                                               art.periodicity,
                                                               art.anomalies,
                                                               visualize,
                                                           )

        # Stage 9: Corroboration
        art.corroboration                                = self.corroborate(
                                                               art.periodicity,
                                                               art.anomalies,
                                                               dns_log_path,
                                                               http_log_path,
                                                               ssl_log_path,
                                                               visualize,
                                                           )

        # Stage 10: MITRE ATT&CK annotation
        if not art.corroboration.empty:
            art.corroboration                            = self.mitre_map(art.corroboration)

        n_prefiltered = len(art.prefiltered) if not art.prefiltered.empty else 0
        n_pairs      = len(art.sax) if not art.sax.empty else 0
        n_sax_pass   = int(art.sax["sax_prescreen_pass"].sum()) if not art.sax.empty else 0
        n_beacon     = int(art.periodicity["is_beacon_pair"].sum()) if not art.periodicity.empty else 0
        n_corr       = int(art.corroboration["corroborated"].sum()) if not art.corroboration.empty else 0

        log.info(
            "Pipeline complete — %d pairs pre-filtered → %d pairs evaluated → "
            "%d SAX pass → %d beacon pairs → %d corroborated leads",
            n_prefiltered, n_pairs, n_sax_pass, n_beacon, n_corr,
        )
        return art


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main() -> None:
    import argparse

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )

    parser = argparse.ArgumentParser(description="CADENCE — C2 Beacon Detection Analytic")
    parser.add_argument("--input",    default=None,   help="Path to Zeek conn CSV")
    parser.add_argument("--dns",      default=None,   help="Path to Zeek dns.log CSV")
    parser.add_argument("--http",     default=None,   help="Path to Zeek http.log CSV")
    parser.add_argument("--output",   default="output", help="Output directory")
    parser.add_argument("--config",   default=None,   help="Path to config JSON")
    parser.add_argument("--no-plots", action="store_true", help="Suppress visualisations")
    parser.add_argument("--report",   action="store_true", help="Generate HTML report")
    args = parser.parse_args()

    cfg = BDPConfig.from_json(args.config) if args.config else BDPConfig()
    if args.input:
        cfg.io.input_csv = Path(args.input)
    cfg.io.output_dir = Path(args.output)
    cfg.io.output_dir.mkdir(parents=True, exist_ok=True)

    if args.report:
        from .report import ReportContext
        with ReportContext(output_dir=args.output) as report:
            pipe = BDPPipeline(cfg)
            art  = pipe.run(
                dns_log_path  = args.dns,
                http_log_path = args.http,
                visualize     = True,
            )
            report.finalise(art)
    else:
        pipe = BDPPipeline(cfg)
        art  = pipe.run(
            dns_log_path  = args.dns,
            http_log_path = args.http,
            visualize     = not args.no_plots,
        )
        art.priority.to_csv(cfg.io.output_dir / "priority.csv", index=False)
        if not art.periodicity.empty:
            art.periodicity.to_csv(cfg.io.output_dir / "periodicity.csv", index=False)
        if not art.changepoints.empty:
            art.changepoints.to_csv(cfg.io.output_dir / "changepoints.csv", index=False)
        if not art.corroboration.empty:
            art.corroboration.to_csv(cfg.io.output_dir / "corroboration.csv", index=False)
            print_analyst_brief(art.corroboration)
        else:
            print(art.priority.head(20).to_string())


if __name__ == "__main__":
    main()
