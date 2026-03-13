"""
run_full_scale.py
==================
Runs the CADENCE pipeline against full-scale 30-day synthetic data and
prints a structured evaluation report.

Architecture note: DBSCAN clustering has been removed. The pipeline now
works directly on (src_ip, dst_ip) pairs after IForest pre-filtering.
The noise-pair analysis stage is also gone — all pairs go through the
same SAX → ACF path now.

Usage
------
    # Basic — all defaults, outputs to ./results/
    python run_full_scale.py

    # Custom output dir and open HTML report in browser
    python run_full_scale.py --report --output /tmp/cadence_run --browser

    # Quick smoke test before committing to full run
    python run_full_scale.py --days 5 --bg-rows 3000

    # Generate HTML report
    python run_full_scale.py --report

Expected results at full scale (30 days, 30k bg rows/day):
    fast_https_dga        Should be detected (high confidence, DGA signal)
    slow_http_fixed       Should be detected (clear periodicity, rare UA)
    multi_host_campaign   Should be detected (DGA + NXDomain)
    exfil_slow            Should be detected (~120 firings in 30 days)
    decoy_windows_update  Should NOT be corroborated (benign DNS)
    decoy_ntp             Should NOT be corroborated (benign DNS, port 123)
"""
from __future__ import annotations

import argparse
import logging
import sys
import time
from pathlib import Path

import pandas as pd

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("run_full_scale")


# ---------------------------------------------------------------------------
# CLI args
# ---------------------------------------------------------------------------

def parse_args():
    p = argparse.ArgumentParser(
        description="CADENCE full-scale evaluation against synthetic data",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("--output",    default="results",  help="Output directory (default: ./results)")
    p.add_argument("--days",      type=int, default=30,     help="Simulation days (default: 30)")
    p.add_argument("--bg-rows",   type=int, default=30_000, help="Background rows/day (default: 30000)")
    p.add_argument("--noisy-rows",type=int, default=1_000,  help="Noisy rows/day (default: 1000)")
    p.add_argument("--seed",      type=int, default=42,     help="RNG seed (default: 42)")
    p.add_argument("--report",    action="store_true", help="Generate HTML report")
    p.add_argument("--browser",   action="store_true", help="Open HTML report in browser when done")
    p.add_argument("--visualize", action="store_true", help="Render matplotlib plots (slow)")
    return p.parse_args()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _section(title: str) -> None:
    width = 68
    print(f"\n{'=' * width}")
    print(f"  {title}")
    print(f"{'=' * width}")


def _print_funnel(art) -> None:
    _section("Pipeline Funnel")
    n_raw         = len(art.raw)
    n_prefiltered = len(art.prefiltered) if not art.prefiltered.empty else 0
    n_anomalies   = len(art.anomalies)
    n_pairs       = len(art.sax) if not art.sax.empty else 0
    n_sax_pass    = int(art.sax["sax_prescreen_pass"].sum()) if not art.sax.empty else 0
    n_beacon      = int(art.periodicity["is_beacon_pair"].sum()) if not art.periodicity.empty else 0
    n_corr        = int(art.corroboration["corroborated"].sum()) if not art.corroboration.empty else 0

    print(f"  {'Stage':<40} {'Count':>10}")
    print(f"  {'-'*40} {'-'*10}")
    print(f"  {'Conn log rows':<40} {n_raw:>10,}")
    print(f"  {'Pre-filter removed (known benign)':<40} {n_prefiltered:>10,}")
    print(f"  {'IForest anomalies':<40} {n_anomalies:>10,}")
    print(f"  {'Unique (src,dst) pairs evaluated':<40} {n_pairs:>10,}")
    print(f"  {'SAX-passing pairs → full ACF':<40} {n_sax_pass:>10,}")
    print(f"  {'Beacon pairs (is_beacon_pair)':<40} {n_beacon:>10,}")
    print(f"  {'Corroborated leads':<40} {n_corr:>10,}")


def _print_beacon_detail(art) -> None:
    _section("Beacon Pair Detail")

    if art.periodicity.empty:
        print("  No periodicity results.")
        return

    beacons = art.periodicity[art.periodicity["is_beacon_pair"]].copy()
    if beacons.empty:
        print("  No beacon pairs detected.")
        return

    print(f"  {len(beacons)} beacon pair(s) found:\n")
    for _, row in beacons.iterrows():
        period_s   = float(row.get("dominant_period_s", 0))
        period_str = (
            f"{period_s:.0f}s" if period_s < 60
            else f"{period_s/60:.1f}min" if period_s < 3600
            else f"{period_s/3600:.1f}h"
        )
        print(f"    {row['src_ip']:<16} → {row['dst_ip']:<16}  "
              f"period={period_str:<10}  confidence={float(row['beacon_confidence']):.3f}")


def _print_detection(results: pd.DataFrame) -> None:
    _section("Detection Results vs. Ground Truth")

    if results.empty:
        print("  No evaluation results — corroboration output was empty.")
        return

    print(f"  {'Scenario':<30} {'Malicious':>10} {'Detected':>10}")
    print(f"  {'-'*30} {'-'*10} {'-'*10}")

    for _, row in results.iterrows():
        detected_str = "YES ✓" if row.get("detected") else "MISS ✗"
        mal_str      = "malicious" if row.get("malicious") else "decoy"
        print(f"  {row['scenario']:<30} {mal_str:>10} {detected_str:>10}")

    print()
    precision = float(results["precision"].iloc[0])
    recall    = float(results["recall"].iloc[0])
    f1        = float(results["f1"].iloc[0])
    print(f"  Precision : {precision:.3f}")
    print(f"  Recall    : {recall:.3f}")
    print(f"  F1        : {f1:.3f}")

    if recall < 0.75:
        print(f"\n  ⚠ WARNING: Recall {recall:.2f} below 0.75 target.")
    else:
        print(f"\n  ✓ Recall {recall:.2f} meets the >= 0.75 target.")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    args = parse_args()

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    _section("CADENCE Full-Scale Evaluation")
    print(f"  Days           : {args.days}")
    print(f"  BG rows/day    : {args.bg_rows:,}")
    print(f"  Noisy rows/day : {args.noisy_rows:,}")
    print(f"  Output dir     : {output_dir.resolve()}")

    # ------------------------------------------------------------------
    # Step 1: Generate synthetic data
    # ------------------------------------------------------------------
    _section("Step 1/3 — Generating Synthetic Data")
    t0 = time.perf_counter()

    from analytic_pipeline.generate_synthetic_data import SyntheticDataGenerator, evaluate_detection

    gen = SyntheticDataGenerator(seed=args.seed)
    conn, dns, http, labels = gen.generate(
        days=args.days,
        bg_rows_per_day=args.bg_rows,
        noisy_rows_per_day=args.noisy_rows,
    )

    conn_path = output_dir / "conn.csv"
    dns_path  = output_dir / "dns.csv"
    http_path = output_dir / "http.csv"
    conn.to_csv(conn_path, index=False)
    dns.to_csv(dns_path,   index=False)
    http.to_csv(http_path, index=False)

    elapsed = time.perf_counter() - t0
    print(f"  Generated {len(conn):,} conn rows, {len(dns):,} DNS rows, "
          f"{len(http):,} HTTP rows in {elapsed:.1f}s")
    print(f"  Ground-truth labels: {len(labels)} scenario entries")
    print(f"  Written to {output_dir}/")

    # ------------------------------------------------------------------
    # Step 2: Run the pipeline
    # ------------------------------------------------------------------
    _section("Step 2/3 — Running Pipeline")
    t1 = time.perf_counter()

    from analytic_pipeline import BDPConfig, BDPPipeline

    cfg = BDPConfig()
    cfg.io.input_csv  = conn_path
    cfg.io.output_dir = output_dir / "pipeline_output"
    cfg.io.output_dir.mkdir(exist_ok=True)
    cfg.io.query_start = str(pd.to_datetime(conn["timestamp"].min(), unit="s", utc=True))[:19]
    cfg.io.query_end   = str(pd.to_datetime(conn["timestamp"].max(), unit="s", utc=True))[:19]

    visualize = args.visualize

    if args.report:
        from analytic_pipeline.report import ReportContext
        report_dir = output_dir / "report"
        report_dir.mkdir(exist_ok=True)
        with ReportContext(output_dir=report_dir, open_browser=args.browser) as report:
            pipe = BDPPipeline(cfg)
            art  = pipe.run(
                dns_log_path  = str(dns_path),
                http_log_path = str(http_path),
                visualize     = visualize,
            )
            report_path = report.finalise(art)
        print(f"  HTML report: {report_path.resolve()}")
    else:
        pipe = BDPPipeline(cfg)
        art  = pipe.run(
            dns_log_path  = str(dns_path),
            http_log_path = str(http_path),
            visualize     = visualize,
        )

    elapsed = time.perf_counter() - t1
    print(f"\n  Pipeline completed in {elapsed:.1f}s  ({elapsed/60:.1f} min)")

    # ------------------------------------------------------------------
    # Step 3: Print results
    # ------------------------------------------------------------------
    _section("Step 3/3 — Results")

    _print_funnel(art)
    _print_beacon_detail(art)

    if not art.corroboration.empty:
        from analytic_pipeline.corroboration import print_analyst_brief
        _section("Analyst Brief")
        print_analyst_brief(art.corroboration)

        results = evaluate_detection(art.corroboration, labels, art.anomalies)
        _print_detection(results)
    else:
        print("\n  No corroborated leads — check DNS/HTTP log alignment or lower min_score.")

    # Save summary JSON
    summary = {
        "days":              args.days,
        "bg_rows_per_day":   args.bg_rows,
        "n_conn_rows":       len(art.raw),
        "n_prefiltered":     len(art.prefiltered) if not art.prefiltered.empty else 0,
        "n_anomalies":       len(art.anomalies),
        "n_pairs_evaluated": len(art.sax) if not art.sax.empty else 0,
        "n_sax_pass":        int(art.sax["sax_prescreen_pass"].sum()) if not art.sax.empty else 0,
        "n_beacon_pairs":    int(art.periodicity["is_beacon_pair"].sum()) if not art.periodicity.empty else 0,
        "n_corroborated":    int(art.corroboration["corroborated"].sum()) if not art.corroboration.empty else 0,
        "runtime_s":         round(elapsed, 1),
    }

    import json
    summary_path = output_dir / "run_summary.json"
    summary_path.write_text(json.dumps(summary, indent=2))
    print(f"\n  Summary saved to {summary_path.resolve()}")

    total = time.perf_counter() - t0
    _section(f"Done — total wall time {total:.1f}s  ({total/60:.1f} min)")


if __name__ == "__main__":
    main()
