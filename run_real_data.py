"""
run_real_data.py
=================
Runs CADENCE on real Zeek data (or pcaps) and, if ground truth is given,
scores the run at the (src_ip, dst_ip) pair level with a per-stage account
of where each C2 pair stopped.

Inputs (pick one):
    --zeek-dir DIR      native Zeek logs, TSV or JSON, rotated/gzipped is fine
    --pcap FILE ...     raw captures; needs `zeek` on PATH
    --cadence-dir DIR   conn.csv / dns.csv / http.csv / ssl.csv already converted

Examples
--------
    # CTU-13 scenario 1: campus hosts are public addresses, so mark them internal.
    # Conn-only first, because the truncated full capture has almost no
    # application-layer payload for background traffic (see README).
    python -m analytic_pipeline.ground_truth ctu13 \\
        --binetflow data/ctu13/1/capture20110810.binetflow --out data/ctu13/1/gt.csv
    python run_real_data.py --zeek-dir data/ctu13/1/zeek --output results/ctu13_s1 \\
        --internal-cidr 147.32.0.0/16 --conn-only --gt data/ctu13/1/gt.csv

    # Active Countermeasures capture with a 5 s beacon: lower the period floor
    python -m analytic_pipeline.ground_truth pairs \\
        --pair 192.168.100.129 143.198.3.13 --out data/ac/sliver/gt.csv
    python run_real_data.py --pcap data/ac/sliver/*.pcap --output results/ac_sliver \\
        --min-period-s 2 --gt data/ac/sliver/gt.csv

    # Re-score a finished run against different ground truth without re-running
    python -m analytic_pipeline.ground_truth score --run-dir results/ctu13_s1 --gt other_gt.csv
"""
from __future__ import annotations

import argparse
import json
import logging
import math
import sys
import tempfile
import time
from pathlib import Path

import pandas as pd

log = logging.getLogger("run_real_data")


def parse_args(argv=None):
    p = argparse.ArgumentParser(description="CADENCE on real Zeek data",
                                formatter_class=argparse.RawDescriptionHelpFormatter,
                                epilog=__doc__)
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--zeek-dir", help="Directory of native Zeek logs")
    src.add_argument("--pcap", nargs="+", help="pcap file(s); requires zeek on PATH")
    src.add_argument("--cadence-dir", help="Directory with already-converted conn.csv etc.")
    p.add_argument("--output", required=True, help="Run output directory")
    p.add_argument("--gt", help="Ground-truth CSV from analytic_pipeline.ground_truth")
    p.add_argument("--config", help="BDPConfig JSON; CLI flags below override it")
    p.add_argument("--conn-only", action="store_true",
                   help="Skip DNS/HTTP/TLS corroboration logs (run them as a separate ablation)")
    p.add_argument("--internal-cidr", action="append", default=[],
                   help="Extra internal network, repeatable (e.g. 147.32.0.0/16 for CTU-13)")
    p.add_argument("--min-period-s", type=float, help="Periodicity floor in seconds (default 60)")
    p.add_argument("--min-sources-for-fanin", type=int,
                   help="Skip the fan-in filter below this many unique sources (default 10)")
    p.add_argument("--fanin-threshold", type=float, help="Fan-in fraction treated as shared infra")
    p.add_argument("--min-pair-flows", type=int, help="Minimum flows per channel (default 8)")
    p.add_argument("--max-pairs", type=int, help="Cap on pairs sent to SAX (default 5000)")
    p.add_argument("--contamination", type=float, help="IsolationForest contamination")
    p.add_argument("--zeek-script", action="append", default=[],
                   help="Extra Zeek script/package for --pcap, e.g. ja3")
    return p.parse_args(argv)


def build_config(args, input_dir: Path, out_dir: Path, conn: pd.DataFrame):
    from analytic_pipeline import BDPConfig

    cfg = BDPConfig.from_json(args.config) if args.config else BDPConfig()
    cfg.io.input_csv = input_dir / "conn.csv"
    cfg.io.output_dir = out_dir / "pipeline_output"
    cfg.io.output_dir.mkdir(parents=True, exist_ok=True)
    t0, t1 = float(conn["timestamp"].min()), float(conn["timestamp"].max())
    cfg.io.query_start = str(pd.to_datetime(math.floor(t0), unit="s", utc=True))[:19]
    cfg.io.query_end   = str(pd.to_datetime(math.ceil(t1) + 1, unit="s", utc=True))[:19]

    if args.internal_cidr:
        cfg.prefilter.internal_cidrs = tuple(cfg.prefilter.internal_cidrs) + tuple(args.internal_cidr)
    if args.min_sources_for_fanin is not None:
        cfg.prefilter.min_sources_for_fanin = args.min_sources_for_fanin
    if args.fanin_threshold is not None:
        cfg.prefilter.dst_fanin_threshold = args.fanin_threshold
    if args.min_period_s is not None:
        cfg.periodicity.min_period_s = args.min_period_s
    if args.min_pair_flows is not None:
        cfg.pair.min_pair_flows = args.min_pair_flows
        cfg.pair.min_observations = min(cfg.pair.min_observations, args.min_pair_flows)
    if args.max_pairs is not None:
        cfg.pair.max_pairs = args.max_pairs
    if args.contamination is not None:
        cfg.isolation.contamination = args.contamination
    return cfg


def save_stages(art, stage_dir: Path) -> None:
    stage_dir.mkdir(parents=True, exist_ok=True)
    raw_pairs = (art.raw.groupby(["src_ip", "dst_ip"]).size().rename("n_flows").reset_index()
                 if not art.raw.empty else pd.DataFrame(columns=["src_ip", "dst_ip", "n_flows"]))
    raw_pairs.to_csv(stage_dir / "raw_pairs.csv", index=False)
    for name in ("scaled", "prefiltered", "sax", "periodicity", "priority",
                 "changepoints", "corroboration"):
        df = getattr(art, name)
        if df is not None and not df.empty:
            df = df[[c for c in df.columns if not c.endswith("_stdz")]]
            df.to_csv(stage_dir / f"{name}.csv", index=False)


def main(argv=None) -> None:
    logging.basicConfig(level=logging.INFO, datefmt="%H:%M:%S",
                        format="%(asctime)s  %(levelname)-7s  %(name)s  %(message)s")
    args = parse_args(argv)
    out_dir = Path(args.output)
    out_dir.mkdir(parents=True, exist_ok=True)
    t_start = time.perf_counter()

    from analytic_pipeline.zeek_adapter import convert_dir, run_zeek

    # --- 1. Get CADENCE-format CSVs ---
    if args.cadence_dir:
        input_dir = Path(args.cadence_dir)
    else:
        input_dir = out_dir / "cadence_input"
        if args.pcap:
            with tempfile.TemporaryDirectory(prefix="cadence_zeek_") as tmp:
                run_zeek(args.pcap, tmp, extra_scripts=args.zeek_script)
                convert_dir(tmp, input_dir)
        else:
            convert_dir(args.zeek_dir, input_dir)

    conn_path = input_dir / "conn.csv"
    if not conn_path.exists():
        sys.exit(f"No conn.csv in {input_dir}")
    conn = pd.read_csv(conn_path, usecols=["timestamp"])
    aux = {k: (input_dir / f"{k}.csv") for k in ("dns", "http", "ssl")}
    aux = {k: str(v) if (v.exists() and not args.conn_only) else None for k, v in aux.items()}

    # --- 2. Run the pipeline ---
    from analytic_pipeline import BDPPipeline
    cfg = build_config(args, input_dir, out_dir, conn)
    cfg.to_json(str(out_dir / "run_config.json"))
    log.info("Corroboration logs: %s", {k: bool(v) for k, v in aux.items()})
    art = BDPPipeline(cfg).run(dns_log_path=aux["dns"], http_log_path=aux["http"],
                               ssl_log_path=aux["ssl"], visualize=False)
    save_stages(art, out_dir / "stages")

    def _n(df, col=None):
        if df is None or df.empty:
            return 0
        return int(df[col].astype(bool).sum()) if col else len(df)

    summary = {
        "conn_rows":           len(art.raw),
        "pairs_in_conn":       int(art.raw.groupby(["src_ip", "dst_ip"]).ngroups) if not art.raw.empty else 0,
        "channels_prefiltered": _n(art.prefiltered),
        "anomalous_flows":     _n(art.anomalies),
        "pairs_sax_evaluated": _n(art.sax),
        "pairs_sax_pass":      _n(art.sax, "sax_prescreen_pass"),
        "beacon_pairs":        _n(art.periodicity, "is_beacon_pair"),
        "corroborated_pairs":  _n(art.corroboration, "corroborated"),
        "conn_only":           bool(args.conn_only),
        "runtime_s":           round(time.perf_counter() - t_start, 1),
    }
    (out_dir / "run_summary.json").write_text(json.dumps(summary, indent=2))
    print("\nFunnel")
    for k, v in summary.items():
        print(f"  {k:<22} {v}")

    # --- 3. Score ---
    if args.gt:
        from analytic_pipeline.ground_truth import load_ground_truth, score, stage_table
        tbl = stage_table(
            pd.read_csv(out_dir / "stages" / "raw_pairs.csv", dtype={"src_ip": str, "dst_ip": str}),
            art.scaled, art.prefiltered, art.sax, art.periodicity, art.corroboration,
        )
        metrics, per_gt = score(tbl, load_ground_truth(args.gt))
        (out_dir / "metrics.json").write_text(json.dumps(metrics, indent=2))
        per_gt.to_csv(out_dir / "gt_pairs_by_stage.csv", index=False)
        tbl.to_csv(out_dir / "stages" / "pair_stages.csv", index=False)
        s = metrics["strict"]
        print("\nScore (pair level, strict)")
        print(f"  C2 pairs in conn      {metrics['n_gt_c2_pairs_in_conn']} of {metrics['n_gt_c2_pairs']}")
        for stage in ("beacon_stage", "corroborated_stage"):
            m = s[stage]
            print(f"  {stage:<21} P={m['precision']:.3f}  R={m['recall']:.3f}  F1={m['f1']:.3f}  "
                  f"(tp={m['tp']} fp={m['fp']} fn={m['fn']})")
        print(f"  average_precision     {s['average_precision']}")
        print(f"  C2 pairs by stage     {metrics['c2_pairs_by_stage']}")
        print(f"\n  Full metrics: {out_dir / 'metrics.json'}")


if __name__ == "__main__":
    main()
