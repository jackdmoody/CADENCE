"""
Synthetic evaluation for the paper, scored at the (src_ip, dst_ip) pair level.

For each seed: generate the default 30-day synthetic set, run CADENCE through
run_real_data.py, and score against pair-level ground truth (pairs carrying the
generator's `malicious` label). Decoy pairs are benign, so flagging one is a
false positive. Also records the original scenario-level evaluator's numbers
for seed 42 so the paper can report both.

Usage:
    python paper/experiments/synthetic_eval.py --out /tmp/synth --seeds 42 0 1 2 3 4 5 6 7 8 9
Outputs (in --out):
    seed_<s>/...                 full run directories
    synthetic_summary.json       per-seed metrics, stage-cut ablation, per-scenario table
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from analytic_pipeline.generate_synthetic_data import SyntheticDataGenerator, evaluate_detection  # noqa: E402
from analytic_pipeline import ground_truth as gtm  # noqa: E402
import run_real_data  # noqa: E402

import analytic_pipeline.periodicity as _per  # noqa: E402
from scipy import signal as _signal  # noqa: E402


def _spectral_original(iat_or_ts, min_period_s):
    """The pre-v3.1 implementation: Welch on the IAT sequence with fs=1.0 (units bug)."""
    ts = np.asarray(iat_or_ts, dtype=float)
    iat = np.diff(ts)
    iat = iat[iat > 0]
    n = len(iat)
    if n < 8:
        return 0.0, 0.0
    freqs, psd = _signal.welch(iat, fs=1.0, nperseg=min(n, 64))
    with np.errstate(divide="ignore", invalid="ignore"):
        periods = np.where(freqs > 0, 1.0 / freqs, 0.0)
    valid = (freqs > 0) & (periods >= min_period_s)
    if not valid.any():
        return 0.0, 0.0
    i = int(np.argmax(psd[valid]))
    return float(periods[valid][i]), float(psd[valid][i] / (psd[valid].sum() + 1e-12))


SPECTRAL_VARIANTS = {
    "fixed": _per._fft_dominant_period,
    "original": _spectral_original,
    "none": lambda ts, m: (0.0, 0.0),
}

# Stage cuts for the ablation: "stop the pipeline after stage X and alarm on everything that reached it"
CUTS = {
    "IForest anomaly (stages 1-4)":   gtm.STAGE_RANK["sax_not_evaluated"],
    "+ SAX pass (stage 5)":           gtm.STAGE_RANK["not_beacon"],
    "+ periodicity (stage 6)":        gtm.STAGE_RANK["beacon_uncorroborated"],
    "+ corroboration (stage 9)":      gtm.STAGE_RANK["corroborated"],
}


def run_seed(seed: int, out: Path, days: int, bg: int, noisy: int, extra: list | None = None) -> dict:
    d = out / f"seed_{seed}"
    inp = d / "input"
    inp.mkdir(parents=True, exist_ok=True)
    conn, dns, http, ssl, labels = SyntheticDataGenerator(seed=seed).generate(
        days=days, bg_rows_per_day=bg, noisy_rows_per_day=noisy)
    conn.drop(columns=["label", "scenario"]).to_csv(inp / "conn.csv", index=False)
    dns.to_csv(inp / "dns.csv", index=False)
    http.to_csv(inp / "http.csv", index=False)
    ssl.to_csv(inp / "ssl.csv", index=False)

    pairs = conn[["source.ip", "destination.ip", "label", "scenario"]].drop_duplicates()
    mal = pairs[pairs["label"] == "malicious"]
    gt = gtm.from_pairs(list(map(tuple, mal[["source.ip", "destination.ip"]].drop_duplicates().to_numpy())))
    gt.to_csv(d / "gt.csv", index=False)

    run_real_data.main(["--cadence-dir", str(inp), "--output", str(d / "run"), "--gt", str(d / "gt.csv"),
                        *(extra or [])])
    metrics = json.loads((d / "run" / "metrics.json").read_text())
    tbl = pd.read_csv(d / "run" / "stages" / "pair_stages.csv", dtype={"src_ip": str, "dst_ip": str})

    # Stage-cut ablation
    pos = set(map(tuple, gt[["src_ip", "dst_ip"]].to_numpy()))
    decoys = pairs[pairs["label"] == "decoy"][["source.ip", "destination.ip"]]
    decoy_set = set(map(tuple, decoys.to_numpy()))
    ablation = {}
    for name, rank in CUTS.items():
        flagged = set(map(tuple, tbl.loc[tbl["stage_rank"] >= rank, ["src_ip", "dst_ip"]].to_numpy()))
        tp, fp = len(flagged & pos), len(flagged - pos)
        ablation[name] = {
            "flagged": len(flagged), "tp": tp, "fp": fp,
            "decoy_fp": len(flagged & decoy_set),
            "precision": round(tp / len(flagged), 4) if flagged else 0.0,
            "recall": round(tp / len(pos), 4) if pos else 0.0,
        }

    # Per-scenario table
    stage_of = {(r.src_ip, r.dst_ip): r for r in tbl.itertuples()}
    per = pd.read_csv(d / "run" / "stages" / "periodicity.csv", dtype={"src_ip": str, "dst_ip": str}) \
        if (d / "run" / "stages" / "periodicity.csv").exists() else pd.DataFrame()
    corr = pd.read_csv(d / "run" / "stages" / "corroboration.csv", dtype={"src_ip": str, "dst_ip": str}) \
        if (d / "run" / "stages" / "corroboration.csv").exists() else pd.DataFrame()
    scen_rows = []
    for scen, g in pairs[pairs["label"].isin(["malicious", "decoy"])].groupby("scenario"):
        ps = list(map(tuple, g[["source.ip", "destination.ip"]].drop_duplicates().to_numpy()))
        stages = [stage_of[p].stage if p in stage_of else "not_in_conn" for p in ps]
        def _get(df, col):
            if df.empty or col not in df.columns:
                return None
            m = df[[ (s, t) in set(ps) for s, t in zip(df["src_ip"], df["dst_ip"])]]
            return None if m.empty else m[col].tolist()
        scen_rows.append({
            "scenario": scen, "label": g["label"].iloc[0], "n_pairs": len(ps),
            "stages": stages,
            "dominant_period_s": _get(per, "dominant_period_s"),
            "beacon_confidence": _get(per, "beacon_confidence"),
            "corroboration_score": _get(corr, "corroboration_score"),
            "mitre_techniques": _get(corr, "mitre_techniques"),
        })

    old = None
    if seed == 42:
        # The original evaluator, unchanged, for the side-by-side comparison
        corr_full = pd.read_csv(d / "run" / "stages" / "corroboration.csv")
        conn_l = conn.rename(columns={"source.ip": "src_ip", "destination.ip": "dst_ip"})
        res = evaluate_detection(corr_full, labels, conn_l)
        old = {"precision": float(res["precision"].iloc[0]), "recall": float(res["recall"].iloc[0]),
               "f1": float(res["f1"].iloc[0]),
               "detected": res.loc[res["detected"], "scenario"].tolist()}

    summary = json.loads((d / "run" / "run_summary.json").read_text())
    return {"seed": seed, "metrics": metrics, "ablation": ablation, "scenarios": scen_rows,
            "funnel": summary, "old_evaluator": old,
            "n_conn_rows": int(len(conn)), "n_mal_pairs": len(pos), "n_decoy_pairs": len(decoy_set)}


def main() -> None:
    logging.basicConfig(level=logging.WARNING)
    p = argparse.ArgumentParser()
    p.add_argument("--out", required=True)
    p.add_argument("--seeds", type=int, nargs="+", default=[42])
    p.add_argument("--days", type=int, default=30)
    p.add_argument("--bg-rows", type=int, default=30_000)
    p.add_argument("--noisy-rows", type=int, default=1_000)
    p.add_argument("--spectral", choices=list(SPECTRAL_VARIANTS), default="fixed",
                   help="Spectral confirmation variant (ablation of the v3.1 fix)")
    p.add_argument("--dns-link-window-s", type=float, default=None,
                   help="Opt-in H2 linking window (ablation); default keeps host-wide H2")
    a = p.parse_args()
    _per._fft_dominant_period = SPECTRAL_VARIANTS[a.spectral]
    extra = ["--dns-link-window-s", str(a.dns_link_window_s)] if a.dns_link_window_s else []
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    results = []
    for s in a.seeds:
        r = run_seed(s, out, a.days, a.bg_rows, a.noisy_rows, extra)
        r["spectral"] = a.spectral
        r["dns_link_window_s"] = a.dns_link_window_s or 0.0
        m = r["metrics"]["strict"]
        print(f"seed {s:>3}  rows {r['n_conn_rows']:,}  corr P={m['corroborated_stage']['precision']:.3f} "
              f"R={m['corroborated_stage']['recall']:.3f}  beacon P={m['beacon_stage']['precision']:.3f} "
              f"R={m['beacon_stage']['recall']:.3f}  by_stage={r['metrics']['c2_pairs_by_stage']}", flush=True)
        results.append(r)
        (out / "synthetic_summary.json").write_text(json.dumps(results, indent=1, default=str))


if __name__ == "__main__":
    main()
