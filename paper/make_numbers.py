"""
Turn experiment outputs into LaTeX macros and tables for main.tex.

Inputs
    paper/data/synthetic_{fixed,original,none}.json   from experiments/synthetic_eval.py
    results/real_data/<run>/{metrics.json,dataset_info.json,gt_periodicity.csv}
Outputs
    paper/generated/numbers.tex        \newcommand macros
    paper/generated/synth_scen.tex     per-scenario table body (seed 42, fixed)
    paper/generated/synth_ablate.tex   stage-cut and spectral-variant table body
    paper/generated/real_table.tex     real-data table body (one row per run)
    paper/generated/real_periods.tex   published vs estimated period rows (if any)

Run from the repo root:  python paper/make_numbers.py
"""
from __future__ import annotations

import ast
import json
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "paper" / "data"
GEN = ROOT / "paper" / "generated"
REAL = ROOT / "results" / "real_data"

TRUE = {  # generator parameters (analytic_pipeline/generate_synthetic_data.py)
    "fast_https_dga":       (300, 0.10, "HTTPS, DGA"),
    "slow_http_fixed":      (3600, 0.05, "HTTP, fixed domain, old UA"),
    "multi_host_campaign":  (900, 0.15, "HTTP/8080, DGA, NXDomain"),
    "exfil_slow":           (21600, 0.08, "Large variable payload"),
    "decoy_windows_update": (3600, 0.20, "Benign update agent"),
    "decoy_ntp":            (1024, 0.05, "NTP, no HTTP"),
}
TEX_NAME = {k: r"\texttt{" + k.replace("_", r"\_") + "}" for k in TRUE}


def cmd(name: str, value) -> str:
    return f"\\newcommand{{\\{name}}}{{{value}}}\n"


def fmt(x, nd=2):
    return "--" if x is None or (isinstance(x, float) and np.isnan(x)) else f"{x:.{nd}f}"


def pm(vals, nd=2):
    v = np.asarray([x for x in vals if x is not None], dtype=float)
    if len(v) == 0:
        return "--"
    if v.std() < 10 ** (-nd) / 2:
        return f"{v.mean():.{nd}f}"
    return f"{v.mean():.{nd}f}$\\pm${v.std(ddof=1):.{nd}f}"


def period_str(s):
    if s is None:
        return "--"
    s = float(s)
    if s >= 3600:
        return f"{s / 3600:.2f}\\,h"
    if s >= 60:
        return f"{s / 60:.1f}\\,min"
    return f"{s:.0f}\\,s"


def load_synth(variant):
    p = DATA / f"synthetic_{variant}.json"
    return json.loads(p.read_text()) if p.exists() else []


def synthetic(out: list[str]) -> None:
    runs = {v: load_synth(v) for v in ("fixed", "original", "none")}
    fx = runs["fixed"]
    if not fx:
        out.append(cmd("SynSeeds", r"\TBD"))
        return
    s42 = next((r for r in fx if r["seed"] == 42), fx[0])
    out += [
        cmd("SynSeeds", len(fx)),
        cmd("SynRows", f"{s42['n_conn_rows']:,}".replace(",", "{,}")),
        cmd("SynPairs", f"{s42['funnel']['pairs_in_conn']:,}".replace(",", "{,}")),
        cmd("SynMalPairs", s42["n_mal_pairs"]),
        cmd("SynDecoyPairs", s42["n_decoy_pairs"]),
        cmd("SynRuntime", f"{np.mean([r['funnel']['runtime_s'] for r in fx]):.0f}"),
    ]
    # Funnel for seed 42 from the stage table counts
    f = s42["funnel"]
    out += [
        cmd("FunPrefilteredChannels", f"{f['channels_prefiltered']:,}".replace(",", "{,}")),
        cmd("FunAnomFlows", f"{f['anomalous_flows']:,}".replace(",", "{,}")),
        cmd("FunSax", f["pairs_sax_evaluated"]),
        cmd("FunSaxPass", f["pairs_sax_pass"]),
        cmd("FunBeacon", f["beacon_pairs"]),
        cmd("FunCorr", f["corroborated_pairs"]),
    ]
    abl = s42["ablation"]
    first = next(iter(abl.values()))
    out.append(cmd("FunIforestPairs", first["flagged"]))

    # Headline metrics across seeds (fixed)
    def col(rs, view, stage, key):
        return [r["metrics"][view][stage][key] for r in rs]
    for stage, tag in (("corroborated_stage", "Corr"), ("beacon_stage", "Beacon")):
        for key, k in (("precision", "P"), ("recall", "R"), ("f1", "F")):
            out.append(cmd(f"Syn{tag}{k}", pm(col(fx, "strict", stage, key))))
    out.append(cmd("SynAP", pm([r["metrics"]["strict"]["average_precision"] for r in fx])))

    # Old evaluator (scenario-level) on seed 42
    old = s42.get("old_evaluator") or {}
    out.append(cmd("OldEvalF", fmt(old.get("f1"))))

    h2p = DATA / "synthetic_h2.json"
    if h2p.exists():
        h2 = json.loads(h2p.read_text())
        out.append(cmd("HtwoPairs", h2["pairs_scored"]))
        out.append(cmd("HtwoTrue", h2["h2_true"]))
    else:
        out += [cmd("HtwoPairs", r"\TBD"), cmd("HtwoTrue", r"\TBD")]

    # Decoy corroboration margin across seeds
    dec = []
    for r in fx:
        for s in r["scenarios"]:
            if s["label"] == "decoy" and s["corroboration_score"]:
                dec.append(max(s["corroboration_score"]))
    if dec:
        out += [cmd("DecoyCorrMax", f"{max(dec):.3f}"),
                cmd("DecoyCorrMargin", f"{0.55 - max(dec):.3f}")]

    # Per-scenario table (seed 42, fixed)
    rows = []
    for s in sorted(s42["scenarios"], key=lambda s: (s["label"] != "malicious", s["scenario"])):
        name = s["scenario"]
        T, j, sig = TRUE.get(name, (None, None, ""))
        est = s["dominant_period_s"][0] if s["dominant_period_s"] else None
        conf = s["beacon_confidence"][0] if s["beacon_confidence"] else None
        cs = s["corroboration_score"][0] if s["corroboration_score"] else None
        techs = "--"
        if s["mitre_techniques"]:
            try:
                tl = ast.literal_eval(s["mitre_techniques"][0])
                ids = sorted({t["technique_id"] for t in tl})
                techs = ", ".join(ids) if ids else "--"
            except (ValueError, SyntaxError):
                pass
        stage = s["stages"][0].replace("_", " ")
        lab = "mal." if s["label"] == "malicious" else "decoy"
        rows.append(f"{TEX_NAME.get(name, name)} & {lab} & {period_str(T)} ({int(j*100)}\\%) & "
                    f"{period_str(est)} & {fmt(conf)} & {fmt(cs)} & {stage} \\\\")
    (GEN / "synth_scen.tex").write_text("\n".join(rows) + "\n")
    out.append("\\newcommand{\\SynScenRows}{%\n" + "\n".join(rows) + "}\n")

    # Stage-cut ablation (fixed) + spectral variants at beacon and corroborated stages
    lines = []
    for cut in abl:
        P = pm([r["ablation"][cut]["precision"] for r in fx])
        R = pm([r["ablation"][cut]["recall"] for r in fx])
        FP = pm([r["ablation"][cut]["fp"] for r in fx], 1)
        lines.append(f"{cut} & {P} & {R} & {FP} \\\\")
    lines.append(r"\midrule")
    names = {"fixed": "Spectral term on counts (this paper)",
             "original": "Spectral term on IAT index (uninformative)",
             "none": "No spectral term"}
    for v in ("fixed", "original", "none"):
        rs = runs[v]
        if not rs:
            lines.append(f"{names[v]} & \\multicolumn{{3}}{{c}}{{pending}} \\\\")
            continue
        bp = pm(col(rs, "strict", "beacon_stage", "precision"))
        br = pm(col(rs, "strict", "beacon_stage", "recall"))
        cp = pm(col(rs, "strict", "corroborated_stage", "f1"))
        lines.append(f"{names[v]} & {bp} & {br} & F1$_{{corr}}$ {cp} \\\\")
    (GEN / "synth_ablate.tex").write_text("\n".join(lines) + "\n")
    out.append("\\newcommand{\\SynAblateRows}{%\n" + "\n".join(lines) + "}\n")

    # Exfil (slow beacon) confidence under each variant: where the fix matters most
    for v, tag in (("fixed", "Fix"), ("original", "Orig"), ("none", "None")):
        conf = []
        for r in runs[v]:
            for s in r["scenarios"]:
                if s["scenario"] == "exfil_slow" and s["beacon_confidence"]:
                    conf.append(s["beacon_confidence"][0])
        out.append(cmd(f"ExfilConf{tag}", pm(conf) if conf else r"\TBD"))


def real(out: list[str]) -> None:
    rows, prow = [], []
    runs = sorted(p for p in REAL.glob("*") if (p / "metrics.json").exists()) if REAL.exists() else []
    for d in runs:
        m = json.loads((d / "metrics.json").read_text())
        info = json.loads((d / "dataset_info.json").read_text()) if (d / "dataset_info.json").exists() else {}
        s = m["strict"]
        name = d.name.replace("_", r"\_")
        fam = info.get("malware_family", "")
        b, c = s["beacon_stage"], s["corroborated_stage"]
        stages = m.get("c2_pairs_by_stage", {})
        top_miss = max(((k, v) for k, v in stages.items() if k not in ("corroborated",)),
                       key=lambda kv: kv[1], default=("--", 0))
        rows.append(
            f"\\texttt{{{name}}} & {fam} & {m['n_gt_c2_pairs_in_conn']} & "
            f"{fmt(b['precision'])} & {fmt(b['recall'])} & {fmt(c['precision'])} & {fmt(c['recall'])} & "
            f"{fmt(s.get('average_precision'))} & {top_miss[0].replace('_', ' ')} ({top_miss[1]}) \\\\")
        gp = d / "gt_periodicity.csv"
        pub = info.get("published_period_s")
        if pub and gp.exists():
            g = pd.read_csv(gp)
            if not g.empty and "dominant_period_s" in g:
                est = g["dominant_period_s"].iloc[0]
                conf = g["beacon_confidence"].iloc[0] if "beacon_confidence" in g else None
                jit = info.get("published_jitter", "")
                prow.append(f"\\texttt{{{name}}} & {period_str(pub)} & {jit} & {period_str(est)} & {fmt(conf)} \\\\")
    if not rows:
        rows = [r"\multicolumn{9}{c}{\textit{Real-data runs pending}} \\"]
    (GEN / "real_table.tex").write_text("\n".join(rows) + "\n")
    (GEN / "real_periods.tex").write_text("\n".join(prow) + "\n" if prow else "")
    out.append("\\newcommand{\\RealRows}{%\n" + "\n".join(rows) + "}\n")
    out.append("\\newcommand{\\RealPeriodRows}{%\n" + ("\n".join(prow) if prow else
               r"\multicolumn{5}{c}{\textit{pending}} \\") + "}\n")
    out.append(cmd("RealRuns", len(runs)))


def main() -> None:
    GEN.mkdir(parents=True, exist_ok=True)
    out = ["% Generated by paper/make_numbers.py. Do not edit by hand.\n",
           "\\providecommand{\\TBD}{\\textcolor{red}{TBD}}\n"]
    synthetic(out)
    real(out)
    (GEN / "numbers.tex").write_text("".join(out))
    print(f"wrote {GEN}")


if __name__ == "__main__":
    main()
