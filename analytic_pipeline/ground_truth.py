"""
Ground truth and scoring for real-data runs
============================================
Builds pair-level C2 ground truth from public datasets and scores a CADENCE
run against it, including which stage dropped each missed C2 pair.

Why pair level:
    Stages 5–9 (SAX, periodicity, scoring, PELT, corroboration) group flows
    by (src_ip, dst_ip), so that is the unit CADENCE flags. A pair is C2 if
    any of its flows carries a C2 label in the source dataset.

Ground-truth CSV schema (one row per pair):
    src_ip, dst_ip, gt_class, n_flows, dst_ports, labels
    gt_class ∈ {"c2", "malicious_other"}
    malicious_other = infected-host traffic that is not C2 (spam, scans, DDoS).
    Scoring reports two views of it:
        strict   — malicious_other pairs count as negatives (a flag is a FP)
        lenient  — malicious_other pairs are dropped from the universe

Builders:
    from_ctu13_binetflow   CTU-13 labeled Argus .binetflow files
    from_zeek_labeled      Zeek conn.log with label / detailed-label columns (IoT-23)
    from_pairs             Hand-entered victim → C2 pairs (Active Countermeasures,
                           malware-traffic-analysis, red team reports)

CLI:
    python -m analytic_pipeline.ground_truth ctu13 --binetflow capture20110810.binetflow --out gt.csv
    python -m analytic_pipeline.ground_truth zeek-labeled --conn conn.log.labeled --out gt.csv
    python -m analytic_pipeline.ground_truth pairs --pair 192.168.2.115 64.23.212.29 --out gt.csv
    python -m analytic_pipeline.ground_truth score --run-dir results/ctu13_s1 --gt gt.csv
"""
from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path
from typing import Iterable, Optional, Sequence

import numpy as np
import pandas as pd

log = logging.getLogger(__name__)

GT_COLUMNS = ["src_ip", "dst_ip", "gt_class", "n_flows", "dst_ports", "labels"]

# CTU-13 C&C labels look like "flow=From-Botnet-V42-TCP-CC6-Plain-HTTP-Encrypted-Data"
CTU13_C2_PATTERN     = r"From-Botnet.*-CC"
CTU13_BOTNET_PATTERN = r"From-Botnet"
# IoT-23 detailed-label values: C&C, C&C-HeartBeat, C&C-FileDownload, C&C-Torii, ...
IOT23_C2_PATTERN     = r"C&C"

# Ordered stages; a pair's stage is the furthest one it reached.
STAGES = [
    "not_in_conn",            # pair never appears in the loaded conn data
    "below_min_flows",        # fewer than cfg.pair.min_pair_flows flows on every channel
    "prefiltered",            # removed by the domain-knowledge pre-filter
    "iforest_normal",         # survived pre-filter, IForest scored it normal
    "sax_not_evaluated",      # IForest anomaly but no SAX row (pair cap or too few obs)
    "sax_reject",             # SAX pre-screen said non-periodic
    "not_beacon",             # full ACF/FFT ran, is_beacon_pair False
    "beacon_uncorroborated",  # is_beacon_pair True, corroboration False
    "corroborated",           # corroborated True
]
STAGE_RANK = {s: i for i, s in enumerate(STAGES)}


# ---------------------------------------------------------------------------
# Builders
# ---------------------------------------------------------------------------

def _pick(df: pd.DataFrame, *names: str) -> str:
    lower = {c.lower(): c for c in df.columns}
    for n in names:
        if n.lower() in lower:
            return lower[n.lower()]
    raise KeyError(f"None of {names} in columns {list(df.columns)}")


def _summarise(df: pd.DataFrame, src: str, dst: str, port: Optional[str],
               label: str, is_c2: pd.Series) -> pd.DataFrame:
    df = df.assign(_c2=is_c2.values)
    rows = []
    for (s, d), g in df.groupby([src, dst], sort=False):
        ports = ""
        if port is not None:
            ports = ",".join(sorted({str(p) for p in g[port].dropna().unique()})[:10])
        rows.append({
            "src_ip":    str(s),
            "dst_ip":    str(d),
            "gt_class":  "c2" if g["_c2"].any() else "malicious_other",
            "n_flows":   int(len(g)),
            "dst_ports": ports,
            "labels":    "|".join(sorted({str(x) for x in g[label].dropna().unique()})[:5]),
        })
    out = pd.DataFrame(rows, columns=GT_COLUMNS)
    log.info("Ground truth: %d c2 pairs, %d malicious_other pairs",
             int((out["gt_class"] == "c2").sum()), int((out["gt_class"] != "c2").sum()))
    return out


def from_ctu13_binetflow(
    paths: Iterable[str | Path],
    c2_pattern: str = CTU13_C2_PATTERN,
    botnet_pattern: str = CTU13_BOTNET_PATTERN,
) -> pd.DataFrame:
    """
    Pair-level ground truth from CTU-13 labeled bidirectional NetFlows.

    SrcAddr in Argus is the flow originator, which matches Zeek's id.orig_h
    for nearly all flows. Pairs whose direction disagrees show up in the
    scorer's `reverse_in_conn` diagnostic rather than being silently flipped.
    """
    frames = [pd.read_csv(p, low_memory=False, skipinitialspace=True) for p in paths]
    df = pd.concat(frames, ignore_index=True)
    src, dst = _pick(df, "SrcAddr"), _pick(df, "DstAddr")
    port, label = _pick(df, "Dport"), _pick(df, "Label")
    lab = df[label].astype(str)
    bot = df[lab.str.contains(botnet_pattern, regex=True, na=False)].copy()
    is_c2 = bot[label].astype(str).str.contains(c2_pattern, regex=True, na=False)
    log.info("CTU-13: %d flows, %d botnet flows, %d C&C flows", len(df), len(bot), int(is_c2.sum()))
    return _summarise(bot, src, dst, port, label, is_c2)


def from_zeek_labeled(
    paths: Iterable[str | Path],
    c2_pattern: str = IOT23_C2_PATTERN,
    malicious_label: str = "malicious",
) -> pd.DataFrame:
    """Pair-level ground truth from Zeek conn logs carrying label / detailed-label (IoT-23)."""
    from .zeek_adapter import read_zeek_log
    df = pd.concat([read_zeek_log(p) for p in paths], ignore_index=True)
    detail = _pick(df, "detailed-label", "detailed_label")
    label = _pick(df, "label")
    mal = df[df[label].astype(str).str.strip().str.lower().eq(malicious_label)].copy()
    is_c2 = mal[detail].astype(str).str.contains(c2_pattern, regex=False, na=False)
    log.info("Zeek-labeled: %d flows, %d malicious, %d C&C", len(df), len(mal), int(is_c2.sum()))
    return _summarise(mal, "id.orig_h", "id.resp_h", "id.resp_p", detail, is_c2)


def from_pairs(pairs: Sequence[tuple[str, str]], gt_class: str = "c2",
               label: str = "manual") -> pd.DataFrame:
    """Ground truth from known victim → C2 pairs, e.g. from a Malware of the Day post."""
    return pd.DataFrame(
        [{"src_ip": s, "dst_ip": d, "gt_class": gt_class, "n_flows": np.nan,
          "dst_ports": "", "labels": label} for s, d in pairs],
        columns=GT_COLUMNS,
    )


def load_ground_truth(path: str | Path) -> pd.DataFrame:
    gt = pd.read_csv(path, dtype={"src_ip": str, "dst_ip": str})
    missing = {"src_ip", "dst_ip", "gt_class"} - set(gt.columns)
    if missing:
        raise ValueError(f"{path} is missing columns {sorted(missing)}")
    bad = set(gt["gt_class"]) - {"c2", "malicious_other"}
    if bad:
        raise ValueError(f"Unknown gt_class values {sorted(bad)}; use c2 or malicious_other")
    # A pair labelled c2 anywhere wins over malicious_other
    gt = gt.sort_values("gt_class").drop_duplicates(["src_ip", "dst_ip"], keep="first")
    return gt.reset_index(drop=True)


# ---------------------------------------------------------------------------
# Stage attribution
# ---------------------------------------------------------------------------

def _as_bool(s: pd.Series) -> pd.Series:
    """Booleans survive CSV round trips as bools, strings or NaN; normalise all of them."""
    if s.dtype == bool:
        return s
    return s.map(lambda v: str(v).strip().lower() in ("true", "1", "1.0", "t", "yes"))


def _pairs(df: pd.DataFrame, mask: Optional[pd.Series] = None) -> set[tuple[str, str]]:
    if df is None or df.empty or "src_ip" not in df.columns:
        return set()
    if mask is not None:
        df = df[_as_bool(mask).to_numpy()]
    return set(zip(df["src_ip"].astype(str), df["dst_ip"].astype(str)))


def stage_table(
    raw_pairs: pd.DataFrame,
    scaled: pd.DataFrame,
    prefiltered: pd.DataFrame,
    sax: pd.DataFrame,
    periodicity: pd.DataFrame,
    corroboration: pd.DataFrame,
) -> pd.DataFrame:
    """
    One row per (src_ip, dst_ip) in the conn data with the furthest stage it
    reached plus the scores needed for ranking metrics.

    raw_pairs     columns src_ip, dst_ip, n_flows (from the loaded conn data)
    scaled        post-prefilter channel table with iforest_label (1 normal, -1 anomaly)
    prefiltered   channels removed by the pre-filter, with prefilter_reason
    """
    tbl = raw_pairs[["src_ip", "dst_ip", "n_flows"]].drop_duplicates(["src_ip", "dst_ip"]).copy()
    tbl["src_ip"] = tbl["src_ip"].astype(str)
    tbl["dst_ip"] = tbl["dst_ip"].astype(str)
    key = list(zip(tbl["src_ip"], tbl["dst_ip"]))

    kept = _pairs(scaled)
    anomalous = (_pairs(scaled, pd.to_numeric(scaled["iforest_label"], errors="coerce").eq(-1))
                 if "iforest_label" in scaled else kept)
    removed_reason: dict[tuple[str, str], str] = {}
    if prefiltered is not None and not prefiltered.empty:
        for s, d, r in zip(prefiltered["src_ip"].astype(str), prefiltered["dst_ip"].astype(str),
                           prefiltered.get("prefilter_reason", pd.Series("", index=prefiltered.index))):
            removed_reason.setdefault((s, d), str(r))
    sax_seen = _pairs(sax)
    sax_pass = _pairs(sax, sax["sax_prescreen_pass"]) if "sax_prescreen_pass" in sax else set()
    per_seen = _pairs(periodicity)
    beacons  = _pairs(periodicity, periodicity["is_beacon_pair"]) if "is_beacon_pair" in periodicity else set()
    corr     = _pairs(corroboration, corroboration["corroborated"]) if "corroborated" in corroboration else set()

    def _stage(p: tuple[str, str]) -> str:
        if p in corr:
            return "corroborated"
        if p in beacons:
            return "beacon_uncorroborated"
        if p in per_seen or p in sax_pass:
            return "not_beacon"
        if p in sax_seen:
            return "sax_reject"
        if p in anomalous:
            return "sax_not_evaluated"
        if p in kept:
            return "iforest_normal"
        if p in removed_reason:
            return "prefiltered"
        return "below_min_flows"

    tbl["stage"] = [_stage(p) for p in key]
    tbl["prefilter_reason"] = [removed_reason.get(p, "") if s == "prefiltered" else ""
                               for p, s in zip(key, tbl["stage"])]
    tbl["stage_rank"] = tbl["stage"].map(STAGE_RANK)

    def _score_map(df: pd.DataFrame, col: str) -> dict:
        if df is None or df.empty or col not in df.columns:
            return {}
        g = df.assign(src_ip=df["src_ip"].astype(str), dst_ip=df["dst_ip"].astype(str))
        return g.groupby(["src_ip", "dst_ip"])[col].max().to_dict()

    bc = _score_map(periodicity, "beacon_confidence")
    cs = _score_map(corroboration, "corroboration_score")
    tbl["beacon_confidence"]   = [float(bc.get(p, 0.0) or 0.0) for p in key]
    tbl["corroboration_score"] = [float(cs.get(p, 0.0) or 0.0) for p in key]
    # Ranking score: stage first, then the stage's own confidence in [0, 1)
    within = np.where(tbl["stage"].eq("corroborated"), tbl["corroboration_score"], tbl["beacon_confidence"])
    tbl["rank_score"] = tbl["stage_rank"] + np.clip(within, 0, 0.999)
    return tbl


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------

def _prf(flagged: set, pos: set, universe: set) -> dict:
    flagged = flagged & universe
    tp, fp, fn = len(flagged & pos), len(flagged - pos), len(pos - flagged)
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    f = 2 * p * r / (p + r) if p + r else 0.0
    return {"tp": tp, "fp": fp, "fn": fn, "n_flagged": len(flagged),
            "precision": round(p, 4), "recall": round(r, 4), "f1": round(f, 4)}


def _average_precision(scores: np.ndarray, y: np.ndarray) -> Optional[float]:
    if y.sum() == 0:
        return None
    order = np.argsort(-scores, kind="stable")
    y = y[order]
    hits = np.cumsum(y)
    precision_at_hit = hits[y == 1] / (np.flatnonzero(y == 1) + 1)
    return round(float(precision_at_hit.mean()), 4)


def score(tbl: pd.DataFrame, gt: pd.DataFrame, ks: Sequence[int] = (10, 50, 100)) -> tuple[dict, pd.DataFrame]:
    """
    Score a stage table against ground truth.

    Returns (metrics dict, per-GT-pair table with the stage each reached).
    """
    gt = gt.copy()
    gt["src_ip"] = gt["src_ip"].astype(str)
    gt["dst_ip"] = gt["dst_ip"].astype(str)
    c2_all = set(zip(gt.loc[gt["gt_class"] == "c2", "src_ip"], gt.loc[gt["gt_class"] == "c2", "dst_ip"]))
    other  = set(zip(gt.loc[gt["gt_class"] != "c2", "src_ip"], gt.loc[gt["gt_class"] != "c2", "dst_ip"]))

    present = set(zip(tbl["src_ip"], tbl["dst_ip"]))
    c2 = c2_all & present
    flagged_beacon = set(zip(*[tbl.loc[tbl["stage_rank"] >= STAGE_RANK["beacon_uncorroborated"], c]
                               for c in ("src_ip", "dst_ip")]))
    flagged_corr = set(zip(*[tbl.loc[tbl["stage"] == "corroborated", c] for c in ("src_ip", "dst_ip")]))
    detectable = set(zip(*[tbl.loc[tbl["stage_rank"] > STAGE_RANK["below_min_flows"], c]
                           for c in ("src_ip", "dst_ip")]))

    metrics: dict = {
        "n_pairs_in_conn": len(present),
        "n_gt_c2_pairs": len(c2_all),
        "n_gt_c2_pairs_in_conn": len(c2),
        "n_gt_c2_pairs_detectable": len(c2 & detectable),
        "n_gt_malicious_other_pairs_in_conn": len(other & present),
    }
    for view, universe in (("strict", present), ("lenient", present - other)):
        metrics[view] = {
            "beacon_stage":       _prf(flagged_beacon, c2, universe),
            "corroborated_stage": _prf(flagged_corr, c2, universe),
            # Same, but C2 pairs CADENCE could never evaluate (< min flows) are dropped
            "corroborated_stage_detectable_only": _prf(flagged_corr, c2 & detectable,
                                                       universe - (c2 - detectable)),
        }
        sub = tbl[[p in universe for p in zip(tbl["src_ip"], tbl["dst_ip"])]]
        y = np.array([p in c2 for p in zip(sub["src_ip"], sub["dst_ip"])], dtype=int)
        s = sub["rank_score"].to_numpy(dtype=float)
        metrics[view]["average_precision"] = _average_precision(s, y)
        order = np.argsort(-s, kind="stable")
        for k in ks:
            metrics[view][f"recall_at_{k}"] = round(float(y[order][:k].sum() / y.sum()), 4) if y.sum() else None

    # Where each C2 pair stopped — the miss-attribution table for the paper
    by_pair = tbl.set_index(["src_ip", "dst_ip"])
    rows = []
    for _, g in gt.iterrows():
        p = (g["src_ip"], g["dst_ip"])
        if p in by_pair.index:
            r = by_pair.loc[p]
            stage, reason, nf = r["stage"], r["prefilter_reason"], int(r["n_flows"])
            bconf, cscore = float(r["beacon_confidence"]), float(r["corroboration_score"])
        else:
            stage, reason, nf, bconf, cscore = "not_in_conn", "", 0, 0.0, 0.0
        rows.append({**g.to_dict(), "stage": stage, "prefilter_reason": reason,
                     "n_flows_in_conn": nf, "beacon_confidence": bconf,
                     "corroboration_score": cscore,
                     "reverse_in_conn": (p[1], p[0]) in present if stage == "not_in_conn" else False})
    per_gt = pd.DataFrame(rows)
    c2_rows = per_gt[per_gt["gt_class"] == "c2"]
    metrics["c2_pairs_by_stage"] = {s: int((c2_rows["stage"] == s).sum()) for s in STAGES
                                    if (c2_rows["stage"] == s).any()}
    pre = c2_rows.loc[c2_rows["stage"] == "prefiltered", "prefilter_reason"].value_counts()
    if len(pre):
        metrics["c2_prefilter_reasons"] = {str(k): int(v) for k, v in pre.items()}
    return metrics, per_gt


def score_run_dir(run_dir: str | Path, gt_path: str | Path) -> tuple[dict, pd.DataFrame]:
    """Re-score a saved run_real_data.py output directory against a ground-truth CSV."""
    d = Path(run_dir) / "stages"

    def _read(name: str) -> pd.DataFrame:
        p = d / f"{name}.csv"
        return pd.read_csv(p, dtype={"src_ip": str, "dst_ip": str}) if p.exists() else pd.DataFrame()

    tbl = stage_table(_read("raw_pairs"), _read("scaled"), _read("prefiltered"),
                      _read("sax"), _read("periodicity"), _read("corroboration"))
    return score(tbl, load_ground_truth(gt_path))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: Optional[list[str]] = None) -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s  %(levelname)-7s  %(message)s",
                        datefmt="%H:%M:%S")
    p = argparse.ArgumentParser(description="Build ground truth or score a CADENCE run")
    sub = p.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("ctu13", help="From CTU-13 labeled .binetflow files")
    a.add_argument("--binetflow", nargs="+", required=True)
    a.add_argument("--c2-pattern", default=CTU13_C2_PATTERN)
    a.add_argument("--botnet-pattern", default=CTU13_BOTNET_PATTERN)
    a.add_argument("--out", required=True)

    b = sub.add_parser("zeek-labeled", help="From Zeek conn logs with label columns (IoT-23)")
    b.add_argument("--conn", nargs="+", required=True)
    b.add_argument("--c2-pattern", default=IOT23_C2_PATTERN)
    b.add_argument("--out", required=True)

    c = sub.add_parser("pairs", help="From known victim → C2 pairs")
    c.add_argument("--pair", nargs=2, action="append", required=True, metavar=("SRC", "DST"))
    c.add_argument("--label", default="manual")
    c.add_argument("--out", required=True)

    d = sub.add_parser("score", help="Score a saved run directory")
    d.add_argument("--run-dir", required=True)
    d.add_argument("--gt", required=True)

    args = p.parse_args(argv)
    if args.cmd == "score":
        metrics, per_gt = score_run_dir(args.run_dir, args.gt)
        out = Path(args.run_dir)
        (out / "metrics.json").write_text(json.dumps(metrics, indent=2))
        per_gt.to_csv(out / "gt_pairs_by_stage.csv", index=False)
        print(json.dumps(metrics, indent=2))
        return

    if args.cmd == "ctu13":
        gt = from_ctu13_binetflow(args.binetflow, args.c2_pattern, args.botnet_pattern)
    elif args.cmd == "zeek-labeled":
        gt = from_zeek_labeled(args.conn, args.c2_pattern)
    else:
        gt = from_pairs([tuple(x) for x in args.pair], label=args.label)
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    gt.to_csv(args.out, index=False)
    print(f"Wrote {len(gt)} pairs to {args.out}  "
          f"(c2={int((gt['gt_class'] == 'c2').sum())}, other={int((gt['gt_class'] != 'c2').sum())})")


if __name__ == "__main__":
    main()
