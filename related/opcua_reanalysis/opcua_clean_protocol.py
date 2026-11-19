"""
Clean-protocol re-evaluation of Lo et al., "Risk-based OPC UA Network Anomaly
Detection for Interconnected Cyber-Physical Systems" (IEEE SNGC 2026).
Data and notebook from github.com/carolsworld/FactoryIOOPCUA.

This extends opcua_baselines.py (left untouched) and reuses its loaders.

Usage:
  python opcua_clean_protocol.py <opcua_instance1-60_sliced_1min.csv> <3sep_file1.csv> <3sep_file2.csv>
        [--repo <clone of FactoryIOOPCUA>] [--seeds 200] [--out <dir>] [--jobs 2]

Sections
  A. Does a written-value field exist anywhere? (every CSV column, plus the repo's Step 1-4 scripts)
  B. The three protocol issues, with evidence
  C. Clean protocol: LOO over normals, training-only mode size, a-priori or FP-budget contamination;
     200 seeds; exact binomial and bootstrap CIs
  D. Recall by attack path (trusted HMI vs new client UA Expert) for every detector
  E. Oracle-value bound on the 13 value-indistinguishable minutes (HYPOTHETICAL)
  F. 3 Sep 2025 multi-stage run: per-minute and per-stage detection, time to first detection

Outputs (small CSVs) go to --out (default: <script dir>/out).
"""
import argparse
import os
import re
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from joblib import Parallel, delayed
from scipy.stats import beta
from sklearn.ensemble import IsolationForest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from opcua_baselines import FEATS, instance_features, load_frame  # noqa: E402

HMI_IP, UAX_IP = "192.168.1.16", "192.168.1.36"
C_GRID = [0.01, 0.05, 0.1, 0.15, 0.2, 0.25, 0.3, 0.35, 0.4, 0.45, 0.5]
BUDGETS = [0, 1]          # max held-out calibration normals (of 9) allowed to alarm
STAGE_BINS = [0, 4, 7, 20, 105, 110, 999]
STAGE_LABELS = ["S1", "S2", "S3", "S4", "S5", "post"]
STAGE_START = {"S1": 1, "S2": 5, "S3": 8, "S4": 21, "S5": 106, "post": 111}
# Scenario definitions from the notebook (cell 7): commanded conveyor speed
SPEED_RANGE = {"Normal_Speed": "4 to 6", "Speed_TooFast": "8 to 10", "Speed_TooSlow": "0 to 3",
               "WrongDirection": "negative", "Oscillate": "up and down", "VariousThreats": "multi-vector"}


def hr(title):
    print("\n" + "=" * 100)
    print(title)
    print("=" * 100)


def cp(k, n, a=0.05):
    """Exact Clopper-Pearson interval for k successes of n."""
    lo = 0.0 if k == 0 else beta.ppf(a / 2, k, n - k + 1)
    hi = 1.0 if k == n else beta.ppf(1 - a / 2, k + 1, n - k)
    return lo, hi


def f1_from(tp, fp, fn):
    d = 2 * tp + fp + fn
    return 0.0 if d == 0 else 2 * tp / d


# --------------------------------------------------------------------------- instance table
def per_instance(df):
    """Per-minute raw ingredients; features for any mode size are built from these."""
    g = df.groupby("instance")
    sp = df[df["is_sp_write"]]
    out = pd.DataFrame({
        "total_packets": g["msg_size"].count(),
        "clients": g["id.orig_h"].agg(lambda s: frozenset(s)),
    })
    out["sp_sizes"] = sp.groupby("instance")["msg_size"].agg(list).reindex(out.index)
    out["sp_sizes"] = out["sp_sizes"].apply(lambda v: v if isinstance(v, list) else [])
    out["sp_writers"] = sp.groupby("instance")["id.orig_h"].agg(lambda s: frozenset(s)).reindex(out.index)
    out["sp_writers"] = out["sp_writers"].apply(lambda v: v if isinstance(v, frozenset) else frozenset())
    out["write_ops_count"] = out["sp_sizes"].apply(len)
    return out.reset_index()


def mode_size(tab, idx):
    sizes = [s for v in tab.loc[idx, "sp_sizes"] for s in v]
    return None if not sizes else pd.Series(sizes).mode().iloc[0]


def feats(tab, mode):
    """Lo et al.'s three features; mode=None means no reference size, so every setpoint write deviates."""
    an = tab["sp_sizes"].apply(lambda v: sum(1 for s in v if mode is None or s != mode)).astype(float)
    tp = tab["total_packets"].astype(float)
    return np.column_stack([an, an / tp, tab["write_ops_count"] / tp])


def if_scores(Xtr, Xev, seed):
    # contamination only sets offset_ after the trees are grown, so one fit serves every threshold
    m = IsolationForest(n_estimators=100, random_state=seed).fit(Xtr)
    return m.score_samples(Xtr), m.score_samples(Xev)


def offsets(train_scores):
    o = {c: np.percentile(train_scores, 100.0 * c) for c in C_GRID}
    o["auto"] = -0.5
    return o


# --------------------------------------------------------------------------- rules
def rule_preds(tab, train_idx):
    tr = tab.loc[train_idx]
    clients = set().union(*tr["clients"])
    writers = set().union(*tr["sp_writers"])
    max_w = tr["write_ops_count"].max()
    new_client = tab["clients"].apply(lambda c: int(any(x not in clients for x in c))).values
    return {
        "Any setpoint write": (tab["write_ops_count"] >= 1).astype(int).values,
        "New client": new_client,
        "Writes > train max OR new client": ((tab["write_ops_count"] > max_w).values | (new_client == 1)).astype(int),
        "New setpoint writer (post hoc)": tab["sp_writers"].apply(lambda w: int(any(x not in writers for x in w))).values,
    }


# --------------------------------------------------------------------------- clean protocol, one seed
def clean_seed(tab, normals, seed):
    """Outer LOO over normals; inner LOO on the 9 training normals selects contamination by FP budget."""
    n = len(tab)
    res = {k: np.zeros((len(normals), n), dtype=np.int8) for k in ["IF auto", "IF c=0.2 (ref)"] + [f"IF budget {b}/9" for b in BUDGETS]}
    csel = {b: [] for b in BUDGETS}
    for fi, held in enumerate(normals):
        tr = [i for i in normals if i != held]
        m = mode_size(tab, tr)
        X = feats(tab, m)
        trs, evs = if_scores(X[tr], X, seed)
        off = offsets(trs)
        res["IF auto"][fi] = evs < off["auto"]
        res["IF c=0.2 (ref)"][fi] = evs < off[0.2]
        # inner LOO for FP-budget selection, on training normals only
        inner_fp = {c: 0 for c in C_GRID}
        for j in tr:
            tr2 = [i for i in tr if i != j]
            X2 = feats(tab, mode_size(tab, tr2))
            t2, e2 = if_scores(X2[tr2], X2[[j]], seed)
            o2 = offsets(t2)
            for c in C_GRID:
                inner_fp[c] += int(e2[0] < o2[c])
        for b in BUDGETS:
            ok = [c for c in C_GRID if inner_fp[c] <= b]
            c_sel = max(ok) if ok else min(C_GRID)
            csel[b].append(c_sel)
            res[f"IF budget {b}/9"][fi] = evs < off[c_sel]
    return seed, res, csel


def paper_seed(tab60, sep_tab, normals, seed):
    """Their protocol: train on normals 1-10, mode over all 60, c=0.2, score all 60; 3 Sep with its own mode."""
    X = feats(tab60, mode_size(tab60, list(tab60.index)))
    trs, evs = if_scores(X[normals], X, seed)
    p60 = evs < np.percentile(trs, 20.0)
    m = IsolationForest(n_estimators=100, random_state=seed).fit(X[normals])
    Xs = feats(sep_tab, mode_size(sep_tab, list(sep_tab.index)))
    psep = m.score_samples(Xs) < np.percentile(trs, 20.0)
    return p60.astype(np.int8), psep.astype(np.int8)


def clean_sep_seed(tab60, sep_tab, normals, seed):
    """Clean model for 3 Sep: train on all 10 normals, training-only mode; FP-budget chosen by LOO over the 10."""
    m = mode_size(tab60, normals)
    X = feats(tab60, m)
    Xs = feats(sep_tab, m)
    trs, evs = if_scores(X[normals], Xs, seed)
    off = offsets(trs)
    out = {"IF auto": evs < off["auto"], "IF c=0.2 (ref)": evs < off[0.2]}
    inner_fp = {c: 0 for c in C_GRID}
    for j in normals:
        tr2 = [i for i in normals if i != j]
        X2 = feats(tab60, mode_size(tab60, tr2))
        t2, e2 = if_scores(X2[tr2], X2[[j]], seed)
        o2 = offsets(t2)
        for c in C_GRID:
            inner_fp[c] += int(e2[0] < o2[c])
    sel = {}
    for b in [0, 1]:
        ok = [c for c in C_GRID if inner_fp[c] <= b]
        sel[b] = max(ok) if ok else min(C_GRID)
        out[f"IF budget {b}/10"] = evs < off[sel[b]]
    return {k: v.astype(np.int8) for k, v in out.items()}, sel


# --------------------------------------------------------------------------- A
def section_a(paths, frames, repo):
    hr("A. DOES A WRITTEN-VALUE FIELD EXIST?  (every column of every released CSV; the repo's Step 1-4 scripts)")
    for p, df in zip(paths, frames):
        print(f"  {Path(p).name}: {len(df):,} rows, columns = {list(df.columns)}")
    df = frames[0]
    sp = df[df["is_sp_write"]]
    print("\n  Setpoint WriteRequests in the 60-instance file: per column, distinct values (overall / within one client)")
    for c in df.columns:
        if c in ("is_sp_write", "is_output_write"):
            continue
        tot = sp[c].nunique(dropna=False)
        per = sp.groupby("id.orig_h")[c].nunique(dropna=False).to_dict()
        print(f"    {c:<16} {tot:>4}   per client {per}")
    print("\n  msg_size of setpoint writes, by scenario and client (scenarios command different speeds):")
    ct = sp.groupby(["scenario", "id.orig_h"])["msg_size"].agg(lambda s: sorted(set(s))).unstack()
    print("    " + ct.to_string().replace("\n", "\n    "))
    print("    -> one size per client in every scenario (165 HMI, 161 UA Expert) whether the commanded speed is 4-6, 8-10, 0-3")
    print("       or negative, so msg_size reflects the client's encoding, not the value. No column carries the value.")
    if repo and Path(repo, "scripts").is_dir():
        print("\n  Extraction scripts (" + str(Path(repo, "scripts")) + "):")
        for f in sorted(Path(repo, "scripts").rglob("*")):
            if not f.is_file():
                continue
            txt = f.read_text(errors="replace")
            hits = [ln.strip() for ln in txt.splitlines()
                    if re.search(r"value|variant|_write\.log|write_log\)|selected_columns =|icsnpp|zeek -C", ln, re.I)]
            print(f"    {f.relative_to(repo)}")
            for h in hits:
                print(f"       | {h[:150]}")
        print("    -> Step 1 runs Zeek with the full icsnpp/opcua-binary analyzer, which writes several opcua_binary_*.log files.")
        print("       Step 2 joins opcua_binary.log to opcua_binary_write.log keeping only opcua_link_id, node_id_string and")
        print("       req_status_code_link_id; Step 3 then drops req_status_code_link_id. Nothing value-related survives into the")
        print("       released CSVs. Whether the values are in the authors' unreleased Zeek logs depends on the ICSNPP version used;")
        print("       the raw pcaps would settle it.")
    else:
        print("\n  (repo scripts not found; pass --repo to scan them)")


# --------------------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("p60"); ap.add_argument("sep1"); ap.add_argument("sep2")
    ap.add_argument("--repo", default=None)
    ap.add_argument("--seeds", type=int, default=200)
    ap.add_argument("--jobs", type=int, default=2)
    ap.add_argument("--out", default=str(HERE / "out"))
    ap.add_argument("--boot", type=int, default=5000)
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    seeds = list(range(a.seeds))
    rng = np.random.default_rng(20261119)

    raw60 = pd.read_csv(a.p60)
    df = load_frame(raw60)
    sep_raw = pd.concat([pd.read_csv(a.sep1), pd.read_csv(a.sep2)], ignore_index=True)
    sep = load_frame(sep_raw)
    section_a([a.p60, f"{Path(a.sep1).name} + {Path(a.sep2).name}"], [df, sep], a.repo)

    tab = per_instance(df)
    scen = df.groupby("instance")["scenario"].first()
    tab["scenario"] = tab["instance"].map(scen)
    tab["label"] = (tab["instance"] > 10).astype(int)
    tab["path"] = np.where(tab["label"] == 0, "normal",
                           np.where(tab["clients"].apply(lambda c: UAX_IP in c), "UA Expert", "HMI"))
    normals = list(tab.index[tab["label"] == 0])
    attacks = list(tab.index[tab["label"] == 1])
    y = tab["label"].values

    # ------------------------------------------------------------------ B
    hr("B. THE THREE PROTOCOL ISSUES")
    inst_paper, mode_all = instance_features(df)
    mode_train = mode_size(tab, normals)
    print("  (1) Training normals are scored. Instances 1-10 train the model and are 10 of the 60 evaluated.")
    print("      With contamination=c, IsolationForest sets its threshold at the c-quantile of its own training scores,")
    print("      so about c*10 of those same normals are flagged by construction (c=0.2 -> 2 FPs).")
    X_paper = inst_paper[FEATS].values
    fp_by_c = {}
    for c in [0.1, 0.2, 0.3, 0.4]:
        fps = []
        for s in seeds:
            m = IsolationForest(n_estimators=100, contamination=c, random_state=s).fit(X_paper[:10])
            fps.append(int((m.predict(X_paper[:10]) == -1).sum()))
        fp_by_c[c] = pd.Series(fps).value_counts().sort_index().to_dict()
    for c, d in fp_by_c.items():
        print(f"      contamination {c}: FP count on the 10 training normals over {len(seeds)} seeds = {d}")
    print(f"\n  (2) 'Normal' message size is the mode over all 60 runs, attacks included: {mode_all} bytes.")
    sp = df[df["is_sp_write"]]
    by = sp.groupby(["id.orig_h", sp["instance"] <= 10])["msg_size"].agg(["count", lambda s: sorted(set(s))])
    by.columns = ["setpoint_writes", "sizes"]
    by.index = by.index.set_names(["client", "in_training_normals"])
    print("      " + by.to_string().replace("\n", "\n      "))
    print(f"      Mode over training normals only: {mode_train} bytes. The all-runs mode (161) is the UA Expert client's size,")
    print("      a client that appears only in attack runs, so 'size deviation' flags the trusted HMI's writes, including")
    print("      the four in training normals 6, 8, 9, 10. With the training-only mode it flags UA Expert writes instead.")
    sep_tab = per_instance(sep)
    sw = sep[sep["is_sp_write"]].groupby("id.orig_h").size().to_dict()
    print(f"      3 Sep run: setpoint writes per client {sw}; mode computed on that run alone = {mode_size(sep_tab, list(sep_tab.index))}"
          " (a 7-7 tie, broken by pandas' sort order).")
    print("\n  (3) Contamination chosen by F1 on the evaluation set. Notebook cell 41: 'contamination = 0.4 is chosen as it is")
    print("      an optimal value based on F1-score on the evaluation set'; the saved/reported model uses 0.2.")
    for c in [0.05, 0.1, 0.15, 0.2, 0.25, 0.4]:
        m = IsolationForest(n_estimators=100, contamination=c, random_state=42).fit(X_paper[:10])
        p = (m.predict(X_paper) == -1).astype(int)
        tp, fp = int(((p == 1) & (y == 1)).sum()), int(((p == 1) & (y == 0)).sum())
        print(f"      c={c:<5} TP {tp:2d}/50  FP {fp:2d}/10  F1 {f1_from(tp, fp, 50 - tp):.3f}")
    print("      The usable range (F1 > 0) begins at c=0.15; anything below gives recall 0. The choice needs attack labels.")

    # ------------------------------------------------------------------ C
    hr(f"C. CLEAN PROTOCOL  (LOO over 10 normals; mode from training normals only; {len(seeds)} seeds)")
    print("  Each normal is scored only by the model trained on the other 9. Attacks are scored by all 10 fold models")
    print("  (recall = mean over folds). Contamination: 'auto' (sklearn default, fixed a priori), or chosen per fold by")
    print(f"  an FP budget from an inner LOO over that fold's 9 training normals: largest c in {C_GRID}")
    print("  with at most b of 9 inner held-out normals alarmed. c=0.2 is shown for reference only (it was picked on")
    print("  evaluation F1). Rules are rebuilt per fold from the 9 training normals.")
    out = Parallel(n_jobs=a.jobs)(delayed(clean_seed)(tab, normals, s) for s in seeds)
    out.sort(key=lambda t: t[0])
    det_names = list(out[0][1].keys())
    # normals: pred of the fold that held it out; attacks: (seeds, folds, 50)
    norm_pred = {k: np.array([[r[k][fi, normals[fi]] for fi in range(len(normals))] for _, r, _ in out]) for k in det_names}
    att_pred = {k: np.array([r[k][:, attacks] for _, r, _ in out]) for k in det_names}
    csel = {b: pd.Series([c for _, _, cs in out for c in cs[b]]).value_counts().sort_index().to_dict() for b in BUDGETS}
    for b in BUDGETS:
        print(f"  contamination selected under budget {b}/9 (all folds x seeds): {csel[b]}")

    # rules, LOO
    rule_norm, rule_att = {}, {}
    for fi, held in enumerate(normals):
        tr = [i for i in normals if i != held]
        rp = rule_preds(tab, tr)
        for k, v in rp.items():
            rule_norm.setdefault(k, np.zeros(len(normals), int))[fi] = v[held]
            rule_att.setdefault(k, np.zeros((len(normals), len(attacks)), int))[fi] = v[attacks]

    # paper protocol over seeds (for the comparison row) and on 3 Sep
    pap = Parallel(n_jobs=a.jobs)(delayed(paper_seed)(tab, sep_tab, normals, s) for s in seeds)
    pap60 = np.array([p for p, _ in pap])
    papsep = np.array([q for _, q in pap])

    rows, inst_rows, seed_rows = [], [], []

    def summarise(name, nflag, aflag, seedwise=None):
        """nflag: per-normal flag prob (10,), aflag: per-attack flag prob (50,)"""
        fp_e, tp_e = nflag.sum(), aflag.sum()
        fp_k, tp_k = int(round(fp_e)), int(round(tp_e))
        fp_lo, fp_hi = cp(fp_k, len(normals))
        r_lo, r_hi = cp(tp_k, len(attacks))
        boots = []
        for _ in range(a.boot):
            ni = rng.integers(0, len(normals), len(normals))
            ai = rng.integers(0, len(attacks), len(attacks))
            tp, fp = aflag[ai].sum(), nflag[ni].sum()
            boots.append(f1_from(tp, fp, len(attacks) - tp))
        f1 = f1_from(tp_e, fp_e, len(attacks) - tp_e)
        b_lo, b_hi = np.percentile(boots, [2.5, 97.5])
        row = dict(detector=name, FP=fp_e, FPR=fp_e / len(normals), FPR_lo=fp_lo, FPR_hi=fp_hi,
                   TP=tp_e, recall=tp_e / len(attacks), recall_lo=r_lo, recall_hi=r_hi,
                   precision=tp_e / max(tp_e + fp_e, 1e-9), F1=f1, F1_lo=b_lo, F1_hi=b_hi)
        hmi = tab.loc[attacks, "path"].values == "HMI"
        for pth, msk in [("HMI", hmi), ("UAX", ~hmi)]:
            k = int(round(aflag[msk].sum()))
            lo, hi = cp(k, int(msk.sum()))
            row[f"recall_{pth}"] = aflag[msk].mean()
            row[f"recall_{pth}_lo"], row[f"recall_{pth}_hi"] = lo, hi
        if seedwise is not None:
            row.update(seedwise)
        rows.append(row)
        for idx, p in zip(normals, nflag):
            inst_rows.append(dict(detector=name, instance=int(tab.loc[idx, "instance"]), flag_rate=float(p)))
        for idx, p in zip(attacks, aflag):
            inst_rows.append(dict(detector=name, instance=int(tab.loc[idx, "instance"]), flag_rate=float(p)))

    def seed_stats(fp_s, rec_s):
        f1_s = np.array([f1_from(r * 50, f, 50 - r * 50) for f, r in zip(fp_s, rec_s)])
        return dict(seed_FP_med=np.median(fp_s), seed_FP_min=fp_s.min(), seed_FP_max=fp_s.max(),
                    seed_rec_med=np.median(rec_s), seed_rec_p2=np.percentile(rec_s, 2.5), seed_rec_p97=np.percentile(rec_s, 97.5),
                    seed_F1_med=np.median(f1_s), seed_F1_p2=np.percentile(f1_s, 2.5), seed_F1_p97=np.percentile(f1_s, 97.5),
                    seed_F1_min=f1_s.min(), seed_F1_max=f1_s.max())

    # paper protocol row
    fp_s = pap60[:, normals].sum(1).astype(float)
    rec_s = pap60[:, attacks].mean(1)
    summarise("Paper protocol: IF c=0.2 (train=test normals, all-runs mode)", pap60[:, normals].mean(0),
              pap60[:, attacks].mean(0), seed_stats(fp_s, rec_s))
    for s, f, r in zip(seeds, fp_s, rec_s):
        seed_rows.append(dict(detector="paper", seed=s, FP=f, recall=r))
    for k in det_names:
        fp_s = norm_pred[k].sum(1).astype(float)
        rec_s = att_pred[k].mean((1, 2))
        summarise(f"Clean: {k}", norm_pred[k].mean(0), att_pred[k].mean((0, 1)), seed_stats(fp_s, rec_s))
        for s, f, r in zip(seeds, fp_s, rec_s):
            seed_rows.append(dict(detector=k, seed=s, FP=f, recall=r))
    for k in rule_norm:
        summarise(f"Clean: {k}", rule_norm[k].astype(float), rule_att[k].mean(0))

    summ = pd.DataFrame(rows)
    summ.to_csv(Path(a.out, "clean_protocol_summary.csv"), index=False, float_format="%.4f")
    pd.DataFrame(inst_rows).to_csv(Path(a.out, "per_instance_flag_rates.csv"), index=False, float_format="%.4f")
    pd.DataFrame(seed_rows).to_csv(Path(a.out, "seed_distribution.csv"), index=False, float_format="%.4f")

    print("\n  Seed-averaged expected counts; 95% CIs: exact Clopper-Pearson for FPR (n=10) and recall (n=50) at the rounded")
    print("  count; stratified instance bootstrap (5000) for F1. With 10 normals an FPR CI is necessarily wide")
    print("  (0/10 -> [0.00, 0.31]; 2/10 -> [0.03, 0.56]).\n")
    print(f"  {'detector':<64} {'FP/10':>6} {'FPR 95% CI':>14} {'recall':>7} {'recall 95% CI':>14} {'prec':>6} {'F1':>6} {'F1 95% CI':>14}")
    for r in rows:
        print(f"  {r['detector']:<64} {r['FP']:6.2f} [{r['FPR_lo']:.2f}, {r['FPR_hi']:.2f}] {r['recall']:7.3f} "
              f"[{r['recall_lo']:.2f}, {r['recall_hi']:.2f}] {r['precision']:6.3f} {r['F1']:6.3f} [{r['F1_lo']:.2f}, {r['F1_hi']:.2f}]")
    print("\n  Distribution over seeds (IF only): FP count median [min, max]; recall median [2.5%, 97.5%]; F1 median [2.5%, 97.5%] (min-max)")
    for r in rows:
        if "seed_FP_med" in r and not pd.isna(r.get("seed_FP_med")):
            print(f"  {r['detector']:<64} FP {r['seed_FP_med']:.0f} [{r['seed_FP_min']:.0f}, {r['seed_FP_max']:.0f}]   "
                  f"recall {r['seed_rec_med']:.3f} [{r['seed_rec_p2']:.3f}, {r['seed_rec_p97']:.3f}]   "
                  f"F1 {r['seed_F1_med']:.3f} [{r['seed_F1_p2']:.3f}, {r['seed_F1_p97']:.3f}] ({r['seed_F1_min']:.3f}-{r['seed_F1_max']:.3f})")

    # ------------------------------------------------------------------ D
    hr("D. RECALL BY ATTACK PATH  (HMI = trusted client, n=20; UA Expert = new client, n=30; 95% Clopper-Pearson)")
    print(f"  {'detector':<64} {'HMI':>6} {'95% CI':>14} {'UA Expert':>10} {'95% CI':>14}")
    for r in rows:
        print(f"  {r['detector']:<64} {r['recall_HMI']:6.3f} [{r['recall_HMI_lo']:.2f}, {r['recall_HMI_hi']:.2f}] "
              f"{r['recall_UAX']:10.3f} [{r['recall_UAX_lo']:.2f}, {r['recall_UAX_hi']:.2f}]")
    pir = pd.DataFrame(inst_rows).pivot(index="instance", columns="detector", values="flag_rate")
    by_scen = pir.join(tab.set_index("instance")[["scenario", "path"]]).query("path != 'normal'").groupby(["scenario", "path"]).mean()
    print("\n  Recall by scenario x path (mean flag rate):")
    short = {"Paper protocol: IF c=0.2 (train=test normals, all-runs mode)": "paper IF", "Clean: IF auto": "IF auto",
             "Clean: IF budget 1/9": "IF budget 1/9", "Clean: Any setpoint write": "any write",
             "Clean: New client": "new client", "Clean: Writes > train max OR new client": ">max writes|new"}
    print("    " + by_scen[list(short)].rename(columns=short).round(2).to_string().replace("\n", "\n    "))

    # ------------------------------------------------------------------ E
    hr("E. ORACLE-VALUE BOUND  (HYPOTHETICAL: written values are NOT in the released data)")
    twin_mask = (tab["write_ops_count"] == 1) & (tab["clients"].apply(lambda c: UAX_IP not in c))
    twin = tab[twin_mask]
    print(f"  {len(twin)} minutes have exactly one setpoint write, from the trusted HMI, and no new client:")
    print("    normals  " + str(twin.query("label == 0")["instance"].tolist()))
    print("    attacks  " + str(twin.query("label == 1")[["instance", "scenario"]].values.tolist()))
    print("  Without the value these 13 are the same event (one HMI write of iSpeedSetPoint). Scenario definitions")
    print("  (notebook cell 7): normal 4-6, too fast 8-10, too slow 0-3, wrong direction negative. A range check")
    print("  'commanded speed outside [4, 6]' would, IF each run's single write carried a value inside its scenario's")
    print("  stated range, separate them exactly:")
    tw_n = twin.query("label == 0")["instance"].tolist()
    tw_a = twin.query("label == 1")["instance"].tolist()
    print(f"    {'detector':<64} {'TP/9':>5} {'FP/4':>5}")
    for name in ["Paper protocol: IF c=0.2 (train=test normals, all-runs mode)", "Clean: IF auto", "Clean: IF budget 1/9",
                 "Clean: Any setpoint write", "Clean: New client", "Clean: Writes > train max OR new client"]:
        tp = pir.loc[tw_a, name].sum()
        fp = pir.loc[tw_n, name].sum()
        print(f"    {name:<64} {tp:5.2f} {fp:5.2f}")
    print(f"    {'Hypothetical range check, commanded speed outside [4, 6]':<64} {len(tw_a):5d} {0:5d}")
    cw = {"Speed_TooFast": "overspeed (+2 to +4 above band)", "Speed_TooSlow": "underspeed (1 to 4 below band)",
          "WrongDirection": "reversal (sign change)"}
    print("  A consequence-weighted version would also rank them: " +
          "; ".join(f"{k}: {v}" for k, v in cw.items()) + ".")
    print("  Caveats: the bound assumes the scenario label describes the value actually written; 'approximately 4 to 6'")
    print("  leaves the band edges uncertain; Oscillate/VariousThreats are not in this group. Only the pcaps can test it.")

    # ------------------------------------------------------------------ F
    hr("F. 3 SEP 2025 MULTI-STAGE RUN  (per minute; positives = Step 3 inst 8-20 and Step 5 inst 106-110, their table)")
    sep_tab["stage"] = pd.cut(sep_tab["instance"], STAGE_BINS, labels=STAGE_LABELS).astype(str)
    sep_tab["label"] = sep_tab["stage"].isin(["S3", "S5"]).astype(int)
    ys = sep_tab["label"].values
    cs = Parallel(n_jobs=a.jobs)(delayed(clean_sep_seed)(tab, sep_tab, normals, s) for s in seeds)
    sep_preds = {"Paper IF c=0.2 (saved-model protocol)": papsep}
    for k in cs[0][0]:
        sep_preds[f"Clean {k}"] = np.array([c[0][k] for c in cs])
    sel_sep = {b: pd.Series([c[1][b] for c in cs]).value_counts().sort_index().to_dict() for b in [0, 1]}
    print(f"  clean model: mode from training normals = {mode_train}; contamination chosen by LOO FP budget on the 10 normals: "
          f"budget 0 -> {sel_sep[0]}, budget 1 -> {sel_sep[1]}")
    rp = rule_preds(pd.concat([tab, sep_tab], ignore_index=True), normals)
    for k, v in rp.items():
        sep_preds[k] = np.tile(v[len(tab):], (len(seeds), 1))
    per_min = sep_tab[["instance", "stage", "label", "write_ops_count", "total_packets"]].copy()
    per_min["sp_writers"] = sep_tab["sp_writers"].apply(lambda w: ";".join(sorted(w)))
    per_min["clients"] = sep_tab["clients"].apply(lambda w: ";".join(sorted(w)))
    i42 = seeds.index(42) if 42 in seeds else 0
    print(f"\n  Per-minute scores (IF: seed {seeds[i42]} and flag rate over {len(seeds)} seeds):")
    print(f"  {'detector':<44} {'TP':>3} {'FP':>4} {'FN':>3} {'TN':>4} {'prec':>6} {'rec':>6} {'F1':>6}   {'F1 over seeds med [min,max]':>28}")
    srows = []
    first_write = sep_tab[sep_tab["write_ops_count"] > 0].groupby("stage")["instance"].min().to_dict()
    for k, P in sep_preds.items():
        per_min[k + " (seed42)"] = P[i42]
        per_min[k + " (rate)"] = P.mean(0)
        p = P[i42]
        tp, fp = int(((p == 1) & (ys == 1)).sum()), int(((p == 1) & (ys == 0)).sum())
        fn, tn = int(((p == 0) & (ys == 1)).sum()), int(((p == 0) & (ys == 0)).sum())
        f1s = [f1_from(((q == 1) & (ys == 1)).sum(), ((q == 1) & (ys == 0)).sum(), ((q == 0) & (ys == 1)).sum()) for q in P]
        print(f"  {k:<44} {tp:3d} {fp:4d} {fn:3d} {tn:4d} {tp / max(tp + fp, 1):6.3f} {tp / max(tp + fn, 1):6.3f} "
              f"{f1_from(tp, fp, fn):6.3f}   {np.median(f1s):.3f} [{min(f1s):.3f}, {max(f1s):.3f}]")
        for st in STAGE_LABELS:
            g = sep_tab["stage"].values == st
            first = [int(sep_tab["instance"].values[g][q[g] == 1].min()) if q[g].any() else None for q in P]
            fl = [int(q[g].sum()) for q in P]
            f42 = first[i42]
            srows.append(dict(detector=k, stage=st, minutes=int(g.sum()), flagged_seed42=fl[i42],
                              flagged_mean=float(np.mean(fl)), first_flag_seed42=f42,
                              ttd_min_seed42=(None if f42 is None else f42 - STAGE_START[st]),
                              first_write_in_stage=first_write.get(st),
                              ttd_from_first_write_seed42=(None if f42 is None or st not in first_write
                                                           else f42 - first_write[st]),
                              share_seeds_detecting=float(np.mean([f is not None for f in first]))))
    per_min.to_csv(Path(a.out, "sep3_per_minute.csv"), index=False, float_format="%.3f")
    st_df = pd.DataFrame(srows)
    st_df.to_csv(Path(a.out, "sep3_per_stage.csv"), index=False, float_format="%.3f")
    print(f"\n  Per stage (seed {seeds[i42]}): flagged minutes / stage minutes, and time to first detection in minutes from stage start")
    print("  (minute granularity; S1, S2, S4 and post contain no OPC UA manipulation per their table, so any flag there is a false alarm).")
    print(f"  First minute with a setpoint write, by stage: {first_write}. Stage start is when the attacker began the step;")
    print("  the write comes later (S3: RDP session to the HMI first), so '@+k' includes attacker dwell before the write.")
    piv = st_df.assign(cell=lambda d: d.apply(
        lambda r: f"{r.flagged_seed42}/{r.minutes}" + ("" if pd.isna(r.ttd_min_seed42) else f" @+{int(r.ttd_min_seed42)}"), axis=1))
    print("    " + piv.pivot(index="detector", columns="stage", values="cell")[STAGE_LABELS].to_string().replace("\n", "\n    "))
    w = sep[sep["is_sp_write"]][["ts", "instance", "id.orig_h", "id.orig_p", "msg_size"]].copy()
    w["stage"] = pd.cut(w["instance"], STAGE_BINS, labels=STAGE_LABELS)
    print("\n  Every setpoint write in the run:")
    print("    " + w.to_string(index=False).replace("\n", "\n    "))
    print(f"\n  Note: {UAX_IP} (the UA Expert workstation) is connected in all {sep_tab['clients'].apply(lambda c: UAX_IP in c).sum()}"
          f" of {len(sep_tab)} minutes (reads/publish), so 'new client' fires on every minute here.")
    print("  Instance 21 (13:40, first minute of S4) holds two HMI writes, 21 s after the stated end of Step 3; their table")
    print("  makes it a false positive for every write-based detector. Re-labelling it S3 is a judgement call; numbers above")
    print("  keep their labels.")


if __name__ == "__main__":
    main()
