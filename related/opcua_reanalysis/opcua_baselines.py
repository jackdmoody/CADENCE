"""
Re-analysis of Lo et al., "Risk-based OPC UA Network Anomaly Detection for
Interconnected Cyber-Physical Systems" (IEEE SNGC 2026).
Data and notebook from github.com/carolsworld/FactoryIOOPCUA.

Usage:
  python opcua_baselines.py <opcua_instance1-60_sliced_1min.csv> <3sep_file1.csv> <3sep_file2.csv>

Sections
  1. Reproduce their instance features and Isolation Forest (seed 42, contamination sweep)
  2. Trivial baselines on the same 60 instances and the same protocol
  3. What the msg-size feature actually encodes
  4. Instances that are indistinguishable without written values
  5. Seed sensitivity of the reported configuration
  6. The 3 Sep 2025 multi-stage run, scored per minute against their own stage table
"""
import sys
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score, confusion_matrix

SETPOINT = "iSpeedSetPoint"
WRITE_REQ = 673            # OPC UA WriteRequest binary encoding id
FEATS = ["write_anomaly_count", "write_anomaly_ratio", "write_ops_ratio"]   # their final feature set


def load(path):
    df = pd.read_csv(path)
    df = df[df["identifier"] != "-"].copy()
    df["identifier"] = pd.to_numeric(df["identifier"], errors="coerce")
    df = df.dropna(subset=["identifier"])
    df["identifier"] = df["identifier"].astype(int)
    df["msg_size"] = pd.to_numeric(df["msg_size"], errors="coerce")
    df["is_sp_write"] = ((df["identifier"] == WRITE_REQ)
                         & df["node_id_string"].str.contains(SETPOINT, case=False, na=False))
    df["is_output_write"] = ((df["identifier"] == WRITE_REQ)
                             & df["node_id_string"].str.contains(r"\.o[A-Z]", na=False))
    return df


def instance_features(df):
    """Exactly their Step 2 aggregation (mode size computed over the whole file, as they do)."""
    mode_size = df.loc[df["is_sp_write"], "msg_size"].mode().iloc[0]
    df = df.assign(write_msg_anomaly=(df["is_sp_write"] & (df["msg_size"] != mode_size)).astype(int),
                   is_WriteOps=df["is_sp_write"].astype(int))
    g = df.groupby("instance")
    out = pd.DataFrame({
        "write_anomaly_count": g["write_msg_anomaly"].sum(),
        "write_anomaly_ratio": g["write_msg_anomaly"].mean(),
        "write_ops_count": g["is_WriteOps"].sum(),
        "write_ops_ratio": g["is_WriteOps"].mean(),
        "total_packets": g["msg_size"].count(),
        "output_writes": g["is_output_write"].sum(),
        "clients": g["id.orig_h"].agg(lambda s: tuple(sorted(set(s)))),
    }).reset_index()
    return out, mode_size


def scores(y, p):
    return dict(acc=accuracy_score(y, p), prec=precision_score(y, p, zero_division=0),
                rec=recall_score(y, p, zero_division=0), f1=f1_score(y, p, zero_division=0),
                cm=confusion_matrix(y, p, labels=[0, 1]).ravel().tolist())   # tn, fp, fn, tp


def fmt(name, s):
    tn, fp, fn, tp = s["cm"]
    return (f"  {name:<44} acc {s['acc']:.3f}  F1 {s['f1']:.3f}  "
            f"prec {s['prec']:.3f}  rec {s['rec']:.3f}  (TP {tp} FP {fp} FN {fn} TN {tn})")


def main(p60, p_sep1, p_sep2):
    df = load(p60)
    inst, mode_size = instance_features(df)
    scen = df.groupby("instance")["scenario"].first()
    inst["scenario"] = inst["instance"].map(scen)
    inst["label"] = (inst["instance"] > 10).astype(int)
    y = inst["label"].values
    train = inst[inst["instance"] <= 10]

    # ------------------------------------------------------------------ 1
    print("=" * 100)
    print("1. REPRODUCTION  (train on normal instances 1-10, evaluate on all 60 incl. those 10)")
    print("=" * 100)
    for c in [0.05, 0.1, 0.15, 0.2, 0.25, 0.3, 0.35, 0.4, 0.45, 0.5]:
        m = IsolationForest(n_estimators=100, contamination=c, random_state=42).fit(train[FEATS])
        pred = (m.predict(inst[FEATS]) == -1).astype(int)
        print(fmt(f"IsolationForest contamination={c}", scores(y, pred)))
    iso = IsolationForest(n_estimators=100, contamination=0.2, random_state=42).fit(train[FEATS])
    inst["iso_pred"] = (iso.predict(inst[FEATS]) == -1).astype(int)
    inst["iso_score"] = iso.decision_function(inst[FEATS])

    # ------------------------------------------------------------------ 2
    print("\n" + "=" * 100)
    print("2. TRIVIAL BASELINES  (same 60 instances, no training)")
    print("=" * 100)
    normal_clients = set(c for cl in train["clients"] for c in cl)
    inst["new_client"] = inst["clients"].apply(lambda cl: int(any(c not in normal_clients for c in cl)))
    rules = {
        "Paper: IsolationForest c=0.2 seed 42": inst["iso_pred"],
        "Always alarm": np.ones(len(inst), int),
        "Any write to iSpeedSetPoint in the minute": (inst["write_ops_count"] >= 1).astype(int),
        "Client never seen in normal runs": inst["new_client"],
        "Any write to an output tag (o*)": (inst["output_writes"] >= 1).astype(int),
        ">=2 setpoint writes OR new client": ((inst["write_ops_count"] >= 2) | (inst["new_client"] == 1)).astype(int),
    }
    for k, p in rules.items():
        print(fmt(k, scores(y, np.asarray(p))))

    # ------------------------------------------------------------------ 3
    print("\n" + "=" * 100)
    print("3. WHAT 'MESSAGE SIZE DEVIATION' ENCODES")
    print("=" * 100)
    sp = df[df["is_sp_write"]]
    print(sp.groupby(["id.orig_h", "msg_size"]).size().rename("setpoint_writes").to_string())
    print(f"  mode size used as 'normal' = {mode_size} bytes")
    by_host = sp.groupby("id.orig_h")["instance"].apply(lambda s: sorted(set(s)))
    for h, ii in by_host.items():
        print(f"  {h} writes setpoint in instances: normal={[i for i in ii if i <= 10]} attack_count={sum(i > 10 for i in ii)}")

    # ------------------------------------------------------------------ 4
    print("\n" + "=" * 100)
    print("4. INDISTINGUISHABLE WITHOUT WRITTEN VALUES  (exactly one HMI setpoint write, no new client)")
    print("=" * 100)
    twin = inst[(inst["write_ops_count"] == 1) & (inst["new_client"] == 0)]
    print(twin[["instance", "scenario", "label", "write_ops_count", "write_anomaly_count",
                "total_packets", "write_ops_ratio", "iso_score", "iso_pred"]].to_string(index=False))
    t = twin.sort_values("total_packets")
    print("  -> iso_pred within this group is decided by total_packets (the ratio denominator), "
          "not by anything about the write.")

    # per-scenario and per-attack-path recall
    att = inst[inst["label"] == 1].copy()
    att["path"] = np.where(att["new_client"] == 1, "UA Expert (new client)", "HMI (trusted client)")
    print("\n  Recall by attack path (paper's IF c=0.2 / any-setpoint-write rule):")
    for path, g in att.groupby("path"):
        print(f"    {path:<26} n={len(g):2d}  IF recall {g['iso_pred'].mean():.2f}   "
              f"any-write recall {(g['write_ops_count'] >= 1).mean():.2f}")
    print("  Recall by scenario (paper's IF):")
    print(att.groupby("scenario")["iso_pred"].mean().round(2).to_string())

    # ------------------------------------------------------------------ 5
    print("\n" + "=" * 100)
    print("5. SEED SENSITIVITY  (c=0.2, seeds 0-199; FP count on the 10 normals)")
    print("=" * 100)
    rows = []
    for s in range(200):
        m = IsolationForest(n_estimators=100, contamination=0.2, random_state=s).fit(train[FEATS])
        p = (m.predict(inst[FEATS]) == -1).astype(int)
        r = scores(y, p)
        rows.append((s, r["acc"], r["f1"], r["cm"][1], r["cm"][3]))
    sd = pd.DataFrame(rows, columns=["seed", "acc", "f1", "fp", "tp"])
    print(f"  acc  min {sd.acc.min():.3f}  median {sd.acc.median():.3f}  max {sd.acc.max():.3f}")
    print(f"  F1   min {sd.f1.min():.3f}  median {sd.f1.median():.3f}  max {sd.f1.max():.3f}")
    print(f"  share of seeds matching the reported 0.933/0.96: {((sd.acc.round(3) == 0.933) & (sd.f1.round(2) == 0.96)).mean():.2f}")
    print("  FP count distribution:", sd.fp.value_counts().sort_index().to_dict())
    print("  TP count distribution:", sd.tp.value_counts().sort_index().to_dict())
    print("  note: contamination=0.2 on 10 training points sets the FP budget to ~2 of the 10 normals by construction,")
    print("        and those same 10 normals are part of the evaluation set.")

    # ------------------------------------------------------------------ 6
    print("\n" + "=" * 100)
    print("6. 3 SEP 2025 MULTI-STAGE RUN  (per minute; positives = their Step 3 inst 8-20 and Step 5 inst 106-110)")
    print("=" * 100)
    sep = pd.concat([pd.read_csv(p_sep1), pd.read_csv(p_sep2)], ignore_index=True)
    sep = load_frame(sep)
    sinst, smode = instance_features(sep)
    sinst["iso_pred"] = (iso.predict(sinst[FEATS]) == -1).astype(int)
    stage = pd.cut(sinst["instance"], [0, 4, 7, 20, 105, 110, 999], labels=["S1", "S2", "S3", "S4", "S5", "post"])
    sinst["stage"] = stage
    sinst["label"] = sinst["stage"].isin(["S3", "S5"]).astype(int)
    sinst["any_write"] = (sinst["write_ops_count"] >= 1).astype(int)
    print(f"  clients seen: {sorted(set(sep['id.orig_h']))}   mode setpoint size this run: {smode}")
    sw = sep[sep["is_sp_write"]].groupby(["instance", "id.orig_h", "msg_size"]).size().rename("n").reset_index()
    sw["stage"] = pd.cut(sw["instance"], [0, 4, 7, 20, 105, 110, 999], labels=["S1", "S2", "S3", "S4", "S5", "post"])
    print("  setpoint writes by minute:")
    print(sw.to_string(index=False))
    ys = sinst["label"].values
    print(fmt("Paper IF (their saved c=0.2 model)", scores(ys, sinst["iso_pred"].values)))
    print(fmt("Any write to iSpeedSetPoint in the minute", scores(ys, sinst["any_write"].values)))
    for st in ["S3", "S5"]:
        g = sinst[sinst["stage"] == st]
        print(f"  {st}: minutes={len(g)}  with any setpoint write={g['any_write'].sum()}  IF flagged={g['iso_pred'].sum()}")
    fl = sinst[sinst["iso_pred"] == 1][["instance", "stage", "write_ops_count", "write_anomaly_count"]]
    print("  IF-flagged minutes:")
    print(fl.to_string(index=False))


def load_frame(df):
    df = df[df["identifier"] != "-"].copy()
    df["identifier"] = pd.to_numeric(df["identifier"], errors="coerce")
    df = df.dropna(subset=["identifier"])
    df["identifier"] = df["identifier"].astype(int)
    df["msg_size"] = pd.to_numeric(df["msg_size"], errors="coerce")
    df["is_sp_write"] = ((df["identifier"] == WRITE_REQ)
                         & df["node_id_string"].str.contains(SETPOINT, case=False, na=False))
    df["is_output_write"] = ((df["identifier"] == WRITE_REQ)
                             & df["node_id_string"].str.contains(r"\.o[A-Z]", na=False))
    return df


if __name__ == "__main__":
    main(*sys.argv[1:4])
