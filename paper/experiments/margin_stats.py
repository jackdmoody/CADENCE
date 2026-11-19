"""
Corroboration separation margins across synthetic seeds.

For each run directory (one per H2 variant), reads every seed's Stage-9 table and
reports: the lowest corroboration score among malicious pairs, the highest among
non-malicious pairs (decoys and background that reached Stage 9), lead-stage
precision and recall, and the margin between the two.

Usage:
    python paper/experiments/margin_stats.py paper/data/synthetic_margins.json \
        host_wide=/path/to/synth_fixed linked5=/path/to/synth_link5
"""
import glob
import json
import sys

import numpy as np
import pandas as pd

out = sys.argv[1]
res = {}
for spec in sys.argv[2:]:
    name, root = spec.split("=", 1)
    rows = []
    for seed_dir in sorted(glob.glob(f"{root}/seed_*")):
        c = pd.read_csv(f"{seed_dir}/run/stages/corroboration.csv", dtype={"src_ip": str, "dst_ip": str})
        gt = pd.read_csv(f"{seed_dir}/gt.csv", dtype={"src_ip": str, "dst_ip": str})
        pos = set(zip(gt["src_ip"], gt["dst_ip"]))
        mal = c[[p in pos for p in zip(c["src_ip"], c["dst_ip"])]]
        ben = c[[p not in pos for p in zip(c["src_ip"], c["dst_ip"])]]
        leads = c[c["corroborated"].astype(bool)]
        tp = sum(p in pos for p in zip(leads["src_ip"], leads["dst_ip"]))
        rows.append({
            "seed": seed_dir.rsplit("_", 1)[-1],
            "mal_min": float(mal["corroboration_score"].min()) if len(mal) else np.nan,
            "ben_max": float(ben["corroboration_score"].max()) if len(ben) else np.nan,
            "precision": tp / len(leads) if len(leads) else 0.0,
            "recall": tp / len(pos) if pos else 0.0,
            "h2_rate": float(c["h2_dns_anomaly"].astype(bool).mean()),
        })
    d = pd.DataFrame(rows)
    res[name] = {
        "seeds": len(d),
        "mal_min": float(d["mal_min"].min()), "ben_max": float(d["ben_max"].max()),
        "margin_worst": float((d["mal_min"] - d["ben_max"]).min()),
        "precision_mean": float(d["precision"].mean()), "precision_sd": float(d["precision"].std(ddof=1)),
        "recall_mean": float(d["recall"].mean()), "recall_sd": float(d["recall"].std(ddof=1)),
        "h2_rate": float(d["h2_rate"].mean()),
    }
json.dump(res, open(out, "w"), indent=1)
print(json.dumps(res, indent=1))
