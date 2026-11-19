"""
Count how often H2 (DNS anomaly) fires among pairs scored at Stage 9, across
synthetic runs. Usage: python paper/experiments/h2_stats.py <synthetic_eval --out dir> paper/data/synthetic_h2.json
"""
import glob
import json
import sys

import pandas as pd

runs, out = sys.argv[1], sys.argv[2]
rows = []
for f in sorted(glob.glob(f"{runs}/seed_*/run/stages/corroboration.csv")):
    c = pd.read_csv(f)
    for _, r in c.iterrows():
        rows.append({"seed": f.split("/")[-4], "pair": r["pair_id"], "h2": bool(r["h2_dns_anomaly"]),
                     "h1": bool(r["h1_dns_regularity"]), "S": float(r["corroboration_score"]),
                     "lead": bool(r["corroborated"])})
d = pd.DataFrame(rows)
res = {"pairs_scored": int(len(d)), "h2_true": int(d["h2"].sum()),
       "non_lead_scores": sorted(set(round(x, 4) for x in d.loc[~d["lead"], "S"]))}
json.dump(res, open(out, "w"), indent=1)
print(res)
