# Real-data evaluation day: results (19 Nov 2026)

> **BLOCKED: no real-data CADENCE numbers today.** This run's sandbox network policy refuses the dataset hosts. At 08:11 EST (13:11 UTC), `curl -sI --max-time 20` against `https://mcfp.felk.cvut.cz/publicDatasets/`, `https://www.activecountermeasures.com/` and `https://download.opensuse.org/repositories/security:/zeek/xUbuntu_24.04/` each returned `403 Forbidden (agent proxy: no rule or network setting allows this host)`; over plain HTTP they don't resolve. The environment's network access was not opened for these hosts. So Zeek could not be installed, and CTU-13 (§3), Active Countermeasures (§4) and IoT-23 (§5) did not run. As the brief and the scheduled task say, I did only the GitHub-reachable work (the OPC UA re-analysis) and stopped. To unblock, allow `mcfp.felk.cvut.cz`, `www.activecountermeasures.com` (plus whatever host its download links point to) and `download.opensuse.org` in the environment's network settings, then re-run the task. The commands are below.

## What ran and what did not

| Brief section | Status | Notes |
|---|---|---|
| 0. Setup | Partly done | Python deps installed; `python -m pytest analytic_pipeline -q` gives **65 passed**, including `test_priority_score_monotone_with_beacon_confidence`, which is fixed on this branch. Zeek **not installed**: download.opensuse.org is blocked. JA3 skipped. |
| 1. OPC UA re-analysis | **Done** | See `related/opcua_reanalysis/FINDINGS.md`. The original script reproduces `results_reproduction.txt` line for line. |
| 2. Synthetic baseline | Skipped on purpose | The brief (as edited at 07:59 today) says the main session handles it and not to duplicate. See "Decisions" below. |
| 3. CTU-13 | Not run | Blocked: mcfp.felk.cvut.cz. |
| 4. Active Countermeasures | Not run | Blocked: activecountermeasures.com. |
| 5. IoT-23 | Not run | Blocked: the IoT-23 logs are also on mcfp.felk.cvut.cz. |
| 6. Wrap-up | Done | This file. |

No `results/real_data/<dataset>/` directories were created, because there is nothing to put in them. `paper/generated/real_table.tex` still reads "Real-data runs pending". I did not touch anything under `paper/`.

## Per-dataset tables (CTU-13, ACM, IoT-23)

None of these ran, so there are no numbers: no conn-only or full runs, no beacon or corroborated stage scores (strict or lenient), no AP, and no C2-pairs-by-stage miss attribution. Nothing here should be read as a result.

## Non-default settings

None. No CADENCE run happened, so no `--internal-cidr`, `--min-period-s`, `--max-pairs` or other flag was set, and nothing was tuned.

## Bugs fixed

None. `zeek_adapter.py`, `ground_truth.py` and `run_real_data.py` never met a real-format input today, so there was nothing to break or fix. No detection logic was changed. `analytic_pipeline/` is untouched.

## OPC UA re-analysis: headline (details in `related/opcua_reanalysis/FINDINGS.md`)

| Detector | Published protocol, 60 instances: FP/10, recall, F1 | Clean protocol: FP/10, recall, F1 [95% CI] | 3 Sep run, per minute: TP/FP, F1 |
|---|---|---|---|
| Isolation Forest c=0.2 (published, seed 42) | 2, 0.96, **0.960** | reference only: 0.6, 0.89, 0.934 | 5/1, **0.417** |
| IF contamination `auto` (a priori) | – | 4.8, 0.98, 0.946 [0.92, 0.97] | 6/1, 0.480 |
| IF, contamination by FP budget ≤1/9 on held-out normals | – | 0.0, 0.66, 0.796 [0.77, 0.81] | 6/1, 0.480 |
| Any setpoint write in the minute | 4, 1.00, 0.962 | same | 6/1, 0.480 |
| New client | 0, 0.60, 0.750 | same | 18/93, 0.279 |
| ≥2 writes OR new client | 0, 0.82, 0.901 | same | 18/93, 0.279 |

Key points:

1. **No written-value field exists in the released CSVs.** Step 2 of their extraction keeps only `opcua_link_id`, `node_id_string` and `req_status_code_link_id` from the write log, and `msg_size` is fixed per client.
2. **The three protocol issues are confirmed with evidence.** With a clean protocol (LOO over normals, training-only mode size, FP-budget contamination), Isolation Forest recall drops to 0.32–0.66 at 0/10 false positives. Otherwise it collapses to the any-write rule (FP 4–10 of 10).
3. **With 10 normals every FPR interval is wide.** For example, 0/10 gives [0, 0.31].
4. **The trusted-HMI path (20 runs) is where client-identity rules fail.** New-client recall there is 0/20.
5. **On the 3 Sep run any detector that needs a setpoint write is capped at per-minute recall 6/18.** Only 6 of the 18 attack minutes contain one. Our own "new client" and "≥2 writes OR new client" rules fire on all 111 minutes, because the UA Expert workstation is connected throughout. They looked perfect on the 60 one-minute captures for a reason that does not transfer.
6. **Oracle bound (hypothetical).** A commanded-speed range check would separate the 13 value-indistinguishable minutes 9/9 with 0 FP, against any-write 9/4 and published IF about 7.2/2.

## Decisions taken without Jack (most reasonable reading; revisit if wrong)

- **Synthetic old-vs-new comparison skipped.** The scheduled task's text lists "synthetic old-vs-new scoring" and says to complete it when the network is blocked. But `docs/agent_brief.md` was changed at 07:59 today (commit `ffffd60`) to "Synthetic baseline (skip) … The main session is re-running the synthetic evaluation … Do not duplicate it". The brief is the newer and more specific instruction, and the task says to follow it exactly, so I skipped it. If you still want it from this branch, it is a short job: run the default 30-day synthetic set through `run_real_data.py --cadence-dir` with pair-level ground truth, next to `generate_synthetic_data.evaluate_detection`.
- **No hunting for dataset mirrors.** The task says to stop if the dataset hosts are unreachable, so I did not look for copies of CTU-13 or IoT-23 elsewhere.
- **OPC UA clean protocol.**
  - "Contamination fixed a priori" became sklearn's `auto`.
  - "Chosen by FP budget on held-out normals only" became a nested leave-one-out: within each outer fold, pick the largest c in {0.01, 0.05, 0.1, …, 0.5} whose inner held-out false alarms stay within 0 or 1 of 9.
  - c=0.2 under the clean protocol is shown for reference only.
  - Attacks are scored by all 10 fold models (recall = mean over folds).
  - The ">=2 writes" threshold is rebuilt per fold as "more than any training normal", which gives ≥2.
- **OPC UA 3 Sep labels.** Kept the authors' stage table. Minute 21 (two HMI writes 21–26 s after their Step 3 window) stays a false positive. Relabelling it would add 1 TP and remove 1 FP for every detector that flags it.
- **A "new setpoint writer" variant** is reported, labelled as defined after seeing the 3 Sep run.
- **Seed 42** is used as the representative seed where a single seed is shown, because it is the published one. Distributions over seeds 0–199 are given alongside.

## Reproduce

### OPC UA (ran today)

```bash
git checkout real-data-eval
pip install --break-system-packages pandas numpy scikit-learn scipy statsmodels matplotlib seaborn pytest
git clone --depth 1 https://github.com/carolsworld/FactoryIOOPCUA data/FactoryIOOPCUA     # commit a1b712e
mkdir -p data/opcua && for z in data/FactoryIOOPCUA/datasets/*/*.zip; do unzip -o -q "$z" -d data/opcua; done
F=data/opcua; A=$F/opcua_instance1-60_sliced_1min.csv
S1=$F/20250903_Network_OPCUA_enriched_features_instanced_file1.csv; S2=$F/20250903_Network_OPCUA_enriched_features_instanced_file2.csv
python related/opcua_reanalysis/opcua_baselines.py $A $S1 $S2 | diff - related/opcua_reanalysis/results_reproduction.txt
python related/opcua_reanalysis/opcua_clean_protocol.py $A $S1 $S2 --repo data/FactoryIOOPCUA --seeds 200 --jobs 2 \
  > related/opcua_reanalysis/results_clean_protocol.txt       # ~18 min on 2 CPUs
```

Zip SHA-256 values:

- `opcua_instance1-60_sliced_1min.zip`: `f499a1b7245c9f00544aad1ba9943260443da61deca37c10ef7e2c5134267d4e`
- `…instanced_file1.zip`: `756f9f469ed96750ecc9da8399d97b11d992a0baf2558ad115f870fbdb5505f2`
- `…instanced_file2.zip`: `71aaa8a8d2699a68a5c88a9868615d98be462db5fc997aedd961d6712c118c5e`

Environment: Ubuntu 24.04.5, Python 3.13.18, scikit-learn 1.9.1, pandas 3.0.5, numpy 2.5.3, scipy 1.18.1.

### Real-data sections (for the re-run once the hosts are allowed; not executed today)

```bash
# connectivity check (all three must return 200/301, not 403 from the proxy)
for u in https://mcfp.felk.cvut.cz/publicDatasets/ https://www.activecountermeasures.com/ \
         https://download.opensuse.org/repositories/security:/zeek/xUbuntu_24.04/; do curl -sI --max-time 20 "$u" | head -1; done

# Zeek from the openSUSE Build Service (Ubuntu 24.04)
echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_24.04/ /' | sudo tee /etc/apt/sources.list.d/security:zeek.list
curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_24.04/Release.key | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/security_zeek.gpg >/dev/null
sudo apt update && sudo apt install -y zeek && export PATH=/opt/zeek/bin:$PATH

# CTU-13 scenario N lives at https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-(41+N)/
# per scenario, one at a time, under data/ctu13/<N>/ ; delete the pcap before the next one
bunzip2 -k *.truncated.pcap.bz2
python -m analytic_pipeline.ground_truth ctu13 --binetflow *.binetflow --out gt.csv     # check C&C labels exist (From-Botnet.*-CC)
python run_real_data.py --pcap *.truncated.pcap --output results/real_data/ctu13-sN-conn --gt gt.csv \
  --conn-only --internal-cidr 147.32.0.0/16                                               # headline; confirm range from labels first
python run_real_data.py --pcap *.truncated.pcap --output results/real_data/ctu13-sN-full --gt gt.csv \
  --internal-cidr 147.32.0.0/16                                                           # ablation, with the truncation caveat

# Active Countermeasures (per post: victim and C2 IPs from the post; intervals < 60 s)
python -m analytic_pipeline.ground_truth pairs --pair <victim> <c2> --out gt.csv
python run_real_data.py --zeek-dir <unzipped zeek logs> --output results/real_data/acm-<name> --gt gt.csv --min-period-s 2

# IoT-23 (logs-only release)
python -m analytic_pipeline.ground_truth zeek-labeled --conn conn.log.labeled --out gt.csv
python run_real_data.py --zeek-dir <scenario dir> --output results/real_data/iot23-<scenario> --gt gt.csv --conn-only
```

Default-config runs come first. Any flag changed after seeing metrics is "tuned" and gets reported separately.

## What this means for the IEA/AIE paper (deadline 15 Dec 2026)

- **Still no real-data result.** CADENCE's only validation is the synthetic F1 1.000, so the paper's real-data table stays empty. Reviewers will weigh a synthetic-only detector heavily. Getting even conn-only CTU-13 numbers on 4 scenarios before mid-December is the most valuable next step, and it needs only the network allow-list plus one re-run of this task.
- **The OPC UA work is related-work and motivation, not a CADENCE result.** It supports a short argument: evaluation protocol choices can move a reported F1 from about 0.96 to 0.48–0.80 once false alarms are held to a budget, value-blind write detection is capped by what the logs carry, and an OT write detector alone sees 7 of 111 minutes of a multi-stage attack. That motivates fusing it with CADENCE and DRIFT. The same discipline applies to CADENCE's own synthetic 1.000: report default-config numbers, report FP rates with CIs, and say what the data cannot show.
- **Lesson for CADENCE's own evaluation.** A rule that is perfect on short per-scenario captures broke on a continuous capture. Expect CADENCE's real-data numbers to fall well below the synthetic ones, and plan the paper's framing for that rather than against it.
