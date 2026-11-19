# OPC UA write detection on the Lo et al. Factory IO data: re-analysis findings

Data and notebook: github.com/carolsworld/FactoryIOOPCUA (commit `a1b712e`, 11 Mar 2026). Paper: Lo et al., "Risk-based OPC UA Network Anomaly Detection for Interconnected Cyber-Physical Systems", IEEE SNGC 2026.
Scripts: `opcua_baselines.py` (reproduction, unchanged) and `opcua_clean_protocol.py` (this note). Raw output: `results_reproduction.txt`, `results_clean_protocol.txt`, CSVs in `out/`. Run on 19 Nov 2026.

The authors released their per-message CSVs, extraction scripts and notebook, which is what made this re-analysis possible. Everything below uses only those files.

## Headline

| Detector | 60-instance set, published protocol: FP / recall / F1 | 60-instance set, clean protocol: FP/10, recall, F1 [95% CI] | 3 Sep run, per minute: TP / FP, F1 |
|---|---|---|---|
| Isolation Forest c=0.2 (published) | 2/10, 0.96, **0.960** (seed 42); 200 seeds: F1 median 0.960, range 0.556–0.970 | not a clean setting (c came from a sweep scored on the evaluation set); for reference 0.6/10, 0.89, 0.934 | 5 / 1, **0.417** |
| Isolation Forest, contamination `auto` (a priori) | – | 4.8/10, 0.98, 0.946 [0.92, 0.97] | 6 / 1, 0.480 |
| Isolation Forest, c chosen by FP budget ≤1/9 on held-out normals | – | 0.0/10, 0.66, 0.796 [0.77, 0.81] | 6 / 1, 0.480 (median over seeds 0.417) |
| Isolation Forest, c chosen by FP budget 0/9 | – | 0.0/10, 0.32, 0.481 [0.45, 0.52] | 0 / 0, 0.000 (detects anything in 38% of seeds) |
| Any write to `iSpeedSetPoint` in the minute | 4/10, 1.00, 0.962 | same (no training) | 6 / 1, 0.480 |
| Client never seen in normal runs | 0/10, 0.60, 0.750 | same | 18 / 93, 0.279 |
| Setpoint writes > training max OR new client | 0/10, 0.82, 0.901 | same | 18 / 93, 0.279 |

Clean protocol: leave-one-out over the 10 normals, message-size mode from training normals only, contamination fixed a priori or chosen by false-positive budget on held-out normals; 200 seeds. IF numbers in the clean column are seed-averaged. 3 Sep IF numbers are seed 42 (the published seed). The 3 Sep run has 18 positive minutes (their Step 3 and Step 5 windows) and 93 negative.

In short: the reported F1 0.96 depends on two choices that draw on the evaluation data. The contamination level came from a sweep scored on the evaluation set, and the "normal" message size was computed over attack runs too. Under a protocol that avoids them, Isolation Forest either behaves like the one-line "any setpoint write" rule (FP 4–10 of 10) or, once its threshold is held to a false-positive budget, recall falls to 0.32–0.66. On the 3 Sep multi-stage run, any detector that needs a setpoint write to alarm, including ours, is capped at per-minute recall 6/18 = 0.33, because only 6 of the 18 attack minutes contain one. The "new client" rule that looks perfect on the 60-instance set fires on all 111 minutes of the 3 Sep run.

## 1. Reproduction

`opcua_baselines.py` re-run against the public repo on 19 Nov 2026 reproduces `results_reproduction.txt` line for line: Isolation Forest (seed 42, contamination 0.2, features `write_anomaly_count`, `write_anomaly_ratio`, `write_ops_ratio`) gives TP 48, FP 2, FN 2, TN 8 (accuracy 0.933, F1 0.960), as published. On 3 Sep it flags minutes 17, 19, 21, 108, 109, 110, the same six the notebook lists (cell 99).

## 2. Written values are not in the released data

Checked first, because a value field would change everything below. It is not there.

- **Every column.** The 60-instance CSV has `instance, scenario, ts, uid, id.orig_h, id.orig_p, id.resp_h, id.resp_p, is_orig, opcua_link_id, is_final, msg_size, identifier, node_id_string`; the two 3 Sep CSVs have the same minus `scenario` plus `ts_uk`. Across the 167 setpoint WriteRequests, `msg_size` takes exactly one value per client in every scenario: 165 bytes for the HMI and 161 for UA Expert, whether the commanded speed is 4–6, 8–10, 0–3 or negative. So `msg_size` reflects the client's encoding, not the value. Within one client, the only other columns that vary are capture bookkeeping: instance, scenario, timestamp, uid, source port and link ID.
- **Extraction scripts.** Step 1 runs Zeek with the full `icsnpp/opcua-binary` analyzer. Step 2 (only the inference version, `extractlogtoCSV_enriched_inference.py`, is in the repo; the 60-instance CSV has the same columns) joins `opcua_binary.log` to `opcua_binary_write.log` and keeps only `opcua_link_id`, `node_id_string` and `req_status_code_link_id`. Step 3 then drops `req_status_code_link_id`. No value-related field reaches the released CSVs. Whether the authors' Zeek logs hold the written values depends on the ICSNPP version they used. The raw pcaps would settle it.

Consequence: any detector on these CSVs can see *that* a setpoint was written, by whom, and how often, but not *what* was written.

## 3. Three protocol issues, with evidence

**(1) The training normals are also scored.** Instances 1–10 train the model and are 10 of the 60 evaluated. Isolation Forest sets its threshold at the c-quantile of its own training scores, so the false-positive count on those normals is fixed by c rather than measured. Over 200 seeds: c=0.1 gives FP 1 in 200/200 seeds; c=0.2 gives FP 2 in 200/200; c=0.3 gives 3 (178) or 2 (22); c=0.4 gives 4 (134), 3 (44) or 2 (22). The effect cuts both ways. Under the clean protocol at the same c=0.2 (held-out normals and training-only mode together), FP drops to 0.6/10 and recall to 0.89 (F1 0.934). Here the overlap mostly turns the FP figure into an artefact of c rather than inflating F1.

**(2) The "normal" message size is computed over all runs, attacks included.** The mode over all 60 instances is 161 bytes. That is UA Expert's encoding, and UA Expert appears only in attack runs (100 writes). The trusted HMI writes 165 bytes everywhere, including the four writes in training normals 6, 8, 9 and 10. Under the published protocol, "size deviation" therefore means "the HMI wrote", which is present in the normals. With the mode taken from training normals only (165), it means "UA Expert wrote", which on this set is the same as "new client". On the 3 Sep run the per-run mode is a 7–7 tie between the two clients, resolved to 161 by pandas' sort order. The feature's meaning depends on the class mix of the data it is computed on.

**(3) Contamination is chosen by F1 on the evaluation set.** Notebook cell 41 says: "contamination = 0.4 is chosen as it is an optimal value based on F1-score on the evaluation set". The saved and reported model uses 0.2. The sweep at seed 42 shows how much rides on that choice: c=0.05 and 0.1 give recall 0 (F1 0.000), c=0.15 gives 16/50 (F1 0.471), c=0.2 gives 48/50 (0.960) and c≥0.25 gives 50/50 with FP 3 (0.971). Picking a working c needs the attack labels.

## 4. Clean-protocol results

Protocol: outer leave-one-out over the 10 normals, so each normal is scored only by a model trained on the other 9. Attacks are scored by all 10 fold models and recall is the mean over folds. The message-size mode comes from the fold's training normals only (165 in every fold). Contamination is either `auto` (sklearn's default, fixed a priori) or chosen per fold by an inner leave-one-out over that fold's 9 training normals: the largest c in {0.01, 0.05, 0.1, …, 0.5} whose inner held-out false alarms stay within budget (0 or 1 of 9). Rules are rebuilt per fold from the training normals; ">=2 writes" becomes "more setpoint writes than any training normal", which is ≥2 in every fold. 200 seeds (0–199). An independent re-implementation using sklearn's `contamination`/`predict` path directly matched seeds 0, 5 and 42 exactly.

| Detector (clean protocol) | FP/10 | FPR 95% CI | Recall | Recall 95% CI | Precision | F1 | F1 95% CI | Over seeds: FP median [min, max]; F1 median [2.5%, 97.5%] |
|---|---|---|---|---|---|---|---|---|
| Published protocol, IF c=0.2 (for comparison) | 2.00 | [0.03, 0.56] | 0.949 | [0.83, 0.99] | 0.960 | 0.954 | [0.92, 0.98] | 2 [2, 2]; 0.960 [0.844, 0.970] |
| IF `auto` | 4.81 | [0.19, 0.81] | 0.984 | [0.89, 1.00] | 0.911 | 0.946 | [0.92, 0.97] | 4 [4, 10]; 0.956 [0.897, 0.956] |
| IF c=0.2 (reference only) | 0.63 | [0.00, 0.45] | 0.887 | [0.76, 0.95] | 0.986 | 0.934 | [0.90, 0.96] | 1 [0, 2]; 0.941 [0.908, 0.952] |
| IF, FP budget ≤1/9 | 0.00 | [0.00, 0.31] | 0.661 | [0.51, 0.79] | 1.000 | 0.796 | [0.77, 0.81] | 0 [0, 0]; 0.798 [0.764, 0.808] |
| IF, FP budget 0/9 | 0.00 | [0.00, 0.31] | 0.317 | [0.20, 0.47] | 1.000 | 0.481 | [0.45, 0.52] | 0 [0, 0]; 0.221 [0.165, 0.807] |
| Any setpoint write | 4 | [0.12, 0.74] | 1.000 | [0.93, 1.00] | 0.926 | 0.962 | [0.93, 0.99] | – |
| New client | 0 | [0.00, 0.31] | 0.600 | [0.45, 0.74] | 1.000 | 0.750 | [0.63, 0.84] | – |
| Writes > training max OR new client | 0 | [0.00, 0.31] | 0.820 | [0.69, 0.91] | 1.000 | 0.901 | [0.82, 0.96] | – |

CIs: exact Clopper–Pearson for FPR (n=10) and recall (n=50) at the rounded seed-averaged count; stratified instance bootstrap (5000 resamples) for F1. **With 10 normals the FPR intervals are very wide.** 0/10 is compatible with a true false-alarm rate up to 31% per minute, and 4/10 with 12–74%. No result here pins down false-alarm rate well enough for an operational claim, which matters for a per-minute OT detector.

Observations:

- **`auto` reduces to the any-write rule.** It flags the four normals that contain one HMI write in every seed. The six write-free normals have identical features and score within about 0.005 of the `auto` threshold of −0.5 (−0.505 at seed 0, −0.499 at seed 1), so in some seeds all six are flagged too (FP 10/10 at seed 0). Its F1 0.946 is the any-write operating point plus seed noise.
- **An FP budget costs most of the recall.** Selection by held-out normals is bimodal. Under budget ≤1/9 it picks c=0.25 in 56% of folds and c=0.01 in 30%, and recall is close to all-or-nothing per fold. Mean recall is 0.66 (budget 1) or 0.32 (budget 0), with F1 0.80 and 0.48.
- **The rules carry no training risk on this set** (all 10 normals share one client and at most one write per minute). Their weakness shows up on 3 Sep (Section 7).

## 5. Recall by attack path

Each attack scenario has 4 runs through the trusted HMI and 6 through UA Expert from a new client.

| Detector | HMI (trusted client), n=20 | 95% CI | UA Expert (new client), n=30 | 95% CI |
|---|---|---|---|---|
| Published protocol, IF c=0.2 (seed-avg; seed 42 = 0.90 / 1.00) | 0.912 | [0.68, 0.99] | 0.974 | [0.83, 1.00] |
| IF `auto` | 0.959 | [0.75, 1.00] | 1.000 | [0.88, 1.00] |
| IF c=0.2 (reference) | 0.833 | [0.62, 0.97] | 0.922 | [0.78, 0.99] |
| IF, FP budget ≤1/9 | 0.647 | [0.41, 0.85] | 0.670 | [0.47, 0.83] |
| IF, FP budget 0/9 | 0.293 | [0.12, 0.54] | 0.333 | [0.17, 0.53] |
| Any setpoint write | 1.000 | [0.83, 1.00] | 1.000 | [0.88, 1.00] |
| New client | 0.000 | [0.00, 0.17] | 1.000 | [0.88, 1.00] |
| Writes > training max OR new client | 0.550 | [0.32, 0.77] | 1.000 | [0.88, 1.00] |

The HMI path is the hard and realistic one: an insider or a hijacked operator session uses the trusted client. A detector that relies only on client identity gets 0/20 there. Adding a write-count threshold recovers 11/20. Within the HMI path, Speed_TooSlow and WrongDirection are hardest. All four TooSlow HMI runs and three of the four WrongDirection HMI runs hold a single write. Published-protocol IF recall on those HMI runs is 0.75 (TooSlow) and 0.82 (WrongDirection), against 0.99–1.00 for the other HMI scenarios.

## 6. Oracle-value bound (hypothetical, not a result on their data)

13 minutes contain exactly one setpoint write, from the trusted HMI, and no new client: normals 6, 8, 9, 10 and attacks 11, 18 (TooFast), 21, 22, 23, 28 (TooSlow), 31, 32, 33 (WrongDirection). Without the written value these are the same observable event. The notebook (cell 7) defines the scenarios by commanded speed: normal about 4–6, too fast 8–10, too slow 0–3, wrong direction negative.

| On these 13 minutes | TP (of 9) | FP (of 4) |
|---|---|---|
| Published-protocol IF c=0.2 (seed-avg) | 7.2 | 2.0 |
| Clean IF `auto` | 8.2 | 4.0 |
| Clean IF, FP budget ≤1/9 | 5.2 | 0.0 |
| Any setpoint write | 9 | 4 |
| New client; writes > max OR new client | 0 | 0 |
| **Hypothetical range check, commanded speed outside [4, 6]** | **9** | **0** |

Within this group, what Isolation Forest flags is decided by `total_packets`, the denominator of `write_ops_ratio`, not by anything about the write (`results_reproduction.txt` §4). A range check would separate the group exactly *if* each run's single write carried a value inside its scenario's stated range. That assumption is untested. "Approximately 4 to 6" leaves the band edges open, and Oscillate and VariousThreats are not in this group. A consequence-weighted score would also rank these minutes: overspeed of 2–4 units above the band, underspeed of 1–4 below, and direction reversal. This motivates value-aware detection and getting the raw pcaps (or full ICSNPP logs). It is not a measurement.

## 7. The 3 Sep 2025 multi-stage run

Per-minute instances follow their stage table (notebook cell 50): S1 1–4, S2 5–7, S3 8–20 (HMI, positive), S4 21–105, S5 106–110 (UA Expert, positive), post 111. The run has 14 setpoint writes in 7 minutes: the HMI writes in 16, 17, 19 (S3) and 21 (S4, 13:40:21 and 13:40:26), and UA Expert writes in 108, 109, 110 (S5). There are no writes to output tags.

| Detector | TP | FP | FN | TN | Precision | Recall | F1 (seed 42) | F1 over 200 seeds: median [min, max] |
|---|---|---|---|---|---|---|---|---|
| Published IF c=0.2 (saved-model protocol) | 5 | 1 | 13 | 92 | 0.833 | 0.278 | 0.417 | 0.417 [0.190, 0.417] |
| Clean IF `auto` | 6 | 1 | 12 | 92 | 0.857 | 0.333 | 0.480 | 0.480 [0.417, 0.480] |
| Clean IF, FP budget ≤1/10 | 6 | 1 | 12 | 92 | 0.857 | 0.333 | 0.480 | 0.417 [0.417, 0.480] |
| Clean IF, FP budget 0/10 | 0 | 0 | 18 | 93 | – | 0.000 | 0.000 | 0.000 [0.000, 0.480] |
| Any setpoint write | 6 | 1 | 12 | 92 | 0.857 | 0.333 | 0.480 | – |
| New client | 18 | 93 | 0 | 0 | 0.162 | 1.000 | 0.279 | – |
| Writes > training max OR new client | 18 | 93 | 0 | 0 | 0.162 | 1.000 | 0.279 | – |
| New setpoint writer (defined after seeing this run) | 3 | 0 | 15 | 93 | 1.000 | 0.167 | 0.286 | – |

Per stage, at seed 42: flagged minutes out of stage minutes, with time to first detection from stage start.

| Detector | S1 (4) | S2 (3) | S3 (13) | S4 (85) | S5 (5) | post (1) |
|---|---|---|---|---|---|---|
| Published IF c=0.2 | 0 | 0 | 2, +9 min | 1 (min 21) | 3, +2 min | 0 |
| Clean IF `auto` / FP budget ≤1/10 | 0 | 0 | 3, +8 min | 1 (min 21) | 3, +2 min | 0 |
| Any setpoint write | 0 | 0 | 3, +8 min | 1 (min 21) | 3, +2 min | 0 |
| New client; writes > max OR new client | 4 | 3 | 13, +0 | 85 | 5, +0 | 1 |

- **Per-minute recall is capped by the labels, not the detectors.** Only 6 of the 18 positive minutes contain a setpoint write: 3 of 13 in S3 and 3 of 5 in S5. The rest of each window is attacker activity that never reaches OPC UA, such as the remote-desktop session to the HMI (notebook cell 5) before the first write. The two client-identity rules escape this cap only because they fire on every minute. Every Isolation Forest variant flags only minutes that contain a setpoint write and never a write-free minute. In this run it is a setpoint-write detector with a threshold.
- **Time to first detection.** S3 starts at 13:27 (minute 8). The first HMI write is at 13:35:04 (minute 16). Any-write and clean IF alarm in that minute: +8 min from stage start, 0 from the first write. Published IF misses the single-write minute 16 and alarms at 17 (+9). S5 starts at 15:05 (minute 106); the first UA Expert write is at 15:07:43 (minute 108), and every detector that needs a write alarms there (+2). Nothing write-based fires in S1 or S2 (discovery, lateral movement), as expected.
- **The one false positive is minute 21.** Two HMI writes land at 13:40:21 and 13:40:26, 21 s and 26 s after their Step 3 window closes, so by their table they belong to S4. They are plausibly the tail of Step 3. We keep their labels; relabelling would add 1 TP and remove 1 FP for every detector that flags that minute.
- **"New client" does not transfer.** The UA Expert workstation (192.168.1.36) is connected in all 111 minutes (reads and publish requests) but writes only in S5. In the 60 one-minute scenario captures, that host appears only in UA Expert attack runs, so "new client" and our own "≥2 writes OR new client" rule are perfect there for a reason that does not hold in a continuous capture. On 3 Sep both fire every minute (precision 0.16). A "new setpoint writer" variant fixes that (3 TP, 0 FP) but was defined after seeing this run, and it still has zero recall on the HMI path.

## 8. What this motivates

On these data the signal the published detector picks up is "a setpoint write happened in this minute", plus who sent it. A one-line rule matches it, and neither can tell a 5 from a −5. The next step is value-aware, consequence-weighted detection: features from the written value and its physical effect (distance from the operating band, sign reversal, rate of change, the process state it lands in), scored by consequence rather than by rarity. That needs the written values, so the raw pcaps or full ICSNPP variant logs. The 3 Sep run also shows the limit of any OT-only view: only 7 of 111 minutes contain a setpoint write (6 inside the attack windows), and nothing of Steps 1, 2 and 4 reaches OPC UA, which play out on the IT side. That argues for IT/OT fusion, with an OPC UA write detector as one noisy sensor next to CADENCE (C2 and beaconing from Zeek conn/dns/http/ssl) and DRIFT (endpoint ATT&CK technique transitions). Corroborating evidence then decides the alarm. For example, an HMI setpoint write that follows a remote-desktop session from an unusual host should outrank the same write in a routine operator shift.

## Limitations of this re-analysis

- **Small sample.** 10 normals and 50 attack runs of one minute each: every interval above is wide.
- **The 3 Sep run is one run** and is scored against the authors' stage table.
- **Isolation Forest scope.** Only the three published features and Isolation Forest were re-evaluated; other models or the dropped `unique_write_targets_count` feature were not.
- **Selection grid.** FP-budget selection uses a fixed grid over c and an inner leave-one-out over 9 training normals (each inner model fit on 8), so selections are coarse.
- **The oracle bound is hypothetical** and rests on the scenario definitions in the notebook, not on observed values.

## Reproduce

```bash
git clone --depth 1 https://github.com/carolsworld/FactoryIOOPCUA data/FactoryIOOPCUA
mkdir -p data/opcua && for z in data/FactoryIOOPCUA/datasets/*/*.zip; do unzip -o -q "$z" -d data/opcua; done
F=data/opcua
python related/opcua_reanalysis/opcua_baselines.py $F/opcua_instance1-60_sliced_1min.csv \
  $F/20250903_Network_OPCUA_enriched_features_instanced_file1.csv $F/20250903_Network_OPCUA_enriched_features_instanced_file2.csv
python related/opcua_reanalysis/opcua_clean_protocol.py $F/opcua_instance1-60_sliced_1min.csv \
  $F/20250903_Network_OPCUA_enriched_features_instanced_file1.csv $F/20250903_Network_OPCUA_enriched_features_instanced_file2.csv \
  --repo data/FactoryIOOPCUA --seeds 200 --jobs 2      # ~18 min on 2 CPUs
```

Zip SHA-256 values as downloaded:

- `opcua_instance1-60_sliced_1min.zip`: `f499a1b7245c9f00544aad1ba9943260443da61deca37c10ef7e2c5134267d4e`
- `20250903_…_instanced_file1.zip`: `756f9f469ed96750ecc9da8399d97b11d992a0baf2558ad115f870fbdb5505f2`
- `20250903_…_instanced_file2.zip`: `71aaa8a8d2699a68a5c88a9868615d98be462db5fc997aedd961d6712c118c5e`

Environment: Python 3.13, scikit-learn 1.9.1, pandas 3.0.5, numpy 2.5.3, scipy 1.18.1.
