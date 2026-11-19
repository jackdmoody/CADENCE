# Agent brief: real-data evaluation day (19 Nov 2026)

You are working unattended for Jack Moody while he is at work. Nobody will answer questions. When something is ambiguous, take the most reasonable reading, write down which one you took in RESULTS.md, and keep going. Work in the cloud VM. It has 2 CPUs, 7 GB RAM and about 30 GB free disk, so handle large data one piece at a time.

Repository: github.com/jackdmoody/cadence, branch `real-data-eval`. Never push to `main`, never force-push, never rewrite history. Commit and push to `real-data-eval` after each completed unit of work so partial results survive. Never commit raw data, pcaps, Zeek logs, or any file over 5 MB. `data/` is gitignored, so keep downloads there.

## Background

CADENCE is a 10-stage C2 beaconing detector on Zeek telemetry. Until now it has only been validated on synthetic data (reported F1 1.000). This branch adds `analytic_pipeline/zeek_adapter.py`, `analytic_pipeline/ground_truth.py` and `run_real_data.py`. Read the README section "Running on real Zeek data" first. The goal today is honest real-data numbers for an IEA/AIE 2027 submission (deadline 15 Dec 2026), plus a cleaned-up OPC UA re-analysis.

## Ground rules for results

1. For every dataset, report the default-config result first. Change a setting only for a reason that comes from the dataset itself: `--internal-cidr` for the dataset's own address range, or `--min-period-s` when the published beacon interval is under 60 s. Record the reason. Anything changed after looking at detection metrics is "tuned". Report it separately and label it as such.
2. Do not change detection logic to improve numbers. If the adapter, ground-truth builder or scorer breaks on a real format, fix it, add a test in `analytic_pipeline/test_real_data.py`, keep all tests passing (`python -m pytest analytic_pipeline -q`), and note the fix in RESULTS.md. `test_priority_score_monotone_with_beacon_confidence` already fails intermittently on `main`; that is known.
3. Report misses and failures as plainly as successes. A weak honest number is the point.

## Order of work

### 0. Setup and connectivity (first 15 minutes)

- `git checkout real-data-eval`, then `pip install --break-system-packages pandas numpy scikit-learn scipy statsmodels matplotlib seaborn pytest`, then run the tests.
- Check network: `curl -sI --max-time 20` against `https://mcfp.felk.cvut.cz/publicDatasets/`, `https://www.activecountermeasures.com/` and `https://download.opensuse.org/repositories/security:/zeek/xUbuntu_24.04/`. If they are blocked, the environment's network access was not opened. Do sections 1, 2 and 6, skip 3–5, and say so at the top of RESULTS.md.
- Install Zeek (Ubuntu 24.04) from the openSUSE Build Service repo `security:zeek` (package `zeek`, binaries under `/opt/zeek/bin`; add that to PATH). Skip JA3 unless it installs in under 10 minutes.

### 1. OPC UA re-analysis (no special network needed; data is on GitHub)

Files: `related/opcua_reanalysis/`. The script reproduces Lo et al.'s Isolation Forest (seed 42, contamination 0.2, TP 48 FP 2) and shows that a one-line "any write to iSpeedSetPoint in the minute" rule matches it. Extend it as follows. Put new code in a new script next to the old one and leave the original untouched.

1. Re-run the original and confirm it matches `results_reproduction.txt`.
2. **Check whether written values exist anywhere** in the released CSVs (look at every column) or in the repo's extraction scripts (`scripts/Step 1–4`). If a value field exists, everything below changes. Report it first.
3. **Clean protocol.** Their protocol trains on normals 1–10, evaluates on all 60 including those 10, computes the "normal" message size as the mode over all runs including attacks, and picks contamination by F1 on the evaluation set. Re-evaluate Isolation Forest, any-setpoint-write, new-client and ">=2 writes OR new client" under a protocol that avoids all three:
   - leave-one-out over the 10 normals, so no scored normal was in training;
   - mode size from training normals only;
   - contamination fixed a priori, or chosen by false-positive budget on held-out normals only.

   Report the distribution over 200 seeds and bootstrap or exact binomial CIs; with 10 normals the CIs will be wide, so say so.
4. Recall split by attack path, trusted HMI (20 runs) vs new client UA Expert (30 runs), for every detector.
5. **Oracle-value bound, clearly labelled hypothetical.** The notebook defines scenarios by commanded speed range: normal 4–6, too fast 8–10, too slow 0–3, wrong direction negative. Quantify what a range check would do on the 13 minutes that are indistinguishable without values (one HMI write, no new client). This motivates value-aware, consequence-weighted detection and why the raw pcaps are needed. It is not a result on their data.
6. 3 Sep multi-stage run: per-minute and per-stage detection for every detector, plus time to first detection per stage.
7. Write `related/opcua_reanalysis/FINDINGS.md`. It needs a headline table, the three protocol issues with evidence, the clean-protocol results, the attack-path split, the oracle bound, the 3 Sep run, and one short paragraph on what it motivates. That paragraph covers value-aware, consequence-weighted detection and IT/OT fusion, where an OPC UA write detector is one noisy sensor alongside CADENCE (Zeek) and DRIFT (endpoint ATT&CK transitions). Keep the tone factual and collegial, not a rebuttal. Do not draft any email or outreach.

### 2. Synthetic baseline under the new scorer

The old evaluator in `generate_synthetic_data.evaluate_detection` credits a detection when either the source or the destination matches a malicious scenario, counts true positives per scenario and false positives per pair. Run the default 30-day synthetic set through `run_real_data.py --cadence-dir` with pair-level ground truth (malicious pairs from the generator's `label` column, as in `test_real_data.py`). Report both numbers side by side. Do not change the old evaluator.

### 3. CTU-13 (main event)

- Scenario N lives at `https://mcfp.felk.cvut.cz/publicDatasets/CTU-Malware-Capture-Botnet-(41+N)/` (scenario 9 is Botnet-50). Each has a labeled `.binetflow` and a truncated full-capture pcap (`*.truncated.pcap.bz2`).
- Start the first download in the background, then do section 1 while it runs.
- Check directory sizes and choose at least 4 scenarios, smallest first. Cover both IRC C2 (Neris: 1, 2, 9; Rbot: 3, 4, 10, 11) and HTTP-style C2 (e.g. Sogou 7, Virut 5/13). Process one at a time. Decompress, run Zeek, convert, then delete the pcap before the next one.
- Before using `--internal-cidr 147.32.0.0/16`, confirm from the labels that the infected and campus hosts are in that range.
- Ground truth: `python -m analytic_pipeline.ground_truth ctu13 --binetflow ... --out ...`. Check that C&C-labelled flows exist (default pattern `From-Botnet.*-CC`). If the label format differs, adjust the pattern and record it.
- Runs: `--conn-only` is the headline, because the truncated full capture has little application-layer payload for background traffic. A full run with dns/http/ssl is an ablation, reported with that caveat.
- Raise `--max-pairs` if the SAX cap is hit, and record it.
- Expect weak periodicity recall on IRC bots that hold one long session. Report it as a finding.

### 4. Active Countermeasures "Malware of the Day"

Find 3–5 posts with downloadable PCAP or Zeek-log zips, spanning beacon timings. Candidates are Asprox (30 s, 20% jitter), the Sliver tunneling post (5 s, 60%), the IcedID→ALPHV Cobalt Strike post (300 s, 99%) and Numinon (10 s, then 180 s; good for the PELT changepoint stage). Prefer the Zeek zips when offered. Verify SHA-256 when posted. Build ground truth from the post's victim and C2 IPs (`ground_truth pairs`). Use `--min-period-s 2` because the published intervals are under 60 s. Per sample, report detection stage, estimated vs published period, and for Numinon whether PELT finds the phase change. If download links can't be found or fetched, say so and move on.

### 5. IoT-23 (stretch)

Use per-scenario `conn.log.labeled` files (the logs-only release). Pick 2–3 malicious scenarios with `C&C-HeartBeat` labels and 1 benign. Build ground truth with `ground_truth zeek-labeled` and run with `--conn-only`.

### 6. Wrap-up (be done by 17:00 America/New_York)

`RESULTS.md` at the repo root should cover:

- what ran and what did not, and why;
- one table per dataset with conn-only and full numbers, beacon and corroborated stages, strict and lenient, and AP;
- C2 pairs by stage (miss attribution);
- the synthetic old-vs-new comparison;
- every non-default setting and why;
- bugs fixed;
- exact commands to reproduce;
- a short "what this means for the IEA/AIE paper" section.

Commit `results/real_data/<dataset>/{metrics.json,gt_pairs_by_stage.csv,run_summary.json,run_config.json}` (small files only). Push. End the session with a message to Jack of at most 10 lines: headline numbers, the most important finding, and anything that needs his decision.
