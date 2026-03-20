# CADENCE
### C2 Anomaly Detection via Ensemble Network Correlation Evidence

> A multi-stage behavioral analytic for detecting C2 beaconing in Zeek network telemetry. Reduces hundreds of thousands of connection log events to a small set of high-confidence, analyst-actionable leads by sequencing independent detection techniques — each answering a question the previous stage cannot.

---

## The Problem

C2 beacons are designed to look normal. A single beacon connection has unremarkable byte counts, a standard port, and a plausible connection state. No threshold or signature catches it. What makes a beacon detectable is its **behavior over time**: it fires on a fixed schedule, to the same destination, with uniform payloads, and leaves correlated evidence across multiple protocol layers simultaneously.

CADENCE is built around that observation. It doesn't look for a single anomalous flow — it looks for the pattern that only automated, scheduled, malicious processes produce.

---

## How It Works

Each stage answers a specific question that the previous stage cannot:

```
Zeek conn.log, http.log, dns.log, ssl.log  (30 days, ~30k rows/day)
      │
      ▼
┌─────────────────────────────────────────────────────────────────┐
│  Stage 1–2 — Ingest, Feature Engineering & Scaling              │
│  Schema normalisation · Channel-level aggregation               │
│  14 IForest features (IAT MAD, persistence ratio, beat rate...) │
│  945k flows → 166k (src, dst, port, proto) channels             │
└─────────────────────────────────────────────────────────────────┘
      │
      ▼  Question: Which channels are obviously benign?
┌─────────────────────────────────────────────────────────────────┐
│  Stage 3 — Domain-Knowledge Pre-Filter                          │
│  RFC 1918 internal-to-internal · Known CDN/DNS/NTP infra        │
│  High-fanin shared services · Dead connection states            │
│  Configurable thresholds via PrefilterConfig                    │
└─────────────────────────────────────────────────────────────────┘
      │
      ▼  Question: Which channels are volumetrically anomalous?
┌─────────────────────────────────────────────────────────────────┐
│  Stage 4 — Isolation Forest                                     │
│  Joint multivariate anomaly scoring on 14 channel-level features│
│  Stability validation · HHI concentration analysis              │
│  ~5% of channels pass through                                   │
└─────────────────────────────────────────────────────────────────┘
      │
      ▼  Question: Does this channel's timing show symbolic regularity?
┌─────────────────────────────────────────────────────────────────┐
│  Stage 5 — SAX Pre-Screening                                    │
│  Symbolic Aggregate approXimation on inter-arrival times        │
│  Fast O(N) elimination of non-periodic channels                 │
│  ~35% of anomalous channels pass through                        │
└─────────────────────────────────────────────────────────────────┘
      │
      ▼  Question: Is this channel statistically periodic?
┌─────────────────────────────────────────────────────────────────┐
│  Stage 6 — Binned-Count ACF + Welch PSD Periodicity Analysis    │
│  Per-channel IAT autocorrelation (binned for jitter robustness) │
│  Spectral density estimation · Corrected period estimation      │
│  Composite beacon confidence scoring (threshold ≥ 0.45)         │
└─────────────────────────────────────────────────────────────────┘
      │
      ▼  Question: When did beaconing start? Did the interval change?
┌─────────────────────────────────────────────────────────────────┐
│  Stage 8 — PELT Changepoint Detection                           │
│  Estimated beacon start time · Interval shift detection         │
│  Operator interaction flagging                                  │
└─────────────────────────────────────────────────────────────────┘
      │
      ▼  Question: Is there independent cross-layer evidence of C2?
┌─────────────────────────────────────────────────────────────────┐
│  Stage 9 — Multi-Source Corroboration (H1–H6)                   │
│                                                                 │
│  DNS:   H1 Regularity · H2 DGA/NXDomain/FastFlux               │
│  HTTP:  H3 Behavioral Consistency · H4 Evasion Indicators       │
│  TLS:   H5 Session Consistency · H6 TLS Evasion Indicators      │
│                                                                 │
│  Adaptive weight redistribution across available log types      │
│  ~1–5 high-confidence leads                                     │
└─────────────────────────────────────────────────────────────────┘
      │
      ▼  Question: What ATT&CK techniques does this map to?
┌─────────────────────────────────────────────────────────────────┐
│  Stage 10 — MITRE ATT&CK Annotation                             │
│  Evidence-based technique mapping (T1071, T1568, T1573, etc.)   │
│  Tactic-grouped output per corroborated lead                    │
└─────────────────────────────────────────────────────────────────┘
      │
      ▼
  Analyst Brief — corroborated channels with full H1–H6 evidence
                  chain and ATT&CK technique annotations
```

### Why this sequence

| Stage | Technique | Beacon property tested | Why the previous stage couldn't answer this |
|---|---|---|---|
| Pre-Filter | Domain knowledge allowlists | Is it obviously benign infrastructure? | Without removing known-benign internal and infrastructure channels first, IForest wastes its anomaly budget on traffic that could never be C2. |
| Isolation Forest | Ensemble anomaly scoring | Is it behaviorally unusual across 14 dimensions? | Thresholding on individual features misses multivariate anomalies. A beacon with moderate bytes AND moderate duration AND moderate frequency looks normal on any single axis. |
| SAX Pre-Screening | Symbolic time-series encoding | Does its timing show regularity? | IForest scores feature distributions, not temporal patterns. A channel can be volumetrically anomalous but completely aperiodic. SAX eliminates these cheaply before expensive ACF. |
| Binned-Count ACF + Welch PSD | Spectral periodicity analysis | Is it statistically periodic with quantifiable confidence? | SAX is a fast heuristic filter, not a statistical test. Two channels can both pass SAX but one has a weak, noisy pattern and the other has a strong, jitter-tolerant periodicity. ACF + PSD provides the confidence score. |
| PELT Changepoint | Changepoint detection | When did it start? Did the operator interact? | Periodicity analysis confirms the beacon exists but doesn't tell you when it activated or whether the interval shifted mid-campaign (indicating a human operator reconfiguring the implant). |
| DNS + HTTP + TLS Corroboration | Cross-layer hypothesis testing (H1–H6) | Is it C2 specifically, not just automated? | Periodicity alone cannot distinguish C2 beacons from Windows Update, NTP, or health monitors. Independent protocol-layer evidence filters legitimate automated services. |
| MITRE ATT&CK Mapping | Evidence-to-technique annotation | What tradecraft does this represent? | Corroboration confirms a lead is malicious, but doesn't tell the analyst which ATT&CK techniques are in play or how to frame the finding for IR handoff. |

---

## Installation

```bash
# Clone and create a virtual environment
git clone https://github.com/jackdmoody/CADENCE.git
cd CADENCE
python -m venv .venv

# Activate (Windows)
.venv\Scripts\activate

# Activate (Linux/Mac)
source .venv/bin/activate

# Install dependencies
pip install -e .
```

**Requirements:** Python 3.10+

---

## Data Sources

CADENCE ingests four Zeek log types exported as CSV. Each table below lists every field the pipeline reads, whether it is required or optional, and what happens when it is absent.

---

### conn.log — Connection log (required)

The primary input. Every flow record from Zeek's `conn.log`, exported to CSV via `zeek-cut` or your SIEM's Zeek integration.

**Zeek export command:**
```bash
zeek-cut ts id.orig_h id.orig_p id.resp_h id.resp_p proto service duration \
    orig_bytes resp_bytes orig_pkts resp_pkts conn_state \
    < conn.log > conn.csv
```

**Expected columns** (Zeek native names — the pipeline also accepts the ISF/ECS dotted-key variants shown in parentheses):

| Zeek column | ISF/ECS alias | Required | Used for |
|---|---|---|---|
| `ts` | `timestamp` | **Yes** | Timestamp; must be Unix float seconds |
| `id.orig_h` | `source.ip` | **Yes** | Source IP address |
| `id.orig_p` | `source.port` | **Yes** | Source port |
| `id.resp_h` | `destination.ip` | **Yes** | Destination IP address |
| `id.resp_p` | `destination.port` | **Yes** | Destination port; part of channel key |
| `proto` | `network.transport` | No | Protocol label (tcp/udp); part of channel key if present |
| `service` | `network.protocol` | **Yes** | Application protocol (http, ssl, dns…); used for OHE features |
| `duration` | `event.duration` | **Yes** | Flow duration in seconds; used for `duration_cv` IForest feature |
| `orig_bytes` | `source.bytes` | No | Request bytes; used for `req_resp_asymmetry` |
| `resp_bytes` | `destination.bytes` | No | Response bytes; used for `bytes_cv`, `zero_payload_frac` |
| `orig_pkts` | `source.packets` | No | Originator packet count |
| `resp_pkts` | `destination.packets` | No | Responder packet count |
| `conn_state` | `network.connection.state` | No | Zeek connection state (SF, S0, REJ…); used for `conn_state_entropy` and dead-pair pre-filter |

**Minimum viable conn.log:** `ts`, `id.orig_h`, `id.orig_p`, `id.resp_h`, `id.resp_p`, `service`, `duration`. All other columns degrade gracefully — missing bytes columns zero-fill, missing `conn_state` skips the dead-pair filter.

**Window size:** 30 days minimum recommended. Slow beacons (6-hour intervals) produce only ~120 firings over 30 days; shorter windows may not have enough observations for reliable ACF peaks.

---

### dns.log — DNS log (optional, enables H1 + H2)

Without this log, DNS corroboration hypotheses H1 and H2 do not fire. The pipeline still detects beacons via conn log periodicity alone, but corroboration scores will be lower.

**Zeek export command:**
```bash
zeek-cut ts id.orig_h query rcode_name answers TTLs \
    < dns.log > dns.csv
```

| Zeek column | Required | Used for |
|---|---|---|
| `ts` | **Yes** | Timestamp for window filtering and DNS IAT computation |
| `id.orig_h` | **Yes** | Source IP; matched against beacon channel src_ip |
| `query` | **Yes** | Queried domain name; DGA detection, period matching |
| `rcode_name` | No | Response code (NOERROR, NXDOMAIN…); H2 NXDomain rate |
| `answers` | No | Resolved IP addresses; H1 IP validation, H2 fast-flux detection |
| `TTLs` | No | DNS TTL values; H2 short-TTL / fast-flux detection |

---

### http.log — HTTP log (optional, enables H3 + H4)

Without this log, HTTP consistency and evasion hypotheses H3 and H4 do not fire. Weight is automatically redistributed to DNS hypotheses. Required for detecting unencrypted (port 80) C2.

**Zeek export command:**
```bash
zeek-cut ts id.orig_h id.resp_h uri user_agent method \
    request_body_len response_body_len status_code \
    < http.log > http.csv
```

| Zeek column | Required | Used for |
|---|---|---|
| `ts` | No | Window filtering |
| `id.orig_h` | **Yes** | Source IP; matched against beacon channel src_ip |
| `id.resp_h` | No | Destination IP; narrows match to the specific channel dst_ip |
| `uri` | No | H3 URI length CV and path CV; H4 high-entropy URI detection |
| `user_agent` | No | H4 rare UA (global frequency) and UA monotony detection |
| `method` | No | H4 abnormal HTTP method detection |
| `response_body_len` | No | H3 response body CV (trimmed) |
| `request_body_len` | No | Loaded but not currently scored (reserved for future H3 expansion) |
| `status_code` | No | Loaded but not currently scored |

---

### ssl.log — TLS/SSL log (optional, enables H5 + H6)

Without this log, TLS consistency and evasion hypotheses H5 and H6 do not fire. Critical for detecting HTTPS beacons where HTTP evidence is unavailable. Zeek generates this from `ssl` and `x509` analyzers.

**Zeek export command:**
```bash
zeek-cut ts id.orig_h id.resp_h server_name ja3 ja3s \
    cert_chain_fuids validation_status resumed established \
    < ssl.log > ssl.csv
```

| Zeek column | Required | Used for |
|---|---|---|
| `ts` | **Yes** | Timestamp for window filtering |
| `id.orig_h` | No* | Source IP; matched against beacon channel src_ip |
| `id.resp_h` | No | Destination IP; narrows match to channel dst_ip |
| `server_name` | No | H5 SNI stability; H6 absent SNI detection |
| `ja3` | No | H5 JA3 fingerprint monotony; H6 known C2 JA3 matching |
| `ja3s` | No | H5 JA3S server fingerprint |
| `cert_chain_fuids` | No | H5 certificate reuse across sessions |
| `validation_status` | No | H6 self-signed / validation-failing certificate detection |
| `resumed` | No | H6 high session resumption rate |
| `established` | No | Loaded; not currently scored |

\* `id.orig_h` is not marked required by the loader but without it no pair matching occurs and TLS scoring returns null results.

**Enabling JA3/JA3S in Zeek:** Requires loading the `ja3` package:
```bash
zkg install zeek/salesforce/ja3
```

---

### CSV export tips for real-world data

**From a live Zeek sensor:**
```bash
# Rotate and export last 30 days of logs
find /opt/zeek/logs -name "conn.*.log.gz" -mtime -30 \
    | xargs zcat | zeek-cut ts id.orig_h id.orig_p id.resp_h id.resp_p \
      proto service duration orig_bytes resp_bytes orig_pkts resp_pkts conn_state \
    > conn.csv
```

**From Zeek's TSV format:** Zeek's default log format is tab-separated with a `#fields` header line. Export with `zeek-cut` (shown above) or use `zeek-cut -d ,` for comma-separated output. Remove the `#` comment lines before ingesting.

**From a SIEM:** If your SIEM indexes Zeek logs using ECS (Elastic Common Schema) field names (`source.ip`, `destination.port`, `event.duration` etc.), CADENCE accepts those directly — `loaders.py` renames them automatically before processing.

**Timestamp format:** The pipeline expects `ts` as Unix float seconds (e.g. `1729123456.123`). If your export uses ISO 8601 strings, convert first:
```python
import pandas as pd
df = pd.read_csv("conn.csv")
df["ts"] = pd.to_datetime(df["ts"]).astype("int64") / 1e9
df.to_csv("conn.csv", index=False)
```

---



### Run the full pipeline with synthetic data

The simplest way to validate the pipeline end-to-end:

```bash
# Default: 30 days, 30k background rows/day, CLI output only
python run_full_scale.py

# With HTML report
python run_full_scale.py --report

# With report auto-opened in browser
python run_full_scale.py --report --browser

# Quick smoke test (5 days, smaller dataset)
python run_full_scale.py --days 5 --bg-rows 3000 --report

# Custom output directory
python run_full_scale.py --report --output /path/to/output
```

Synthetic data generation (conn, dns, http, **and ssl** logs), pipeline execution, ground-truth evaluation, and report generation all happen automatically in a single command.

### Run from Python

```python
from bdp_analytic import BDPPipeline, BDPConfig
from pathlib import Path

cfg = BDPConfig()
cfg.io.input_csv = Path("data/conn.csv")

art = BDPPipeline(cfg).run(
    dns_log_path  = "data/dns.csv",
    http_log_path = "data/http.csv",
    ssl_log_path  = "data/ssl.csv",   # optional: enables H5/H6 TLS corroboration
)

from bdp_analytic.corroboration import print_analyst_brief
print_analyst_brief(art.corroboration)
```

### Run with HTML report from Python

```python
from bdp_analytic.report import ReportContext

with ReportContext(output_dir="results", open_browser=True) as report:
    art = BDPPipeline(cfg).run(
        dns_log_path  = "data/dns.csv",
        http_log_path = "data/http.csv",
        ssl_log_path  = "data/ssl.csv",
    )
    report.finalise(art)
```

---

## CLI Reference

```
python run_full_scale.py [OPTIONS]

Options:
  --output      Output directory           (default: ./results)
  --days        Simulation days             (default: 30)
  --bg-rows     Background rows per day     (default: 30000)
  --noisy-rows  Noisy rows per day          (default: 1000)
  --seed        RNG seed                    (default: 42)
  --report      Generate HTML report        (off by default)
  --browser     Auto-open report in browser (off by default)
  --visualize   Render matplotlib plots     (off by default, slow)
```

---

## Configuration

Export the default configuration to a JSON file and edit as needed:

```python
from bdp_analytic import BDPConfig
BDPConfig().to_json("config.json")
```

Every tunable parameter is documented below with its default value and a justification explaining **why** that default was chosen. When deploying against your own traffic, use these justifications to decide whether the default fits your environment or needs adjustment.

---

### Channel Grouping (`pair`)

| Parameter | Default | Justification |
|---|---|---|
| `pair.min_pair_flows` | `8` | A channel needs at least 8 inter-arrival intervals to produce a meaningful SAX word and ACF correlogram. Fewer observations make periodicity estimation unreliable and inflate false positives. Aligned with `sax.min_observations` to prevent a dead-code gap where channels pass the flow gate but fail the SAX gate. |
| `pair.min_observations` | `8` | Mirrors `min_pair_flows` — this is the SAX-stage minimum. Channels with fewer than 8 observations produce SAX words shorter than one motif window, making symbolic regularity detection statistically unsound. |
| `pair.max_pairs` | `5000` | Safety cap that prevents the SAX and periodicity stages from becoming a runtime bottleneck. In 30-day enterprise windows with ~100k anomalous flows, IForest typically yields 10k–50k unique channels. The cap applies after sorting by flow count descending so the most data-rich (and therefore most detectable) channels are always evaluated first. Increase for very large deployments if runtime is acceptable. |

> **Channel key:** Channels are grouped by `(src_ip, dst_ip, dst_port, proto)` rather than the legacy `(src_ip, dst_ip)` pair. This prevents a single src→dst pair that beacons on port 443 from being diluted by unrelated traffic on port 80 to the same destination, producing a cleaner IAT sequence for periodicity analysis. The key is set in the feature engineering stage, not in `PairConfig`.

---

### Data Window (`io`)

| Parameter | Default | Justification |
|---|---|---|
| `io.query_start` | Auto-detected from data | Auto-detection uses the earliest timestamp in the conn log, ensuring no data is silently dropped by a misconfigured window. Override when you want to focus analysis on a specific incident timeframe. |
| `io.query_end` | Auto-detected from data | Auto-detection uses the latest timestamp. **30-day minimum windows are strongly recommended**: a 6-hour beacon produces only ~120 firings in 30 days, and ACF needs at least 2–3 full cycles at the dominant lag to produce a statistically significant peak. Shorter windows degrade recall for slow beacons. |
| `io.query_limit` | `1,000,000` | Row cap for SQL-based ingestion. Set high enough to cover 30 days × 30k rows/day with headroom for bursty traffic. Increase for high-volume sensors; decrease to limit memory on constrained systems. |

---

### Pre-Filter (`prefilter`)

These thresholds are defined as module-level constants in `prefilter.py` (not yet migrated to a `PrefilterConfig` dataclass).

| Parameter | Default | Justification |
|---|---|---|
| `dst_fanin_threshold` | `0.50` | A destination contacted by more than 50% of all unique source IPs in the dataset is almost certainly shared infrastructure (DNS resolver, proxy, CDN edge). C2 servers are contacted by one or a small number of infected hosts, not by half the network. Setting this below ~0.30 risks filtering C2 destinations in small networks; above ~0.70 lets shared services leak through. 0.50 balances these risks for medium-to-large enterprise networks. |
| `failed_conn_threshold` | `0.90` | If >90% of a channel's connection states are failure codes (S0, REJ, RSTO, etc.), the channel represents scanning, port probes, or dead services — not a functioning C2 link. Real C2 beacons require successful TCP handshakes to receive commands, so their failure rate is typically <10%. The 90% threshold is conservative: it only removes channels that are overwhelmingly failed, minimising the risk of filtering a C2 channel that experienced transient connectivity issues. |

---

### Isolation Forest (`isolation`)

| Parameter | Default | Justification |
|---|---|---|
| `isolation.n_estimators` | `200` | The number of isolation trees in the ensemble. 200 provides stable anomaly scores with low variance across runs — empirically, increasing beyond 200 yields diminishing improvements in score stability while linearly increasing fit time. For datasets with >100k channels, 200 is a good balance between computational cost and score reliability. The original scikit-learn default (100) showed higher run-to-run variance on our synthetic validation data. |
| `isolation.max_samples` | `3000` | The subsample size drawn per tree. Each tree trains on a random subsample to ensure diversity. 3000 is large enough to capture the distributional shape of 14 features across typical enterprise channel populations, but small enough to keep per-tree training fast. Increasing this provides diminishing benefit because IForest's power comes from ensemble diversity, not per-tree sample size. |
| `isolation.contamination` | `0.05` | The fraction of channels flagged as anomalous. Fixed at 5% rather than `"auto"` because `"auto"` (which uses a theoretical offset) produces unpredictable anomaly set sizes that vary with `max_samples` and data distribution. 5% ensures a known, bounded output size (~8k channels from ~166k) that downstream stages can process in reasonable time. On the synthetic dataset, 5% captures all 4 malicious scenarios with ample margin; on real traffic, tuning ±2% may be appropriate depending on the threat density. |
| `isolation.stability_threshold` | `0.80` | The minimum Jaccard overlap between anomalous sets from the train and test splits. If overlap falls below 80%, the anomaly boundary is unstable — small perturbations in the data produce materially different anomaly sets. This triggers a warning (not a halt) so the analyst knows the IForest results may not be reproducible. 80% is a pragmatic threshold: above it, the same channels would be flagged in most re-runs; below it, results are sensitive to random sampling. |
| `isolation.test_size` | `0.30` | The fraction of channels held out for stability checking. A 70/30 split provides enough training data for reliable tree construction while retaining a sufficiently large test set for meaningful Jaccard overlap measurement. |
| `isolation.random_state` | `42` | Fixed seed for reproducibility. Ensures identical anomaly scores across runs on the same dataset, which is critical for pipeline validation and debugging. |

---

### SAX Pre-Screening (`sax`)

SAX is an intentionally permissive filter — its job is to cheaply eliminate clearly non-periodic channels before the expensive ACF + Welch PSD analysis, not to make final beacon decisions.

| Parameter | Default | Justification |
|---|---|---|
| `sax.alphabet_size` | `4` | Four symbols (a, b, c, d) map IAT values to quartiles of the normal distribution via breakpoints at z = {-0.67, 0, 0.67}. This is the standard SAX alphabet size from the original Lin et al. (2003) formulation. Smaller alphabets (2–3) lose sensitivity to moderate jitter patterns; larger alphabets (6+) overfit to noise in short IAT sequences and increase the motif search space exponentially. |
| `sax.word_length` | `20` | The number of SAX symbols per channel's IAT time series. 20 provides enough resolution to detect 2–3 repetitions of a motif pattern in a typical 30-day beacon sequence (e.g., a 1-hour beacon produces ~720 observations, piecewise-aggregated into 20 symbols). Shorter words lose temporal resolution; longer words become sparse and increase false negatives from jitter-induced symbol variation. |
| `sax.cv_threshold` | `0.60` | If a channel's IAT coefficient of variation exceeds 0.60, its inter-arrival times are too dispersed to be periodic, and SAX symbolic analysis would produce noise. This threshold is shared with the downstream periodicity stage (`periodicity.cv_threshold`) for consistency — a channel that fails the CV gate at SAX would also fail at periodicity, so early elimination saves computation. 0.60 accommodates typical C2 jitter (5–15% of the base period) while filtering genuinely aperiodic traffic. |
| `sax.acf_threshold` | `0.30` | Minimum lag-1 autocorrelation in the SAX-encoded symbol sequence. Periodic signals produce strong positive autocorrelation at the dominant lag; aperiodic signals hover near zero. 0.30 is deliberately lower than the downstream `periodicity.acf_significance_threshold` (0.25, applied to the raw ACF) because SAX discretization attenuates autocorrelation strength. |
| `sax.motif_threshold` | `0.40` | Fraction of SAX word positions that must participate in a repeated motif. If fewer than 40% of the symbols form a recognizable repeating pattern, the channel lacks the sustained regularity characteristic of beaconing. This catches channels with a brief periodic burst amid otherwise random traffic. |
| `sax.min_tests_passing` | `2` | Of the three SAX sub-tests (CV gate, autocorrelation, motif frequency), at least 2 must pass. Requiring all 3 is too strict and misses jittered beacons; requiring only 1 is too permissive and passes noisy channels through to the expensive periodicity stage. 2-of-3 is a majority-vote rule that tolerates one weak indicator. |
| `sax.min_observations` | `8` | Aligned with `pair.min_pair_flows`. Channels with fewer than 8 IAT observations cannot produce a meaningful 20-symbol SAX word (each symbol would aggregate <0.5 observations on average), making all sub-tests unreliable. |
| `sax.max_acf_lag` | `10` | Maximum lag for SAX-level autocorrelation. Limited to 10 (rather than the full word length) because SAX autocorrelation is a screening heuristic, not a precise period estimator. Lags beyond 10 in a 20-symbol word have very few sample pairs, producing noisy estimates. |

---

### Periodicity (`periodicity`)

| Parameter | Default | Justification |
|---|---|---|
| `periodicity.min_observations` | `10` | Minimum IAT observations for reliable ACF and Welch PSD computation. With fewer than 10 inter-arrival times, ACF peak height is dominated by sampling noise, and the Welch spectral estimate has too few segments to resolve frequency peaks. 10 is slightly above the `pair.min_pair_flows` gate (8) to provide an additional safety margin. |
| `periodicity.acf_nlags` | `20` | Maximum number of lags computed in the binned-count autocorrelation. **Note:** The README previously recommended 40 for slow beacon coverage, but the current codebase default is 20. For beacons with periods >2 hours, increasing to 40 ensures the ACF window spans at least 2 full cycles at the dominant lag. When using 30-day windows with minute-level binning, 40 lags is computationally negligible. Consider overriding to 40 for deployments that must detect 6h+ beacons. |
| `periodicity.acf_significance_threshold` | `0.25` | Minimum height for the dominant ACF peak to be considered statistically significant. In white noise, ACF peaks at lag k follow approximately N(0, 1/N); for a 100-observation sequence, the 95% confidence bound is ~0.20. Setting the threshold at 0.25 provides a small margin above the noise floor, filtering spurious peaks while retaining beacons with moderate jitter (CV ~0.15–0.30). Lowering below 0.20 admits noise-driven false positives; raising above 0.40 misses heavily jittered beacons. |
| `periodicity.cv_threshold` | `0.60` | Maximum IAT coefficient of variation for a channel to be considered periodic. Shared with `sax.cv_threshold` for pipeline consistency. A beacon with 10% jitter on a 300s period has CV ≈ 0.10; even aggressive 30% jitter gives CV ≈ 0.30. A CV of 0.60 accommodates beacons with significant jitter while filtering genuinely random connection patterns. |
| `periodicity.fft_power_ratio_threshold` | `0.15` | Minimum fraction of total spectral power concentrated in the dominant Welch PSD frequency bin. Periodic signals concentrate power at their fundamental frequency; white noise distributes power uniformly across all bins. For N=50 frequency bins, uniform distribution gives ~2% per bin, so 15% represents a ~7.5× concentration above the noise floor. This is permissive enough to catch beacons whose power is split between fundamental and harmonics, while filtering channels with no clear spectral peak. |
| `periodicity.min_period_s` | `60` | Periods shorter than 60 seconds are filtered because sub-minute intervals overlap heavily with legitimate keepalive traffic (TCP keepalives at 30s, DNS TTL refreshes, health checks). Below this threshold, the false positive rate from automated infrastructure dominates. Adjust downward if your threat model includes high-frequency C2 (e.g., interactive shells), but expect significantly more false positives. |
| `periodicity.confidence_threshold` | `0.45` | The composite beacon confidence score that gates entry to downstream stages (PELT, corroboration). The score is a weighted combination of ACF peak strength, spectral concentration, and IAT regularity. 0.45 was empirically tuned on the synthetic dataset to pass all 4 malicious scenarios while rejecting both decoys. Lowering to ~0.35 increases recall at the cost of more false candidates reaching corroboration; raising to ~0.55 risks missing slow beacons (e.g., `exfil_slow`) that produce weaker periodicity signals due to fewer observations. |

---

### PELT Changepoint Detection (`pelt`)

| Parameter | Default | Justification |
|---|---|---|
| `pelt.penalty` | `"bic"` | Bayesian Information Criterion penalty for the PELT cost function. BIC balances model complexity against fit quality, naturally adapting to the sequence length — longer sequences tolerate more changepoints while shorter ones are penalised for overfitting. BIC is preferred over fixed penalties because beacon IAT sequences vary widely in length (tens to thousands of observations). A fixed penalty that works for a 100-observation sequence would either over-segment or under-segment a 1000-observation sequence. |
| `pelt.min_segment_length` | `5` | Minimum number of observations between consecutive changepoints. Prevents the algorithm from detecting spurious micro-changes caused by a few jittered intervals. A beacon that shifts its period needs at least 5 observations at the new rate to be distinguishable from noise. This also prevents O(N²) blowup in pathological cases. |
| `pelt.min_observations` | `15` | Channels with fewer than 15 IAT observations skip changepoint analysis entirely. PELT needs enough data to estimate both the pre-change and post-change distributions — with `min_segment_length=5`, a single changepoint requires at least 10 observations (5 per segment), and 15 provides a reasonable margin for the BIC penalty to distinguish signal from noise. |
| `pelt.max_changepoints` | `10` | Hard cap on detected changepoints per channel. Real C2 operators rarely reconfigure beacon intervals more than a handful of times per campaign. More than 10 changepoints almost certainly indicates noisy, non-stationary traffic rather than operator interaction. The cap also bounds PELT's output size for downstream processing. |

---

### Corroboration (`corroboration`)

| Parameter | Default | Justification |
|---|---|---|
| `corroboration.period_tolerance_pct` | `0.15` | Maximum relative difference between the beacon period estimated from conn log ACF and the DNS query period estimated from H1. A 15% tolerance accommodates clock drift, network delay variation, and the fact that DNS caching may shift the observed query interval slightly. Tighter tolerances (5%) produce false negatives when jitter desynchronises the two measurements; looser tolerances (30%) admit coincidental period matches from unrelated DNS traffic. |
| `corroboration.dga_entropy_threshold` | `3.5` | Shannon entropy of the domain's second-level label above which the domain is flagged as DGA-generated. Legitimate domains (e.g., "google", "amazon") have entropy ~2.5–3.2; DGA domains (e.g., "nmg5kr6dcjttx") typically have entropy ~3.8–4.5. The 3.5 threshold sits in the gap between these distributions. Combined with consonant-run and digit-run heuristics, this reduces false positives from legitimate high-entropy domains (e.g., CDN hashes like "d3fy1a2r0.cloudfront.net"). |
| `corroboration.dga_min_label_len` | `8` | Minimum length of the second-level domain label for DGA analysis to apply. Short labels (< 8 chars) don't have enough characters to produce reliable entropy estimates — a 5-character label with all unique characters has entropy ~2.3, overlapping with the legitimate range. Skipping short labels prevents false DGA flags on domains like "t.co" or "goo.gl". |
| `corroboration.short_ttl_threshold_s` | `300` | DNS TTL below which the response is flagged as short-lived, indicative of fast-flux infrastructure. Legitimate authoritative DNS typically uses TTLs of 300s–86400s. C2 infrastructure using fast-flux DNS rotation sets TTLs to 60–300s to enable rapid IP changes. The 300s threshold captures aggressive fast-flux while excluding normal CDN TTLs (which often sit at 300s exactly). |
| `corroboration.http_body_cv_threshold` | `0.30` | Maximum coefficient of variation of HTTP response body lengths for H3 (consistency) to fire. C2 polling responses tend to have uniform payload sizes (CV < 0.10) because the implant receives the same "no tasking" response repeatedly. Legitimate web browsing produces highly variable body sizes (CV > 1.0). The 0.30 threshold admits some variation from C2 protocols that embed variable-length metadata while filtering clearly non-uniform traffic. |
| `corroboration.http_uri_cv_threshold` | `0.40` | Maximum CV of URI lengths for H3 consistency. C2 implants often use fixed or templated URIs (e.g., `/api/check`, `/beacon/status`) producing low CV. Legitimate browsing hits many different URI paths. 0.40 is slightly more permissive than the body CV threshold because URI templates with variable parameters (e.g., session tokens) produce more length variation than body payloads. |
| `corroboration.rare_ua_threshold` | `0.05` | A User-Agent string that appears in fewer than 5% of all HTTP requests in the dataset is classified as "rare" for H4 (evasion). C2 implants often use hardcoded or absent UAs that don't match the deployment's browser population. 5% is low enough to flag unusual implant UAs while excluding legitimate minority browsers (e.g., mobile Safari, curl for health checks) that typically exceed 5% in enterprise traffic. |
| `corroboration.uri_entropy_threshold` | `4.0` | Shannon entropy of the URI string above which H4 flags it as potentially obfuscated. Base64-encoded C2 commands in URIs produce entropy ~4.5–5.5; normal URIs like `/index.html` have entropy ~3.0–3.5. The 4.0 threshold catches encoded payloads while passing through typical API paths with some parameter variation. |
| `corroboration.min_score` | `0.35` | Minimum weighted corroboration score to confirm a lead. This is the final decision threshold — channels below 0.35 are filtered as unconfirmed. The score combines DNS (H1/H2), HTTP (H3/H4), and TLS (H5/H6) evidence with adaptive weights. 0.35 was tuned to confirm all 4 malicious synthetic scenarios (including `exfil_slow`, which scores near this threshold due to limited DGA and HTTP evidence) while rejecting both decoys. On real traffic, raising to 0.40–0.45 reduces false positives at the cost of potentially missing low-evidence beacons. |

---

### TLS Corroboration (`corroboration.tls`)

> **Implementation note:** The parameters below are documented as the target TLS corroboration configuration. In the current codebase, some of these are hardcoded in `corroboration.py` rather than exposed as a `TLSCorroborationConfig` dataclass. A future refactor will migrate them to a typed config for consistency with other stages.

| Parameter | Default | Justification |
|---|---|---|
| `tls.ja3_monotony_threshold` | `0.90` | Fraction of TLS sessions using the same JA3 fingerprint above which the channel is flagged as monotonic (H5). Legitimate browsers negotiate different cipher suites depending on server support, session caching, and TLS version upgrades — producing JA3 diversity. C2 implants use a single hardcoded TLS stack, producing near-100% JA3 monotony. 0.90 allows for minor variation from session resumption or library updates while flagging the overwhelming uniformity characteristic of implants. |
| `tls.sni_entropy_threshold` | `1.0` | Shannon entropy of SNI (Server Name Indication) values above which H6 flags DGA-like hostnames. A channel that always connects to the same SNI has entropy 0; one that rotates through DGA-generated hostnames has high entropy. The 1.0 threshold catches channels that use even 2–3 distinct SNIs (entropy ~1.0–1.6), which is unusual for a single src→dst channel and suggests domain rotation. |
| `tls.cert_reuse_min_sessions` | `3` | Minimum number of TLS sessions reusing the same certificate chain before H5 flags certificate reuse. C2 servers typically serve the same self-signed or cheaply-obtained certificate across all beacon connections. Requiring 3 sessions (rather than 2) prevents false positives from short-lived connections that happen to share a certificate due to session caching. |
| `tls.ja3_known_c2` | See config | Tuple of known C2 JA3 fingerprint MD5 hashes (e.g., Cobalt Strike, Metasploit default profiles). Matching any of these triggers H6. This is a signature-based check layered on top of the behavioral analysis — it catches known toolkits even when their behavioral patterns are otherwise unremarkable. The list should be updated periodically from public threat intelligence (e.g., JA3er.com, Salesforce's JA3 repository). |

---

### Triage Scoring (`triage`)

| Parameter | Default | Justification |
|---|---|---|
| `triage.beaconing_std_thresh` | `0.5` | Maximum IAT standard deviation (in units of the mean) for a channel to receive the beaconing regularity score bonus. Channels with IAT std < 50% of the mean are highly regular and receive higher priority. |
| `triage.rare_dst_thresh` | `25` | If a destination IP is contacted by fewer than 25 unique sources, it receives a "rare destination" score bonus. C2 servers are typically contacted by 1–5 infected hosts; shared infrastructure is contacted by hundreds. |
| `triage.high_volume_pct` | `0.05` | Channels in the top 5% by flow count receive a volume bonus. High-volume channels are more suspicious because C2 beacons produce many small flows over time. |
| `triage.off_hour_range` | `(6, 22)` | Hours 06:00–22:00 are considered "business hours." Channels with significant activity outside this range receive an off-hours bonus, as C2 beacons operate 24/7 regardless of business schedules. |

---

### Corroboration Weight Tiers (adaptive, not configurable)

Weights are redistributed automatically based on which log types are available, so that channels are not penalised for missing evidence:

| Evidence available | DNS weight | HTTP weight | TLS weight | Rationale |
|---|---|---|---|---|
| DNS + HTTP + TLS | 0.30 | 0.30 | 0.20 | Full evidence. TLS weighted slightly lower because H5/H6 overlap partially with H3/H4 indicators. Remaining 0.20 comes from conn-log periodicity (always available). |
| DNS + HTTP only | 0.20 (boolean) | 0.20 (boolean) | — redistributed | No TLS log means no H5/H6; the 0.20 TLS weight is redistributed equally to DNS and HTTP so the maximum achievable score remains the same. |
| DNS + TLS only | 0.40 | — redistributed | 0.40 | No HTTP log (common for HTTPS-only C2). DNS and TLS share the HTTP weight equally, reflecting that both provide independent evidence of C2 behavior. |
| DNS only | 0.45 | — | — | Only conn + DNS available. DNS carries the full protocol-layer weight. The channel can still be confirmed via strong H1 + H2 evidence combined with conn-log periodicity. |

---

## Output Files

| File | Description |
|---|---|
| `priority.csv` | All channels ranked by priority score (beacon confidence + payload stability + persistence) |
| `periodicity.csv` | Per-channel periodicity metrics: ACF peak, IAT CV, dominant period, beacon confidence |
| `sax_screening.csv` | SAX pre-screening results: which channels passed symbolic regularity check |
| `changepoints.csv` | PELT changepoint results: estimated beacon start times, interval shifts |
| `corroboration.csv` | Final confirmed leads with full H1–H6 hypothesis results, corroboration score, and MITRE ATT&CK annotations |
| `run_summary.json` | Machine-readable summary of pipeline funnel counts and runtime |
| `cadence_report.html` | Interactive HTML dashboard (with `--report` flag) |

### Analyst brief (terminal output)

For each corroborated channel CADENCE prints a structured evidence chain:

```
======================================================================
  BEACON ANALYTIC -- TOP 4 CORROBORATED CANDIDATES
======================================================================

  #1  10.0.2.100 -> 203.0.113.55  (2898 flows)
  ────────────────────────────────────────────────────────────
  Beacon period     : 898s  (15.0 min)
  Beacon confidence : 0.925  Corroboration score: 0.690

  DNS evidence:
    H1 Regularity  ✗  DNS period=0s  (Δ=100.0% vs conn period)
    H2 Anomaly     ✓  DGA=10  NXD=892 (32.1%)  ShortTTL=0  FastFlux=0
             DGA candidate: nmg5kr6dcjttx.com

  HTTP evidence:
    H3 Consistency ✗  body_CV=nan  uri_CV=nan  path_CV=nan
    H4 Evasion     ✗  rare_UA=False  ua_monotony=False

  TLS evidence:
    H5 Consistency ✓  sni_stable=False  ja3_monotonic=True  cert_reused=True
    H6 Evasion     ✓  self_signed=False  known_ja3=False  absent_sni=True  high_resume=True
```

### HTML Report

The `--report` flag generates an interactive dashboard with:

- Pipeline flow visualization with funnel counts at each stage
- Triage summary table with severity ratings (CRITICAL / HIGH / MEDIUM) and H1–H6 evidence badges
- Evidence cards per lead: infected host, C2 destination, channel key (port/proto), H1–H6 hypothesis results, score breakdown, suggested next steps
- Operator interaction warnings when PELT detects beacon interval shifts
- Diagnostic plot gallery (with `--visualize`)
- CSV download buttons for all pipeline output tables

---

## IForest Feature Set

CADENCE uses 14 channel-level features for Isolation Forest scoring:

| Feature | Description | C2 signal |
|---|---|---|
| `log_n_flows` | log(1 + flow count) | Beacons produce many small flows |
| `iat_cv` | IAT coefficient of variation | Low CV = regular schedule |
| `iat_log_mean` | log(1 + mean IAT) | Encodes beacon period scale |
| `iat_mad_s` | IAT median absolute deviation | Robust jitter measure |
| `iat_ratio` | Median / mean IAT | Near 1.0 = symmetric distribution |
| `missing_beat_rate` | Fraction of expected slots with no connection | Beacons rarely miss |
| `persistence_ratio` | Fraction of window days with activity | Beacons active every day |
| `bytes_cv` | CV of destination bytes per flow | Uniform polling payloads |
| `req_resp_asymmetry` | \|src_bytes - dst_bytes\| / total | C2 polling: near 0; exfil: near 1 |
| `zero_payload_frac` | Fraction of zero-byte flows | Keepalive/heartbeat signals |
| `duration_cv` | CV of flow duration | Uniform connection duration |
| `conn_state_entropy` | Shannon entropy of connection states | Single outcome = automated |
| `sin_time_mean` | Mean sin(time-of-day) | Time clustering |
| `cos_time_mean` | Mean cos(time-of-day) | Time clustering |

---

## Synthetic Test Scenarios

The generator injects six scenarios into 30 days of realistic background traffic, including correlated **conn, dns, http, and ssl logs**:

| Scenario | Type | Period | Key Signals |
|---|---|---|---|
| `fast_https_dga` | **Malicious** | 5 min | DGA domains, short TTL, absent SNI, monotonic JA3, high session resumption |
| `slow_http_fixed` | **Malicious** | 1 hr | Fixed domain, outdated UA, uniform HTTP payloads |
| `multi_host_campaign` | **Malicious** | 15 min | DGA, NXDomain misses, absent UA, absent SNI |
| `exfil_slow` | **Malicious** | 6 hr | Large variable payload, plausible-looking domain, monotonic JA3 |
| `decoy_windows_update` | **Decoy** | 1 hr | Benign domain and UA — should **not** be confirmed |
| `decoy_ntp` | **Decoy** | ~17 min | NTP polling, no HTTP — should **not** be confirmed |

**Expected result at full scale (30 days, 30k bg/day):** Precision 1.000, Recall 1.000, F1 1.000. All 4 malicious scenarios detected, both decoys filtered at the corroboration stage.

---

## Module Reference

| Module | Stage | Description |
|---|---|---|
| `config.py` | — | Typed dataclass configuration. Sub-configs for each pipeline stage including `PrefilterConfig` and `TLSCorroborationConfig`. |
| `loaders.py` | 1 | CSV ingest. Schema normalisation, feature engineering. |
| `features.py` | 2 | Channel-level feature aggregation (14 IForest features), StandardScaler. Key: `(src_ip, dst_ip, dst_port, proto)`. |
| `prefilter.py` | 3 | Domain-knowledge pre-filter. RFC 1918, CDN/DNS/NTP infra, fanin, dead connections. Thresholds from `PrefilterConfig`. |
| `isolation.py` | 4 | Isolation Forest fit on channel features, stability check, HHI concentration analysis. |
| `sax_screening.py` | 5 | SAX symbolic pre-screening on inter-arrival time sequences. Channel-key aware. |
| `periodicity.py` | 6 | Binned-count ACF and Welch PSD. Jitter-robust beacon confidence scoring (acf_nlags raised to 40). |
| `scoring.py` | 7 | Channel priority scoring: beacon confidence × 4 + payload stability × 2 + persistence × 2 + period agreement × 1 + temporal × 1. |
| `changepoint.py` | 8 | PELT changepoint detection for beacon start time and interval shifts. Channel-key aware. |
| `corroboration.py` | 9 | DNS (H1–H2), HTTP (H3–H4), and TLS (H5–H6) hypothesis testing. Adaptive weight redistribution. Analyst brief. |
| `mitre_mapping.py` | 10 | Evidence-based MITRE ATT&CK technique annotation on corroborated leads. |
| `pipeline.py` | — | `BDPPipeline.run()` orchestrator. Sequences all 10 stages. Accepts `ssl_log_path`. |
| `report.py` | — | Self-contained HTML report generator. H1–H6 evidence cards, channel key display, TLS score pills. |
| `generate_synthetic_data.py` | — | Synthetic Zeek log generator (conn + dns + http + ssl). Ground-truth labels for pipeline validation. |

---

## MITRE ATT&CK Coverage

Each corroborated lead is automatically annotated with evidence-based ATT&CK technique mappings. Every mapping is derived directly from pipeline evidence — no external threat intelligence feeds required.

| Technique ID | Name | Tactic | Triggered By |
|---|---|---|---|
| T1029 | Scheduled Transfer | Exfiltration | Every corroborated lead with a confirmed beacon interval |
| T1041 | Exfiltration Over C2 Channel | Exfiltration | Corroborated lead with > 500 flows over the beacon channel |
| T1071.001 | Application Layer Protocol: Web Protocols | Command and Control | H3 (stereotyped HTTP patterns) or H4 (non-standard HTTP methods) |
| T1071.004 | Application Layer Protocol: DNS | Command and Control | H1 (DNS period matches beacon period) or NXDomain responses |
| T1568.001 | Dynamic Resolution: Fast Flux DNS | Command and Control | H2 short DNS TTLs |
| T1568.002 | Dynamic Resolution: Domain Generation Algorithms | Command and Control | H2 DGA detection (entropy + consonant-run + digit-run heuristics) |
| T1573 | Encrypted Channel | Command and Control | Confirmed periodic beacon with no HTTP evidence (HTTPS/TLS) |
| T1571 | Non-Standard Port | Command and Control | PELT-detected beacon interval shift (operator reconfiguration) |
| T1001 | Data Obfuscation | Command and Control | H4 high-entropy URI |
| T1132 | Data Encoding | Command and Control | H4 high-entropy URI |
| T1036 | Masquerading | Defense Evasion | H4 rare or absent User-Agent string |

**Coverage gaps** (noted for completeness): T1090 proxy/redirector chaining, T1102 web service C2, and T1219 remote access tools are not covered — these require log sources beyond Zeek conn/dns/http/ssl. Initial access and lateral movement techniques are out of scope for network beacon detection.

---



- **Encrypted C2 without SSL log:** H5 and H6 will not fire without a `ssl.log`. H3 and H4 will not fire without an `http.log`. Absent log types redistribute weight to DNS hypotheses — the channel is not penalised. For fully DNS-only detection, the pipeline still surfaces beacons via H1/H2 and conn log periodicity.
- **Sub-minute beacons:** Intervals below 60 seconds are filtered by default (`periodicity.min_period_s`). Adjust if your threat model requires it, but expect more false positives from legitimate keepalive traffic.
- **Slow fixed-C2 beacons at short observation windows:** Beacons with 6-hour intervals produce only ~4 firings/day. At 5-day windows, the IAT sequence may be too short for reliable ACF detection. Use 30-day windows for full coverage.
- **Slow fixed-C2 at minimum threshold:** `exfil_slow` (6h interval) corroborates at approximately the `min_score` threshold due to limited DGA and HTTP evidence. This is expected behavior for slow, fixed-domain beacons and is documented as a known limitation.
- **No threat intelligence enrichment:** A beacon to a newly-registered domain without DGA characteristics may score lower than expected. Integrating a passive DNS or TI feed would strengthen H2 coverage.
- **Synthetic-only validation:** Pipeline performance is validated against synthetic ground truth. Real-traffic F1 depends on the threat mix and log completeness in the deployment environment.
- **Channel key and prefilter on synthetic data:** The high-fanin filter may disable itself on synthetic data where all background sources contact the same small destination pool. On real enterprise data with diverse destinations, it operates normally.

---

## License

MIT
