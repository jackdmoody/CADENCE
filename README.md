# CADENCE
### C2 Anomaly Detection via Ensemble Network Correlation Evidence

> A multi-stage behavioral analytic for detecting C2 beaconing in network telemetry. Reduces hundreds of thousands of connection log events to a small set of high-confidence, analyst-actionable leads by sequencing independent detection techniques — each answering a question the previous stage cannot.

---

## The Problem

C2 beacons are designed to look normal. A single beacon connection has unremarkable byte counts, a standard port, and a plausible connection state. No threshold or signature catches it. What makes a beacon detectable is its **behavior over time**: it fires on a fixed schedule, to the same destination, with uniform payloads, and leaves correlated evidence across multiple protocol layers simultaneously.

CADENCE is built around that observation. It doesn't look for a single anomalous flow — it looks for the pattern that only automated, scheduled, malicious processes produce.

---

## How It Works

Each stage answers a specific question that the previous stage cannot:

```
Zeek conn.log  (30 days, ~30k rows/day)
      │
      ▼
┌─────────────────────────────────────────────────────────────────┐
│  Stage 1–2 — Ingest, Feature Engineering & Scaling              │
│  Schema normalisation · Pair-level aggregation · StandardScaler │
│  945k flows → 166k (src, dst) pairs                            │
└─────────────────────────────────────────────────────────────────┘
      │
      ▼  Question: Which pairs are obviously benign?
┌─────────────────────────────────────────────────────────────────┐
│  Stage 3 — Domain-Knowledge Pre-Filter                          │
│  RFC 1918 internal-to-internal · Known CDN/DNS/NTP infra        │
│  High-fanin shared services · Dead connection states            │
│  ~0.5–5% of pairs removed                                      │
└─────────────────────────────────────────────────────────────────┘
      │
      ▼  Question: Which pairs are volumetrically anomalous?
┌─────────────────────────────────────────────────────────────────┐
│  Stage 4 — Isolation Forest                                     │
│  Joint multivariate anomaly scoring on 8 pair-level features    │
│  Stability validation · HHI concentration analysis              │
│  ~5% of pairs pass through                                     │
└─────────────────────────────────────────────────────────────────┘
      │
      ▼  Question: Does this pair's timing show symbolic regularity?
┌─────────────────────────────────────────────────────────────────┐
│  Stage 5 — SAX Pre-Screening                                    │
│  Symbolic Aggregate approXimation on inter-arrival times        │
│  Fast O(N) elimination of non-periodic pairs                    │
│  ~35% of anomalous pairs pass through                          │
└─────────────────────────────────────────────────────────────────┘
      │
      ▼  Question: Is this pair statistically periodic?
┌─────────────────────────────────────────────────────────────────┐
│  Stage 6 — Binned-Count ACF + Welch PSD Periodicity Analysis    │
│  Per-pair IAT autocorrelation (binned for jitter robustness)    │
│  Spectral density estimation · Beacon interval estimation       │
│  Composite beacon confidence scoring (threshold ≥ 0.45)        │
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
│  Stage 9 — Multi-Source Corroboration (H1–H4)                   │
│  DNS regularity · DGA / NXDomain / short-TTL detection          │
│  HTTP behavioral consistency · Evasion indicator analysis       │
│  Benign service filtering · ~1–5 high-confidence leads          │
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
  Analyst Brief — corroborated pairs with full evidence chain
                  and ATT&CK technique annotations
```

### Why this sequence

| Stage | Technique | Beacon property tested | Why the previous stage couldn't answer this |
|---|---|---|---|
| Pre-Filter | Domain knowledge allowlists | Is it obviously benign infrastructure? | Without removing known-benign internal and infrastructure pairs first, IForest wastes its anomaly budget on traffic that could never be C2. |
| Isolation Forest | Ensemble anomaly scoring | Is it volumetrically unusual? | Thresholding on individual features misses multivariate anomalies. A beacon with moderate bytes AND moderate duration AND moderate frequency looks normal on any single axis. |
| SAX Pre-Screening | Symbolic time-series encoding | Does its timing show regularity? | IForest scores feature distributions, not temporal patterns. A pair can be volumetrically anomalous but completely aperiodic. SAX eliminates these cheaply before expensive ACF. |
| Binned-Count ACF + Welch PSD | Spectral periodicity analysis | Is it statistically periodic with quantifiable confidence? | SAX is a fast heuristic filter, not a statistical test. Two pairs can both pass SAX but one has a weak, noisy pattern and the other has a strong, jitter-tolerant periodicity. ACF + PSD provides the confidence score. |
| PELT Changepoint | Changepoint detection | When did it start? Did the operator interact? | Periodicity analysis confirms the beacon exists but doesn't tell you when it activated or whether the interval shifted mid-campaign (indicating a human operator reconfiguring the implant). |
| DNS + HTTP Corroboration | Cross-layer hypothesis testing | Is it C2 specifically, not just automated? | Periodicity alone cannot distinguish C2 beacons from Windows Update, NTP, or health monitors. Requiring correlated DNS anomaly and HTTP evasion signatures filters legitimate automated services. |
| MITRE ATT&CK Mapping | Evidence-to-technique annotation | What tradecraft does this represent? | Corroboration confirms a lead is malicious, but doesn't tell the analyst which ATT&CK techniques are in play or how to frame the finding for incident response handoff. |

---

## Installation

```bash
# Clone and create a virtual environment
git clone https://github.com/yourname/CADENCE.git
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

## Quick Start

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
python run_full_scale.py --report --output C:\Users\me\Desktop\cadence_run
```

Synthetic data generation, pipeline execution, ground-truth evaluation, and report generation all happen automatically in a single command.

### Run from Python

```python
from bdp_analytic import BDPPipeline, BDPConfig
from pathlib import Path

cfg = BDPConfig()
cfg.io.input_csv = Path("data/conn.csv")

art = BDPPipeline(cfg).run(
    dns_log_path  = "data/dns.csv",
    http_log_path = "data/http.csv",
)

# Final analyst-actionable output
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

Without `--report`, the pipeline prints all results to the terminal. With `--report`, it additionally generates a self-contained HTML dashboard.

---

## Configuration

Export the default configuration to a JSON file and edit as needed:

```python
from bdp_analytic import BDPConfig
BDPConfig().to_json("config.json")
```

Key parameters by stage:

**Data Window**
| Parameter | Default | Notes |
|---|---|---|
| `io.query_start` | Auto-detected | Set to your window start |
| `io.query_end` | Auto-detected | 30-day windows are the recommended minimum. Slow beacons (6h, 24h intervals) need enough firings to produce reliable ACF peaks. |

**Isolation Forest**
| Parameter | Default | Notes |
|---|---|---|
| `isolation.n_estimators` | `200` | Higher = more stable scores, slower fit |
| `isolation.contamination` | `0.05` | Fraction of pairs flagged anomalous |
| `isolation.stability_threshold` | `0.80` | Warn if train/test score agreement falls below this |

**SAX Pre-Screening**
| Parameter | Default | Notes |
|---|---|---|
| `sax.alphabet_size` | `4` | Number of SAX symbols |
| `sax.word_length` | `20` | Length of SAX word per pair |
| `sax.cv_threshold` | `0.60` | IAT CV above this → not periodic |
| `sax.min_tests_passing` | `2` | Minimum sub-tests to pass SAX gate |

**Periodicity**
| Parameter | Default | Notes |
|---|---|---|
| `periodicity.min_observations` | `10` | Minimum IAT sequence length for ACF to be meaningful |
| `periodicity.acf_nlags` | `20` | Maximum ACF lags to compute |
| `periodicity.acf_significance_threshold` | `0.25` | Minimum ACF peak height |
| `periodicity.cv_threshold` | `0.60` | Max coefficient of variation to flag as periodic |
| `periodicity.fft_power_ratio_threshold` | `0.15` | Minimum spectral concentration at dominant frequency |
| `periodicity.min_period_s` | `60` | Ignore sub-minute intervals |
| `periodicity.confidence_threshold` | `0.45` | Composite score to flag a pair as a beacon candidate |

**Corroboration**
| Parameter | Default | Notes |
|---|---|---|
| `corroboration.dga_entropy_threshold` | `3.5` | Shannon entropy threshold for DGA classification |
| `corroboration.short_ttl_threshold_s` | `300` | DNS TTL below which fast-flux is flagged |
| `corroboration.rare_ua_threshold` | `0.05` | UA frequency threshold for rare UA detection |
| `corroboration.min_score` | `0.35` | Minimum corroboration score to confirm a lead |

**Corroboration scoring weights** (hardcoded in `corroboration.py`):
| Hypothesis | Weight (with HTTP) | Weight (HTTPS-only) |
|---|---|---|
| H1 DNS regularity | 0.25 | 0.35 |
| H2 DNS anomaly | 0.35 | 0.65 |
| H3 HTTP consistency | 0.20 | — (redistributed to DNS) |
| H4 HTTP evasion | 0.20 | — (redistributed to DNS) |

When no HTTP log entries exist for a pair (HTTPS/TLS beacons), HTTP weight is automatically redistributed to DNS hypotheses so the pair isn't penalised for using encrypted transport.

---

## Output Files

| File | Description |
|---|---|
| `priority.csv` | All pairs ranked by priority score (heuristic + periodicity) |
| `periodicity.csv` | Per-pair periodicity metrics: ACF peak, IAT CV, dominant period, beacon confidence |
| `sax_screening.csv` | SAX pre-screening results: which pairs passed symbolic regularity check |
| `changepoints.csv` | PELT changepoint results: estimated beacon start times, interval shifts |
| `corroboration.csv` | Final confirmed leads with full H1–H4 hypothesis results, corroboration score, and MITRE ATT&CK annotations |
| `run_summary.json` | Machine-readable summary of pipeline funnel counts and runtime |
| `cadence_report.html` | Interactive HTML dashboard (with `--report` flag) |

### Analyst brief (terminal output)

For each corroborated pair CADENCE prints a structured evidence chain:

```
======================================================================
  BEACON ANALYTIC — TOP 4 CORROBORATED CANDIDATES
======================================================================

  #1  10.0.2.100 → 203.0.113.55  (2898 flows)
  ────────────────────────────────────────────────────────────
  Beacon period     : 898s  (15.0 min)
  Beacon confidence : 0.925  Corroboration score: 0.690

  DNS evidence:
    H1 Regularity  ✗  DNS period=0s  (Δ=100.0% vs conn period)
    H2 Anomaly     ✓  DGA=10  NXD=892  ShortTTL=0
             DGA candidate: nmg5kr6dcjttx.com
             DGA candidate: t1q4ygb10c74dw.com

  HTTP evidence:
    H3 Consistency ✓  body_CV=0.081  uri_CV=0.000
    H4 Evasion     ✓  rare_UA=False  high_entropy_URI=True
```

### MITRE ATT&CK annotation (terminal output)

Each corroborated lead is annotated with relevant techniques:

```
  10.0.2.100 → 203.0.113.55
  ──────────────────────────────────────────────
  Exfiltration:
    T1029  Scheduled Transfer
      └─ Scheduled beacon interval: 898s (confidence: 0.925)
  Command and Control:
    T1568.002  Dynamic Resolution: Domain Generation Algorithms
      └─ DGA-generated domains detected: nmg5kr6dcjttx.com, ...
    T1071.001  Application Layer Protocol: Web Protocols
      └─ Stereotyped HTTP patterns consistent with automated C2 polling
```

### HTML Report

The `--report` flag generates an interactive dashboard with:

- Pipeline flow visualization with funnel counts at each stage
- Triage summary table with severity ratings (CRITICAL / HIGH / MEDIUM)
- Evidence cards per lead: infected host, C2 destination, hypothesis results, suggested next steps
- Operator interaction warnings when PELT detects beacon interval shifts
- Diagnostic plot gallery (with `--visualize`)
- CSV download buttons for all pipeline output tables

---

## Synthetic Test Scenarios

The generator injects six scenarios into 30 days of realistic background traffic:

| Scenario | Type | Period | Key Signals |
|---|---|---|---|
| `fast_https_dga` | **Malicious** | 5 min | DGA domains, short TTL, absent UA, HTTPS |
| `slow_http_fixed` | **Malicious** | 1 hr | Fixed domain, outdated UA, uniform HTTP payloads |
| `multi_host_campaign` | **Malicious** | 15 min | DGA, NXDomain misses, absent UA |
| `exfil_slow` | **Malicious** | 6 hr | Large variable payload, plausible-looking domain |
| `decoy_windows_update` | **Decoy** | 1 hr | Benign domain and UA — should **not** be confirmed |
| `decoy_ntp` | **Decoy** | ~17 min | NTP polling, no HTTP — should **not** be confirmed |

**Expected result at full scale (30 days, 30k bg/day):** Precision 1.000, Recall 1.000, F1 1.000. All 4 malicious scenarios detected, both decoys filtered at the corroboration stage.

**Typical pipeline funnel (seed=42):**
```
Conn log rows                       945,615
Pre-filter removed (known benign)       759
IForest anomalies                    58,090
Pairs evaluated (SAX cap)             5,000
SAX-passing pairs → full ACF          1,770
Beacon pairs (is_beacon_pair)            12
Corroborated leads                        4
```

---

## Module Reference

| Module | Stage | Description |
|---|---|---|
| `config.py` | — | Typed dataclass configuration. Sub-configs for each pipeline stage. |
| `loaders.py` | 1 | CSV ingest. Schema normalisation, feature engineering. |
| `features.py` | 2 | Pair-level feature aggregation, StandardScaler on 8 IForest features. |
| `prefilter.py` | 3 | Domain-knowledge pre-filter. RFC 1918, CDN/DNS/NTP infra, fanin, dead connections. |
| `isolation.py` | 4 | Isolation Forest fit on pair features, stability check, HHI concentration analysis. |
| `sax_screening.py` | 5 | SAX symbolic pre-screening on inter-arrival time sequences. |
| `periodicity.py` | 6 | Binned-count ACF and Welch PSD. Jitter-robust beacon confidence scoring. |
| `scoring.py` | 7 | Pair priority scoring integrating periodicity output. Raw feature recovery. |
| `changepoint.py` | 8 | PELT changepoint detection for beacon start time and interval shifts. |
| `corroboration.py` | 9 | DNS and HTTP hypothesis testing (H1–H4). Benign service filtering. Analyst brief. |
| `mitre_mapping.py` | 10 | Evidence-based MITRE ATT&CK technique annotation on corroborated leads. |
| `pipeline.py` | — | `BDPPipeline.run()` orchestrator. Sequences all 10 stages. |
| `report.py` | — | Self-contained HTML report generator with plot capture. |
| `generate_synthetic_data.py` | — | Synthetic Zeek log generator with ground-truth labels for pipeline validation. |

---

## Limitations

- **Encrypted C2 without HTTP log:** Corroboration falls back to DNS-only evidence for HTTPS beacons. H3 and H4 will not fire. HTTP weight is automatically redistributed to DNS hypotheses. The pipeline still detects encrypted beacons via conn log periodicity and DNS anomalies (e.g., `exfil_slow` is detected via H1 DNS regularity alone).
- **Sub-minute beacons:** Intervals below 60 seconds are filtered by default (`periodicity.min_period_s`). Adjust if your threat model requires it, but expect more false positives from legitimate keepalive traffic.
- **Slow fixed-C2 beacons at short observation windows:** Beacons with 6-hour intervals produce only ~4 firings/day. At 5-day windows (`--days 5`), the IAT sequence may be too short for reliable ACF detection. Use 30-day windows for full coverage.
- **No threat intelligence enrichment:** A beacon to a newly-registered domain without DGA characteristics may score lower than expected. Integrating a passive DNS or TI feed would strengthen H2 coverage.
- **Single-host pair model:** The pipeline operates on (src_ip, dst_ip) pairs. Multi-destination C2 that rotates across many IPs requires upstream aggregation (e.g., by resolved domain) before ingestion.
- **Pre-filter fanin on synthetic data:** The high-fanin filter may disable itself on synthetic data where all background sources contact the same small destination pool. On real enterprise data with diverse destinations, it operates normally.

---

## License

MIT
