# Changelog

All notable changes to CADENCE are documented here.

---

## [3.0.0] — Current

### Added
- **Channel-level grouping keys** — The analysis unit is now `(src_ip, dst_ip, dst_port, proto)` rather than `(src_ip, dst_ip)`. Configurable via `cfg.pair.channel_key`. Downstream stages (SAX, periodicity, scoring, corroboration, changepoint) all propagate `channel_id`. Legacy `(src_ip, dst_ip)` behaviour is available by setting `channel_key = ("src_ip", "dst_ip")`.
- **Six new IForest features** — `iat_mad_s`, `iat_ratio`, `missing_beat_rate`, `persistence_ratio`, `req_resp_asymmetry`, `zero_payload_frac`. Total feature count raised from 8 to 14.
- **TLS/SSL corroboration (H5–H6)** — New `load_ssl_logs()`, `score_tls_hypothesis()` functions. H5 tests SNI stability, JA3 monotony, and certificate reuse. H6 tests self-signed certs, known C2 JA3 fingerprints, absent SNI, and session resumption abuse. `corroborate_beacon_candidates()` now accepts optional `ssl_df` parameter.
- **Adaptive corroboration score weighting** — `_corroboration_score()` now distributes weight across whichever of DNS / HTTP / TLS evidence is available. Absent log types are neutral, not penalising.
- **Synthetic SSL log generation** — `generate_synthetic_data.py` now generates correlated `ssl.log` for beacon and background traffic. `SyntheticDataGenerator.generate()` returns a 5-tuple `(conn, dns, http, ssl, labels)`.
- **`PrefilterConfig`** — `dst_fanin_threshold` and `failed_conn_threshold` promoted from hardcoded constants to `BDPConfig.prefilter`. Operator-tunable without source edits.
- **`TLSCorroborationConfig`** — New nested config dataclass under `corroboration.tls` with H5/H6 thresholds and known C2 JA3 fingerprint list.
- **`ssl_log_path` in pipeline** — `BDPPipeline.run()`, `BDPPipeline.corroborate()`, and `run_with_report()` all accept `ssl_log_path`.
- **Reweighted triage scoring** — Priority scoring now weights payload stability (×2) and persistence ratio (×2) over uncommon ports (dropped from score) and high data volume (dropped from score). Score breakdown columns exposed in `priority.csv`.
- **Report H5/H6 evidence cards** — HTML report now renders H5 and H6 hypothesis rows with sub-signal detail, TLS score pill, channel key display in triage table, and SNI/JA3 observation tags.
- **`acf_nlags` raised from 20 to 40** — Improves ACF coverage for slow beacons (6h+ intervals).
- **`min_pair_flows` raised from 3 to 8** — Aligned with `sax.min_observations`. Eliminates the dead 3–7 flow range that could never produce a meaningful SAX word.

### Fixed
- **`iat_median` NameError** — `iat_median` variable was referenced before assignment in `periodicity.py` after a prior refactor. Fixed.
- **Period estimation formula verified correct** — The formula `acf_period_s = acf_lag * iat_median / 2.0` is confirmed correct. The binned-count ACF peaks at lag=2 (not lag=1) because each beacon firing occupies its own bin of size `median_iat/2`, so two consecutive firings span 2 bins = 1 full period. A proposed "fix" (removing the `/2`) doubled the period estimate and was reverted.
- **`iat_median` NameError** — `iat_median` variable was referenced before assignment in `periodicity.py`. Fixed.

### Changed
- `_corroboration_score()` signature now includes `tls_score`, `h5_pass`, `h6_pass`, `ssl_flow_count` parameters.
- `corroborate_beacon_candidates()` now takes optional `ssl_df` keyword argument.
- `_build_triage_rows()` in `report.py` now extracts `channel_id`, all H5/H6 fields, `h2_nxdomain_rate`, `h2_fast_flux_count`, `h3_path_cv`, `h3_consistency_score`, `h4_ua_monotony`.
- Module reference table in README updated to reflect 14-feature IForest, channel-key architecture, and H1–H6 corroboration.

---

## [2.0.0]

### Added
- **v8 corroboration robustness fixes** across DNS and HTTP hypothesis scoring:
  - H1: median IAT + CV gate (burst-resistant), best-delta domain selection, duty-cycle-scaled minimum observation gate, DNS answer IP validation against `dst_ip`.
  - H2: digit-run DGA detection, rate-normalised NXDomain, fast-flux detection via unique answer IPs.
  - H3: weighted consistency score, trimmed body CV, path-component URI CV.
  - H4: global UA rarity (vs. enterprise-wide distribution), UA monotony as distinct signal, fraction-based URI entropy.
  - H1+H2 overlap bonus when the same domain drives both hypotheses.
  - Configurable benign domain allowlist via `extra_benign_domain_suffixes`.

### Fixed
- `KeyError: 'corroborated'` when no DNS or HTTP logs provided.
- Millisecond timestamp handling in `loaders.py` for real Zeek exports.
- RFC 5737 documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) now treated as external IPs in pre-filter, preventing synthetic malicious scenarios from being silently dropped.

---

## [1.0.0]

- Initial pipeline: Isolation Forest → SAX → ACF/FFT → PELT → DNS/HTTP corroboration (H1–H4) → MITRE ATT&CK annotation.
- Synthetic data generator with 4 malicious scenarios + 2 decoys.
- Self-contained HTML report with plot capture.
