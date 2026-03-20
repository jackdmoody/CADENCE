"""
CADENCE Analytic Configuration
================================
Dataclass-based configuration for the CADENCE behavioral anomaly detection
pipeline. Each sub-config maps to a specific pipeline stage.

Architecture note: DBSCAN clustering has been removed. The pipeline now works
directly on (src_ip, dst_ip) pairs after IForest pre-filtering. This eliminates
the cluster-membership gate that was silently dropping beacons that landed in
large mixed clusters, and removes the noise-pair workaround that was added to
recover slow beacons that DBSCAN failed to cluster.

Usage:
    cfg = BDPConfig()                          # full defaults
    cfg = BDPConfig(isolation=IsolationConfig(n_estimators=300))
    cfg = BDPConfig.from_json("config.json")
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional, Tuple


# ---------------------------------------------------------------------------
# Sub-configs
# ---------------------------------------------------------------------------

@dataclass
class IOConfig:
    """I/O paths and CSV persistence."""
    input_csv:   Optional[Path] = None
    output_dir:  Path           = Path("output")
    table_name:  str            = "Conn_logs"
    query_start: str            = "2025-10-22 00:00:00"
    query_end:   str            = "2025-10-22 23:59:59"
    query_limit: int            = 1_000_000
    debug:       bool           = False


@dataclass
class FeatureConfig:
    """
    Feature engineering and schema normalization settings.

    timestamp is kept as a plain float (Unix seconds) so downstream
    stages always have an unambiguous numeric timestamp for IAT computation.
    """
    keep_cols: Tuple[str, ...] = (
        "timestamp", "datetime", "src_ip", "src_p", "src_pkts",
        "dst_ip",    "dst_p",   "resp_pkts", "duration",
        "conn_state", "service", "total_bytes",
        "sin_time", "cos_time",
        "hour", "minute", "scenario",
    )
    protected_features: Tuple[str, ...] = ("sin_time", "cos_time")
    meta_cols:          Tuple[str, ...] = (
        "timestamp", "datetime", "src_ip", "dst_ip",
        "hour", "minute", "scenario",
    )


@dataclass
class ScalingConfig:
    """Variance filtering and feature scaling parameters."""
    threshold:             float = 1.0
    binary_threshold:      float = 0.001
    skew_threshold:        float = 2.0
    range_ratio_threshold: float = 100.0
    min_unique:            int   = 10
    min_max_threshold:     float = 100.0
    scaler_path:           str   = "saved_scalers/scaler_numeric_raw.pkl"
    visualize:             bool  = False


@dataclass
class IsolationConfig:
    """
    Isolation Forest runs on pair-level behavioral features rather than individual
    flows. contamination controls the fraction of *pairs* flagged as anomalous.
    Using an explicit float (rather than "auto") ensures a predictable anomaly
    set size regardless of the max_samples training subsample size.
    """
    """Isolation Forest anomaly pre-filter parameters."""
    n_estimators:              int   = 200
    max_samples:               int   = 3_000
    test_size:                 float = 0.3
    random_state:              int   = 42
    contamination:             float = 0.05
    stability_threshold:       float = 0.80


@dataclass
class PairConfig:
    """
    Per-channel grouping and filtering parameters.

    Point 1: The pipeline now groups flows by a configurable channel key.
    The default key is (src_ip, dst_ip, dst_port, proto), which avoids
    mixing traffic to different services on the same destination host.
    Set channel_key to ("src_ip", "dst_ip") to restore the original
    two-tuple behaviour.

    min_observations (8)
        Minimum number of flows a channel must have to be evaluated.
        Channels below this cannot support reliable IAT statistics.

    max_pairs (5000)
        Safety cap on the number of channels to evaluate. Applied after
        sorting by flow count descending so the richest channels are
        always evaluated.

    min_pair_flows (8)
        Hard minimum: channels with fewer flows than this are skipped.
        Aligned with sax.min_observations to eliminate the dead 3-7
        flow range that could never produce a meaningful SAX word.
    """
    min_observations: int   = 8
    min_pair_flows:   int   = 8
    max_pairs:        int   = 5_000
    # Point 1: configurable channel key tuple
    channel_key: Tuple[str, ...] = ("src_ip", "dst_ip", "dst_port", "proto")


@dataclass
class SAXConfig:
    """
    SAX periodicity pre-screening parameters.

    SAX is a fast O(N) symbolic encoder that eliminates clearly non-periodic
    (src, dst) pairs before the more expensive ACF + FFT analysis.
    It is intentionally permissive — the goal is to reduce computation,
    not to make final decisions.
    """
    word_length:       int   = 20
    alphabet_size:     int   = 4
    cv_threshold:      float = 0.60
    acf_threshold:     float = 0.30
    motif_threshold:   float = 0.40
    min_tests_passing: int   = 2
    min_observations:  int   = 8
    max_acf_lag:       int   = 10


@dataclass
class PeriodicityConfig:
    """Inter-arrival time periodicity analysis parameters."""
    min_observations:           int   = 10
    acf_nlags:                  int   = 40   # raised from 20 for slow beacon coverage
    acf_significance_threshold: float = 0.25
    cv_threshold:               float = 0.60
    fft_power_ratio_threshold:  float = 0.15
    min_period_s:               float = 60.0
    confidence_threshold:       float = 0.45


@dataclass
class PELTConfig:
    """PELT changepoint detection parameters."""
    penalty:            str | float = "bic"
    min_segment_length: int         = 5
    min_observations:   int         = 15
    max_changepoints:   int         = 10


@dataclass
class PrefilterConfig:
    """
    Domain-knowledge pre-filter parameters (previously hardcoded constants).
    Promoted to config so operators can tune without editing source.
    """
    dst_fanin_threshold:   float = 0.50   # fraction of unique srcs above which dst is shared infra
    failed_conn_threshold: float = 0.90   # fraction of failed conn states to call a pair "dead"


@dataclass
class TLSCorroborationConfig:
    """
    Point 7: TLS/SSL log corroboration parameters (H5-H6).

    H5 — TLS Consistency: SNI stability, JA3 fingerprint consistency,
         low certificate churn across sessions.
    H6 — TLS Evasion: self-signed cert, very new cert, JA3 known-C2
         fingerprint, absent/mismatched SNI, session resumption abuse.
    """
    # H5 thresholds
    sni_entropy_threshold:      float = 1.0    # high entropy SNI = DGA-like hostname
    ja3_monotony_threshold:     float = 0.90   # fraction using same JA3 = beacon-consistent
    cert_reuse_min_sessions:    int   = 3      # min sessions on same cert to flag reuse
    # H6 thresholds
    cert_age_new_days:          int   = 30     # cert issued within this many days = suspicious
    ja3_known_c2: Tuple[str, ...] = (          # well-known C2 JA3 fingerprints
        "e7d705a3286e19ea42f587b344ee6865",    # Cobalt Strike default
        "6d4e5b73a8e1c8a0f9c6e62f7b2d1a9c",    # common Metasploit profile
    )
    # Scoring weights
    h5_weight: float = 0.30
    h6_weight: float = 0.30


@dataclass
class CorroborationConfig:
    """Multi-source corroboration parameters for DNS, HTTP, and TLS validation."""
    period_tolerance_pct:   float = 0.15
    short_ttl_threshold_s:  float = 300.0
    dga_entropy_threshold:  float = 3.5
    dga_min_label_len:      int   = 8
    http_body_cv_threshold: float = 0.30
    http_uri_cv_threshold:  float = 0.40
    rare_ua_threshold:      float = 0.05
    uri_entropy_threshold:  float = 4.0
    min_score:              float = 0.55

    # v8 robustness fields
    dns_min_obs_duty_cycle:        float = 0.50
    nxdomain_rate_threshold:       float = 0.10
    fast_flux_unique_ip_threshold: int   = 5
    global_ua_rare_threshold:      float = 0.01
    high_entropy_uri_frac:         float = 0.25
    extra_benign_domain_suffixes:  Tuple[str, ...] = ()
    body_cv_trim_pct:              float = 0.05

    # Point 7: TLS corroboration config (nested)
    tls: TLSCorroborationConfig = field(default_factory=TLSCorroborationConfig)


@dataclass
class TriageConfig:
    """
    Pair prioritization scoring thresholds.

    Scores are now computed per (src_ip, dst_ip) pair rather than per
    DBSCAN cluster. The heuristics are unchanged; only the grouping unit
    has changed.
    """
    beaconing_std_thresh: float = 0.5
    rare_dst_thresh:      int   = 25
    high_volume_pct:      float = 0.05
    off_hour_range:       Tuple[int, int] = (6, 22)
    common_ports: Tuple[int, ...] = (
        20, 21, 22, 23, 25, 53, 67, 68, 69,
        80, 123, 135, 137, 138, 139,
        161, 162, 389, 445, 514, 636,
        443, 8443, 9443,
        110, 143, 465, 587, 993, 995,
        1433, 1434, 1521, 2483, 2484, 3306, 5432, 27017, 27018,
        3389, 5222, 5223, 7071, 8080, 8081,
        500, 563, 1194, 1723, 4500,
    )


# ---------------------------------------------------------------------------
# Top-level config
# ---------------------------------------------------------------------------

@dataclass
class BDPConfig:
    """
    Master configuration for the CADENCE behavioral anomaly detection pipeline.

    Usage:
        cfg = BDPConfig()                                  # all defaults
        cfg = BDPConfig(io=IOConfig(input_csv=Path(...)))  # load from CSV
        cfg = BDPConfig.from_json("config.json")           # from file
    """
    io:            IOConfig                = field(default_factory=IOConfig)
    features:      FeatureConfig           = field(default_factory=FeatureConfig)
    scaling:       ScalingConfig           = field(default_factory=ScalingConfig)
    isolation:     IsolationConfig         = field(default_factory=IsolationConfig)
    pair:          PairConfig              = field(default_factory=PairConfig)
    triage:        TriageConfig            = field(default_factory=TriageConfig)
    sax:           SAXConfig               = field(default_factory=SAXConfig)
    pelt:          PELTConfig              = field(default_factory=PELTConfig)
    periodicity:   PeriodicityConfig       = field(default_factory=PeriodicityConfig)
    corroboration: CorroborationConfig     = field(default_factory=CorroborationConfig)
    prefilter:     PrefilterConfig         = field(default_factory=PrefilterConfig)

    def as_dict(self) -> Dict[str, Any]:
        import dataclasses
        return dataclasses.asdict(self)

    def to_json(self, path: str) -> None:
        with open(path, "w") as f:
            json.dump(self.as_dict(), f, indent=2, default=str)

    @classmethod
    def from_json(cls, path: str) -> "BDPConfig":
        with open(path) as f:
            d = json.load(f)
        corr_d = d.get("corroboration", {})
        tls_d  = corr_d.pop("tls", {})
        return cls(
            io=IOConfig(**d.get("io", {})),
            features=FeatureConfig(**d.get("features", {})),
            scaling=ScalingConfig(**d.get("scaling", {})),
            isolation=IsolationConfig(**d.get("isolation", {})),
            pair=PairConfig(**d.get("pair", {})),
            triage=TriageConfig(**d.get("triage", {})),
            sax=SAXConfig(**d.get("sax", {})),
            pelt=PELTConfig(**d.get("pelt", {})),
            periodicity=PeriodicityConfig(**d.get("periodicity", {})),
            corroboration=CorroborationConfig(
                **corr_d,
                tls=TLSCorroborationConfig(**tls_d),
            ),
            prefilter=PrefilterConfig(**d.get("prefilter", {})),
        )
