"""
CADENCE: C2 Anomaly Detection via Ensemble Network Correlation Evidence.

A multi-stage behavioral analytic pipeline for detecting C2 beaconing from
Zeek conn, dns, http, and ssl logs. Combines unsupervised machine learning
(Isolation Forest) with statistical time-series analysis (binned-count ACF,
Welch PSD, PELT) and six-layer cross-protocol hypothesis testing (H1-H6)
to surface high-confidence analyst-actionable leads.

Architecture (v3)
------------------
- Channel-level grouping: (src_ip, dst_ip, dst_port, proto) by default.
- 14 IForest features including IAT MAD, persistence ratio, missing beat rate,
  request/response asymmetry, and zero-payload fraction.
- Corroboration via DNS (H1-H2), HTTP (H3-H4), and TLS/SSL (H5-H6) with
  adaptive weight redistribution across available log types.
- Corrected period estimation: acf_period_s = acf_lag * iat_median.

Quick start
-----------
    from bdp_analytic import BDPPipeline, BDPConfig
    from pathlib import Path

    cfg = BDPConfig()
    cfg.io.input_csv = Path("data/conn.csv")

    art = BDPPipeline(cfg).run(
        dns_log_path  = "data/dns.csv",
        http_log_path = "data/http.csv",
        ssl_log_path  = "data/ssl.csv",   # enables H5/H6 TLS corroboration
    )

    from bdp_analytic.corroboration import print_analyst_brief
    print_analyst_brief(art.corroboration)
"""
from .config import (
    BDPConfig,
    IsolationConfig,
    PairConfig,
    PrefilterConfig,
    TriageConfig,
    PeriodicityConfig,
    CorroborationConfig,
    TLSCorroborationConfig,
    SAXConfig,
    PELTConfig,
)
from .pipeline import BDPPipeline, BDPArtifacts
from .report import ReportContext

__version__ = "3.0.0"

__all__ = [
    # Pipeline
    "BDPPipeline",
    "BDPArtifacts",
    "ReportContext",
    # Config
    "BDPConfig",
    "IsolationConfig",
    "PairConfig",
    "PrefilterConfig",
    "TriageConfig",
    "PeriodicityConfig",
    "CorroborationConfig",
    "TLSCorroborationConfig",
    "SAXConfig",
    "PELTConfig",
]
