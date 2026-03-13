"""
CADENCE: C2 Beacon Detection Analytic for Zeek Connection Telemetry.

A multi-stage network anomaly detection pipeline combining Isolation Forest
pre-filtering, per-(src,dst)-pair SAX pre-screening, inter-arrival time
periodicity analysis (ACF + FFT), and DNS/HTTP corroboration to identify
C2 beaconing with high confidence from Zeek conn, dns, and http logs.

Architecture: DBSCAN clustering removed in v6. The pipeline now works
directly on (src_ip, dst_ip) pairs after IForest pre-filtering, eliminating
the cluster-membership gate that was silently dropping beacon signals.
"""
from .config import (
    BDPConfig,
    IsolationConfig,
    PairConfig,
    TriageConfig,
    PeriodicityConfig,
    CorroborationConfig,
    SAXConfig,
    PELTConfig,
)
from .pipeline import BDPPipeline, BDPArtifacts
from .report import ReportContext

__all__ = [
    "BDPConfig",
    "IsolationConfig",
    "PairConfig",
    "TriageConfig",
    "PeriodicityConfig",
    "CorroborationConfig",
    "SAXConfig",
    "PELTConfig",
    "BDPPipeline",
    "BDPArtifacts",
    "ReportContext",
]
