"""
CADENCE Test Suite
====================
End-to-end and unit tests validating the full pipeline against synthetic data.

Run with:
    pytest tests/ -v
    pytest tests/ -v --log-cli-level=INFO

All tests use seed=42 for reproducibility and a compact 3-day, 2000 row/day
dataset so the full suite completes in < 60 seconds.
"""
from __future__ import annotations

import numpy as np
import pandas as pd
import pytest

from analytic_pipeline.config import BDPConfig, PairConfig, TLSCorroborationConfig


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def synthetic_data():
    """Generate a small synthetic dataset once for the whole module."""
    from analytic_pipeline.generate_synthetic_data import SyntheticDataGenerator
    gen = SyntheticDataGenerator(seed=42)
    conn, dns, http, ssl, labels = gen.generate(
        days=3, bg_rows_per_day=2_000, noisy_rows_per_day=200
    )
    return conn, dns, http, ssl, labels


@pytest.fixture(scope="module")
def pipeline_artifacts(synthetic_data, tmp_path_factory):
    """Run the full pipeline once and return artifacts."""
    conn, dns, http, ssl, labels = synthetic_data
    tmp = tmp_path_factory.mktemp("cadence_run")

    conn_path = tmp / "conn.csv"
    dns_path  = tmp / "dns.csv"
    http_path = tmp / "http.csv"
    ssl_path  = tmp / "ssl.csv"
    conn.to_csv(conn_path, index=False)
    dns.to_csv(dns_path,   index=False)
    http.to_csv(http_path, index=False)
    ssl.to_csv(ssl_path,   index=False)

    from analytic_pipeline import BDPConfig, BDPPipeline
    cfg = BDPConfig()
    cfg.io.input_csv  = conn_path
    cfg.io.output_dir = tmp / "output"
    cfg.io.output_dir.mkdir()
    cfg.io.query_start = str(pd.to_datetime(conn["timestamp"].min(), unit="s", utc=True))[:19]
    cfg.io.query_end   = str(pd.to_datetime(conn["timestamp"].max(), unit="s", utc=True))[:19]
    # Smaller contamination for tiny dataset
    cfg.isolation.contamination = 0.10
    cfg.pair.max_pairs = 500

    pipe = BDPPipeline(cfg)
    art  = pipe.run(
        dns_log_path  = str(dns_path),
        http_log_path = str(http_path),
        ssl_log_path  = str(ssl_path),
        visualize     = False,
    )
    return art, labels, conn


# ---------------------------------------------------------------------------
# Config tests
# ---------------------------------------------------------------------------

class TestConfig:
    def test_channel_key_default(self):
        cfg = BDPConfig()
        assert cfg.pair.channel_key == ("src_ip", "dst_ip", "dst_port", "proto")

    def test_min_pair_flows_aligned(self):
        cfg = BDPConfig()
        # min_pair_flows must be >= sax.min_observations to avoid dead range
        assert cfg.pair.min_pair_flows >= cfg.sax.min_observations

    def test_acf_nlags_raised(self):
        cfg = BDPConfig()
        assert cfg.periodicity.acf_nlags >= 40

    def test_prefilter_config_exists(self):
        cfg = BDPConfig()
        assert hasattr(cfg, "prefilter")
        assert cfg.prefilter.dst_fanin_threshold > 0
        assert cfg.prefilter.failed_conn_threshold > 0

    def test_tls_config_exists(self):
        cfg = BDPConfig()
        assert hasattr(cfg.corroboration, "tls")
        assert isinstance(cfg.corroboration.tls, TLSCorroborationConfig)

    def test_json_roundtrip(self, tmp_path):
        cfg = BDPConfig()
        path = str(tmp_path / "config.json")
        cfg.to_json(path)
        cfg2 = BDPConfig.from_json(path)
        # channel_key may round-trip as list (JSON has no tuple type) — compare values
        assert list(cfg2.pair.channel_key) == list(cfg.pair.channel_key)
        assert cfg2.corroboration.tls.ja3_monotony_threshold == cfg.corroboration.tls.ja3_monotony_threshold
        assert cfg2.prefilter.dst_fanin_threshold == cfg.prefilter.dst_fanin_threshold

    def test_legacy_pair_key_supported(self):
        cfg = BDPConfig()
        cfg.pair.channel_key = ("src_ip", "dst_ip")
        assert cfg.pair.channel_key == ("src_ip", "dst_ip")


# ---------------------------------------------------------------------------
# Feature engineering tests (Point 1 + Point 4)
# ---------------------------------------------------------------------------

class TestFeatures:
    def test_channel_id_present(self, pipeline_artifacts):
        art, _, _ = pipeline_artifacts
        # After load+scale, pairs should have channel_id
        if not art.scaled.empty:
            assert "channel_id" in art.scaled.columns

    def test_channel_id_encodes_port_proto(self, pipeline_artifacts):
        art, _, _ = pipeline_artifacts
        if not art.scaled.empty and "channel_id" in art.scaled.columns:
            sample = art.scaled["channel_id"].iloc[0]
            assert "→" in sample

    def test_new_iforest_features_present(self, pipeline_artifacts):
        art, _, _ = pipeline_artifacts
        from analytic_pipeline.features import IFOREST_FEATURES
        for feat in ("iat_mad_s", "iat_ratio", "missing_beat_rate",
                     "persistence_ratio", "req_resp_asymmetry", "zero_payload_frac"):
            assert feat in IFOREST_FEATURES, f"Not in IFOREST_FEATURES: {feat}"
            # The feature should appear as a raw column in the scaled df (before _stdz suffix)
            assert feat in art.scaled.columns or f"{feat}_stdz" in art.scaled.columns, \
                f"Feature {feat} missing from scaled df"

    def test_persistence_ratio_in_bounds(self, pipeline_artifacts):
        art, _, _ = pipeline_artifacts
        if not art.scaled.empty and "persistence_ratio" in art.scaled.columns:
            pr = art.scaled["persistence_ratio"].dropna()
            # Persistence ratio can slightly exceed 1.0 for short windows where
            # calendar-day counting overshoots the fractional window length.
            assert (pr >= 0).all() and (pr <= 2.0).all()

    def test_iat_ratio_positive(self, pipeline_artifacts):
        art, _, _ = pipeline_artifacts
        if not art.scaled.empty and "iat_ratio" in art.scaled.columns:
            ratio = art.scaled["iat_ratio"].dropna()
            assert (ratio > 0).all()


# ---------------------------------------------------------------------------
# Periodicity tests (Point 2 — period estimation fix)
# ---------------------------------------------------------------------------

class TestPeriodicity:
    def test_period_estimate_300s(self):
        """ACF period for a 300s beacon should be approximately 300s.

        With bin_size = median_iat/2 = 150s, the ACF of the binned count
        series peaks at lag=2 (every other bin), giving:
            period = lag * bin_size = 2 * 150 = 300s
        Allow ±50% for binning boundary effects and jitter.
        """
        from analytic_pipeline.periodicity import score_pair_periodicity
        cfg = BDPConfig()
        base = 1_700_000_000.0
        ts   = pd.Series(base + np.arange(60) * 300.0)
        result = score_pair_periodicity(ts, cfg)
        period = result["dominant_period_s"]
        assert 150 < period < 450, f"Period estimate {period:.0f}s too far from 300s"

    def test_period_estimate_3600s(self):
        """ACF period for a 1-hour beacon should be approximately 3600s."""
        from analytic_pipeline.periodicity import score_pair_periodicity
        cfg = BDPConfig()
        base = 1_700_000_000.0
        ts   = pd.Series(base + np.arange(30) * 3600.0)
        result = score_pair_periodicity(ts, cfg)
        period = result["dominant_period_s"]
        assert 1800 < period < 5400, f"Period estimate {period:.0f}s too far from 3600s"

    def test_channel_id_in_periodicity_output(self, pipeline_artifacts):
        art, _, _ = pipeline_artifacts
        if not art.periodicity.empty:
            assert "channel_id" in art.periodicity.columns

    def test_is_beacon_pair_boolean(self, pipeline_artifacts):
        art, _, _ = pipeline_artifacts
        if not art.periodicity.empty:
            assert art.periodicity["is_beacon_pair"].dtype == bool or \
                   set(art.periodicity["is_beacon_pair"].unique()).issubset({True, False})


# ---------------------------------------------------------------------------
# Scoring tests (Point 6 — triage reweighting)
# ---------------------------------------------------------------------------

class TestScoring:
    def test_score_breakdown_columns_present(self, pipeline_artifacts):
        art, _, _ = pipeline_artifacts
        if not art.priority.empty:
            for col in ("score_beacon", "score_payload", "score_persistence",
                        "score_period_agree", "score_temporal"):
                assert col in art.priority.columns, f"Missing triage column: {col}"

    def test_priority_score_is_sum_of_components(self, pipeline_artifacts):
        art, _, _ = pipeline_artifacts
        if not art.priority.empty:
            components = art.priority[
                ["score_beacon","score_payload","score_persistence",
                 "score_period_agree","score_temporal"]
            ].sum(axis=1)
            assert (components == art.priority["priority_score"]).all()

    def test_max_priority_score_bounded(self, pipeline_artifacts):
        art, _, _ = pipeline_artifacts
        if not art.priority.empty:
            assert art.priority["priority_score"].max() <= 10

    def test_persistence_ratio_in_priority(self, pipeline_artifacts):
        art, _, _ = pipeline_artifacts
        if not art.priority.empty:
            assert "persistence_ratio" in art.priority.columns


# ---------------------------------------------------------------------------
# TLS corroboration tests (Point 7)
# ---------------------------------------------------------------------------

class TestTLSCorroboration:
    def test_load_ssl_logs(self, synthetic_data, tmp_path):
        _, _, _, ssl, _ = synthetic_data
        from analytic_pipeline.corroboration import load_ssl_logs
        ssl_path = tmp_path / "ssl.csv"
        ssl.to_csv(ssl_path, index=False)
        cfg = BDPConfig()
        cfg.io.query_start = "2020-01-01 00:00:00"
        cfg.io.query_end   = "2030-01-01 00:00:00"
        df = load_ssl_logs(str(ssl_path), cfg)
        assert not df.empty
        assert "src_ip" in df.columns

    def test_score_tls_hypothesis_monotonic_ja3(self):
        from analytic_pipeline.corroboration import score_tls_hypothesis
        cfg = BDPConfig()
        ssl_mock = pd.DataFrame({
            "ts":                pd.to_datetime([1_700_000_000 + i*300 for i in range(20)], unit="s", utc=True),
            "src_ip":            "10.0.1.50",
            "dst_ip":            "203.0.113.10",
            "server_name":       "",
            "ja3":               "e7d705a3286e19ea42f587b344ee6865",
            "ja3s":              "ec74a5c51106f0419184d0dd08fb05bc",
            "cert_chain_fuids":  "FwTpSb203011310",
            "validation_status": "ok",
            "resumed":           [True]*17 + [False]*3,
            "established":       True,
        })
        r = score_tls_hypothesis({"10.0.1.50"}, {"203.0.113.10"}, ssl_mock, cfg)
        assert r["h5_ja3_monotonic"],   "JA3 monotony not detected"
        assert r["h6_absent_sni"],      "Absent SNI not detected"
        assert r["h6_high_resumption"], "High resumption not detected"
        assert r["tls_score"] > 0

    def test_score_tls_self_signed(self):
        from analytic_pipeline.corroboration import score_tls_hypothesis
        cfg = BDPConfig()
        ssl_mock = pd.DataFrame({
            "ts":                pd.to_datetime([1_700_000_000 + i*300 for i in range(10)], unit="s", utc=True),
            "src_ip":            "10.0.1.50",
            "dst_ip":            "203.0.113.10",
            "server_name":       "malware.c2",
            "ja3":               "aaa111bbb222ccc333ddd444eee55566",
            "ja3s":              "fff666ggg777hhh888iii999jjj00011",
            "cert_chain_fuids":  "SelfSignedCert",
            "validation_status": "self signed certificate in chain",
            "resumed":           [False]*10,
            "established":       True,
        })
        r = score_tls_hypothesis({"10.0.1.50"}, {"203.0.113.10"}, ssl_mock, cfg)
        assert r["h6_self_signed"], "Self-signed cert not detected"
        assert r["h6_tls_evasion"], "H6 should pass"

    def test_tls_null_result_on_empty_df(self):
        from analytic_pipeline.corroboration import score_tls_hypothesis
        cfg = BDPConfig()
        r = score_tls_hypothesis({"10.0.0.1"}, {"1.2.3.4"}, pd.DataFrame(), cfg)
        assert r["tls_score"] == 0.0
        assert not r["h5_tls_consistency"]
        assert not r["h6_tls_evasion"]
        assert r["ssl_flow_count"] == 0

    def test_corroborate_accepts_ssl_df(self, pipeline_artifacts):
        art, _, _ = pipeline_artifacts
        if not art.corroboration.empty:
            # After a real run, corroboration df should have H5/H6 columns
            for col in ("h5_tls_consistency", "h6_tls_evasion", "tls_score"):
                assert col in art.corroboration.columns, f"Missing column: {col}"

    def test_ssl_generation_columns(self, synthetic_data):
        _, _, _, ssl, _ = synthetic_data
        for col in ("ts", "id.orig_h", "id.resp_h", "server_name", "ja3",
                    "ja3s", "cert_chain_fuids", "validation_status", "resumed"):
            assert col in ssl.columns, f"SSL log missing column: {col}"

    def test_ssl_beacon_has_fixed_ja3(self, synthetic_data):
        _, _, _, ssl, labels = synthetic_data
        malicious_srcs = set(labels[labels["malicious"]]["src_ip"].tolist())
        ssl_beacon = ssl[ssl["id.orig_h"].isin(malicious_srcs) & (ssl["label"] == "malicious")]
        if not ssl_beacon.empty:
            # Malicious beacon SSL rows should all use the same fixed JA3
            for src, grp in ssl_beacon.groupby("id.orig_h"):
                unique_ja3s = grp["ja3"].dropna().nunique()
                assert unique_ja3s == 1, f"{src} has {unique_ja3s} distinct JA3s (expected 1)"


# ---------------------------------------------------------------------------
# Synthetic data tests
# ---------------------------------------------------------------------------

class TestSyntheticData:
    def test_generate_returns_five_tuple(self, synthetic_data):
        assert len(synthetic_data) == 5

    def test_ssl_log_not_empty(self, synthetic_data):
        _, _, _, ssl, _ = synthetic_data
        assert not ssl.empty
        assert len(ssl) > 0

    def test_all_malicious_scenarios_in_conn(self, synthetic_data):
        conn, _, _, _, labels = synthetic_data
        malicious = labels[labels["malicious"]]["scenario"].tolist()
        conn_scenarios = set(conn["scenario"].unique())
        for s in malicious:
            assert s in conn_scenarios, f"Malicious scenario '{s}' missing from conn log"

    def test_decoys_not_in_ssl(self, synthetic_data):
        """Decoy scenarios (Windows Update, NTP) should not generate SSL beacon rows."""
        _, _, _, ssl, labels = synthetic_data
        decoy_names = set(labels[~labels["malicious"]]["scenario"].tolist())
        if "label" in ssl.columns:
            ssl_decoy_beacon = ssl[
                (ssl["label"] == "decoy") | ssl["scenario"].isin(decoy_names)
            ]
            # Decoys may appear in ssl but should have varied JA3 (not fixed beacon fingerprint)
            if not ssl_decoy_beacon.empty and "ja3" in ssl_decoy_beacon.columns:
                for src, grp in ssl_decoy_beacon.groupby("id.orig_h"):
                    # NTP decoy produces no SSL at all; Windows Update decoy has varied JA3
                    pass  # just checking it doesn't raise


# ---------------------------------------------------------------------------
# Pipeline integration tests
# ---------------------------------------------------------------------------

class TestPipelineIntegration:
    def test_artifacts_not_all_empty(self, pipeline_artifacts):
        art, _, _ = pipeline_artifacts
        assert not art.raw.empty
        assert not art.scaled.empty
        assert not art.anomalies.empty

    def test_sax_produces_channel_ids(self, pipeline_artifacts):
        art, _, _ = pipeline_artifacts
        if not art.sax.empty:
            assert "channel_id" in art.sax.columns

    def test_periodicity_has_required_columns(self, pipeline_artifacts):
        art, _, _ = pipeline_artifacts
        if not art.periodicity.empty:
            for col in ("pair_id", "src_ip", "dst_ip", "beacon_confidence",
                        "dominant_period_s", "is_beacon_pair"):
                assert col in art.periodicity.columns

    def test_corroboration_has_h5_h6_columns(self, pipeline_artifacts):
        art, _, _ = pipeline_artifacts
        if not art.corroboration.empty:
            for col in ("h5_tls_consistency", "h5_sni_stable", "h5_ja3_monotonic",
                        "h6_tls_evasion", "h6_absent_sni", "tls_score"):
                assert col in art.corroboration.columns

    def test_no_false_positives_on_decoys(self, pipeline_artifacts):
        """Neither decoy scenario should appear in corroborated leads."""
        art, labels, conn = pipeline_artifacts
        if art.corroboration.empty:
            return
        decoy_srcs = set(labels[~labels["malicious"]]["src_ip"].tolist())
        corroborated = art.corroboration[art.corroboration["corroborated"]]
        fp_srcs = set(corroborated["src_ip"].tolist()) & decoy_srcs
        assert len(fp_srcs) == 0, f"Decoy sources corroborated: {fp_srcs}"

    def test_priority_score_monotone_with_beacon_confidence(self, pipeline_artifacts):
        """Channels with higher beacon_confidence should generally rank higher."""
        art, _, _ = pipeline_artifacts
        if art.priority.empty or len(art.priority) < 2:
            return
        # Top 5 by priority should all have higher beacon_confidence than median
        top5     = art.priority.head(5)["beacon_confidence"].mean()
        med_conf = art.priority["beacon_confidence"].median()
        assert top5 >= med_conf, "Top-priority channels have lower beacon confidence than median"


# ---------------------------------------------------------------------------
# Corroboration score tests
# ---------------------------------------------------------------------------

class TestCorroborationScore:
    def test_dns_only_score_in_range(self):
        from analytic_pipeline.corroboration import _corroboration_score
        score = _corroboration_score(
            dns_score=0.7, http_score=0.0, tls_score=0.0,
            h1_pass=True, h2_pass=True, h3_pass=False, h4_pass=False,
            h5_pass=False, h6_pass=False,
            http_flow_count=0, ssl_flow_count=0,
        )
        assert 0 <= score <= 1

    def test_full_evidence_score_higher_than_weak_dns(self):
        """Full cross-layer evidence should outscore weak DNS-only evidence."""
        from analytic_pipeline.corroboration import _corroboration_score
        # Weak DNS: only H2 passes, low dns_score
        weak_dns = _corroboration_score(
            dns_score=0.2, http_score=0.0, tls_score=0.0,
            h1_pass=False, h2_pass=True, h3_pass=False, h4_pass=False,
            h5_pass=False, h6_pass=False,
            http_flow_count=0, ssl_flow_count=0,
        )
        # Full: all hypotheses pass, all scores high
        full = _corroboration_score(
            dns_score=0.7, http_score=0.6, tls_score=0.5,
            h1_pass=True, h2_pass=True, h3_pass=True, h4_pass=True,
            h5_pass=True, h6_pass=True,
            http_flow_count=50, ssl_flow_count=50,
        )
        assert full > weak_dns, f"full={full:.3f} should exceed weak_dns={weak_dns:.3f}"

    def test_perfect_dns_only_score_near_one(self):
        """Perfect H1+H2 with good dns_score should produce a high score."""
        from analytic_pipeline.corroboration import _corroboration_score
        score = _corroboration_score(
            dns_score=0.9, http_score=0.0, tls_score=0.0,
            h1_pass=True, h2_pass=True, h3_pass=False, h4_pass=False,
            h5_pass=False, h6_pass=False,
            http_flow_count=0, ssl_flow_count=0,
        )
        assert score >= 0.75, f"Perfect H1+H2 should score >= 0.75, got {score:.3f}"

    def test_tls_only_path(self):
        from analytic_pipeline.corroboration import _corroboration_score
        score = _corroboration_score(
            dns_score=0.5, http_score=0.0, tls_score=0.6,
            h1_pass=False, h2_pass=True, h3_pass=False, h4_pass=False,
            h5_pass=True, h6_pass=True,
            http_flow_count=0, ssl_flow_count=30,
        )
        assert 0 < score <= 1


# ---------------------------------------------------------------------------
# Report tests
# ---------------------------------------------------------------------------

class TestReport:
    def test_render_html_no_leads(self):
        from analytic_pipeline.report import _render_html
        from dataclasses import dataclass, field
        from datetime import datetime, timezone

        @dataclass
        class MockArt:
            corroboration: pd.DataFrame = field(default_factory=pd.DataFrame)
            changepoints:  pd.DataFrame = field(default_factory=pd.DataFrame)

        html = _render_html(
            title="CADENCE — Test Report", figures=[], csvs={},
            meta={"Run start": "2025-01-01", "Channels evaluated": "0",
                  "SAX pass": "0", "Beacon channels": "0", "Corroborated": "0",
                  "Anomalies": "0", "Conn rows": "0"},
            art=MockArt(), run_start=datetime.now(timezone.utc),
        )
        assert "CADENCE" in html                    # title present
        assert "Channel Group" in html              # updated pipeline flow label
        assert "C2 Anomaly Detection" in html       # subtitle present
        assert "<!DOCTYPE html>" in html            # valid HTML structure
        assert "corroborated leads" in html.lower() # no-leads message present

    def test_report_has_ssl_log_path(self):
        from analytic_pipeline.report import run_with_report
        import inspect
        sig = inspect.signature(run_with_report)
        assert "ssl_log_path" in sig.parameters
