"""
Tests for the real-data path: Zeek adapter, prefilter guards, ground truth,
scoring, and an end-to-end round trip through native Zeek log formats.

Run with:
    pytest analytic_pipeline/test_real_data.py -v
"""
from __future__ import annotations

import gzip
import json
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from analytic_pipeline.config import BDPConfig
from analytic_pipeline.zeek_adapter import (
    conn_to_cadence, convert_dir, read_zeek_log,
)
from analytic_pipeline import prefilter as pf
from analytic_pipeline import ground_truth as gtm


# ---------------------------------------------------------------------------
# Helpers that write logs the way Zeek does
# ---------------------------------------------------------------------------

CONN_FIELDS = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto",
               "service", "duration", "orig_bytes", "resp_bytes", "conn_state",
               "orig_pkts", "resp_pkts"]
CONN_TYPES = ["time", "string", "addr", "port", "addr", "port", "enum", "string",
              "interval", "count", "count", "string", "count", "count"]


def _fmt(v, t):
    if v is None or (isinstance(v, float) and np.isnan(v)) or v is pd.NA:
        return "-"
    if t == "time" or t == "interval":
        return f"{float(v):.6f}"
    if t == "bool":
        return "T" if bool(v) else "F"
    if t in ("count", "port"):
        return str(int(v))
    s = str(v)
    return "(empty)" if s == "" else s


def write_zeek_tsv(df: pd.DataFrame, path: Path, fields, types, log_path="conn", gz=False):
    lines = ["#separator \\x09", "#set_separator\t,", "#empty_field\t(empty)",
             "#unset_field\t-", f"#path\t{log_path}", "#open\t2026-11-19-00-00-00",
             "#fields\t" + "\t".join(fields), "#types\t" + "\t".join(types)]
    for row in df[fields].itertuples(index=False):
        lines.append("\t".join(_fmt(v, t) for v, t in zip(row, types)))
    lines.append("#close\t2026-11-19-01-00-00")
    data = ("\n".join(lines) + "\n").encode()
    if gz:
        path.write_bytes(gzip.compress(data))
    else:
        path.write_bytes(data)


# ---------------------------------------------------------------------------
# Adapter
# ---------------------------------------------------------------------------

def test_tsv_conn_maps_to_cadence_schema(tmp_path):
    df = pd.DataFrame({
        "ts": [1.5, 2.5], "uid": ["C1", "C2"],
        "id.orig_h": ["10.0.0.5", "10.0.0.5"], "id.orig_p": [5000, 5001],
        "id.resp_h": ["1.2.3.4", "1.2.3.4"], "id.resp_p": [443, 8080],
        "proto": ["tcp", "tcp"], "service": ["ssl", np.nan],
        "duration": [0.25, np.nan], "orig_bytes": [100, np.nan], "resp_bytes": [200, np.nan],
        "conn_state": ["SF", "S0"], "orig_pkts": [3, 1], "resp_pkts": [2, 0],
    })
    write_zeek_tsv(df, tmp_path / "conn.log", CONN_FIELDS, CONN_TYPES)
    out = conn_to_cadence(read_zeek_log(tmp_path / "conn.log"))
    assert list(out["source.ip"]) == ["10.0.0.5", "10.0.0.5"]
    assert list(out["destination.port"]) == [443, 8080]
    # "-" service would be dropped by the loader; adapter must keep the row
    assert list(out["network.protocol"]) == ["ssl", "unknown"]
    assert out["event.duration"].tolist() == [0.25, 0.0]
    assert out["source.bytes"].tolist() == [100, 0]
    assert out["timestamp"].tolist() == [1.5, 2.5]


def test_iot23_space_separated_label_columns(tmp_path):
    header = ("#separator \\x09\n#set_separator\t,\n#empty_field\t(empty)\n#unset_field\t-\n"
              "#path\tconn\n#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\t"
              "service\tduration\torig_bytes\tresp_bytes\tconn_state\torig_pkts\tresp_pkts\t"
              "tunnel_parents   label   detailed-label\n"
              "#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring\tinterval\tcount\tcount\t"
              "string\tcount\tcount\tset[string]   string   string\n")
    rows = ("1525879831.0\tC1\t192.168.100.103\t51524\t65.1.2.3\t23\ttcp\t-\t2.9\t0\t0\tS0\t3\t0\t"
            "-   Malicious   PartOfAHorizontalPortScan\n"
            "1525879832.0\tC2\t192.168.100.103\t40000\t5.6.7.8\t6667\ttcp\tirc\t1.0\t10\t20\tSF\t5\t4\t"
            "(empty)   Malicious   C&C-HeartBeat\n#close\tx\n")
    (tmp_path / "conn.log.labeled").write_text(header + rows)
    df = read_zeek_log(tmp_path / "conn.log.labeled")
    assert list(df["label"]) == ["Malicious", "Malicious"]
    assert list(df["detailed-label"]) == ["PartOfAHorizontalPortScan", "C&C-HeartBeat"]
    assert df["tunnel_parents"].isna().iloc[0] and df["tunnel_parents"].iloc[1] == ""
    out = conn_to_cadence(df)
    assert "detailed-label" in out.columns

    gt = gtm.from_zeek_labeled([tmp_path / "conn.log.labeled"])
    c2 = gt[gt["gt_class"] == "c2"]
    assert list(zip(c2["src_ip"], c2["dst_ip"])) == [("192.168.100.103", "5.6.7.8")]
    assert (gt["gt_class"] == "malicious_other").sum() == 1


def test_json_dns_iso_timestamps_and_lists(tmp_path):
    recs = [
        {"ts": "2023-02-20T10:00:00.500000Z", "id.orig_h": "10.0.0.5", "id.resp_h": "10.0.0.1",
         "query": "a.example.com", "rcode_name": "NOERROR",
         "answers": ["1.2.3.4", "5.6.7.8"], "TTLs": [60.0, 60.0]},
        {"ts": "2023-02-20T10:01:00Z", "id.orig_h": "10.0.0.5", "id.resp_h": "10.0.0.1",
         "query": "b.example.com", "rcode_name": "NXDOMAIN"},
    ]
    (tmp_path / "dns.log").write_text("\n".join(json.dumps(r) for r in recs) + "\n")
    df = read_zeek_log(tmp_path / "dns.log")
    assert df["ts"].iloc[0] == pytest.approx(1676887200.5)
    assert df["answers"].iloc[0] == "1.2.3.4,5.6.7.8"
    assert df["TTLs"].iloc[0] == "60.0,60.0"


def test_convert_dir_concatenates_rotated_gz(tmp_path):
    zdir = tmp_path / "zeek"
    zdir.mkdir()
    base = dict(uid="C", proto="tcp", service="http", duration=1.0, orig_bytes=1,
                resp_bytes=1, conn_state="SF", orig_pkts=1, resp_pkts=1)
    a = pd.DataFrame([{**base, "ts": 20.0, "id.orig_h": "10.0.0.1", "id.orig_p": 1,
                       "id.resp_h": "9.9.9.1", "id.resp_p": 80}])
    b = pd.DataFrame([{**base, "ts": 10.0, "id.orig_h": "10.0.0.2", "id.orig_p": 2,
                       "id.resp_h": "9.9.9.2", "id.resp_p": 80}])
    write_zeek_tsv(a, zdir / "conn.01:00:00-02:00:00.log.gz", CONN_FIELDS, CONN_TYPES, gz=True)
    write_zeek_tsv(b, zdir / "conn.00:00:00-01:00:00.log.gz", CONN_FIELDS, CONN_TYPES, gz=True)
    written = convert_dir(zdir, tmp_path / "out")
    conn = pd.read_csv(written["conn"])
    assert conn["timestamp"].tolist() == [10.0, 20.0]   # merged and time-sorted
    assert written["dns"] is None


# ---------------------------------------------------------------------------
# Prefilter guards
# ---------------------------------------------------------------------------

def test_internal_cidr_marks_public_campus_space_internal():
    nets = pf._parse_networks(["147.32.0.0/16"])
    assert not pf._is_internal("147.32.84.165")
    assert pf._is_internal("147.32.84.165", nets)
    assert not pf._is_internal("8.8.4.4", nets)
    assert pf._classify_pair("147.32.84.165", "147.32.80.9", 443, set(), set(),
                             internal_networks=nets) == "both_internal"
    assert pf._classify_pair("147.32.84.165", "147.32.80.9", 443, set(), set()) is None


def test_fanin_guard_skips_small_source_populations():
    few = pd.DataFrame({"src_ip": ["10.0.0.1", "10.0.0.2"], "dst_ip": ["6.6.6.6", "6.6.6.6"]})
    assert pf._build_high_fanin_set(few, 0.5, min_sources=10) == set()
    assert pf._build_high_fanin_set(few, 0.5, min_sources=0) == {"6.6.6.6"}

    many = pd.DataFrame({"src_ip": [f"10.0.0.{i}" for i in range(20)],
                         "dst_ip": ["6.6.6.6"] * 20})
    assert pf._build_high_fanin_set(many, 0.5, min_sources=10) == {"6.6.6.6"}


def test_prefilter_config_round_trips_through_json(tmp_path):
    cfg = BDPConfig()
    cfg.prefilter.internal_cidrs = ("147.32.0.0/16",)
    cfg.prefilter.min_sources_for_fanin = 3
    cfg.to_json(str(tmp_path / "c.json"))
    back = BDPConfig.from_json(str(tmp_path / "c.json"))
    assert tuple(back.prefilter.internal_cidrs) == ("147.32.0.0/16",)
    assert back.prefilter.min_sources_for_fanin == 3


# ---------------------------------------------------------------------------
# Ground truth
# ---------------------------------------------------------------------------

def test_ctu13_binetflow_ground_truth(tmp_path):
    csv = (
        "StartTime,Dur,Proto,SrcAddr,Sport,Dir,DstAddr,Dport,State,sTos,dTos,TotPkts,TotBytes,SrcBytes,Label\n"
        "2011/08/10 09:46:59.6,1.0,tcp,147.32.84.165,1027,   ->,66.1.1.1,6667,S_RA,0,0,4,276,156,flow=From-Botnet-V42-TCP-CC1-IRC\n"
        "2011/08/10 09:47:59.6,1.0,tcp,147.32.84.165,1028,   ->,66.1.1.1,6667,S_RA,0,0,4,276,156,flow=From-Botnet-V42-TCP-Established\n"
        "2011/08/10 09:48:00.0,0.1,tcp,147.32.84.165,1029,   ->,77.2.2.2,25,S_RA,0,0,2,120,60,flow=From-Botnet-V42-TCP-Attempt-SPAM\n"
        "2011/08/10 09:48:01.0,0.1,udp,147.32.84.10,53000,  <->,147.32.80.9,53,CON,0,0,2,180,80,flow=Background-UDP-Established\n"
        "2011/08/10 09:48:02.0,0.1,tcp,147.32.84.165,1030,   ->,66.1.1.1,0x0050,S_RA,0,0,2,120,60,flow=From-Botnet-V42-TCP-CC1-HTTP\n"
    )
    p = tmp_path / "s1.binetflow"
    p.write_text(csv)
    gt = gtm.from_ctu13_binetflow([p]).set_index(["src_ip", "dst_ip"])
    assert gt.loc[("147.32.84.165", "66.1.1.1"), "gt_class"] == "c2"
    assert gt.loc[("147.32.84.165", "66.1.1.1"), "n_flows"] == 3
    assert gt.loc[("147.32.84.165", "77.2.2.2"), "gt_class"] == "malicious_other"
    assert ("147.32.84.10", "147.32.80.9") not in gt.index


def test_score_strict_vs_lenient_and_stage_attribution():
    raw = pd.DataFrame({"src_ip": ["a", "a", "b", "c", "d"],
                        "dst_ip": ["X", "Y", "X", "Z", "W"], "n_flows": [50, 50, 50, 50, 3]})
    scaled = pd.DataFrame({"src_ip": ["a", "a", "b"], "dst_ip": ["X", "Y", "X"],
                           "iforest_label": [-1, -1, 1]})
    pre = pd.DataFrame({"src_ip": ["c"], "dst_ip": ["Z"], "prefilter_reason": ["known_cdn"]})
    sax = pd.DataFrame({"src_ip": ["a", "a"], "dst_ip": ["X", "Y"], "sax_prescreen_pass": [True, True]})
    per = pd.DataFrame({"src_ip": ["a", "a"], "dst_ip": ["X", "Y"],
                        "is_beacon_pair": [True, True], "beacon_confidence": [0.9, 0.8]})
    corr = pd.DataFrame({"src_ip": ["a", "a"], "dst_ip": ["X", "Y"],
                         "corroborated": [True, False], "corroboration_score": [0.7, 0.1]})
    tbl = gtm.stage_table(raw, scaled, pre, sax, per, corr)
    st = dict(zip(zip(tbl.src_ip, tbl.dst_ip), tbl.stage))
    assert st == {("a", "X"): "corroborated", ("a", "Y"): "beacon_uncorroborated",
                  ("b", "X"): "iforest_normal", ("c", "Z"): "prefiltered",
                  ("d", "W"): "below_min_flows"}

    gt = pd.DataFrame({"src_ip": ["a", "c", "d", "e", "a"], "dst_ip": ["X", "Z", "W", "Q", "Y"],
                       "gt_class": ["c2", "c2", "c2", "c2", "malicious_other"]})
    m, per_gt = gtm.score(tbl, gt)
    assert m["n_gt_c2_pairs"] == 4 and m["n_gt_c2_pairs_in_conn"] == 3
    # beacon stage flags a→X (c2) and a→Y (malicious_other)
    assert m["strict"]["beacon_stage"]["fp"] == 1
    assert m["lenient"]["beacon_stage"]["fp"] == 0
    assert m["strict"]["corroborated_stage"]["recall"] == pytest.approx(1 / 3, abs=1e-3)
    assert m["strict"]["corroborated_stage_detectable_only"]["recall"] == pytest.approx(0.5)
    assert m["c2_pairs_by_stage"] == {"not_in_conn": 1, "below_min_flows": 1,
                                      "prefiltered": 1, "corroborated": 1}
    assert m["c2_prefilter_reasons"] == {"known_cdn": 1}
    # ranking aX(+), aY, bX, cZ(+), dW(+) → AP = (1/1 + 2/4 + 3/5) / 3
    assert m["strict"]["average_precision"] == pytest.approx(0.7, abs=1e-3)


# ---------------------------------------------------------------------------
# End-to-end round trip
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def synthetic(tmp_path_factory):
    from analytic_pipeline.generate_synthetic_data import SyntheticDataGenerator
    conn, dns, http, ssl, labels = SyntheticDataGenerator(seed=42).generate(
        days=3, bg_rows_per_day=2_000, noisy_rows_per_day=200)
    root = tmp_path_factory.mktemp("rt")

    # Normalise once so both paths see identical bytes: Zeek prints 6 decimals,
    # TTLs as strings, and logs in time order.
    conn = conn.copy()
    conn["timestamp"] = conn["timestamp"].round(6)
    conn["event.duration"] = conn["event.duration"].round(6)
    conn = conn.sort_values("timestamp", kind="stable").reset_index(drop=True)
    dns = dns.copy()
    dns["ts"] = dns["ts"].round(6)
    dns["TTLs"] = dns["TTLs"].map(lambda v: "" if pd.isna(v) else f"{float(v)}")
    for d in (http, ssl):
        d["ts"] = d["ts"].round(6)

    # Path A: ECS-style CSVs straight from the generator
    direct = root / "direct"
    direct.mkdir()
    conn.drop(columns=["label", "scenario"]).to_csv(direct / "conn.csv", index=False)
    dns.sort_values("ts", kind="stable").to_csv(direct / "dns.csv", index=False)
    http.sort_values("ts", kind="stable").to_csv(direct / "http.csv", index=False)
    ssl.sort_values("ts", kind="stable").to_csv(direct / "ssl.csv", index=False)

    # Path B: the same data as native Zeek logs (TSV conn/http/ssl, JSON dns)
    zeek = root / "zeek"
    zeek.mkdir()
    native = conn.rename(columns={
        "timestamp": "ts", "source.ip": "id.orig_h", "source.port": "id.orig_p",
        "destination.ip": "id.resp_h", "destination.port": "id.resp_p",
        "network.protocol": "service", "event.duration": "duration",
        "source.bytes": "orig_bytes", "destination.bytes": "resp_bytes",
        "network.connection.state": "conn_state", "source.packets": "orig_pkts",
        "destination.packets": "resp_pkts"})
    native["uid"] = [f"C{i}" for i in range(len(native))]
    native["proto"] = np.where(native["service"].isin(["dns", "ntp"]), "udp", "tcp")
    half = len(native) // 2
    write_zeek_tsv(native.iloc[:half], zeek / "conn.00:00:00-12:00:00.log.gz", CONN_FIELDS, CONN_TYPES, gz=True)
    write_zeek_tsv(native.iloc[half:], zeek / "conn.12:00:00-00:00:00.log.gz", CONN_FIELDS, CONN_TYPES, gz=True)

    with open(zeek / "dns.log", "w") as fh:
        for r in dns.to_dict("records"):
            rec = {k: r[k] for k in ("ts", "id.orig_h", "query", "rcode_name") if pd.notna(r[k])}
            if pd.notna(r["answers"]):
                rec["answers"] = str(r["answers"]).split(",")
            if r["TTLs"]:
                rec["TTLs"] = [float(x) for x in str(r["TTLs"]).split(",")]
            fh.write(json.dumps(rec) + "\n")
    http_f = ["ts", "id.orig_h", "id.resp_h", "uri", "user_agent", "method", "status_code",
              "request_body_len", "response_body_len"]
    write_zeek_tsv(http, zeek / "http.log", http_f,
                   ["time", "addr", "addr", "string", "string", "string", "count", "count", "count"], "http")
    ssl_f = ["ts", "id.orig_h", "id.resp_h", "server_name", "ja3", "ja3s", "cert_chain_fuids",
             "validation_status", "resumed", "established"]
    write_zeek_tsv(ssl, zeek / "ssl.log", ssl_f,
                   ["time", "addr", "addr", "string", "string", "string", "vector[string]",
                    "string", "bool", "bool"], "ssl")

    mal = conn[conn["label"] == "malicious"][["source.ip", "destination.ip"]].drop_duplicates()
    gt = gtm.from_pairs(list(map(tuple, mal.to_numpy())))
    gt.to_csv(root / "gt.csv", index=False)
    return root


def _run(args):
    import run_real_data
    run_real_data.main(args)


def test_round_trip_native_zeek_matches_direct(synthetic):
    root = synthetic
    common = ["--gt", str(root / "gt.csv"), "--contamination", "0.10"]
    _run(["--cadence-dir", str(root / "direct"), "--output", str(root / "out_direct"), *common])
    _run(["--zeek-dir", str(root / "zeek"), "--output", str(root / "out_zeek"), *common])

    def _stages(d):
        return pd.read_csv(root / d / "stages" / "pair_stages.csv").sort_values(["src_ip", "dst_ip"]) \
                 .reset_index(drop=True)

    a, b = _stages("out_direct"), _stages("out_zeek")
    pd.testing.assert_frame_equal(a[["src_ip", "dst_ip", "n_flows", "stage"]],
                                  b[["src_ip", "dst_ip", "n_flows", "stage"]])
    np.testing.assert_allclose(a["rank_score"], b["rank_score"], atol=1e-9)

    ma = json.loads((root / "out_direct" / "metrics.json").read_text())
    mb = json.loads((root / "out_zeek" / "metrics.json").read_text())
    assert ma == mb
    assert ma["n_gt_c2_pairs_in_conn"] == ma["n_gt_c2_pairs"] > 0
    assert sum(ma["c2_pairs_by_stage"].values()) == ma["n_gt_c2_pairs"]
    assert ma["strict"]["corroborated_stage"]["tp"] >= 1


def test_rescore_saved_run_matches(synthetic):
    root = synthetic
    if not (root / "out_zeek" / "stages").exists():
        pytest.skip("round-trip test did not run")
    m_saved = json.loads((root / "out_zeek" / "metrics.json").read_text())
    m_re, _ = gtm.score_run_dir(root / "out_zeek", root / "gt.csv")
    assert json.loads(json.dumps(m_re)) == m_saved


def test_pcap_path_runs_zeek_in_its_own_dir(tmp_path):
    """Stand-in zeek binary: records its arguments and drops a conn.log in cwd."""
    from analytic_pipeline.zeek_adapter import run_zeek
    fake = tmp_path / "zeek"
    fake.write_text(
        "#!/bin/sh\n"
        "echo \"$@\" > args.txt\n"
        "printf '#separator \\\\x09\\n#fields\\tts\\tid.orig_h\\tid.orig_p\\tid.resp_h\\tid.resp_p\\t"
        "proto\\tservice\\tduration\\torig_bytes\\tresp_bytes\\tconn_state\\torig_pkts\\tresp_pkts\\n"
        "1.0\\t10.0.0.1\\t1\\t9.9.9.9\\t443\\ttcp\\tssl\\t0.5\\t10\\t20\\tSF\\t1\\t1\\n' > conn.log\n"
    )
    fake.chmod(0o755)
    pcap = tmp_path / "cap.pcap"
    pcap.write_bytes(b"")
    out = run_zeek([pcap], tmp_path / "z", zeek_bin=str(fake), extra_scripts=["ja3"])
    work = next((out).iterdir())
    assert (work / "args.txt").read_text().split() == ["-C", "-r", str(pcap.resolve()), "ja3"]
    written = convert_dir(out, tmp_path / "csv")
    conn = pd.read_csv(written["conn"])
    assert conn.loc[0, "destination.ip"] == "9.9.9.9" and conn.loc[0, "network.protocol"] == "ssl"


def test_missing_zeek_binary_gives_clear_error(tmp_path):
    from analytic_pipeline.zeek_adapter import run_zeek
    with pytest.raises(FileNotFoundError, match="--zeek-dir"):
        run_zeek([tmp_path / "x.pcap"], tmp_path / "z", zeek_bin="definitely-not-zeek")
