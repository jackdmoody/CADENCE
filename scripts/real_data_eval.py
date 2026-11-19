"""
One-command real-data evaluation for CADENCE (run on a machine with normal internet).

Downloads public datasets, runs Zeek, runs CADENCE, scores against ground truth,
and writes small, committable result folders that paper/make_numbers.py reads.

    python scripts/real_data_eval.py                       # default CTU-13 scenarios
    python scripts/real_data_eval.py --ctu13 7 9 --iot23 CTU-IoT-Malware-Capture-1-1
    python scripts/real_data_eval.py --acm-pcap capture.pcap --acm-name sliver \\
        --acm-victim 10.0.0.5 --acm-c2 1.2.3.4 --acm-period 5 --acm-jitter 0.6

Layout:
    data/real/<run>/...                 downloads, Zeek logs, full run outputs (gitignored)
    results/real_data/<run>/            metrics.json, gt_pairs_by_stage.csv, run_summary.json,
                                        run_config.json, gt_periodicity.csv, dataset_info.json

Protocol (the same rules as the paper):
    * default configuration everywhere;
    * --internal-cidr only from the dataset's own address plan (checked against labels);
    * --min-period-s lowered only when a capture's published beacon interval is < 60 s;
    * CTU-13: conn-only run is the headline; the full run (with dns/http/ssl) is an
      ablation, because the truncated full capture has little payload for background.
"""
from __future__ import annotations

import argparse
import bz2
import ipaddress
import json
import logging
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import urljoin

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from analytic_pipeline import ground_truth as gtm  # noqa: E402
from analytic_pipeline.zeek_adapter import convert_dir  # noqa: E402
import run_real_data  # noqa: E402

log = logging.getLogger("real_data_eval")

CTU13_BASE = "https://mcfp.felk.cvut.cz/publicDatasets/"
CTU13_FAMILY = {1: "Neris", 2: "Neris", 3: "Rbot", 4: "Rbot", 5: "Virut", 6: "Menti", 7: "Sogou",
                8: "Murlo", 9: "Neris", 10: "Rbot", 11: "Rbot", 12: "NSIS.ay", 13: "Virut"}
# Covers IRC C2 (Neris, Rbot) and HTTP-style C2 (Sogou, Virut, Menti); smallest captures first
DEFAULT_CTU13 = [7, 11, 6, 5, 9, 1]
IOT23_BASE = "https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/IndividualScenarios/"
H2_LINK = 5.0   # opt-in DNS-linking ablation window (s); set to 0 with --no-h2-link
SMALL_FILES = ("metrics.json", "gt_pairs_by_stage.csv", "run_summary.json", "run_config.json")


# ---------------------------------------------------------------------------
# Downloads
# ---------------------------------------------------------------------------

def list_links(url: str) -> list[str]:
    """Hrefs from an Apache-style directory index."""
    html = subprocess.run(["curl", "-sSfL", "--max-time", "60", url], check=True,
                          capture_output=True, text=True).stdout
    return parse_index(html)


def parse_index(html: str) -> list[str]:
    hrefs = re.findall(r'href="([^"?#]+)"', html)
    return [h for h in hrefs if not h.startswith(("/", "http", "..", "mailto:"))]


def download(url: str, dest: Path) -> Path:
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists() and dest.stat().st_size > 0:
        log.info("have %s", dest.name)
        return dest
    log.info("downloading %s", url)
    subprocess.run(["curl", "-sSfL", "-C", "-", "--retry", "3", "-o", str(dest), url], check=True)
    return dest


def bunzip(path: Path) -> Path:
    if path.suffix != ".bz2":
        return path
    out = path.with_suffix("")
    if not out.exists():
        log.info("decompressing %s", path.name)
        with bz2.open(path, "rb") as src, open(out, "wb") as dst:
            shutil.copyfileobj(src, dst, length=16 << 20)
    return out


def run_zeek(pcap: Path, out_dir: Path) -> Path:
    if shutil.which("zeek") is None:
        sys.exit("zeek not found on PATH (macOS: brew install zeek)")
    out_dir.mkdir(parents=True, exist_ok=True)
    if not (out_dir / "conn.log").exists():
        log.info("zeek on %s", pcap.name)
        subprocess.run(["zeek", "-C", "-r", str(pcap.resolve())], cwd=out_dir, check=True)
    return out_dir


# ---------------------------------------------------------------------------
# Packaging
# ---------------------------------------------------------------------------

def package(run_dir: Path, result_dir: Path, info: dict) -> dict:
    """Copy small files and write gt_periodicity.csv and dataset_info.json."""
    result_dir.mkdir(parents=True, exist_ok=True)
    for f in SMALL_FILES:
        if (run_dir / f).exists():
            shutil.copy2(run_dir / f, result_dir / f)
    per = run_dir / "stages" / "periodicity.csv"
    gtp = result_dir / "gt_pairs_by_stage.csv"
    if per.exists() and gtp.exists():
        p = pd.read_csv(per, dtype={"src_ip": str, "dst_ip": str})
        g = pd.read_csv(gtp, dtype={"src_ip": str, "dst_ip": str})
        keys = set(zip(g.loc[g["gt_class"] == "c2", "src_ip"], g.loc[g["gt_class"] == "c2", "dst_ip"]))
        p[[k in keys for k in zip(p["src_ip"], p["dst_ip"])]].to_csv(result_dir / "gt_periodicity.csv", index=False)
    summ = json.loads((run_dir / "run_summary.json").read_text()) if (run_dir / "run_summary.json").exists() else {}
    m = json.loads((run_dir / "metrics.json").read_text()) if (run_dir / "metrics.json").exists() else {}
    info = {**info, "conn_rows": summ.get("conn_rows"), "c2_pairs": m.get("n_gt_c2_pairs_in_conn")}
    (result_dir / "dataset_info.json").write_text(json.dumps(info, indent=2, default=str))
    return info


def conn_facts(cadence_dir: Path) -> dict:
    c = pd.read_csv(cadence_dir / "conn.csv", usecols=["timestamp", "source.ip", "destination.ip"])
    hosts = pd.concat([c["source.ip"], c["destination.ip"]]).nunique()
    return {"capture_hours": round(float(c["timestamp"].max() - c["timestamp"].min()) / 3600, 2),
            "unique_hosts": int(hosts)}


def infer_internal_cidr(gt: pd.DataFrame) -> str | None:
    """CTU-13 infected hosts sit on CTU's public range. Use the /16 they share, if they share one."""
    srcs = {s for s in gt["src_ip"] if ":" not in s}
    nets = {ipaddress.ip_network(f"{s}/16", strict=False) for s in srcs}
    if len(nets) == 1:
        net = next(iter(nets))
        if not net.is_private:
            return str(net)
    return None


def cadence(cadence_dir: Path, run_dir: Path, gt_csv: Path, extra: list[str]) -> None:
    args = ["--cadence-dir", str(cadence_dir), "--output", str(run_dir), "--gt", str(gt_csv), *extra]
    log.info("run_real_data %s", " ".join(args))
    run_real_data.main(args)


# ---------------------------------------------------------------------------
# Datasets
# ---------------------------------------------------------------------------

def ctu13(n: int, work: Path, results: Path, keep_pcap: bool, skip_full: bool) -> None:
    cap = f"CTU-Malware-Capture-Botnet-{41 + n}"
    base = urljoin(CTU13_BASE, cap + "/")
    d = work / f"ctu13_s{n}"
    links = list_links(base)
    flow_dir = next((l for l in links if "bidirectional" in l and l.endswith("/")), None)
    flow_links = [urljoin(base + flow_dir, l) for l in list_links(base + flow_dir)] if flow_dir else []
    flow_links += [urljoin(base, l) for l in links]
    binetflow = next((u for u in flow_links if u.endswith(".binetflow")), None)
    pcap_url = next((urljoin(base, l) for l in links if "truncated" in l and ".pcap" in l), None)
    if not binetflow or not pcap_url:
        log.error("scenario %d: binetflow=%s truncated pcap=%s, skipping", n, binetflow, pcap_url)
        return

    bf = download(binetflow, d / Path(binetflow).name)
    gt = gtm.from_ctu13_binetflow([bf])
    if (gt["gt_class"] == "c2").sum() == 0:
        log.error("scenario %d: no C&C-labelled flows with pattern %s, skipping", n, gtm.CTU13_C2_PATTERN)
        return
    gt_csv = d / "gt.csv"
    gt.to_csv(gt_csv, index=False)
    cidr = infer_internal_cidr(gt)

    pcap = bunzip(download(pcap_url, d / Path(pcap_url).name))
    zdir = run_zeek(pcap, d / "zeek")
    if not keep_pcap:
        for p in d.glob("*.pcap*"):
            p.unlink()
    cdir = d / "cadence_input"
    if not (cdir / "conn.csv").exists():
        convert_dir(zdir, cdir)

    extra = ["--internal-cidr", cidr] if cidr else []
    info = {"dataset": "CTU-13", "source_url": base, "scenario": n, "malware_family": CTU13_FAMILY.get(n),
            "published_period_s": None, "published_jitter": None,
            "settings_changed": {"internal_cidr": cidr} if cidr else {},
            "notes": "conn-only headline; truncated full capture", **conn_facts(cdir)}
    modes = ["connonly"] + ([] if skip_full else ["full"] + (["full_h2link"] if H2_LINK else []))
    for mode in modes:
        run_dir = d / f"run_{mode}"
        flags = list(extra)
        if mode == "connonly":
            flags.append("--conn-only")
        if mode.endswith("h2link"):
            flags += ["--dns-link-window-s", str(H2_LINK)]
        note = info["notes"]
        if mode != "connonly":
            note += "; FULL run is an ablation: app-layer logs exist mainly for botnet traffic"
        if mode.endswith("h2link"):
            note += f"; opt-in H2 linking window {H2_LINK}s (not default)"
        settings = dict(info["settings_changed"])
        if mode.endswith("h2link"):
            settings["dns_link_window_s"] = H2_LINK
        cadence(cdir, run_dir, gt_csv, flags)
        package(run_dir, results / f"ctu13_s{n}_{mode}", {**info, "notes": note, "settings_changed": settings})


def iot23(name: str, work: Path, results: Path) -> None:
    base = urljoin(IOT23_BASE, name + "/")
    d = work / f"iot23_{name}"
    links = list_links(base)
    bro = next((l for l in links if l.rstrip("/").endswith("bro")), "bro/")
    url = urljoin(base + bro, "conn.log.labeled")
    conn = download(url, d / "zeek" / "conn.log.labeled")
    gt = gtm.from_zeek_labeled([conn])
    gt_csv = d / "gt.csv"
    gt.to_csv(gt_csv, index=False)
    cdir = d / "cadence_input"
    if not (cdir / "conn.csv").exists():
        convert_dir(d / "zeek", cdir)
    run_dir = d / "run_connonly"
    cadence(cdir, run_dir, gt_csv, ["--conn-only"])
    package(run_dir, results / f"iot23_{name}",
            {"dataset": "IoT-23", "source_url": base, "scenario": name, "malware_family": None,
             "published_period_s": None, "published_jitter": None, "settings_changed": {},
             "notes": "labels from conn.log.labeled (C&C* detailed labels)", **conn_facts(cdir)})


def acm(a, work: Path, results: Path) -> None:
    d = work / f"acm_{a.acm_name}"
    zdir = run_zeek(Path(a.acm_pcap), d / "zeek")
    cdir = d / "cadence_input"
    if not (cdir / "conn.csv").exists():
        convert_dir(zdir, cdir)
    gt_csv = d / "gt.csv"
    gtm.from_pairs([(a.acm_victim, a.acm_c2)], label="acm").to_csv(gt_csv, index=False)
    extra = []
    changed = {}
    if a.acm_period and a.acm_period < 60:
        floor = max(1.0, a.acm_period / 2)
        extra = ["--min-period-s", str(floor)]
        changed = {"min_period_s": floor, "reason": "published beacon interval below 60 s"}
    base_info = {"dataset": "Active Countermeasures Malware of the Day", "source_url": a.acm_url,
                 "scenario": a.acm_name, "malware_family": a.acm_name, "published_period_s": a.acm_period,
                 "published_jitter": a.acm_jitter, "notes": "ground truth = published victim and C2 IPs",
                 **conn_facts(cdir)}
    cadence(cdir, d / "run", gt_csv, extra)
    package(d / "run", results / f"acm_{a.acm_name}", {**base_info, "settings_changed": changed})
    if H2_LINK:
        cadence(cdir, d / "run_h2link", gt_csv, extra + ["--dns-link-window-s", str(H2_LINK)])
        package(d / "run_h2link", results / f"acm_{a.acm_name}_h2link",
                {**base_info, "settings_changed": {**changed, "dns_link_window_s": H2_LINK},
                 "notes": base_info["notes"] + f"; opt-in H2 linking window {H2_LINK}s (not default)"})


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s  %(levelname)-7s  %(message)s",
                        datefmt="%H:%M:%S")
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--ctu13", type=int, nargs="*", default=None,
                   help=f"CTU-13 scenario numbers (default {DEFAULT_CTU13}; pass none to skip)")
    p.add_argument("--iot23", nargs="*", default=[], help="IoT-23 scenario folder names")
    p.add_argument("--acm-pcap"), p.add_argument("--acm-name"), p.add_argument("--acm-url", default="")
    p.add_argument("--acm-victim"), p.add_argument("--acm-c2")
    p.add_argument("--acm-period", type=float), p.add_argument("--acm-jitter", type=float)
    p.add_argument("--work", default=str(ROOT / "data" / "real"))
    p.add_argument("--results", default=str(ROOT / "results" / "real_data"))
    p.add_argument("--keep-pcap", action="store_true")
    p.add_argument("--skip-full", action="store_true", help="CTU-13: conn-only runs only")
    p.add_argument("--no-h2-link", action="store_true",
                   help="skip the extra opt-in H2-linking ablation runs (_h2link)")
    a = p.parse_args()
    global H2_LINK
    if a.no_h2_link:
        H2_LINK = 0.0
    work, results = Path(a.work), Path(a.results)

    scen = DEFAULT_CTU13 if a.ctu13 is None else a.ctu13
    t0 = time.time()
    for n in scen:
        try:
            ctu13(n, work, results, a.keep_pcap, a.skip_full)
        except Exception as e:  # keep going; one bad scenario should not sink the night
            log.exception("CTU-13 scenario %d failed: %s", n, e)
    for name in a.iot23:
        try:
            iot23(name, work, results)
        except Exception as e:
            log.exception("IoT-23 %s failed: %s", name, e)
    if a.acm_pcap:
        acm(a, work, results)
    log.info("done in %.0f min. Next: python paper/make_numbers.py && (cd paper && latexmk -pdf main.tex)",
             (time.time() - t0) / 60)


if __name__ == "__main__":
    main()
