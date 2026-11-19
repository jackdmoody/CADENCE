"""
Zeek → CADENCE adapter
=======================
Converts native Zeek logs into the CSV files CADENCE's loaders expect, so the
pipeline can run on public datasets (CTU-13, IoT-23, Active Countermeasures
"Malware of the Day", OpTC, UWF-ZeekData22) instead of synthetic data only.

Accepted inputs (gzip is fine for all of them):
    * Zeek ASCII/TSV logs with the usual #separator / #fields / #types header
    * Zeek JSON logs (LogAscii::use_json=T), epoch or ISO-8601 timestamps
    * CSV or Parquet exports that keep the native Zeek field names
    * Raw pcaps, if a `zeek` binary is on PATH (see run_zeek)

Outputs (written to --out):
    conn.csv   ECS-style columns read by analytic_pipeline.loaders
               (timestamp, source.ip, destination.bytes, ...)
    dns.csv    native field names, read by corroboration.load_dns_logs
    http.csv   native field names, read by corroboration.load_http_logs
    ssl.csv    native field names, read by corroboration.load_ssl_logs

Why the conn mapping matters:
    * loaders.load_and_prepare() only understands ECS-style names, so a raw
      conn.log (id.orig_h, orig_bytes, ts) would lose every key column.
    * Zeek writes "-" for service when it cannot identify the protocol and
      for duration on single-packet connections. The loader drops rows with
      a missing service or duration, which would silently delete custom-
      protocol C2. Unidentified services become "unknown" and missing
      durations become 0.0.

Dataset quirk handled here:
    * IoT-23 conn.log.labeled separates its last three columns
      (tunnel_parents, label, detailed-label) with runs of spaces instead of
      tabs. Those columns are split back out so labels survive conversion.

CLI:
    python -m analytic_pipeline.zeek_adapter --zeek-dir /data/ctu13/s1/zeek --out /data/ctu13/s1/cadence
    python -m analytic_pipeline.zeek_adapter --pcap capture.pcap --out /data/run1/cadence
"""
from __future__ import annotations

import argparse
import csv
import gzip
import io
import json
import logging
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Iterable, Optional

import numpy as np
import pandas as pd

log = logging.getLogger(__name__)

LOG_TYPES = ("conn", "dns", "http", "ssl")

# Native Zeek conn.log field → column name expected by loaders.load_and_prepare()
CONN_FIELD_MAP = {
    "ts":          "timestamp",
    "uid":         "uid",
    "id.orig_h":   "source.ip",
    "id.orig_p":   "source.port",
    "id.resp_h":   "destination.ip",
    "id.resp_p":   "destination.port",
    "proto":       "network.transport",
    "service":     "network.protocol",
    "duration":    "event.duration",
    "orig_bytes":  "source.bytes",
    "resp_bytes":  "destination.bytes",
    "conn_state":  "network.connection.state",
    "orig_pkts":   "source.packets",
    "resp_pkts":   "destination.packets",
}

# Label columns some public datasets ship inside conn.log (IoT-23, UWF).
CONN_LABEL_COLS = ("label", "detailed-label", "detailed_label", "mitre_attack_tactics")

# Fields the corroboration loaders read; everything else is dropped to keep
# the CSVs small. Missing fields are simply absent.
KEEP_FIELDS = {
    "dns":  ("ts", "uid", "id.orig_h", "id.resp_h", "id.resp_p", "proto", "query",
             "qtype_name", "rcode_name", "answers", "TTLs"),
    "http": ("ts", "uid", "id.orig_h", "id.resp_h", "id.resp_p", "host", "uri",
             "user_agent", "method", "status_code", "request_body_len",
             "response_body_len"),
    "ssl":  ("ts", "uid", "id.orig_h", "id.resp_h", "id.resp_p", "version", "server_name",
             "ja3", "ja3s", "validation_status", "resumed", "established",
             "cert_chain_fuids", "cert_chain_fps"),
}

_NUMERIC_TYPES = ("time", "interval", "double", "count", "int", "port")


# ---------------------------------------------------------------------------
# Reading
# ---------------------------------------------------------------------------

def _open_text(path: Path) -> io.TextIOBase:
    if path.suffix == ".gz":
        return io.TextIOWrapper(gzip.open(path, "rb"), encoding="utf-8", errors="replace")
    return open(path, "r", encoding="utf-8", errors="replace")


def _sniff_format(path: Path) -> str:
    name = path.name.lower().removesuffix(".gz")
    if name.endswith(".parquet"):
        return "parquet"
    if name.endswith(".csv"):
        return "csv"
    with _open_text(path) as fh:
        for line in fh:
            s = line.strip()
            if not s:
                continue
            if s.startswith("{"):
                return "json"
            if s.startswith("#"):
                return "tsv"
            break
    raise ValueError(f"Cannot tell whether {path} is Zeek TSV or JSON")


def _decode_separator(raw: str) -> str:
    raw = raw.strip()
    if raw.startswith("\\x"):
        return bytes.fromhex(raw[2:]).decode()
    return raw or "\t"


def _read_tsv(path: Path) -> pd.DataFrame:
    sep, set_sep, empty, unset = "\t", ",", "(empty)", "-"
    fields: list[str] = []
    types: list[str] = []
    n_header = 0
    with _open_text(path) as fh:
        for line in fh:
            line = line.rstrip("\r\n")
            if not line.startswith("#"):
                break
            n_header += 1
            if line.startswith("#separator"):
                sep = _decode_separator(line[len("#separator"):])
                continue
            key, *vals = line[1:].split(sep)
            if key == "fields":
                fields = vals
            elif key == "types":
                types = vals
            elif key == "set_separator" and vals:
                set_sep = vals[0]
            elif key == "empty_field" and vals:
                empty = vals[0]
            elif key == "unset_field" and vals:
                unset = vals[0]
    if not fields:
        raise ValueError(f"{path} has no #fields header")

    df = pd.read_csv(
        path, sep=sep, header=None, names=list(range(len(fields))), skiprows=n_header,
        dtype=str, na_filter=False, quoting=csv.QUOTE_NONE, engine="c" if len(sep) == 1 else "python",
        compression="gzip" if path.suffix == ".gz" else None, on_bad_lines="warn",
    )
    # Drop #close lines and any #open/#fields blocks from concatenated files
    df = df[~df[0].astype(str).str.startswith("#")]

    # IoT-23: the last header token holds space-separated names, and each row's
    # last field holds the matching values separated by runs of spaces.
    last_names = re.split(r"\s+", fields[-1].strip())
    if len(last_names) > 1:
        k = len(last_names) - 1
        tail = df[len(fields) - 1].astype(str).str.strip().str.split(r"\s{2,}", n=k, expand=True)
        if tail.shape[1] < len(last_names):
            tail = df[len(fields) - 1].astype(str).str.strip().str.split(r"\s+", n=k, expand=True)
        tail = tail.reindex(columns=range(len(last_names)))
        df = pd.concat([df.drop(columns=[len(fields) - 1]).reset_index(drop=True),
                        tail.reset_index(drop=True)], axis=1)
        fields = fields[:-1] + last_names
        if types:
            types = types[:-1] + re.split(r"\s+", types[-1].strip())
    df.columns = fields
    df = df.reset_index(drop=True).replace({unset: np.nan, empty: ""})

    type_of = dict(zip(fields, types)) if types else {}
    for col in df.columns:
        t = type_of.get(col, "")
        if t in _NUMERIC_TYPES:
            df[col] = pd.to_numeric(df[col], errors="coerce")
        elif t == "bool":
            df[col] = df[col].map({"T": True, "F": False})
        elif set_sep != "," and (t.startswith("set") or t.startswith("vector")):
            df[col] = df[col].str.replace(set_sep, ",", regex=False)
    if not type_of and "ts" in df.columns:
        df["ts"] = pd.to_numeric(df["ts"], errors="coerce")
    return df


def _read_json(path: Path) -> pd.DataFrame:
    records = []
    with _open_text(path) as fh:
        for line in fh:
            line = line.strip()
            if line.startswith("{"):
                records.append(json.loads(line))
    df = pd.DataFrame.from_records(records)
    for col in df.columns:
        if df[col].map(lambda v: isinstance(v, (list, tuple))).any():
            df[col] = df[col].map(
                lambda v: ",".join(str(x) for x in v) if isinstance(v, (list, tuple)) else v
            )
    return df


def read_zeek_log(path: str | Path) -> pd.DataFrame:
    """Read one Zeek log (TSV, JSON, CSV or Parquet, optionally gzipped)."""
    path = Path(path)
    fmt = _sniff_format(path)
    if fmt == "tsv":
        df = _read_tsv(path)
    elif fmt == "json":
        df = _read_json(path)
    elif fmt == "csv":
        df = pd.read_csv(path, low_memory=False)
    else:
        df = pd.read_parquet(path)
    if "ts" in df.columns:
        df["ts"] = _to_epoch(df["ts"])
    log.info("Read %s (%s): %d rows", path.name, fmt, len(df))
    return df


def _to_epoch(ts: pd.Series) -> pd.Series:
    """Zeek timestamps arrive as epoch floats or ISO-8601 strings."""
    num = pd.to_numeric(ts, errors="coerce")
    if num.notna().any() or ts.isna().all():
        return num.astype(float)
    parsed = pd.to_datetime(ts, utc=True, errors="coerce", format="mixed")
    return (parsed - pd.Timestamp("1970-01-01", tz="UTC")).dt.total_seconds()


# ---------------------------------------------------------------------------
# Normalising
# ---------------------------------------------------------------------------

def conn_to_cadence(df: pd.DataFrame) -> pd.DataFrame:
    """Map a native Zeek conn.log frame onto CADENCE's conn CSV schema."""
    already_ecs = "source.ip" in df.columns and "id.orig_h" not in df.columns
    if already_ecs:
        out = df.copy()
        if "timestamp" not in out.columns:
            for cand in ("ts", "@timestamp", "_timestamp"):
                if cand in out.columns:
                    out["timestamp"] = _to_epoch(out[cand])
                    break
    else:
        missing = [f for f in ("ts", "id.orig_h", "id.resp_h") if f not in df.columns]
        if missing:
            raise ValueError(f"conn log is missing {missing}; columns: {list(df.columns)[:25]}")
        keep = [c for c in CONN_FIELD_MAP if c in df.columns]
        out = df[keep].rename(columns=CONN_FIELD_MAP)
        for col in CONN_LABEL_COLS:
            if col in df.columns:
                out[col] = df[col].values

    for col in ("source.bytes", "destination.bytes", "source.packets", "destination.packets"):
        if col not in out.columns:
            out[col] = 0
        out[col] = pd.to_numeric(out[col], errors="coerce").fillna(0).astype("int64")
    if "event.duration" not in out.columns:
        out["event.duration"] = 0.0
    out["event.duration"] = pd.to_numeric(out["event.duration"], errors="coerce").fillna(0.0)

    svc = out.get("network.protocol", pd.Series(index=out.index, dtype=object))
    svc = svc.astype(object).where(svc.notna() & (svc.astype(str).str.strip() != ""), "unknown")
    out["network.protocol"] = svc.astype(str).str.lower()

    for col in ("source.port", "destination.port"):
        if col in out.columns:
            out[col] = pd.to_numeric(out[col], errors="coerce").astype("Int64")

    out["timestamp"] = pd.to_numeric(out["timestamp"], errors="coerce")
    before = len(out)
    out = out.dropna(subset=["timestamp", "source.ip", "destination.ip"])
    if len(out) < before:
        log.info("conn: dropped %d rows with no timestamp or address", before - len(out))
    return out.sort_values("timestamp", kind="stable").reset_index(drop=True)


def aux_to_cadence(df: pd.DataFrame, log_type: str) -> pd.DataFrame:
    """Trim dns/http/ssl frames to the fields the corroboration stage reads."""
    keep = [c for c in KEEP_FIELDS[log_type] if c in df.columns]
    out = df[keep].copy()
    for col in ("resumed", "established"):
        if col in out.columns:
            out[col] = out[col].map({True: True, False: False, "T": True, "F": False,
                                     "true": True, "false": False}).astype(object)
    return out.dropna(subset=["ts"]).sort_values("ts", kind="stable").reset_index(drop=True)


# ---------------------------------------------------------------------------
# Directory / pcap conversion
# ---------------------------------------------------------------------------

def _find_logs(zeek_dir: Path, log_type: str) -> list[Path]:
    """Match conn.log, conn.00:00:00-01:00:00.log.gz, conn.log.labeled, conn.json ..."""
    pat = re.compile(rf"^{log_type}([._-].*)?\.(log|json|csv|parquet|labeled)(\.gz)?$"
                     rf"|^{log_type}\.log\.labeled(\.gz)?$")
    return sorted(p for p in zeek_dir.rglob("*") if p.is_file() and pat.match(p.name))


def convert_dir(zeek_dir: str | Path, out_dir: str | Path) -> dict[str, Optional[Path]]:
    """Convert every conn/dns/http/ssl log under zeek_dir; rotated files are concatenated."""
    zeek_dir, out_dir = Path(zeek_dir), Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    written: dict[str, Optional[Path]] = {}
    for log_type in LOG_TYPES:
        paths = _find_logs(zeek_dir, log_type)
        if not paths:
            log.warning("No %s logs found under %s", log_type, zeek_dir)
            written[log_type] = None
            continue
        frames = [read_zeek_log(p) for p in paths]
        df = pd.concat(frames, ignore_index=True)
        df = conn_to_cadence(df) if log_type == "conn" else aux_to_cadence(df, log_type)
        dest = out_dir / f"{log_type}.csv"
        df.to_csv(dest, index=False)
        written[log_type] = dest
        log.info("Wrote %s (%d rows from %d file(s))", dest, len(df), len(paths))
    if written.get("conn") is None:
        raise FileNotFoundError(f"No conn logs under {zeek_dir}; CADENCE needs conn.log at minimum")
    return written


def run_zeek(pcaps: Iterable[str | Path], zeek_out: str | Path, zeek_bin: str = "zeek",
             extra_scripts: Iterable[str] = ()) -> Path:
    """
    Run Zeek over one or more pcaps. -C ignores checksum errors, which are
    common in public captures. JA3/JA3S fields only appear if a JA3 package is
    installed and passed in extra_scripts (e.g. "ja3"); without it the H5/H6
    JA3 checks simply have nothing to score.
    """
    if shutil.which(zeek_bin) is None:
        raise FileNotFoundError(
            f"'{zeek_bin}' not found on PATH. Install Zeek, or run it yourself and "
            "pass the log directory with --zeek-dir."
        )
    zeek_out = Path(zeek_out)
    zeek_out.mkdir(parents=True, exist_ok=True)
    for i, pcap in enumerate(pcaps):
        pcap = Path(pcap).resolve()
        work = zeek_out / f"{i:03d}_{pcap.stem}"
        work.mkdir(exist_ok=True)
        cmd = [zeek_bin, "-C", "-r", str(pcap), *extra_scripts]
        log.info("Running %s in %s", " ".join(cmd), work)
        subprocess.run(cmd, cwd=work, check=True)
    return zeek_out


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: Optional[list[str]] = None) -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s  %(levelname)-7s  %(message)s",
                        datefmt="%H:%M:%S")
    p = argparse.ArgumentParser(description="Convert Zeek logs or pcaps into CADENCE CSVs")
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--zeek-dir", help="Directory of Zeek logs (searched recursively)")
    src.add_argument("--pcap", nargs="+", help="pcap file(s); requires zeek on PATH")
    p.add_argument("--out", required=True, help="Output directory for conn/dns/http/ssl CSVs")
    p.add_argument("--zeek-bin", default="zeek")
    p.add_argument("--zeek-script", action="append", default=[],
                   help="Extra Zeek script/package to load, e.g. --zeek-script ja3")
    args = p.parse_args(argv)

    if args.pcap:
        with tempfile.TemporaryDirectory(prefix="cadence_zeek_") as tmp:
            run_zeek(args.pcap, tmp, args.zeek_bin, args.zeek_script)
            written = convert_dir(tmp, args.out)
    else:
        written = convert_dir(args.zeek_dir, args.out)
    for k, v in written.items():
        print(f"  {k:<5} {v if v else '(none found)'}")


if __name__ == "__main__":
    main()
