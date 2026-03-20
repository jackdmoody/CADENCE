"""
Data Loading
=============
Zeek conn log ingestion from ISF (via ionic_scripting_framework) or CSV.
Handles schema normalisation, timestamp parsing, periodic time encoding,
feature derivation, one-hot encoding, and initial data cleaning.

Canonical output columns after load_and_prepare():
    datetime, src_ip, src_p, src_pkts, dst_ip, dst_p, resp_pkts,
    duration, total_bytes, sin_time, cos_time,
    src_ip_freq, dst_ip_freq,
    conn_state_* (OHE), service_* (OHE)
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

import numpy as np
import pandas as pd

from .config import BDPConfig

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# ISF query
# ---------------------------------------------------------------------------

def query_isf(cfg: BDPConfig) -> pd.DataFrame:
    """
    Execute the Zeek conn log query against GN via ISF.

    Returns the raw DataFrame exactly as returned by isf.run_query().
    Persists the result to CSV at cfg.io.table_name + '.csv' so that
    ISF is only queried once per session.
    """
    from ionic_scripting_framework import isf  # type: ignore

    sql = f"""
        SELECT
            timestamp,
            event.duration,
            destination.bytes,      destination.ip,         destination.port,
            destination.ip_bytes,   destination.packets,    destination.mac,
            source.bytes,           source.ip,              source.ip_bytes,
            source.port,            source.packets,         source.mac,
            network.transport,      network.protocol,       network.connection.state

        FROM zeek_conn_p

        WHERE
            "_timestamp" >= CAST('{cfg.io.query_start}' AS TIMESTAMP)
            AND "_timestamp" < CAST('{cfg.io.query_end}'  AS TIMESTAMP)

        LIMIT {cfg.io.query_limit}
    """

    log.info("Querying ISF: %s → %s (limit %d)",
             cfg.io.query_start, cfg.io.query_end, cfg.io.query_limit)
    df = isf.run_query(sql)

    csv_path = f"{cfg.io.table_name}.csv"
    df.to_csv(csv_path, index=False)
    log.info("Query result persisted to %s (%d rows)", csv_path, len(df))
    return df


def load_csv(path: Path) -> pd.DataFrame:
    """Load a previously saved Zeek conn CSV."""
    log.info("Loading CSV: %s", path)
    return pd.read_csv(path, low_memory=False)


# ---------------------------------------------------------------------------
# Feature engineering helpers
# ---------------------------------------------------------------------------

def _convert_object_columns(df: pd.DataFrame) -> pd.DataFrame:
    """
    Coerce object-typed columns to float where possible; fall back to string.
    Prevents downstream sklearn errors from mixed-type columns.
    """
    for col in df.select_dtypes(include="object").columns:
        try:
            df[col] = df[col].astype(float)
        except (ValueError, TypeError):
            df[col] = df[col].astype("string")
    return df


def _encode_time_periodically(df: pd.DataFrame, timestamp_col: str = "timestamp") -> pd.DataFrame:
    """
    Project wall-clock time onto a 24-hour unit circle as sin/cos components.

    This preserves the cyclic boundary condition (23:59 ≈ 00:01) for
    distance-based models such as DBSCAN and Isolation Forest.
    """
    df[timestamp_col] = pd.to_datetime(df[timestamp_col], utc=True)

    hour        = df[timestamp_col].dt.hour
    minute      = df[timestamp_col].dt.minute
    second      = df[timestamp_col].dt.second
    millisecond = df[timestamp_col].dt.microsecond // 1000

    ms_since_midnight = (
        hour * 3_600_000
        + minute * 60_000
        + second * 1_000
        + millisecond
    )
    df["sin_time"] = np.sin(2 * np.pi * ms_since_midnight / 86_400_000)
    df["cos_time"] = np.cos(2 * np.pi * ms_since_midnight / 86_400_000)
    return df


def _rename_and_subset(df: pd.DataFrame, keep_cols: tuple) -> pd.DataFrame:
    """Rename Zeek field names to analyst-friendly short names and subset columns."""
    df = df.rename(columns={
        "source.ip":                "src_ip",
        "destination.ip":           "dst_ip",
        "source.port":              "src_p",
        "destination.port":         "dst_p",
        "source.packets":           "src_pkts",
        "destination.packets":      "resp_pkts",
        "event.duration":           "duration",
        "network.connection.state": "conn_state",
        "network.protocol":         "service",
    })
    present = [c for c in keep_cols if c in df.columns]
    return df[present]


def _drop_missing_required(df: pd.DataFrame) -> pd.DataFrame:
    """Remove rows where service or duration are missing or empty."""
    before = len(df)
    df = df.dropna(subset=["service"])
    df = df[~(df["duration"].isna() | (df["duration"] == ""))]
    log.info("Dropped %d rows with missing service/duration (%d remain)",
             before - len(df), len(df))
    return df.copy()


def _frequency_encode_ips(df: pd.DataFrame) -> pd.DataFrame:
    """
    Add src_ip_freq and dst_ip_freq columns encoding how often each IP
    appears in the dataset. Rare IPs (low frequency) are stronger anomaly signals.
    """
    df["src_ip_freq"] = df["src_ip"].map(df["src_ip"].value_counts())
    df["dst_ip_freq"] = df["dst_ip"].map(df["dst_ip"].value_counts())
    return df


def _one_hot_encode(df: pd.DataFrame) -> pd.DataFrame:
    """One-hot encode conn_state and service columns with integer dtype."""
    df = pd.get_dummies(df, columns=["conn_state"], dtype=int)
    df = pd.get_dummies(df, columns=["service"],    dtype=int)

    bool_cols = df.select_dtypes(include="bool").columns
    df[bool_cols] = df[bool_cols].astype("int64")
    return df


def _clean(df: pd.DataFrame) -> pd.DataFrame:
    """
    Remove rows containing NaN values and true duplicate rows.
    Cast packet-count columns to integer.

    IMPORTANT: deduplication is scoped to the subset of columns that uniquely
    identify a connection event.  Full drop_duplicates() would collapse beacon
    flows — which repeat with nearly identical feature vectors — down to a
    single row per pair, destroying the IAT sequence that periodicity analysis
    depends on.  Timestamp must be included so each firing is kept.

    To restrict scope to web traffic only, uncomment the dst_p filter below.
    """
    df = df.dropna()
    # Deduplicate on the columns that define a unique connection event.
    # Keeping timestamp means repeated beacon flows are preserved.
    dedup_cols = ["timestamp", "src_ip", "dst_ip", "src_p", "dst_p"]
    dedup_cols = [c for c in dedup_cols if c in df.columns]
    if dedup_cols:
        df = df.drop_duplicates(subset=dedup_cols)
    else:
        df = df.drop_duplicates()
    df["src_pkts"]  = df["src_pkts"].astype(int)
    df["resp_pkts"] = df["resp_pkts"].astype(int)

    # Optional: narrow to web ports only.
    # http_ports = [80, 443, 8080, 8443, 2083, 2087, 2099, 6443, 9443]
    # df = df.query(f"dst_p in {http_ports}")

    return df


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def load_and_prepare(cfg: BDPConfig) -> pd.DataFrame:
    """
    Full ingestion and feature engineering pipeline.

    Loads data from ISF or CSV, applies all transformations, and returns
    a clean DataFrame ready for the scaling stage.

    Parameters
    ----------
    cfg : BDPConfig
        Pipeline configuration. Set cfg.io.input_csv to bypass ISF.

    Returns
    -------
    pd.DataFrame
        Cleaned, encoded, frequency-enriched DataFrame with canonical columns.
    """
    # --- 1. Ingest ---
    if cfg.io.input_csv is not None:
        df = load_csv(cfg.io.input_csv)
    else:
        df = query_isf(cfg)

    # --- 2. Parse timestamps ---
    df["datetime"] = pd.to_datetime(df["timestamp"], unit="s")
    df["hour"]     = df["datetime"].dt.hour
    df["minute"]   = df["datetime"].dt.minute

    log.info("Unique calendar days in extract: %d",
             pd.to_datetime(df["timestamp"], unit="s").dt.date.nunique())

    # --- 3. Type coercion ---
    df = _convert_object_columns(df)

    # --- 4. Periodic time encoding ---
    # Keep timestamp as numeric Unix seconds for IAT/ACF calculations.
    # The datetime column (already created above with unit="s") is used for
    # display and time-window filtering; overwriting timestamp with a datetime
    # causes silent failures in periodicity.py float conversions.
    df = _encode_time_periodically(df, timestamp_col="datetime")

    # --- 5. Derived features ---
    df["total_bytes"] = df[["destination.bytes", "source.bytes"]].fillna(0).sum(axis=1)

    # --- 6. Schema normalisation ---
    df = _rename_and_subset(df, cfg.features.keep_cols)

    # --- 7. Drop incomplete rows ---
    df = _drop_missing_required(df)

    # --- 8. Frequency encoding ---
    df = _frequency_encode_ips(df)

    # --- 9. One-hot encoding ---
    df = _one_hot_encode(df)

    # --- 10. Final clean ---
    df = _clean(df)

    log.info("load_and_prepare() complete — %d rows, %d columns", len(df), len(df.columns))
    return df.reset_index(drop=True)
