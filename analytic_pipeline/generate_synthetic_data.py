"""
Synthetic Zeek Log Generator
==============================
Generates correlated conn.log, dns.log, and http.log CSV files with
known ground-truth beacon labels for end-to-end pipeline validation.

Design goals
------------
1. Ground truth is fully known and machine-readable — every injected beacon
   is recorded in a labels CSV so detection performance (precision, recall,
   F1) can be computed exactly after running the pipeline.

2. The synthetic data exercises every pipeline stage:
   - Background traffic is statistically realistic enough that Isolation Forest
     has a meaningful "normal" distribution to learn from.
   - Beacons are injected with the exact feature signatures the pipeline is
     designed to detect: volumetric anomaly + periodic IATs + DNS regularity
     + HTTP consistency.
   - Decoys (regular-but-benign automated services) are injected to test
     whether the corroboration stage correctly filters them out.

3. Each scenario is independently reproducible by seed.

Traffic taxonomy
-----------------
    Background    ~95% of conn rows. Realistic human-driven web traffic:
                  varied src/dst IPs, ports 80/443, Poisson inter-arrivals,
                  lognormal byte sizes, high-variance durations.

    Noisy hosts   ~3%. High-volume hosts (file servers, NTP, DNS resolvers)
                  with distinctive volumetric signatures. These should be
                  flagged by IForest but cluster separately from beacons.

    Beacons       ~1%. C2 implants with fixed-interval connections, small
                  uniform payloads, DGA domains in DNS, rare UAs in HTTP.
                  Each beacon has a configurable period, jitter, and payload.

    Decoys        ~1%. Legitimate automated services (Windows Update, NTP,
                  health monitors) with periodic timing but benign DNS and
                  HTTP signatures. Should survive periodicity stage but be
                  filtered at corroboration stage.

Usage
-----
    # Generate default dataset (30 days, 5 beacon scenarios)
    python -m bdp_analytic.generate_synthetic_data

    # Custom output directory and seed
    python -m bdp_analytic.generate_synthetic_data \\
        --output data/synthetic/ \\
        --days 30 \\
        --seed 42

    # Programmatic
    from bdp_analytic.generate_synthetic_data import SyntheticDataGenerator
    gen = SyntheticDataGenerator(seed=42)
    conn, dns, http, labels = gen.generate(days=30)
    conn.to_csv("conn.csv", index=False)
"""
from __future__ import annotations

import argparse
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import numpy as np
import pandas as pd

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Beacon / decoy scenario definitions
# ---------------------------------------------------------------------------

@dataclass
class BeaconScenario:
    """
    Defines a single C2 beacon implant to inject into the synthetic dataset.

    Parameters
    ----------
    name            : Human-readable label (written to ground truth CSV).
    src_ip          : Infected host IP address.
    dst_ip          : C2 server IP address.
    period_s        : Nominal beacon interval in seconds.
    jitter_pct      : Fractional jitter added to each interval (e.g. 0.10 = ±10%).
    dst_port        : Destination port. 443 mimics HTTPS C2.
    payload_bytes   : Typical beacon payload size (small = polling, large = exfil).
    payload_cv      : Coefficient of variation on payload_bytes.
                      Low CV (0.05) = uniform polling responses.
                      High CV (0.5) = variable exfiltration.
    conn_state      : Zeek connection state string.
    service         : Protocol label used in conn.log.
    dns_domain      : Domain queried in DNS log (None = no DNS traffic).
    dns_ttl         : DNS TTL in seconds. Short TTL (<300) flags fast-flux.
    http_uri        : URI template (None = no HTTP traffic).
    http_ua         : User-Agent string. Empty string = absent UA (evasion indicator).
    is_dga          : If True, dns_domain is replaced with a DGA-generated name each
                      beacon cycle (tests H2 DGA detection in corroboration).
    malicious       : Written to labels CSV. True for beacons, False for decoys.
    """
    name:          str
    src_ip:        str
    dst_ip:        str
    period_s:      float
    jitter_pct:    float   = 0.10
    dst_port:      int     = 443
    payload_bytes: int     = 512
    payload_cv:    float   = 0.05
    conn_state:    str     = "SF"
    service:       str     = "ssl"
    dns_domain:    Optional[str]  = None
    dns_ttl:       float   = 60.0
    http_uri:      Optional[str]  = "/beacon"
    http_ua:       str     = ""
    is_dga:        bool    = False
    malicious:     bool    = True


# Default scenario suite covering the main C2 archetypes
DEFAULT_SCENARIOS: list[BeaconScenario] = [

    # Scenario 1: Fast HTTPS beacon, 5-minute interval, DGA domain, absent UA
    # Classic Cobalt Strike / Meterpreter profile
    BeaconScenario(
        name        = "fast_https_dga",
        src_ip      = "10.0.1.50",
        dst_ip      = "203.0.113.10",
        period_s    = 300,       # 5 minutes
        jitter_pct  = 0.10,
        dst_port    = 443,
        payload_bytes = 512,
        payload_cv  = 0.05,
        service     = "ssl",
        dns_domain  = None,      # overridden by is_dga=True each cycle
        dns_ttl     = 60.0,      # fast-flux TTL
        http_uri    = None,      # HTTPS, no HTTP log entry
        http_ua     = "",
        is_dga      = True,
        malicious   = True,
    ),

    # Scenario 2: Slow HTTP beacon, 1-hour interval, fixed domain, rare UA
    # Long-haul APT persistent access channel
    BeaconScenario(
        name        = "slow_http_fixed",
        src_ip      = "10.0.1.75",
        dst_ip      = "198.51.100.20",
        period_s    = 3600,      # 1 hour
        jitter_pct  = 0.05,
        dst_port    = 80,
        payload_bytes = 256,
        payload_cv  = 0.03,
        service     = "http",
        dns_domain  = "updates.dyndns-office.com",
        dns_ttl     = 120.0,
        http_uri    = "/api/v2/status",
        http_ua     = "Mozilla/4.0 (compatible; MSIE 6.0)",  # outdated UA
        is_dga      = False,
        malicious   = True,
    ),

    # Scenario 3: Multi-host campaign, 15-minute interval, NXDomain pattern
    # Simulates a worm that has infected multiple hosts connecting to same C2
    BeaconScenario(
        name        = "multi_host_campaign",
        src_ip      = "10.0.2.100",
        dst_ip      = "203.0.113.55",
        period_s    = 900,       # 15 minutes
        jitter_pct  = 0.15,
        dst_port    = 8080,
        payload_bytes = 1024,
        payload_cv  = 0.08,
        service     = "http",
        dns_domain  = None,      # DGA generates NXDomain misses
        dns_ttl     = 30.0,
        http_uri    = "/update",
        http_ua     = "",
        is_dga      = True,
        malicious   = True,
    ),

    # Scenario 4: Exfiltration beacon, 6-hour interval, large variable payload
    # Periodic data staging and exfiltration
    BeaconScenario(
        name        = "exfil_slow",
        src_ip      = "10.0.3.200",
        dst_ip      = "198.51.100.99",
        period_s    = 21600,     # 6 hours
        jitter_pct  = 0.08,
        dst_port    = 443,
        payload_bytes = 50000,   # large exfil payload
        payload_cv  = 0.40,      # variable — staged data sizes differ
        service     = "ssl",
        dns_domain  = "cdn.analytics-platform.net",
        dns_ttl     = 300.0,
        http_uri    = None,
        http_ua     = "",
        is_dga      = False,
        malicious   = True,
    ),

    # Scenario 5: DECOY — Windows Update agent (benign periodic traffic)
    # Should pass periodicity but fail corroboration (benign domain/UA)
    BeaconScenario(
        name        = "decoy_windows_update",
        src_ip      = "10.0.1.20",
        dst_ip      = "13.107.4.50",
        period_s    = 3600,
        jitter_pct  = 0.20,
        dst_port    = 443,
        payload_bytes = 8192,
        payload_cv  = 0.30,
        service     = "ssl",
        dns_domain  = "windowsupdate.microsoft.com",
        dns_ttl     = 3600.0,
        http_uri    = None,
        http_ua     = "Windows-Update-Agent/10.0.10011.16384",
        is_dga      = False,
        malicious   = False,    # ← DECOY: should NOT be flagged as confirmed
    ),

    # Scenario 6: DECOY — NTP polling (benign periodic, no HTTP/DNS anomaly)
    BeaconScenario(
        name        = "decoy_ntp",
        src_ip      = "10.0.1.30",
        dst_ip      = "216.239.35.0",
        period_s    = 1024,
        jitter_pct  = 0.05,
        dst_port    = 123,
        payload_bytes = 48,     # NTP packet size
        payload_cv  = 0.01,
        conn_state  = "SF",
        service     = "ntp",
        dns_domain  = "time.google.com",
        dns_ttl     = 3600.0,
        http_uri    = None,
        http_ua     = "",
        is_dga      = False,
        malicious   = False,    # ← DECOY
    ),
]


# ---------------------------------------------------------------------------
# DGA simulation
# ---------------------------------------------------------------------------

def _generate_dga_domain(seed: int, tld: str = ".com") -> str:
    """
    Generate a pseudo-random domain name mimicking DGA output.

    Uses a linear congruential generator seeded per beacon cycle so the
    same seed always produces the same domain (reproducible ground truth).
    High character entropy (>3.5 bits/char) and consonant-heavy structure
    match the DGA signatures tested in corroboration._is_likely_dga().

    Parameters
    ----------
    seed : Per-cycle integer seed (e.g. unix timestamp // beacon_period).
    tld  : Top-level domain suffix.

    Returns
    -------
    Fully-qualified domain name string.
    """
    rng    = np.random.default_rng(seed % (2**32))
    # Lengths 8–14 characters — typical DGA label length
    length = int(rng.integers(8, 15))
    # Consonant-heavy character pool raises entropy and matches _is_likely_dga
    pool   = "bcdfghjklmnpqrstvwxyz0123456789"
    label  = "".join(rng.choice(list(pool), size=length))
    return label + tld


# ---------------------------------------------------------------------------
# Background traffic generators
# ---------------------------------------------------------------------------

def _generate_background_conn(
    n_rows:     int,
    start_ts:   float,
    end_ts:     float,
    rng:        np.random.Generator,
) -> pd.DataFrame:
    """
    Generate realistic background conn log traffic.

    Models human web browsing: Poisson-distributed inter-arrivals,
    lognormal byte sizes, a mix of HTTP/HTTPS/DNS services, and the
    standard set of Zeek connection states.

    Parameters
    ----------
    n_rows   : Number of background connections to generate.
    start_ts : Window start as Unix timestamp.
    end_ts   : Window end as Unix timestamp.
    rng      : Seeded NumPy Generator for reproducibility.

    Returns
    -------
    pd.DataFrame in raw Zeek conn.log format.
    """
    # Timestamps: Poisson process scaled to window, with diurnal concentration
    # (higher density 08:00–20:00 to mimic business-hours browsing)
    raw_ts   = rng.uniform(start_ts, end_ts, n_rows)
    dt_arr   = pd.to_datetime(raw_ts, unit="s", utc=True)
    hours    = dt_arr.hour.values.astype(float)
    # Diurnal weight: peak at noon, trough at 3am — not uniform
    weights  = 0.5 + 0.5 * np.sin(np.pi * (hours - 3) / 18).clip(0)
    keep_mask = rng.random(n_rows) < weights
    # Ensure we still have ~n_rows by oversampling and trimming
    raw_ts   = rng.uniform(start_ts, end_ts, int(n_rows * 1.5))
    raw_ts   = raw_ts[:n_rows]   # simplification: trim to n_rows

    src_subnets = ["10.0.1.", "10.0.2.", "10.0.3.", "192.168.1."]
    dst_pools   = [f"52.{rng.integers(0,255)}.{rng.integers(0,255)}.{rng.integers(1,254)}"
                   for _ in range(200)]
    svc_choices  = ["http", "ssl", "dns", "smtp", "ftp"]
    svc_weights  = [0.30,   0.50,  0.10,  0.05,  0.05]
    state_choices = ["SF", "S0", "REJ", "RSTO", "RSTOS0"]
    state_weights = [0.70, 0.15, 0.08,  0.05,   0.02]

    src_ips  = [f"{rng.choice(src_subnets)}{rng.integers(1,254)}" for _ in range(n_rows)]
    dst_ips  = rng.choice(dst_pools, size=n_rows).tolist()
    services = rng.choice(svc_choices, size=n_rows, p=svc_weights).tolist()
    states   = rng.choice(state_choices, size=n_rows, p=state_weights).tolist()

    # Port mapping by service
    port_map = {"http": 80, "ssl": 443, "dns": 53, "smtp": 25, "ftp": 21}
    dst_ports = [port_map[s] + rng.integers(-2, 3) for s in services]
    src_ports = rng.integers(1024, 65535, size=n_rows).tolist()

    # Lognormal bytes: mean ~5KB, std ~20KB (realistic web traffic)
    src_bytes  = np.exp(rng.normal(7.0, 1.5, n_rows)).astype(int).clip(40, 500_000)
    dst_bytes  = np.exp(rng.normal(9.0, 1.8, n_rows)).astype(int).clip(40, 2_000_000)
    src_pkts   = np.maximum(1, (src_bytes / 1460).astype(int))
    resp_pkts  = np.maximum(1, (dst_bytes / 1460).astype(int))
    durations  = np.exp(rng.normal(0.5, 1.2, n_rows)).clip(0.001, 300.0)

    return pd.DataFrame({
        "timestamp":                 raw_ts,
        "source.ip":                 src_ips,
        "source.port":               src_ports,
        "source.packets":            src_pkts.tolist(),
        "source.bytes":              src_bytes.tolist(),
        "destination.ip":            dst_ips,
        "destination.port":          dst_ports,
        "destination.packets":       resp_pkts.tolist(),
        "destination.bytes":         dst_bytes.tolist(),
        "event.duration":            durations.tolist(),
        "network.connection.state":  states,
        "network.protocol":          services,
        "label":                     "background",
        "scenario":                  "background",
    })


def _generate_noisy_host_conn(
    n_rows:   int,
    start_ts: float,
    end_ts:   float,
    rng:      np.random.Generator,
) -> pd.DataFrame:
    """
    Generate high-volume 'noisy host' traffic (file servers, NTP, DNS resolvers).

    These hosts produce volumetric signatures that IForest should flag as
    anomalous, but they cluster separately from beacons and fail the
    periodicity test (high IAT variance, irregular timing).
    """
    noisy_src = ["10.0.10.1", "10.0.10.2", "10.0.10.3"]  # dedicated noisy hosts
    raw_ts    = rng.uniform(start_ts, end_ts, n_rows)
    src_ips   = rng.choice(noisy_src, size=n_rows).tolist()
    dst_ips   = [f"10.0.0.{rng.integers(1,254)}" for _ in range(n_rows)]

    # Large, variable byte counts — distinguishable from beacon small payloads
    src_bytes = rng.integers(50_000, 5_000_000, size=n_rows).tolist()
    dst_bytes = rng.integers(1_000, 100_000,    size=n_rows).tolist()
    src_pkts  = [max(1, b // 1460) for b in src_bytes]
    resp_pkts = [max(1, b // 1460) for b in dst_bytes]

    return pd.DataFrame({
        "timestamp":                 raw_ts,
        "source.ip":                 src_ips,
        "source.port":               rng.integers(1024, 65535, size=n_rows).tolist(),
        "source.packets":            src_pkts,
        "source.bytes":              src_bytes,
        "destination.ip":            dst_ips,
        "destination.port":          rng.choice([445, 139, 3389, 22], size=n_rows).tolist(),
        "destination.packets":       resp_pkts,
        "destination.bytes":         dst_bytes,
        "event.duration":            rng.uniform(0.01, 120.0, size=n_rows).tolist(),
        "network.connection.state":  rng.choice(["SF", "S1"], size=n_rows).tolist(),
        "network.protocol":          rng.choice(["smb", "rdp", "ssh"], size=n_rows).tolist(),
        "label":                     "noisy_host",
        "scenario":                  "noisy_host",
    })


# ---------------------------------------------------------------------------
# Beacon / decoy traffic generators
# ---------------------------------------------------------------------------

def _beacon_timestamps(
    scenario:   BeaconScenario,
    start_ts:   float,
    end_ts:     float,
    rng:        np.random.Generator,
) -> np.ndarray:
    """
    Generate a sequence of Unix timestamps for a beacon firing repeatedly
    from start_ts to end_ts with Gaussian jitter on each interval.

    Parameters
    ----------
    scenario  : BeaconScenario defining period and jitter.
    start_ts  : Window start (Unix seconds).
    end_ts    : Window end (Unix seconds).
    rng       : Seeded generator.

    Returns
    -------
    Sorted array of Unix timestamps.
    """
    timestamps = []
    t = start_ts + rng.uniform(0, scenario.period_s)  # random phase offset
    while t < end_ts:
        timestamps.append(t)
        jitter = rng.normal(0, scenario.jitter_pct * scenario.period_s)
        t += scenario.period_s + jitter
    return np.array(sorted(timestamps))


def _generate_beacon_conn(
    scenario:   BeaconScenario,
    timestamps: np.ndarray,
    rng:        np.random.Generator,
) -> pd.DataFrame:
    """Generate conn log rows for one beacon scenario."""
    n = len(timestamps)
    if n == 0:
        return pd.DataFrame()

    payload = rng.normal(
        scenario.payload_bytes,
        scenario.payload_cv * scenario.payload_bytes,
        n,
    ).clip(40, 10_000_000).astype(int)

    # Beacon duration is characteristically short and uniform
    durations = rng.normal(0.05, 0.01, n).clip(0.001, 1.0)

    return pd.DataFrame({
        "timestamp":                 timestamps,
        "source.ip":                 scenario.src_ip,
        "source.port":               rng.integers(1024, 65535, size=n).tolist(),
        "source.packets":            np.maximum(1, payload // 1460).tolist(),
        "source.bytes":              (payload * 0.3).astype(int).tolist(),
        "destination.ip":            scenario.dst_ip,
        "destination.port":          scenario.dst_port,
        "destination.packets":       np.maximum(1, payload // 1460).tolist(),
        "destination.bytes":         payload.tolist(),
        "event.duration":            durations.tolist(),
        "network.connection.state":  scenario.conn_state,
        "network.protocol":          scenario.service,
        "label":                     "malicious" if scenario.malicious else "decoy",
        "scenario":                  scenario.name,
    })


def _generate_beacon_dns(
    scenario:   BeaconScenario,
    timestamps: np.ndarray,
    rng:        np.random.Generator,
) -> pd.DataFrame:
    """Generate DNS log rows corresponding to beacon connection attempts."""
    if scenario.dns_domain is None and not scenario.is_dga:
        return pd.DataFrame()

    rows = []
    for i, ts in enumerate(timestamps):
        # DNS query fires slightly before the connection
        query_ts = ts - rng.uniform(0.01, 0.5)

        if scenario.is_dga:
            # New DGA domain each cycle — some resolve (NOERROR), some don't (NXDOMAIN)
            domain   = _generate_dga_domain(seed=int(ts // scenario.period_s) + i)
            resolved = rng.random() > 0.3   # 70% resolve, 30% NXDomain (DGA misses)
            rcode    = "NOERROR" if resolved else "NXDOMAIN"
            answers  = scenario.dst_ip if resolved else ""
            ttl      = scenario.dns_ttl
        else:
            domain   = scenario.dns_domain
            rcode    = "NOERROR"
            answers  = scenario.dst_ip
            ttl      = scenario.dns_ttl

        rows.append({
            "ts":         query_ts,
            "id.orig_h":  scenario.src_ip,
            "query":      domain,
            "rcode_name": rcode,
            "answers":    answers,
            "TTLs":       str(ttl),
            "label":      "malicious" if scenario.malicious else "decoy",
            "scenario":   scenario.name,
        })

    return pd.DataFrame(rows) if rows else pd.DataFrame()


def _generate_beacon_http(
    scenario:   BeaconScenario,
    timestamps: np.ndarray,
    rng:        np.random.Generator,
) -> pd.DataFrame:
    """Generate HTTP log rows for beacon scenarios using HTTP/plain."""
    if scenario.http_uri is None:
        return pd.DataFrame()

    n = len(timestamps)
    # Small uniform request bodies; uniform response (C2 "no task" reply)
    req_body  = rng.normal(256,  256 * scenario.payload_cv, n).clip(0, 10000).astype(int)
    resp_body = rng.normal(scenario.payload_bytes,
                           scenario.payload_cv * scenario.payload_bytes, n).clip(0, 10_000_000).astype(int)

    # URI: fixed template with minor per-cycle parameter variation
    uris = [
        scenario.http_uri + f"?t={int(ts)}&id={rng.integers(1000,9999)}"
        for ts in timestamps
    ]

    return pd.DataFrame({
        "ts":                  timestamps - rng.uniform(0.001, 0.01, n),
        "id.orig_h":           scenario.src_ip,
        "id.resp_h":           scenario.dst_ip,
        "uri":                 uris,
        "user_agent":          scenario.http_ua if scenario.http_ua else np.nan,
        "method":              "GET",
        "status_code":         200,
        "request_body_len":    req_body.tolist(),
        "response_body_len":   resp_body.tolist(),
        "label":               "malicious" if scenario.malicious else "decoy",
        "scenario":            scenario.name,
    })


def _generate_background_dns(
    n_rows:   int,
    start_ts: float,
    end_ts:   float,
    rng:      np.random.Generator,
) -> pd.DataFrame:
    """Generate realistic background DNS queries (benign)."""
    domains = [
        "www.google.com", "www.microsoft.com", "login.microsoftonline.com",
        "www.amazon.com", "s3.amazonaws.com", "api.github.com",
        "fonts.googleapis.com", "ajax.googleapis.com", "cdn.cloudflare.com",
        "ocsp.digicert.com", "ctldl.windowsupdate.com", "dns.google",
    ]
    src_subnets = ["10.0.1.", "10.0.2.", "10.0.3."]
    raw_ts = rng.uniform(start_ts, end_ts, n_rows)
    src_ips = [f"{rng.choice(src_subnets)}{rng.integers(1,254)}" for _ in range(n_rows)]
    queries = rng.choice(domains, size=n_rows).tolist()
    ttls    = rng.choice([300, 600, 1800, 3600, 7200], size=n_rows).tolist()

    return pd.DataFrame({
        "ts":         raw_ts,
        "id.orig_h":  src_ips,
        "query":      queries,
        "rcode_name": "NOERROR",
        "answers":    [f"1.2.3.{rng.integers(1,254)}" for _ in range(n_rows)],
        "TTLs":       [str(t) for t in ttls],
        "label":      "background",
        "scenario":   "background",
    })


def _generate_background_http(
    n_rows:   int,
    start_ts: float,
    end_ts:   float,
    rng:      np.random.Generator,
) -> pd.DataFrame:
    """Generate realistic background HTTP requests (benign)."""
    src_subnets = ["10.0.1.", "10.0.2.", "10.0.3."]
    dst_pool    = [f"52.{rng.integers(0,255)}.{rng.integers(0,255)}.{rng.integers(1,254)}"
                   for _ in range(50)]
    uas = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/120.0",
        "curl/7.84.0",
    ]
    uris = ["/", "/index.html", "/api/data", "/static/app.js",
            "/images/logo.png", "/favicon.ico", "/robots.txt"]

    raw_ts   = rng.uniform(start_ts, end_ts, n_rows)
    src_ips  = [f"{rng.choice(src_subnets)}{rng.integers(1,254)}" for _ in range(n_rows)]
    dst_ips  = rng.choice(dst_pool, size=n_rows).tolist()
    req_body = rng.integers(0, 2000, size=n_rows).tolist()
    resp_body = np.exp(rng.normal(10, 2, n_rows)).astype(int).clip(100, 5_000_000).tolist()

    return pd.DataFrame({
        "ts":                 raw_ts,
        "id.orig_h":          src_ips,
        "id.resp_h":          dst_ips,
        "uri":                rng.choice(uris, size=n_rows).tolist(),
        "user_agent":         rng.choice(uas, size=n_rows).tolist(),
        "method":             rng.choice(["GET", "POST"], size=n_rows, p=[0.8, 0.2]).tolist(),
        "status_code":        rng.choice([200, 301, 302, 404, 500], size=n_rows,
                                          p=[0.85, 0.05, 0.05, 0.04, 0.01]).tolist(),
        "request_body_len":   req_body,
        "response_body_len":  resp_body,
        "label":              "background",
        "scenario":           "background",
    })


# ---------------------------------------------------------------------------
# Main generator class
# ---------------------------------------------------------------------------

class SyntheticDataGenerator:
    """
    Generates correlated synthetic Zeek conn, dns, and http log DataFrames
    with injected beacon scenarios and full ground-truth labels.

    Parameters
    ----------
    seed      : Master random seed. All sub-generators derive from this.
    scenarios : List of BeaconScenario objects to inject. Defaults to
                DEFAULT_SCENARIOS (4 malicious beacons + 2 decoys).

    Example
    -------
        gen = SyntheticDataGenerator(seed=42)
        conn, dns, http, labels = gen.generate(days=30)
    """

    def __init__(
        self,
        seed:      int = 42,
        scenarios: Optional[list[BeaconScenario]] = None,
    ) -> None:
        self.seed      = seed
        self.scenarios = scenarios or DEFAULT_SCENARIOS
        self._rng      = np.random.default_rng(seed)

    def generate(
        self,
        days:             int   = 30,
        bg_rows_per_day:  int   = 30_000,
        noisy_rows_per_day: int = 1_000,
        start_date:       str   = "2025-10-01",
    ) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame, pd.DataFrame]:
        """
        Generate the full synthetic dataset.

        Parameters
        ----------
        days              : Number of days to simulate. 30 days is the minimum
                            recommended for detecting slow beacons (6h, 24h periods)
                            with enough observations for reliable ACF peaks.
        bg_rows_per_day   : Background conn rows per day.
        noisy_rows_per_day: Noisy-host conn rows per day.
        start_date        : ISO date string for the window start.

        Returns
        -------
        conn_df   : Zeek conn.log format DataFrame.
        dns_df    : Zeek dns.log format DataFrame.
        http_df   : Zeek http.log format DataFrame.
        labels_df : Ground-truth labels per scenario (for evaluation).
        """
        start_ts = pd.Timestamp(start_date, tz="UTC").timestamp()
        end_ts   = start_ts + days * 86400

        log.info("Generating %d days of synthetic data (seed=%d)...", days, self.seed)
        log.info("  %d background rows/day, %d noisy rows/day",
                 bg_rows_per_day, noisy_rows_per_day)
        log.info("  %d beacon/decoy scenarios", len(self.scenarios))

        # --- Background traffic ---
        total_bg    = days * bg_rows_per_day
        total_noisy = days * noisy_rows_per_day

        conn_parts = [
            _generate_background_conn(total_bg,    start_ts, end_ts, self._rng),
            _generate_noisy_host_conn(total_noisy, start_ts, end_ts, self._rng),
        ]
        dns_parts  = [_generate_background_dns(total_bg // 5, start_ts, end_ts, self._rng)]
        http_parts = [_generate_background_http(total_bg // 3, start_ts, end_ts, self._rng)]

        # --- Scenario traffic ---
        label_rows = []
        for scenario in self.scenarios:
            s_rng       = np.random.default_rng(self.seed + hash(scenario.name) % (2**31))
            timestamps  = _beacon_timestamps(scenario, start_ts, end_ts, s_rng)
            n_firings   = len(timestamps)

            if n_firings == 0:
                log.warning("Scenario '%s' produced 0 firings in window.", scenario.name)
                continue

            conn_parts.append(_generate_beacon_conn(scenario, timestamps, s_rng))
            dns_part = _generate_beacon_dns(scenario, timestamps, s_rng)
            if not dns_part.empty:
                dns_parts.append(dns_part)
            http_part = _generate_beacon_http(scenario, timestamps, s_rng)
            if not http_part.empty:
                http_parts.append(http_part)

            label_rows.append({
                "scenario":           scenario.name,
                "src_ip":             scenario.src_ip,
                "dst_ip":             scenario.dst_ip,
                "period_s":           scenario.period_s,
                "jitter_pct":         scenario.jitter_pct,
                "malicious":          scenario.malicious,
                "n_firings":          n_firings,
                "expected_in_conn":   True,
                "expected_in_dns":    scenario.dns_domain is not None or scenario.is_dga,
                "expected_in_http":   scenario.http_uri is not None,
                "is_dga":             scenario.is_dga,
                "notes": (
                    "Should be corroborated (malicious beacon)"
                    if scenario.malicious
                    else "Should survive periodicity but fail corroboration (benign decoy)"
                ),
            })

            log.info("  Scenario '%s': %d firings over %d days",
                     scenario.name, n_firings, days)

        # --- Assemble and sort ---
        conn_df = pd.concat(conn_parts, ignore_index=True).sort_values("timestamp")
        dns_df  = pd.concat(dns_parts,  ignore_index=True).sort_values("ts")
        http_df = pd.concat(http_parts, ignore_index=True).sort_values("ts")

        labels_df = pd.DataFrame(label_rows)

        # Summary
        n_malicious = int(conn_df["label"].eq("malicious").sum())
        n_decoy     = int(conn_df["label"].eq("decoy").sum())
        n_bg        = int(conn_df["label"].eq("background").sum())
        log.info(
            "Generation complete: %d conn rows  (%d bg, %d noisy, %d malicious, %d decoy)",
            len(conn_df), n_bg,
            int(conn_df["label"].eq("noisy_host").sum()),
            n_malicious, n_decoy,
        )
        log.info("  DNS rows: %d   HTTP rows: %d", len(dns_df), len(http_df))

        return conn_df, dns_df, http_df, labels_df


# ---------------------------------------------------------------------------
# Evaluation helpers
# ---------------------------------------------------------------------------

def evaluate_detection(
    corroboration_df: pd.DataFrame,
    labels_df:        pd.DataFrame,
    conn_df:          pd.DataFrame,
    cluster_col:      str = "pair_id",
) -> pd.DataFrame:
    """
    Compute precision, recall, and F1 for the pipeline's final output
    against the known ground-truth labels.

    Maps each corroborated (src_ip, dst_ip) pair back to its scenario
    and checks whether it corresponds to a malicious scenario in labels_df.

    Parameters
    ----------
    corroboration_df : Output of corroboration.corroborate_beacon_candidates().
    labels_df        : Ground-truth labels from SyntheticDataGenerator.generate().
    conn_df          : Original conn DataFrame with 'label' and 'scenario' columns.
    cluster_col      : Unused; kept for API compatibility.

    Returns
    -------
    pd.DataFrame with per-scenario detection results plus aggregate metrics.
    """
    malicious_scenarios = set(
        labels_df[labels_df["malicious"]]["scenario"].tolist()
    )

    if corroboration_df.empty:
        print("No corroboration output to evaluate.")
        return pd.DataFrame()

    detected_scenarios: set[str] = set()
    false_positive_pairs: list[str] = []

    # Determine src/dst column names from conn_df
    src_col = "src_ip" if "src_ip" in conn_df.columns else "source.ip"
    dst_col = "dst_ip" if "dst_ip" in conn_df.columns else "destination.ip"

    corroborated = corroboration_df[corroboration_df["corroborated"]]
    for _, row in corroborated.iterrows():
        src = row.get("src_ip", "")
        dst = row.get("dst_ip", "")
        pair_scenarios = set()
        if "scenario" in conn_df.columns:
            mask = (conn_df[src_col] == src)
            if dst:
                mask |= (conn_df[dst_col] == dst)
            pair_scenarios = set(conn_df[mask]["scenario"].dropna().unique().tolist())

        malicious_in_pair = pair_scenarios & malicious_scenarios
        if malicious_in_pair:
            detected_scenarios |= malicious_in_pair
        else:
            false_positive_pairs.append(f"{src}→{dst}")

    tp = len(detected_scenarios)
    fp = len(false_positive_pairs)
    fn = len(malicious_scenarios - detected_scenarios)

    precision = tp / max(tp + fp, 1)
    recall    = tp / max(tp + fn, 1)
    f1        = 2 * precision * recall / max(precision + recall, 1e-9)

    print("\n" + "=" * 60)
    print("  DETECTION EVALUATION AGAINST GROUND TRUTH")
    print("=" * 60)
    print(f"\n  Malicious scenarios:   {len(malicious_scenarios)}")
    print(f"  Detected:              {tp}  {sorted(detected_scenarios)}")
    print(f"  Missed:                {fn}  {sorted(malicious_scenarios - detected_scenarios)}")
    print(f"  False positive pairs: {fp}  {false_positive_pairs}")
    print(f"\n  Precision : {precision:.3f}")
    print(f"  Recall    : {recall:.3f}")
    print(f"  F1 Score  : {f1:.3f}")
    print("=" * 60)

    rows = []
    for scenario_name in sorted(malicious_scenarios | (set(labels_df["scenario"]) - malicious_scenarios)):
        row = labels_df[labels_df["scenario"] == scenario_name].iloc[0].to_dict()
        row["detected"] = scenario_name in detected_scenarios
        rows.append(row)

    result_df = pd.DataFrame(rows)
    result_df["precision"] = precision
    result_df["recall"]    = recall
    result_df["f1"]        = f1
    return result_df


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(message)s",
    )

    parser = argparse.ArgumentParser(
        description="Generate synthetic Zeek logs for BDP analytic testing."
    )
    parser.add_argument("--output", default="data/synthetic",
                        help="Output directory (default: data/synthetic)")
    parser.add_argument("--days",   type=int, default=30,
                        help="Number of days to simulate (default: 30)")
    parser.add_argument("--seed",   type=int, default=42,
                        help="Random seed (default: 42)")
    parser.add_argument("--bg-rows-per-day", type=int, default=30_000,
                        dest="bg_rows",
                        help="Background conn rows per day (default: 30000)")
    args = parser.parse_args()

    out_dir = Path(args.output)
    out_dir.mkdir(parents=True, exist_ok=True)

    gen = SyntheticDataGenerator(seed=args.seed)
    conn, dns, http, labels = gen.generate(
        days=args.days,
        bg_rows_per_day=args.bg_rows,
    )

    conn.to_csv(out_dir / "conn.csv",   index=False)
    dns.to_csv(out_dir  / "dns.csv",    index=False)
    http.to_csv(out_dir / "http.csv",   index=False)
    labels.to_csv(out_dir / "labels.csv", index=False)

    print(f"\nFiles written to {out_dir}/")
    print(f"  conn.csv   — {len(conn):,} rows")
    print(f"  dns.csv    — {len(dns):,} rows")
    print(f"  http.csv   — {len(http):,} rows")
    print(f"  labels.csv — {len(labels)} beacon/decoy scenarios\n")
    print("Ground truth scenarios:")
    for _, row in labels.iterrows():
        tag = "MALICIOUS" if row["malicious"] else "DECOY   "
        print(f"  [{tag}] {row['scenario']:30s}  "
              f"period={row['period_s']:>6.0f}s  "
              f"n_firings={row['n_firings']:>4d}  "
              f"{row['notes']}")

    print(f"\nTo run the pipeline against this data:")
    print(f"  bdp --input {out_dir}/conn.csv \\")
    print(f"      --dns   {out_dir}/dns.csv  \\")
    print(f"      --http  {out_dir}/http.csv \\")
    print(f"      --output results/")


if __name__ == "__main__":
    main()
