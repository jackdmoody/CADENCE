"""
HTML Report Generator
=======================
Captures all matplotlib figures during a pipeline run and assembles them,
along with the analyst brief and CSV downloads, into a single self-contained
HTML file.

Usage
------
    from bdp_analytic.report import ReportContext

    with ReportContext(output_dir="results") as report:
        art = BDPPipeline(cfg).run(
            dns_log_path  = "data/dns.csv",
            http_log_path = "data/http.csv",
        )
        report.finalise(art)

    # Opens results/cadence_report.html in your browser automatically.

How it works
-------------
ReportContext installs a matplotlib backend switch (Agg) and monkey-patches
plt.show() to save each figure to a base64 PNG instead of opening a window.
At the end, finalise() writes all CSVs and assembles a single self-contained
HTML file with no external dependencies.

What CADENCE is testing
------------------------
CADENCE answers one overarching question:

    "Is this network traffic evidence of an active C2 beacon, or does it
     just look anomalous?"

It answers that via a chain of independent stages, each answering a question
the previous stage cannot:

  Stage 1 — Isolation Forest
    Q: Is this flow volumetrically unusual relative to the fleet?
    Tests joint multivariate anomaly scoring on bytes, packets, duration.
    Cannot: determine whether the anomaly is periodic or random.

  Stage 2 — DBSCAN Clustering
    Q: Do the anomalous flows group into behaviorally coherent clusters?
    Tests density clustering on scaled features with PCA reduction.
    Cannot: determine whether the grouped flows are temporally scheduled.

  Stage 3 — SAX Pre-Screening
    Q: Does this cluster's inter-arrival sequence have symbolic regularity?
    Fast O(N) symbolic encoding; eliminates obviously non-periodic clusters.
    Cannot: provide statistical rigor — that requires ACF + FFT.

  Stage 4 — ACF + FFT Periodicity
    Q: Is this cluster statistically periodic with quantifiable confidence?
    Per-pair IAT autocorrelation and Welch power spectral density.
    Cannot: distinguish C2 from legitimate automated services (NTP, WU).

  Stage 5 — PELT Changepoint Detection
    Q: When did beaconing start, and did the interval change?
    Answers the "when" and detects operator interaction (interval shifts).
    Cannot: confirm the beacon is malicious rather than benign-automated.

  Stage 6 — Corroboration (H1-H4)
    Q: Is there independent cross-layer evidence this is C2?

    H1 — DNS Regularity
         Does the src_ip query the same domain at intervals matching the
         conn log beacon period?

    H2 — DNS Anomaly Indicators
         Does the queried domain show DGA characteristics, NXDomain misses,
         or fast-flux TTLs? Highest-specificity C2 indicator without TI.

    H3 — HTTP Behavioral Consistency
         Does HTTP traffic show stereotyped patterns (uniform URI, response
         size)? Real C2 is automated and repetitive; browsing is not.

    H4 — HTTP Evasion Indicators
         Are there known evasion techniques: rare/absent UA strings,
         high-entropy URIs (encoded payloads), non-standard HTTP methods?

    A cluster passing >= 2 hypotheses at score >= min_score is a confirmed
    lead. Both decoys (Windows Update, NTP) fail here on benign signatures.
"""
from __future__ import annotations

import base64
import io
import logging
import webbrowser
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import pandas as pd

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Plot capture context
# ---------------------------------------------------------------------------

class ReportContext:
    def __init__(
        self,
        output_dir:   str | Path = "results",
        open_browser: bool = True,
        title:        str  = "CADENCE — C2 Beacon Detection Report",
    ) -> None:
        self.output_dir    = Path(output_dir)
        self.open_browser  = open_browser
        self.title         = title
        self._figures:     list[dict] = []
        self._orig_show    = None
        self._orig_backend = None
        self._run_start    = datetime.now(timezone.utc)

    def __enter__(self) -> "ReportContext":
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._install_capture_hook()
        return self

    def __exit__(self, *_) -> None:
        self._uninstall_capture_hook()

    def _install_capture_hook(self) -> None:
        import matplotlib
        import matplotlib.pyplot as plt
        self._orig_backend = matplotlib.get_backend()
        matplotlib.use("Agg")
        report_ctx = self

        def _capture_show():
            fig = plt.gcf()
            if not fig.get_axes():
                plt.close(fig)
                return
            label = ""
            if fig._suptitle:
                label = fig._suptitle.get_text().split("\n")[0]
            elif fig.get_axes():
                label = fig.get_axes()[0].get_title().split("\n")[0]
            label = label.strip() or f"Figure {len(report_ctx._figures) + 1}"
            buf = io.BytesIO()
            fig.savefig(buf, format="png", dpi=120, bbox_inches="tight")
            buf.seek(0)
            png_b64 = base64.b64encode(buf.read()).decode("utf-8")
            buf.close()
            report_ctx._figures.append({"label": label, "png_b64": png_b64})
            plt.close(fig)

        self._orig_show = plt.show
        plt.show = _capture_show

    def _uninstall_capture_hook(self) -> None:
        try:
            import matplotlib
            import matplotlib.pyplot as plt
            if self._orig_show is not None:
                plt.show = self._orig_show
            if self._orig_backend:
                matplotlib.use(self._orig_backend)
        except Exception:
            pass

    def _write_csv(self, df: pd.DataFrame, name: str) -> tuple[str, str]:
        if df is None or df.empty:
            return "", ""
        path = self.output_dir / name
        df.to_csv(path, index=False)
        csv_bytes = df.to_csv(index=False).encode("utf-8")
        b64 = base64.b64encode(csv_bytes).decode("utf-8")
        return name, f"data:text/csv;base64,{b64}"

    def finalise(self, art: "BDPArtifacts") -> Path:  # type: ignore[name-defined]
        run_end = datetime.now(timezone.utc)
        csvs = {}
        for name, df in [
            ("priority.csv",        art.priority),
            ("periodicity.csv",     art.periodicity),
            ("changepoints.csv",    art.changepoints),
            ("corroboration.csv",   art.corroboration),
            ("sax_screening.csv",   art.sax),
        ]:
            fname, uri = self._write_csv(df, name)
            if fname:
                csvs[fname] = uri

        meta = {
            "Run start":     self._run_start.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "Run end":       run_end.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "Duration":      str(run_end - self._run_start).split(".")[0],
            "Conn rows":     f"{len(art.raw):,}" if not art.raw.empty else "—",
            "Pre-filtered":  f"{len(art.prefiltered):,}" if hasattr(art, 'prefiltered') and not art.prefiltered.empty else "0",
            "Anomalies":     f"{len(art.anomalies):,}" if not art.anomalies.empty else "—",
            "Pairs evaluated": str(len(art.sax)) if not art.sax.empty else "—",
            "SAX pass":      str(art.sax["sax_prescreen_pass"].sum()) if not art.sax.empty else "—",
            "Beacon pairs":  str(art.periodicity["is_beacon_pair"].sum()) if not art.periodicity.empty else "—",
            "Corroborated":  str(art.corroboration["corroborated"].sum()) if not art.corroboration.empty else "—",
        }

        html = _render_html(
            title      = self.title,
            meta       = meta,
            figures    = self._figures,
            csvs       = csvs,
            art        = art,
            run_start  = self._run_start,
        )

        report_path = self.output_dir / "cadence_report.html"
        report_path.write_text(html, encoding="utf-8")
        log.info("Report written to %s", report_path)
        print(f"\n  Report: {report_path.resolve()}")
        if self.open_browser:
            webbrowser.open(report_path.resolve().as_uri())
        return report_path


# ---------------------------------------------------------------------------
# Lead enrichment
# ---------------------------------------------------------------------------

def _build_triage_rows(art: "BDPArtifacts") -> list[dict]:  # type: ignore[name-defined]
    if art.corroboration.empty:
        return []
    confirmed = art.corroboration[art.corroboration["corroborated"]].copy()
    if confirmed.empty:
        return []

    cp_lookup: dict[str, dict] = {}
    if not art.changepoints.empty:
        for _, row in art.changepoints.iterrows():
            cp_lookup[str(row["pair_id"])] = row.to_dict()

    leads = []
    for rank, (_, row) in enumerate(
        confirmed.sort_values("corroboration_score", ascending=False).iterrows(), 1
    ):
        pair_id = str(row["pair_id"])
        cp      = cp_lookup.get(pair_id, {})

        conf       = float(row.get("beacon_confidence", 0))
        corr_score = float(row.get("corroboration_score", 0))
        period_s   = float(row.get("dominant_period_s", 0))
        operator   = bool(cp.get("has_interval_shift", False))
        h2         = bool(row.get("h2_dns_anomaly", False))

        leads.append({
            "rank":               rank,
            "pair_id":            pair_id,
            "src_ip":             str(row.get("src_ip", "")),
            "dst_ip":             str(row.get("dst_ip", "")),
            "flow_count":         int(row.get("flow_count", 0)),
            "severity":           _severity(conf, corr_score, operator, h2),
            "period_str":         _fmt_period(period_s),
            "period_s":           period_s,
            "beacon_confidence":  conf,
            "corroboration_score": corr_score,
            "operator_interaction": operator,
            "start_dt":           cp.get("beacon_start_dt") or "Unknown",
            "h1": bool(row.get("h1_dns_regularity", False)),
            "h2": h2,
            "h3": bool(row.get("h3_http_consistency", False)),
            "h4": bool(row.get("h4_evasion_indicators", False)),
            "h2_dga_domains":     list(row.get("h2_dga_domains", []) or []),
            "h2_nxdomain_count":  int(row.get("h2_nxdomain_count", 0)),
            "h2_short_ttl_count": int(row.get("h2_short_ttl_count", 0)),
            "h3_response_body_cv": row.get("h3_response_body_cv"),
            "h3_uri_len_cv":       row.get("h3_uri_len_cv"),
            "h4_rare_ua":          bool(row.get("h4_rare_ua", False)),
            "h4_high_uri_entropy": bool(row.get("h4_high_uri_entropy", False)),
            "h4_abnormal_methods": list(row.get("h4_abnormal_methods", []) or []),
            "matched_domains":     list(row.get("matched_domains", []) or []),
            "unique_user_agents":  list(row.get("unique_user_agents", []) or []),
            "is_periodic":         bool(row.get("is_periodic", False)),
        })
    return leads


def _fmt_period(s: float) -> str:
    if s <= 0:    return "unknown"
    if s < 60:    return f"{s:.0f}s"
    if s < 3600:  return f"{s/60:.1f} min"
    if s < 86400: return f"{s/3600:.1f} hr"
    return f"{s/86400:.1f} days"


def _severity(conf: float, corr: float, operator: bool, h2: bool) -> str:
    if operator or (conf >= 0.80 and corr >= 0.70): return "CRITICAL"
    if conf >= 0.65 and corr >= 0.55:               return "HIGH"
    return "MEDIUM"


# ---------------------------------------------------------------------------
# Next-steps generator
# ---------------------------------------------------------------------------

def _next_steps(lead: dict) -> list[str]:
    src   = lead.get("src_ip", "unknown")
    dst   = lead.get("dst_ip", "unknown")
    start = lead["start_dt"]
    steps = []

    steps.append(
        f"Block outbound to {dst} at the perimeter firewall."
    )
    steps.append(f"Isolate {src} from the network pending investigation.")

    if start != "Unknown":
        steps.append(
            f"Search SIEM for all activity from {src} since {start} — "
            "scope lateral movement, credential access, and data staging."
        )
    else:
        steps.append(
            f"Search SIEM for all outbound traffic from {src} to identify "
            "lateral movement and data staging."
        )

    if lead["operator_interaction"]:
        steps.append(
            "⚠ ESCALATE: Beacon interval shift detected — a human operator "
            "reconfigured this implant mid-campaign. Active, directed intrusion. "
            "Initiate full IR engagement immediately."
        )

    if lead["h2"] and lead["h2_dga_domains"]:
        steps.append(
            f"Acquire memory image from {src}. DGA domain generation "
            f"({', '.join(lead['h2_dga_domains'][:2])}) indicates an in-memory "
            "implant (Cobalt Strike, Sliver, Havoc, or similar). "
            "Run volatility/malfind against the image."
        )

    if lead["h2"] and lead["h2_nxdomain_count"] > 0 and not lead["h2_dga_domains"]:
        domains = ", ".join(lead["matched_domains"][:3]) or "matched domains"
        steps.append(
            f"Submit {domains} to passive DNS / threat intel (VirusTotal, Shodan, MISP). "
            f"NXDomain count: {lead['h2_nxdomain_count']} — domain may be sinkholed "
            "or C2 infrastructure is rotating."
        )

    if lead["h2"] and lead["h2_short_ttl_count"] > 0 and not lead["h2_dga_domains"]:
        steps.append(
            "Short DNS TTLs indicate possible fast-flux C2 infrastructure. "
            "Enrich destination IPs in TI to identify C2 provider / bulletproof hosting."
        )

    if lead["h4"]:
        items = []
        if lead["h4_rare_ua"]:          items.append("rare/absent User-Agent")
        if lead["h4_high_uri_entropy"]: items.append("high-entropy URI (encoded payload)")
        if lead["h4_abnormal_methods"]: items.append(f"abnormal HTTP methods: {lead['h4_abnormal_methods']}")
        steps.append(
            f"Pull full HTTP session logs for {src} → {dst}. "
            f"Evasion indicators: {'; '.join(items)}. "
            "Decode URI payloads for C2 command content."
        )

    if not lead["h3"] and not lead["h4"]:
        steps.append(
            "Beacon may be HTTPS-encrypted. Capture JA3/JA3S fingerprints for "
            f"connections from {src} to {dst} and compare against known "
            "C2 framework signatures."
        )

    return steps


# ---------------------------------------------------------------------------
# HTML renderer
# ---------------------------------------------------------------------------

def _render_html(
    title:     str,
    meta:      dict,
    figures:   list[dict],
    csvs:      dict[str, str],
    art:       "BDPArtifacts",  # type: ignore[name-defined]
    run_start: datetime,
) -> str:
    leads = _build_triage_rows(art)
    SEV   = {"CRITICAL": "#e05c5c", "HIGH": "#f0a500", "MEDIUM": "#4f9cf9"}

    n_pairs        = meta.get("Pairs evaluated", "—")
    n_sax          = meta.get("SAX pass", "—")
    n_beacon       = meta.get("Beacon pairs", "—")
    n_corroborated = meta.get("Corroborated", "—")

    # ── Triage table ──────────────────────────────────────────────────────
    if leads:
        rows_html = ""
        for lead in leads:
            c   = SEV.get(lead["severity"], "#4f9cf9")
            src = lead.get("src_ip", "—")
            dst = lead.get("dst_ip", "—")
            hb  = "".join(
                f'<span class="hb {"p" if lead[f"h{i}"] else "f"}">H{i}</span>'
                for i in range(1, 5)
            )
            op  = ' <span class="op-flag">⚠ OPERATOR</span>' if lead["operator_interaction"] else ""
            rows_html += f"""
            <tr onclick="scrollToLead({lead['rank']})" style="cursor:pointer">
              <td><span class="sev" style="background:{c}">{lead['severity']}</span></td>
              <td class="mono">{src}</td>
              <td class="mono">{dst}</td>
              <td>{lead['period_str']}</td>
              <td>
                <div class="sbar"><div class="sfill" style="width:{lead['beacon_confidence']*100:.0f}%"></div></div>
                <span class="mono" style="font-size:11px">{lead['beacon_confidence']:.2f}</span>
              </td>
              <td>{hb}</td>
              <td class="mono" style="font-size:11px">{lead['start_dt']}{op}</td>
            </tr>"""

        triage_html = f"""
        <div class="section">
          <div class="section-header">🎯 Triage Summary — {len(leads)} Confirmed Lead{"s" if len(leads)!=1 else ""}
            <span class="h-hint">Click a row to jump to its evidence card</span>
          </div>
          <div class="section-body" style="padding:0">
            <table class="ttable">
              <thead><tr>
                <th>Severity</th><th>Infected Host(s)</th><th>C2 Destination</th>
                <th>Beacon Period</th><th>Confidence</th><th>Evidence</th><th>Est. Start</th>
              </tr></thead>
              <tbody>{rows_html}</tbody>
            </table>
          </div>
        </div>"""
    else:
        triage_html = """
        <div class="section">
          <div class="section-header">🎯 Triage Summary</div>
          <div class="section-body">
            <p style="color:var(--muted)">No corroborated leads in this run. Review the
            periodicity and priority tables for clusters below the corroboration threshold.</p>
          </div>
        </div>"""

    # ── Evidence cards ────────────────────────────────────────────────────
    cards_html = ""
    for lead in leads:
        c     = SEV.get(lead["severity"], "#4f9cf9")
        steps = _next_steps(lead)

        steps_li = "".join(
            f'<li class="{"esc" if "⚠" in s else ""}">{s}</li>'
            for s in steps
        )

        def hr(label, passed, detail):
            icon = "✓" if passed else "✗"
            cls  = "pass" if passed else "fail"
            return (f'<div class="hyp {cls}">'
                    f'<span class="hicon">{icon}</span>'
                    f'<span class="hlabel">{label}</span>'
                    f'<span class="hdetail">{detail}</span>'
                    f'</div>')

        dga = f"DGA: {', '.join(lead['h2_dga_domains'][:2])}" if lead["h2_dga_domains"] else ""
        nxd = f"NXD: {lead['h2_nxdomain_count']}"             if lead["h2_nxdomain_count"] else ""
        ttl = f"ShortTTL: {lead['h2_short_ttl_count']}"       if lead["h2_short_ttl_count"] else ""
        h2d = "  |  ".join(filter(None, [dga, nxd, ttl])) or "no anomalies"

        cv_b   = f"{lead['h3_response_body_cv']:.3f}" if lead["h3_response_body_cv"] is not None else "n/a"
        cv_uri = f"{lead['h3_uri_len_cv']:.3f}"       if lead["h3_uri_len_cv"]       is not None else "n/a"
        h3d    = f"body_CV={cv_b}  uri_CV={cv_uri}"

        ev = []
        if lead["h4_rare_ua"]:          ev.append("rare UA")
        if lead["h4_high_uri_entropy"]: ev.append("high-entropy URI")
        if lead["h4_abnormal_methods"]: ev.append(str(lead["h4_abnormal_methods"]))
        h4d = "  |  ".join(ev) or "none"

        op_banner = (
            '<div class="op-banner">⚠ OPERATOR INTERACTION — Beacon interval shift detected. '
            'Human operator reconfigured this implant. Escalate immediately.</div>'
            if lead["operator_interaction"] else ""
        )

        noise_banner = ""

        domains_html = ""
        if lead["matched_domains"]:
            tags = "".join(f'<span class="dtag">{d}</span>' for d in lead["matched_domains"][:5])
            domains_html = f'<div style="margin-top:10px">{tags}</div>'

        meta_pills = ""
        if lead["start_dt"] != "Unknown":
            meta_pills += f'<div class="mpill">Est. start: {lead["start_dt"]}</div>'

        src_s  = lead.get("src_ip", "unknown")
        dst_s  = lead.get("dst_ip", "unknown")

        cards_html += f"""
        <div class="lead-card" id="lead-{lead['rank']}">
          <div class="lead-hdr" style="border-left:4px solid {c}">
            <div class="lead-title">
              <span class="lrank">#{lead['rank']}</span>
              <span class="sev lg" style="background:{c}">{lead['severity']}</span>
              {lead['src_ip']} → {lead['dst_ip']}
              <span class="lmeta">{lead['flow_count']:,} flows · {lead['period_str']} beacon</span>
            </div>
            <div class="score-pills">
              <div class="spill">Beacon confidence<br><strong>{lead['beacon_confidence']:.3f}</strong></div>
              <div class="spill">Corroboration<br><strong>{lead['corroboration_score']:.3f}</strong></div>
            </div>
          </div>
          {op_banner}
          {noise_banner}
          <div class="lead-body">
            <div class="lcol">
              <div class="fg"><div class="fl">INFECTED HOST(S)</div><div class="fv mono">{src_s}</div></div>
              <div class="fg"><div class="fl">C2 DESTINATION(S)</div><div class="fv mono">{dst_s}</div></div>
              <div class="fg"><div class="fl">FLOWS</div><div class="fv mono">{lead['flow_count']:,}</div></div>
              {meta_pills}
              {domains_html}
            </div>
            <div class="lcol">
              <div class="fl" style="margin-bottom:8px">HYPOTHESIS RESULTS</div>
              {hr("H1 — DNS Regularity",         lead['h1'], "DNS query period matches conn period")}
              {hr("H2 — DNS Anomaly Indicators",  lead['h2'], h2d)}
              {hr("H3 — HTTP Consistency",        lead['h3'], h3d)}
              {hr("H4 — HTTP Evasion",            lead['h4'], h4d)}
            </div>
            <div class="lcol">
              <div class="fl" style="margin-bottom:8px">SUGGESTED NEXT STEPS</div>
              <ol class="steps">{steps_li}</ol>
            </div>
          </div>
        </div>"""

    evidence_section = ""
    if leads:
        evidence_section = (
            f'<div class="section">'
            f'<div class="section-header">🔍 Evidence Cards</div>'
            f'<div class="section-body" style="padding:0">{cards_html}</div>'
            f'</div>'
        )

    # ── CSV buttons ───────────────────────────────────────────────────────
    csv_labels = {
        "priority.csv":      "Priority Table",
        "periodicity.csv":   "Periodicity Scores",
        "changepoints.csv":  "Changepoint Analysis",
        "corroboration.csv": "Corroboration Results",
        "sax_screening.csv": "SAX Pre-Screening",
    }
    csv_btns = "".join(
        f'<a class="csv-btn" href="{uri}" download="{fname}">⬇ {csv_labels.get(fname, fname)}</a>\n'
        for fname, uri in csvs.items()
    )

    # ── Figure gallery ────────────────────────────────────────────────────
    gallery = "".join(
        f'<div class="fig-card"><div class="fig-title">{f["label"]}</div>'
        f'<img src="data:image/png;base64,{f["png_b64"]}" alt="{f["label"]}" loading="lazy"'
        f' onclick="openModal(this.src,\'{f["label"]}\')"></div>'
        for f in figures
    )

    meta_rows = "".join(
        f'<tr><td class="mkey">{k}</td><td class="mval">{v}</td></tr>'
        for k, v in meta.items()
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title}</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=IBM+Plex+Sans:wght@300;400;600;700&display=swap');
  :root{{
    --bg:#080b12;--surface:#0e1420;--s2:#131926;--border:#1e2638;
    --accent:#38bdf8;--danger:#e05c5c;--warn:#f0a500;--ok:#34d399;
    --text:#c9d1e0;--muted:#5a6480;
    --mono:'JetBrains Mono','Consolas',monospace;
    --sans:'IBM Plex Sans',sans-serif;
  }}
  *{{box-sizing:border-box;margin:0;padding:0}}
  html{{scroll-behavior:smooth}}
  body{{background:var(--bg);color:var(--text);font-family:var(--sans);font-size:13.5px;line-height:1.65}}
  a{{color:var(--accent);text-decoration:none}}

  .header{{background:var(--surface);border-bottom:1px solid var(--border);padding:16px 36px;
    display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;z-index:100}}
  .hl{{display:flex;align-items:center;gap:14px}}
  .hi{{font-size:24px}}
  .header h1{{font-size:16px;font-weight:700;color:#fff;letter-spacing:-.3px}}
  .header p{{font-size:11px;color:var(--muted);margin-top:1px}}
  .hts{{font-family:var(--mono);font-size:10px;color:var(--muted)}}

  .main{{max-width:1440px;margin:0 auto;padding:28px 36px}}

  .cards{{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:22px}}
  .card{{background:var(--surface);border:1px solid var(--border);border-radius:10px;
    padding:18px 22px;position:relative;overflow:hidden}}
  .card::before{{content:'';position:absolute;top:0;left:0;right:0;height:2px;background:var(--accent)}}
  .card.d::before{{background:var(--danger)}}
  .cnum{{font-size:40px;font-weight:700;color:var(--accent);line-height:1;font-family:var(--mono)}}
  .card.d .cnum{{color:var(--danger)}}
  .clbl{{font-size:10px;color:var(--muted);margin-top:6px;text-transform:uppercase;letter-spacing:.6px}}

  .section{{background:var(--surface);border:1px solid var(--border);border-radius:10px;margin-bottom:18px;overflow:hidden}}
  .section-header{{padding:12px 20px;border-bottom:1px solid var(--border);font-weight:600;font-size:13px;
    color:#fff;display:flex;align-items:center;gap:8px}}
  .h-hint{{font-size:11px;color:var(--muted);font-weight:400;margin-left:auto}}
  .section-body{{padding:20px}}

  .pipe-flow{{display:flex;align-items:center;flex-wrap:wrap;gap:6px;font-size:11.5px}}
  .pstage{{background:var(--s2);border:1px solid var(--border);border-radius:7px;padding:7px 13px;text-align:center;min-width:95px}}
  .psname{{font-weight:600;color:#fff;font-size:12px}}
  .pscount{{color:var(--accent);font-size:10.5px;font-family:var(--mono);margin-top:2px}}
  .parrow{{color:var(--muted);font-size:15px}}

  .ttable{{width:100%;border-collapse:collapse;font-size:12.5px}}
  .ttable th{{padding:9px 14px;text-align:left;font-size:10px;font-weight:600;text-transform:uppercase;
    letter-spacing:.7px;color:var(--muted);border-bottom:1px solid var(--border);background:var(--s2)}}
  .ttable td{{padding:10px 14px;border-bottom:1px solid var(--border);vertical-align:middle}}
  .ttable tr:last-child td{{border-bottom:none}}
  .ttable tr:hover td{{background:var(--s2)}}

  .sev{{display:inline-block;padding:3px 8px;border-radius:4px;font-size:10px;font-weight:700;letter-spacing:.5px;color:#fff}}
  .sev.lg{{font-size:11px;padding:4px 10px}}
  .hb{{display:inline-block;width:26px;text-align:center;padding:2px 0;border-radius:3px;
    font-size:10px;font-weight:700;margin-right:3px;font-family:var(--mono)}}
  .hb.p{{background:rgba(52,211,153,.12);color:var(--ok);border:1px solid rgba(52,211,153,.3)}}
  .hb.f{{background:rgba(90,100,128,.12);color:var(--muted);border:1px solid var(--border)}}
  .sbar{{display:inline-block;width:56px;height:4px;background:var(--border);border-radius:2px;vertical-align:middle;margin-right:5px}}
  .sfill{{height:100%;background:var(--accent);border-radius:2px}}
  .op-flag{{background:rgba(224,92,92,.12);color:var(--danger);border:1px solid rgba(224,92,92,.3);
    font-size:9px;font-weight:700;padding:1px 6px;border-radius:3px;margin-left:6px;vertical-align:middle;letter-spacing:.5px}}
  .noise-flag{{background:rgba(139,92,246,.12);color:#a78bfa;border:1px solid rgba(139,92,246,.3);
    font-size:9px;font-weight:700;padding:1px 6px;border-radius:3px;margin-left:6px;vertical-align:middle;letter-spacing:.5px}}
  .noise-banner{{background:rgba(139,92,246,.06);border-bottom:1px solid rgba(139,92,246,.2);
    padding:11px 20px;font-size:12.5px;color:#c4b5fd;font-weight:500}}

  .lead-card{{background:var(--surface);border:1px solid var(--border);border-radius:10px;margin-bottom:18px;overflow:hidden}}
  .lead-hdr{{padding:15px 20px;border-bottom:1px solid var(--border);display:flex;align-items:center;
    justify-content:space-between;flex-wrap:wrap;gap:10px;background:var(--s2)}}
  .lead-title{{display:flex;align-items:center;gap:10px;font-size:14px;font-weight:700;color:#fff}}
  .lrank{{font-family:var(--mono);font-size:12px;color:var(--muted)}}
  .lmeta{{font-size:11.5px;font-weight:400;color:var(--muted)}}
  .score-pills{{display:flex;gap:10px}}
  .spill{{background:var(--bg);border:1px solid var(--border);border-radius:7px;padding:7px 13px;
    text-align:center;font-size:10.5px;color:var(--muted);line-height:1.4}}
  .spill strong{{display:block;font-size:19px;font-family:var(--mono);color:var(--accent);font-weight:600}}
  .op-banner{{background:rgba(224,92,92,.07);border-bottom:1px solid rgba(224,92,92,.2);
    padding:11px 20px;font-size:12.5px;color:#e07777;font-weight:600}}
  .lead-body{{display:grid;grid-template-columns:1fr 1fr 1fr}}
  .lcol{{padding:17px 20px;border-right:1px solid var(--border)}}
  .lcol:last-child{{border-right:none}}
  .fg{{margin-bottom:13px}}
  .fl{{font-size:9px;font-weight:700;text-transform:uppercase;letter-spacing:1px;color:var(--muted);margin-bottom:4px}}
  .fv{{font-size:13px;color:#fff;line-height:1.5}}
  .mpill{{display:inline-block;background:var(--s2);border:1px solid var(--border);border-radius:5px;
    padding:3px 9px;font-size:11px;font-family:var(--mono);color:var(--text);margin:3px 4px 3px 0}}
  .dtag{{display:inline-block;background:rgba(224,92,92,.07);border:1px solid rgba(224,92,92,.18);
    color:#e07777;border-radius:4px;padding:2px 7px;font-family:var(--mono);font-size:10.5px;margin:2px 3px 2px 0}}

  .hyp{{display:flex;align-items:flex-start;gap:9px;padding:8px 0;border-bottom:1px solid var(--border);font-size:12px}}
  .hyp:last-child{{border-bottom:none}}
  .hyp.pass .hicon{{color:var(--ok)}}
  .hyp.fail .hicon{{color:var(--muted)}}
  .hicon{{font-size:13px;flex-shrink:0;margin-top:1px;font-weight:700}}
  .hlabel{{font-weight:600;color:#c0c8de;min-width:165px;flex-shrink:0;font-size:12px}}
  .hdetail{{color:var(--muted);font-size:11px;font-family:var(--mono)}}

  .steps{{list-style:none;padding:0;counter-reset:s}}
  .steps li{{counter-increment:s;display:flex;gap:9px;padding:7px 0;border-bottom:1px solid var(--border);font-size:12px;color:var(--text);line-height:1.5}}
  .steps li:last-child{{border-bottom:none}}
  .steps li::before{{content:counter(s);background:var(--s2);border:1px solid var(--border);color:var(--accent);
    font-family:var(--mono);font-size:10px;font-weight:700;min-width:19px;height:19px;display:flex;
    align-items:center;justify-content:center;border-radius:4px;flex-shrink:0;margin-top:2px}}
  .steps li.esc{{color:#e07777}}
  .steps li.esc::before{{background:rgba(224,92,92,.12);color:var(--danger);border-color:rgba(224,92,92,.3)}}

  .csv-buttons{{display:flex;flex-wrap:wrap;gap:10px}}
  .csv-btn{{display:inline-block;padding:8px 16px;background:transparent;border:1px solid var(--accent);
    color:var(--accent);border-radius:6px;font-size:12px;font-weight:600;transition:background .15s}}
  .csv-btn:hover{{background:rgba(56,189,248,.1);color:var(--accent)}}

  .gallery{{display:grid;grid-template-columns:repeat(auto-fill,minmax(440px,1fr));gap:14px}}
  .fig-card{{background:var(--bg);border:1px solid var(--border);border-radius:8px;overflow:hidden}}
  .fig-title{{padding:7px 13px;font-size:10px;font-weight:600;color:var(--muted);border-bottom:1px solid var(--border);
    white-space:nowrap;overflow:hidden;text-overflow:ellipsis}}
  .fig-card img{{width:100%;display:block;cursor:zoom-in}}

  .mtable{{border-collapse:collapse;width:100%}}
  .mtable td{{padding:7px 12px;border-bottom:1px solid var(--border)}}
  .mkey{{color:var(--muted);width:180px;font-size:11px}}
  .mval{{font-family:var(--mono);font-size:11px}}

  .modal{{display:none;position:fixed;inset:0;background:rgba(0,0,0,.9);z-index:1000;
    align-items:center;justify-content:center;flex-direction:column;gap:10px}}
  .modal.open{{display:flex}}
  .modal img{{max-width:92vw;max-height:88vh;border-radius:6px}}
  .modal-title{{color:var(--muted);font-size:11px}}
  .modal-close{{position:absolute;top:16px;right:24px;font-size:26px;color:#fff;cursor:pointer}}
  .mono{{font-family:var(--mono)}}

  @media(max-width:1024px){{
    .lead-body{{grid-template-columns:1fr}}
    .lcol{{border-right:none;border-bottom:1px solid var(--border)}}
    .lcol:last-child{{border-bottom:none}}
    .cards{{grid-template-columns:repeat(2,1fr)}}
  }}
  @media(max-width:640px){{.main{{padding:16px}}.gallery{{grid-template-columns:1fr}}.header{{padding:13px 18px}}}}
</style>
</head>
<body>

<div class="header">
  <div class="hl">
    <span class="hi">📡</span>
    <div>
      <h1>{title}</h1>
      <p>C2 Anomaly Detection via Ensemble Network Correlation Evidence</p>
    </div>
  </div>
  <div class="hts">{meta.get("Run start","")}</div>
</div>

<div class="main">

  <div class="cards">
    <div class="card"><div class="cnum">{n_pairs}</div><div class="clbl">Pairs Evaluated</div></div>
    <div class="card"><div class="cnum">{n_sax}</div><div class="clbl">SAX Candidates</div></div>
    <div class="card"><div class="cnum">{n_beacon}</div><div class="clbl">Beacon Clusters</div></div>
    <div class="card d"><div class="cnum">{n_corroborated}</div><div class="clbl">Confirmed Leads</div></div>
  </div>

  <div class="section">
    <div class="section-header">🔗 Pipeline Flow</div>
    <div class="section-body">
      <div class="pipe-flow">
        <div class="pstage"><div class="psname">Conn Log</div><div class="pscount">{meta.get("Conn rows","—")} rows</div></div>
        <span class="parrow">→</span>
        <div class="pstage"><div class="psname">IForest</div><div class="pscount">{meta.get("Anomalies","—")} anomalies</div></div>
        <span class="parrow">→</span>
        <div class="pstage"><div class="psname">Pair Group</div><div class="pscount">{n_pairs} pairs</div></div>
        <span class="parrow">→</span>
        <div class="pstage"><div class="psname">SAX Screen</div><div class="pscount">{n_sax} pass</div></div>
        <span class="parrow">→</span>
        <div class="pstage"><div class="psname">ACF + FFT</div><div class="pscount">{n_beacon} beacons</div></div>
        <span class="parrow">→</span>
        <div class="pstage"><div class="psname">PELT</div><div class="pscount">timeline</div></div>
        <span class="parrow">→</span>
        <div class="pstage"><div class="psname">Corroborate</div><div class="pscount">{n_corroborated} confirmed</div></div>
      </div>
    </div>
  </div>

  {triage_html}
  {evidence_section}

  <div class="section">
    <div class="section-header">📥 Download Results</div>
    <div class="section-body"><div class="csv-buttons">{csv_btns}</div></div>
  </div>

  <div class="section">
    <div class="section-header">📊 Diagnostic Plots ({len(figures)} figures)</div>
    <div class="section-body"><div class="gallery">{gallery}</div></div>
  </div>

  <div class="section">
    <div class="section-header">ℹ Run Metadata</div>
    <div class="section-body"><table class="mtable">{meta_rows}</table></div>
  </div>

</div>

<div class="modal" id="modal" onclick="closeModal()">
  <span class="modal-close" onclick="closeModal()">✕</span>
  <div class="modal-title" id="modal-title"></div>
  <img id="modal-img" src="" alt="">
</div>

<script>
  function openModal(src,title){{
    document.getElementById('modal-img').src=src;
    document.getElementById('modal-title').textContent=title;
    document.getElementById('modal').classList.add('open');
  }}
  function closeModal(){{document.getElementById('modal').classList.remove('open')}}
  function scrollToLead(rank){{
    const el=document.getElementById('lead-'+rank);
    if(el)el.scrollIntoView({{behavior:'smooth',block:'start'}});
  }}
  document.addEventListener('keydown',e=>{{if(e.key==='Escape')closeModal()}});
</script>
</body>
</html>"""


# ---------------------------------------------------------------------------
# Convenience wrapper
# ---------------------------------------------------------------------------

def run_with_report(
    input_csv:     str,
    output_dir:    str = "results",
    dns_log_path:  Optional[str] = None,
    http_log_path: Optional[str] = None,
    config_path:   Optional[str] = None,
    open_browser:  bool = True,
) -> None:
    from .config import BDPConfig
    from .pipeline import BDPPipeline

    cfg = BDPConfig.from_json(config_path) if config_path else BDPConfig()
    cfg.io.input_csv  = Path(input_csv)
    cfg.io.output_dir = Path(output_dir)

    with ReportContext(output_dir=output_dir, open_browser=open_browser) as report:
        pipe = BDPPipeline(cfg)
        art  = pipe.run(
            dns_log_path  = dns_log_path,
            http_log_path = http_log_path,
            visualize     = True,
        )
        report.finalise(art)
