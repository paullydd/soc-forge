from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from jinja2 import Template

HTML_TEMPLATE = Template(
    r"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>SOC-Forge Report</title>
  <style>
    :root{
      --bg:#0b0f14; --panel:#0f1621; --panel2:#0b121b;
      --text:#e6edf3; --muted:#98a2b3; --border:rgba(255,255,255,0.10);

      --critical:#b56cff;
      --high:#ff6b6b;
      --medium:#f7c948;
      --low:#4dd4ac;
    }
    *{box-sizing:border-box}
    body{
      margin:0; padding:24px;
      background:var(--bg);
      color:var(--text);
      font-family:ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial;
      line-height:1.35;
    }
    .container{max-width:1100px;margin:0 auto;}
    .header{
      display:flex; justify-content:space-between; gap:16px; flex-wrap:wrap;
      padding:18px 18px;
      border:1px solid var(--border);
      background:linear-gradient(180deg, rgba(255,255,255,0.03), rgba(255,255,255,0.01));
      border-radius:16px;
    }
    .title{font-size:20px;font-weight:800;margin:0;}
    .meta{color:var(--muted);font-size:12px;margin-top:6px;}
    .cards{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-top:14px;}
    .stat{
      border:1px solid var(--border); background:var(--panel);
      border-radius:14px; padding:12px;
    }
    .stat .k{font-size:11px;color:var(--muted);font-weight:700;text-transform:uppercase;letter-spacing:0.03em;}
    .stat .v{font-size:18px;font-weight:900;margin-top:4px;}

    .filters{display:flex;gap:10px;flex-wrap:wrap;margin:16px 0 8px;}
    .btn{
      cursor:pointer; user-select:none;
      background:rgba(255,255,255,0.06);
      border:1px solid var(--border);
      padding:8px 12px; border-radius:999px;
      color:var(--text); font-size:12px; font-weight:800;
    }
    .btn.active{outline:2px solid rgba(255,255,255,0.18);}

    .card{
      margin-top:12px;
      border:1px solid var(--border);
      background:var(--panel);
      border-radius:16px;
      overflow:hidden;
    }
    .card-head{padding:14px 16px;border-bottom:1px solid var(--border);background:var(--panel2);}
    .card-head .h{display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap;}
    .card-head .h .left{display:flex;gap:10px;align-items:center;flex-wrap:wrap;}
    .card-head .h .right{color:var(--muted);font-size:12px;display:flex;gap:10px;flex-wrap:wrap;}
    .card-body{padding:14px 16px;}

    .badge{
      display:inline-block;
      padding:4px 10px;
      border-radius:999px;
      border:1px solid var(--border);
      font-size:11px;
      font-weight:900;
      letter-spacing:0.04em;
      text-transform:uppercase;
    }
    .badge.critical{border-color:rgba(181,108,255,0.65);color:#f0ddff;}
    .badge.high{border-color:rgba(255,107,107,0.65);color:#ffd2d2;}
    .badge.medium{border-color:rgba(247,201,72,0.65);color:#fff0b8;}
    .badge.low{border-color:rgba(77,212,172,0.65);color:#c9fff0;}

    table{width:100%;border-collapse:collapse;margin-top:8px;}
    th,td{padding:10px 8px;border-bottom:1px solid var(--border);text-align:left;vertical-align:top;font-size:13px;}
    th{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:0.03em;}
    .muted{color:var(--muted);}
    .mono{font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;}
    .hidden{display:none;}
    details{margin-top:10px;}
    details summary{cursor:pointer;color:var(--muted);font-weight:800;}
    .footer{margin-top:18px;color:var(--muted);font-size:12px;text-align:center;}
  </style>
</head>
<body>
<div class="container">

  <div class="header">
    <div>
      <div class="title">SOC-Forge Report</div>
      <div class="meta">Input: <span class="mono">{{ input_name }}</span> • Generated: {{ generated_at }}</div>
    </div>
    <div class="meta">
      Total Alerts: <strong>{{ stats.total }}</strong>
    </div>
  </div>

  <div class="cards">
    <div class="stat"><div class="k">Critical</div><div class="v">{{ stats.critical }}</div></div>
    <div class="stat"><div class="k">High</div><div class="v">{{ stats.high }}</div></div>
    <div class="stat"><div class="k">Medium</div><div class="v">{{ stats.medium }}</div></div>
    <div class="stat"><div class="k">Low</div><div class="v">{{ stats.low }}</div></div>
  </div>

  <div class="filters">
    <div class="btn active" data-level="all" onclick="setFilter('all')">All</div>
    <div class="btn" data-level="critical" onclick="setFilter('critical')">Critical</div>
    <div class="btn" data-level="high" onclick="setFilter('high')">High</div>
    <div class="btn" data-level="medium" onclick="setFilter('medium')">Medium</div>
    <div class="btn" data-level="low" onclick="setFilter('low')">Low</div>
  </div>

  {% if alerts|length == 0 %}
    <div class="card">
      <div class="card-head"><div class="h"><div class="left"><strong>No alerts</strong></div></div></div>
      <div class="card-body muted">No alerts were produced for this input.</div>
    </div>
  {% else %}

    {% if cases|length > 0 %}
      <div class="card">
        <div class="card-head">
          <div class="h">
            <div class="left"><strong>Cases</strong></div>
            <div class="right"><span class="muted">Grouped by correlation_id</span></div>
          </div>
        </div>
        <div class="card-body">
          {% for c in cases %}
            {% set h = c.header %}
            <div class="card case-card" style="margin:10px 0;">
              <div class="card-head">
                <div class="h">
                  <div class="left">
                    <span class="badge {{ h.severity|lower }}">{{ h.severity }}</span>
                    <strong>{{ h.title }}</strong>
                  </div>
                  <div class="right">
                    <span>Case: <span class="mono">{{ c.correlation_id }}</span></span>
                    <span>Time: <span class="mono">{{ h.timestamp }}</span></span>
                    <span>Score: <span class="mono">{{ h.get("score",0) }}</span></span>
                  </div>
                </div>
              </div>
              <div class="card-body">

                {% if h.details and h.details.evidence %}
                  <details>
                    <summary>Evidence (click to expand)</summary>
                    <table>
                      <thead><tr><th>Rule</th><th>Timestamp</th></tr></thead>
                      <tbody>
                        {% for ev in h.details.evidence %}
                          <tr>
                            <td class="mono muted">{{ ev.rule_id }}</td>
                            <td class="mono muted">{{ ev.timestamp }}</td>
                          </tr>
                        {% endfor %}
                      </tbody>
                    </table>
                  </details>
                {% endif %}

                <div class="muted" style="margin-top:10px;font-weight:900;">Alerts in this case</div>
                <table>
                  <thead>
                    <tr>
                      <th>Time</th><th>Severity</th><th>Rule</th><th>Title</th><th>Score</th>
                    </tr>
                  </thead>
                  <tbody>
                    {% for a in c.alerts %}
                      <tr data-sev="{{ a.severity|lower }}">
                        <td class="mono muted">{{ a.timestamp }}</td>
                        <td><span class="badge {{ a.severity|lower }}">{{ a.severity }}</span></td>
                        <td class="mono muted">{{ a.rule_id }}</td>
                        <td>{{ a.title }}</td>
                        <td class="mono muted"><strong>{{ a.get("score",0) }}</strong></td>
                      </tr>
                    {% endfor %}
                  </tbody>
                </table>

              </div>
            </div>
          {% endfor %}
        </div>
      </div>
    {% endif %}

    {% if standalone|length > 0 %}
      <div class="card standalone card">
        <div class="card-head">
          <div class="h">
            <div class="left"><strong>Standalone Alerts</strong></div>
            <div class="right"><span class="muted">No correlation_id</span></div>
          </div>
        </div>
        <div class="card-body">
          <table>
            <thead>
              <tr>
                <th>Time</th><th>Severity</th><th>Rule</th><th>Title</th><th>Score</th>
              </tr>
            </thead>
            <tbody>
              {% for a in standalone %}
                <tr data-sev="{{ a.severity|lower }}">
                  <td class="mono muted">{{ a.timestamp }}</td>
                  <td><span class="badge {{ a.severity|lower }}">{{ a.severity }}</span></td>
                  <td class="mono muted">{{ a.rule_id }}</td>
                  <td>{{ a.title }}</td>
                  <td class="mono muted"><strong>{{ a.get("score",0) }}</strong></td>
                </tr>
              {% endfor %}
            </tbody>
          </table>
        </div>
      </div>
    {% endif %}

  {% endif %}

  <div class="footer">SOC-Forge • Case-based report view</div>

</div>

<script>
  function setFilter(level) {
    document.querySelectorAll(".btn").forEach(b => b.classList.remove("active"));
    const btn = document.querySelector(`.btn[data-level="${level}"]`);
    if (btn) btn.classList.add("active");

    // Filter rows first
    document.querySelectorAll("tr[data-sev]").forEach(tr => {
      const sev = (tr.getAttribute("data-sev") || "").toLowerCase();
      const show = (level === "all" || sev === level);
      tr.classList.toggle("hidden", !show);
    });

    // Then show/hide each case card based on whether it has any visible rows
    document.querySelectorAll(".case-card").forEach(card => {
      if (level === "all") {
        card.classList.remove("hidden");
        return;
      }
      const visibleRows = card.querySelectorAll("tr[data-sev]:not(.hidden)");
      card.classList.toggle("hidden", visibleRows.length === 0);
    });

    // Same logic for the standalone card
    document.querySelectorAll(".standalone-card").forEach(card => {
      if (level === "all") {
        card.classList.remove("hidden");
        return;
      }
      const visibleRows = card.querySelectorAll("tr[data-sev]:not(.hidden)");
      card.classList.toggle("hidden", visibleRows.length === 0);
    });
  }

  setFilter("all");
</script>

</body>
</html>"""
)


def write_html_report(alerts: List[Dict[str, Any]], output_path: Path, input_name: str) -> None:
    # Sort newest-first
    alerts_sorted = sorted(alerts, key=lambda a: a.get("timestamp", ""), reverse=True)

    # Severity stats
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for a in alerts_sorted:
        sev = str(a.get("severity", "")).lower()
        if sev in sev_counts:
            sev_counts[sev] += 1

    stats = {
        "total": len(alerts_sorted),
        "critical": sev_counts["critical"],
        "high": sev_counts["high"],
        "medium": sev_counts["medium"],
        "low": sev_counts["low"],
    }

    # Group into cases + standalone
    cases_map: Dict[str, List[Dict[str, Any]]] = {}
    standalone: List[Dict[str, Any]] = []

    for a in alerts_sorted:
        cid = a.get("correlation_id")
        if cid:
            cases_map.setdefault(str(cid), []).append(a)
        else:
            standalone.append(a)

    cases = []
    for cid, items in cases_map.items():
        items_sorted = sorted(items, key=lambda x: x.get("timestamp", ""), reverse=True)
        header = next(
            (x for x in items_sorted if str(x.get("rule_id", "")).startswith("SOCF-CORR")),
            items_sorted[0],
        )
        cases.append({"correlation_id": cid, "header": header, "alerts": items_sorted})

    cases = sorted(cases, key=lambda c: c["header"].get("timestamp", ""), reverse=True)

    html = HTML_TEMPLATE.render(
        alerts=alerts_sorted,
        cases=cases,
        standalone=standalone,
        stats=stats,
        input_name=input_name,
        generated_at=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
    )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html, encoding="utf-8")
