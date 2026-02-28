from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from jinja2 import Template

HTML_TEMPLATE = Template(
    r"""
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>SOC-Forge Report</title>
  <style>
    :root {
      --bg: #0b1020;
      --card: #111a33;
      --muted: #93a4c7;
      --text: #e8eeff;
      --border: rgba(255,255,255,0.10);
      --shadow: 0 10px 30px rgba(0,0,0,0.35);
      --high: #ff5a5f;
      --medium: #ffbd2e;
      --low: #2ecc71;
      --chip: rgba(255,255,255,0.08);
      --critical: #b56cff;
      --link: #8ab4ff;
    }

    body {
      margin: 0;
      background: radial-gradient(1200px 600px at 15% 10%, rgba(72, 125, 255, 0.25), transparent 60%),
                  radial-gradient(900px 500px at 80% 30%, rgba(255, 90, 95, 0.18), transparent 55%),
                  var(--bg);
      color: var(--text);
      font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial;
      line-height: 1.35;
    }

    .container {
      max-width: 1100px;
      margin: 0 auto;
      padding: 28px 18px 60px;
    }

    header {
      display: flex;
      flex-wrap: wrap;
      gap: 16px;
      align-items: baseline;
      justify-content: space-between;
      margin-bottom: 18px;
    }

    h1 {
      font-size: 28px;
      margin: 0;
      letter-spacing: 0.2px;
    }

    .subtitle {
      color: var(--muted);
      font-size: 14px;
      margin-top: 6px;
    }

    .stats {
      display: flex;
      gap: 10px;
      flex-wrap: wrap;
      justify-content: flex-end;
    }

    .stat {
      background: rgba(255,255,255,0.05);
      border: 1px solid var(--border);
      box-shadow: var(--shadow);
      padding: 10px 12px;
      border-radius: 14px;
      min-width: 150px;
    }

    .stat .label {
      color: var(--muted);
      font-size: 12px;
    }

    .stat .value {
      font-size: 20px;
      font-weight: 700;
      margin-top: 2px;
    }

    .grid {
      display: grid;
      grid-template-columns: 1fr;
      gap: 14px;
      margin-top: 20px;
    }

    .card {
      background: rgba(17, 26, 51, 0.75);
      border: 1px solid var(--border);
      border-radius: 18px;
      box-shadow: var(--shadow);
      overflow: hidden;
    }

    .card-head {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      justify-content: space-between;
      gap: 10px;
      padding: 14px 16px;
      border-bottom: 1px solid var(--border);
    }

    .title {
      display: flex;
      align-items: center;
      gap: 10px;
      font-weight: 700;
      font-size: 16px;
    }

    .meta {
      display: flex;
      gap: 10px;
      flex-wrap: wrap;
      align-items: center;
      color: var(--muted);
      font-size: 12px;
    }

    .badge {
      font-size: 12px;
      font-weight: 700;
      padding: 5px 10px;
      border-radius: 999px;
      border: 1px solid var(--border);
      background: rgba(255,255,255,0.04);
      display: inline-flex;
      align-items: center;
      gap: 6px;
    }
    .badge.critical { border-color: rgba(181,108,255,0.70); color: #f0ddff; }
    .badge.high { border-color: rgba(255,90,95,0.65); color: #ffd0d2; }
    .badge.medium { border-color: rgba(255,189,46,0.65); color: #ffe8b8; }
    .badge.low { border-color: rgba(46,204,113,0.65); color: #c9f6dc; }

    .card-body {
      padding: 14px 16px 16px;
      display: grid;
      gap: 10px;
    }

    .chips {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin-top: 2px;
    }

    .chip {
      background: var(--chip);
      border: 1px solid var(--border);
      color: var(--text);
      padding: 6px 10px;
      border-radius: 999px;
      font-size: 12px;
    }

    table {
      width: 100%;
      border-collapse: collapse;
      margin-top: 6px;
      font-size: 13px;
    }
    th, td {
      text-align: left;
      padding: 10px 10px;
      border-bottom: 1px solid var(--border);
      vertical-align: top;
    }
    th {
      color: var(--muted);
      font-weight: 600;
      font-size: 12px;
      letter-spacing: 0.2px;
      text-transform: uppercase;
    }
    .muted { color: var(--muted); }

    a { color: var(--link); text-decoration: none; }
    a:hover { text-decoration: underline; }

    footer {
      margin-top: 30px;
      color: var(--muted);
      font-size: 12px;
      text-align: center;
    }

    .empty {
      padding: 18px;
      color: var(--muted);
    }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div>
        <h1>SOC-Forge Report</h1>
        <div class="subtitle">
          Generated: <span class="muted">{{ generated_at }}</span>
          &nbsp;•&nbsp; Input: <span class="muted">{{ input_name }}</span>
        </div>
      </div>

      <div class="stats">
        <div class="stat">
          <div class="label">Total Alerts</div>
          <div class="value">{{ stats.total }}</div>
        </div>
        <div class="stat">
          <div class="label">Critical / High / Medium / Low</div>
          <div class="value">{{ stats.crticial }} / {{ stats.high }} / {{ stats.medium }} / {{ stats.low }}</div>
        </div>
        <div class="stat">
          <div class="label">Rules Triggered</div>
          <div class="value">{{ stats.rules }}</div>
        </div>
      </div>
    </header>

    {% if alerts|length == 0 %}
      <div class="card">
        <div class="empty">No alerts generated for this input.</div>
      </div>
    {% else %}

    <div class="card">
      <div class="card-head">
        <div class="title">Alerts Summary</div>
        <div class="meta">Sorted by time (UTC), newest first</div>
      </div>
      <div class="card-body">
        <table>
          <thead>
            <tr>
              <th>Time</th>
              <th>Severity</th>
              <th>Score</th>
              <th>Rule</th>
              <th>Title</th>
              <th>Key Details</th>
              <th>MITRE</th>
            </tr>
          </thead>
          <tbody>
          {% for a in alerts %}
            <tr>
              <td class="muted">{{ a.timestamp }}</td>
              <td>
                <span class="badge {{ a.severity|lower }}">{{ a.severity|upper }}</span>
              </td>
              <td class="muted"><strong>{{ a.get("score", 0) }}</strong></td>
              <td class="muted">{{ a.rule_id }}</td>
              <td>{{ a.title }}</td>
              <td class="muted">
                {% for k, v in a.details.items() %}
                  <div><strong class="muted">{{ k }}:</strong> {{ v }}</div>
                {% endfor %}
              </td>
              <td class="muted">
                {% for m in a.mitre %}
                  <div>{{ m.get("id","") }} — {{ m.get("technique","") }}</div>
                {% endfor %}
              </td>
            </tr>
          {% endfor %}
          </tbody>
        </table>
      </div>
    </div>

    <div class="grid">
      {% for a in alerts %}
      <div class="card">
        <div class="card-head">
          <div class="title">
            <span class="badge {{ a.severity|lower }}">{{ a.severity|upper }}</span>
            {{ a.title }}
          </div>
          <div class="meta">
            <span>Rule: <strong class="muted">{{ a.rule_id }}</strong></span>
            <span>Time: <strong class="muted">{{ a.timestamp }}</strong></span>
          </div>
        </div>
        <div class="card-body">
          <div class="chips">
            {% for m in a.mitre %}
              <span class="chip">{{ m.get("id","") }} • {{ m.get("tactic","") }} • {{ m.get("technique","") }}</span>
            {% endfor %}
          </div>

          <div>
            <div class="muted" style="margin-bottom:6px;">Details</div>
            <table>
              <tbody>
                {% for k, v in a.details.items() %}
                <tr>
                  <th style="width: 240px;">{{ k }}</th>
                  <td class="muted">{{ v }}</td>
                </tr>
                {% endfor %}
              </tbody>
            </table>
          </div>
        </div>
      </div>
      {% endfor %}
    </div>
    {% endif %}

    <footer>
      SOC-Forge • Phase 1 • Local report file (no external resources)
    </footer>
  </div>
</body>
</html>
"""
)


def write_html_report(
    *,
    alerts: List[Dict[str, Any]],
    output_path: Path,
    input_name: str = "unknown",
) -> None:
    # sort newest first by timestamp string (ISO-8601 sorts lexicographically)
    alerts_sorted = sorted(alerts, key=lambda a: a.get("timestamp", ""), reverse=True)

    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    rules = set()

    for a in alerts_sorted:
        sev = str(a.get("severity", "")).lower()
        if sev in sev_counts:
            sev_counts[sev] += 1
        rules.add(a.get("rule_id", "unknown"))

    stats = {
        "total": len(alerts_sorted),
        "critical": sev_counts["critical"],
        "high": sev_counts["high"],
        "medium": sev_counts["medium"],
        "low": sev_counts["low"],
        "rules": len([r for r in rules if r]),
    }

    html = HTML_TEMPLATE.render(
        alerts=alerts_sorted,
        stats=stats,
        input_name=input_name,
        generated_at=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
    )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html, encoding="utf-8")
