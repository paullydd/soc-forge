from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple

from jinja2 import Template

from soc_forge import __version__
from soc_forge.cases.helpers import (
    build_analyst_summary,
    build_attack_chain,
    build_attack_flow,
    build_attack_graph,
    build_attack_path,
    build_case_risk_fallback,
    build_case_timeline,
    build_evidence_fields,
    choose_case_header_alert,
    extract_case_iocs,
    extract_mitre_ids,
    normalize_attack_step,
)

# -------------------------
# HTML Template
# -------------------------
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

    .chain { display:flex; flex-wrap:wrap; gap:8px; margin-top:8px; align-items:center; }
    .chain .node {
      border:1px solid var(--border);
      background:rgba(255,255,255,0.04);
      border-radius:999px;
      padding:6px 10px;
      font-size:12px;
      font-weight:900;
      color:var(--text);
    }
    .chain .arrow { color:var(--muted); font-weight:900; }

    .evidence-list {
      display: flex;
      flex-direction: column;
      gap: 10px;
    }

    .mitre-panel {
      margin-top: 16px;
      padding: 14px;
      border: 1px solid #2a2f3a;
      border-radius: 10px;
      background: #11151c;
    }

    .mitre-row {
      display: grid;
      grid-template-columns: 180px 1fr 50px;
      gap: 10px;
      align-items: center;
      margin: 8px 0;
    }

    .mitre-label {
      font-weight: 700;
      color: #d7dde8;
    }

    .mitre-bar-wrap {
      width: 100%;
      background: #1c2330;
      border-radius: 999px;
      height: 14px;
      overflow: hidden;
    }

    .mitre-bar {
      height: 14px;
      border-radius: 999px;
      background: linear-gradient(90deg, #4da3ff, #7cc4ff);
    }

    .mitre-count {
      text-align: right;
      color: #9fb3c8;
      font-weight: 700;
    }

    .muted {
      color: #93a1b2;
    }

    .attack-flow {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 10px;
      margin-top: 8px;
    }

    .flow-step {
      min-width: 180px;
      max-width: 240px;
      padding: 10px 12px;
      border: 1px solid #2a2f3a;
      border-radius: 12px;
      background: rgba(255,255,255,0.03);
    }

    .flow-label {
      font-weight: 700;
      margin-bottom: 6px;
    }

    .flow-meta {
      display: flex;
      flex-direction: column;
      gap: 4px;
      font-size: 0.9rem;
    }

    .flow-arrow {
      font-size: 1.4rem;
      font-weight: 700;
      opacity: 0.7;
    }

    .evidence-item {
      border: 1px solid #2a2f3a;
      border-radius: 10px;
      padding: 10px;
      background: rgba(255,255,255,0.02);
    }

    .evidence-head {
      display: flex;
      flex-wrap: wrap;
      gap: 8px 12px;
      align-items: center;
      margin-bottom: 8px;
    }

    .evidence-fields {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
    }

    .kv {
      display: inline-flex;
      gap: 6px;
      align-items: center;
      padding: 4px 8px;
      border-radius: 999px;
      background: rgba(255,255,255,0.04);
      border: 1px solid #2a2f3a;
      font-size: 0.9rem;
    }

    .k {
      font-weight: 600;
      opacity: 0.85;
    }

    .v {
      opacity: 0.95;
    }

    .checklist {
      list-style: none;
      padding-left: 0;
      margin: 0.25rem 0 0;
    }
    .checklist li {
      margin: 0.35rem 0;
    }
    .checklist input[type="checkbox"] {
      margin-right: 0.5rem;
      transform: translateY(1px);
    }

    .flow-mitre {
      display: flex;
      flex-wrap: wrap;
      gap: 6px;
      margin-bottom: 8px;
    }

    .mitre-tag {
      display: inline-block;
      padding: 3px 8px;
      border-radius: 999px;
      border: 1px solid #355c7d;
      background: rgba(53, 92, 125, 0.18);
      font-size: 0.82rem;
    }

    .attack-graph {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 10px;
      margin-top: 8px;
    }

    .graph-node {
      min-width: 140px;
      max-width: 220px;
      padding: 10px 12px;
      border-radius: 12px;
      border: 1px solid #2a2f3a;
      background: rgba(255,255,255,0.03);
    }

    .graph-node-type {
      font-size: 0.72rem;
      font-weight: 700;
      letter-spacing: 0.05em;
      opacity: 0.75;
      margin-bottom: 6px;
    }

    .graph-node-label {
      font-size: 0.95rem;
    }

    .graph-ip {
      border-color: #355c7d;
    }

    .graph-user {
      border-color: #6c5b7b;
    }

    .graph-host {
      border-color: #2a9d8f;
    }

    .graph-action {
      border-color: #e9c46a;
    }

    .graph-arrow {
      font-size: 1.3rem;
      font-weight: 700;
      opacity: 0.7;
    }

    .graph-node.ip {
      border-color: #3b82f6;
      box-shadow: 0 0 0 1px rgba(59, 130, 246, 0.15), 0 4px 14px rgba(0, 0, 0, 0.25);
    }

    .graph-node.user {
      border-color: #a855f7;
      box-shadow: 0 0 0 1px rgba(168, 85, 247, 0.15), 0 4px 14px rgba(0, 0, 0, 0.25);
    }

    .graph-node.host {
      border-color: #22c55e;
      box-shadow: 0 0 0 1px rgba(34, 197, 94, 0.15), 0 4px 14px rgba(0, 0, 0, 0.25);
    }

    .graph-node.action {
      border-color: #f59e0b;
      box-shadow: 0 0 0 1px rgba(245, 158, 11, 0.15), 0 4px 14px rgba(0, 0, 0, 0.25);
    }

    .case-meta {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin-top: 10px;
    }

    .badge {
      display: inline-flex;
      align-items: center;
      padding: 6px 10px;
      border-radius: 999px;
      font-size: 12px;
      font-weight: 800;
      letter-spacing: 0.02em;
      border: 1px solid #2b3545;
      background: #18202b;
      color: #dbe7f3;
    }

    .badge-low {
      border-color: #22c55e;
      color: #86efac;
    }

    .badge-medium {
      border-color: #f59e0b;
      color: #fcd34d;
    }

    .badge-high {
      border-color: #ef4444;
      color: #fca5a5;
    }

    .badge-critical {
      border-color: #ff4d6d;
      color: #ff9fb3;
    }

    .investigation-graph {
      display: flex;
      flex-direction: column;
      align-items: center;
      gap: 8px;
      margin-top: 14px;
    }

    .graph-node {
      min-width: 240px;
      max-width: 420px;
      text-align: center;
      padding: 12px 16px;
      border-radius: 14px;
      background: linear-gradient(180deg, #18202b 0%, #141b24 100%);
      border: 1px solid #2b3545;
      color: #e6edf7;
      box-shadow: 0 6px 18px rgba(0, 0, 0, 0.28);
    }

    .graph-node-kind {
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      color: #8fa7c0;
      margin-bottom: 5px;
      font-weight: 800;
    }

    .graph-node-value {
      font-size: 15px;
      font-weight: 800;
      word-break: break-word;
    }


    .graph-arrow {
      color: #7cc4ff;
      font-size: 22px;
      font-weight: 900;
      line-height: 1;
      opacity: 0.9;
    }

    .hunt-badge {
      display: inline-block;
      padding: 4px 10px;
      border-radius: 999px;
      font-size: 0.75rem;
      font-weight: 800;
      background: #4c1d95;
      color: #ffffff;
      border: 1px solid #8b5cf6;
    }
    
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
    .executive-snapshot{
      display:grid;
      grid-template-columns:minmax(0,1.15fr) minmax(280px,0.85fr);
      gap:14px;
      margin-top:14px;
    }
    .snapshot-panel{
      border:1px solid var(--border);
      background:var(--panel);
      border-radius:16px;
      padding:16px;
    }
    .snapshot-title{
      font-size:18px;
      font-weight:900;
      margin-bottom:8px;
    }
    .snapshot-grid{
      display:grid;
      grid-template-columns:repeat(3,minmax(90px,1fr));
      gap:8px;
      margin-top:12px;
    }
    .snapshot-metric{
      border:1px solid var(--border);
      background:rgba(255,255,255,0.03);
      border-radius:12px;
      padding:10px;
    }
    .snapshot-metric .k{
      font-size:11px;
      color:var(--muted);
      text-transform:uppercase;
      letter-spacing:0.04em;
      font-weight:800;
    }
    .snapshot-metric .v{
      font-size:20px;
      font-weight:900;
      margin-top:4px;
    }
    .snapshot-list{
      display:flex;
      flex-wrap:wrap;
      gap:8px;
      margin-top:10px;
    }
    .appendix{
      margin-top:14px;
      border:1px solid var(--border);
      background:rgba(255,255,255,0.025);
      border-radius:16px;
      padding:12px 14px;
    }
    .appendix > summary{
      cursor:pointer;
      color:var(--text);
      font-weight:900;
    }
    .appendix-note{
      margin-top:6px;
      color:var(--muted);
      font-size:13px;
    }
    @media (max-width: 900px){
      .executive-snapshot{grid-template-columns:1fr;}
      .snapshot-grid{grid-template-columns:1fr;}
    }
    .footer{margin-top:18px;color:var(--muted);font-size:12px;text-align:center;}
  </style>
</head>
<body>

<div class="container">
{% set h = {} %}

  <div class="header">
    <div>
      <div class="title">SOC-Forge Incident Report</div>
      <div class="meta">
        Input: <span class="mono">{{ input_name }}</span> &middot; Generated: {{ generated_at }} &middot; Version: {{ version }}
      </div>
    </div>
    <div class="meta">
      Total Alerts: <strong>{{ stats.total }}</strong>
    </div>
  </div>

  {% set top_case = cases[0] if cases and cases|length > 0 else none %}
  {% set top_header = top_case.header if top_case else {} %}
  {% set top_details = top_header.get('details', {}) if top_header else {} %}
  {% set top_quality = top_details.get('case_quality', {}) %}
  {% set top_risk = top_details.get('case_risk', {}) %}
  {% set top_iocs = top_details.get('iocs', {}) %}

  <div class="executive-snapshot">
    <section class="snapshot-panel">
      <div class="snapshot-title">Executive Snapshot</div>
      <div style="font-size:1.45rem; font-weight:900;">
        {{ risk_summary.level|upper }} ({{ risk_summary.overall_score }})
      </div>
      <p class="muted">
        {% if top_quality.get('executive_summary') %}
          {{ top_quality.get('executive_summary') }}
        {% elif top_case %}
          Highest risk case: {{ top_header.get('title', 'Untitled case') }}.
        {% else %}
          No correlated case was generated for this report.
        {% endif %}
      </p>
      <div class="snapshot-grid">
        <div class="snapshot-metric"><div class="k">Alerts</div><div class="v">{{ risk_summary.alerts }}</div></div>
        <div class="snapshot-metric"><div class="k">Correlations</div><div class="v">{{ risk_summary.correlations }}</div></div>
        <div class="snapshot-metric"><div class="k">Hunts</div><div class="v">{{ risk_summary.hunts }}</div></div>
      </div>
    </section>

    <section class="snapshot-panel">
      <div class="snapshot-title">What To Review First</div>
      {% if top_case %}
        <div><strong>{{ top_header.get('title', 'Untitled case') }}</strong></div>
        <div class="case-meta">
          <span class="badge {{ top_risk.get('case_threat_level', top_header.get('severity', 'low'))|lower }}">{{ top_risk.get('case_threat_level', top_header.get('severity', 'low')) }}</span>
          <span class="badge">Score {{ top_risk.get('case_score', top_header.get('score', 0)) }}</span>
          <span class="badge">Alerts {{ top_risk.get('alert_count', top_case.alerts|length) }}</span>
        </div>
        <div class="snapshot-list">
          {% for ip in top_iocs.get('ips', [])[:3] %}<span class="badge mono">IP {{ ip }}</span>{% endfor %}
          {% for host in top_iocs.get('hosts', [])[:3] %}<span class="badge mono">Host {{ host }}</span>{% endfor %}
          {% for user in top_iocs.get('users', [])[:3] %}<span class="badge mono">User {{ user }}</span>{% endfor %}
        </div>
      {% else %}
        <p class="muted">Start with standalone alerts and MITRE coverage in the appendix.</p>
      {% endif %}
    </section>
  </div>

  {% if stats.total == 0 %}
    <div class="card">
      <div class="card-head">
        <div class="h"><div class="left"><strong>No alerts</strong></div></div>
      </div>
      <div class="card-body muted">No alerts were produced for this input.</div>
    </div>
  {% else %}

    {% if cases and cases|length > 0 %}
      <div class="card">
        <div class="card-head">
          <div class="h">
            <div class="left"><strong>Case Narrative</strong></div>
            <div class="right"><span class="muted">Grouped by correlation_id</span></div>
          </div>
        </div>
        <div class="card-body">


          {% for c in cases %}
            {% set h = c.header %}
            {% set cr = (h.get('details', {}) or {}).get('case_risk', {}) %}
            {% set recon = (recon_by_case or {}).get(h.get('case_id')) %}

            <div class="case-meta">
            <span class="badge badge-{{ cr.get('case_severity', h.severity)|lower }}">
              {{ cr.get('case_severity', h.severity)|upper }}
            </span>
            <span class="badge">Score: {{ cr.get('case_score', 0) }}</span>
            <span class="badge">Case: {{ h.correlation_id }}</span>
            <span class="badge">Alerts: {{ cr.get('alert_count', 0) }}</span>
          </div>

            {% set actions = (h.get('details', {}) or {}).get('recommended_actions', []) %}
            {% if actions %}
              <div class="case-section">
                <h3>Recommended Actions</h3>
                <ul class="checklist">
                  {% for a in actions %}
                    <li>
                      <label>
                        <input type="checkbox" />
                        <span>{{ a }}</span>
                      </label>
                    </li>
                  {% endfor %}
                </ul>
              </div>
            {% endif %}

            {% set recon = (recon_by_case or {}).get(h.get('case_id')) %}
            {% if recon %}
              <div class="card" style="margin-top:14px;">
                <div style="font-weight:900; font-size:1.05rem;">Attack Reconstruction</div>

                <div style="margin-top:8px;">
                  <strong>Summary:</strong> {{ recon.get('summary', 'No reconstruction summary available.') }}
                </div>

                <div class="muted" style="margin-top:4px;">
                  Confidence:
                  {{ ((recon.get('confidence', 0) or 0) * 100) | round(0) }}%
                </div>

                {% set attack_path = recon.get('attack_path', []) or [] %}
                {% if attack_path %}
                  <ol style="margin-top:12px; padding-left:20px;">
                    {% for step in attack_path %}
                      <li style="margin-bottom:12px;">
                        <div>
                          <strong>{{ step.get('stage', 'Unknown Stage') }}</strong>
                          - {{ step.get('title', 'Unknown activity') }}
                          {% if step.get('inferred') %}
                            <span class="badge" style="margin-left:8px;">Inferred</span>
                          {% endif %}
                        </div>

                        <div class="muted" style="margin-top:3px;">
                          {{ step.get('timestamp') or 'No timestamp' }}
                          {% if step.get('technique') %}
                            &middot; {{ step.get('technique') }}
                          {% endif %}
                          {% if step.get('confidence') is not none %}
                            &middot; confidence {{ ((step.get('confidence', 0) or 0) * 100) | round(0) }}%
                          {% endif %}
                        </div>

                        {% set entities = step.get('entities', {}) or {} %}
                        {% if entities %}
                          <div style="margin-top:6px;">
                            {% if entities.get('src_ip') %}
                              <code>{{ entities.get('src_ip') }}</code>
                            {% endif %}
                            {% if entities.get('username') %}
                              <code>{{ entities.get('username') }}</code>
                            {% endif %}
                            {% if entities.get('host') %}
                              <code>{{ entities.get('host') }}</code>
                            {% endif %}
                          </div>
                        {% endif %}

                        {% set notes = step.get('notes', []) or [] %}
                        {% if notes %}
                          <ul style="margin-top:6px;">
                            {% for note in notes %}
                              <li>{{ note }}</li>
                            {% endfor %}
                          </ul>
                        {% endif %}
                      </li>
                    {% endfor %}
                  </ol>
                {% else %}
                  <div class="muted" style="margin-top:8px;">No attack path steps were reconstructed.</div>
                {% endif %}

                {% set relationships = recon.get('relationships', []) or [] %}
                {% if relationships %}
                  <details style="margin-top:10px;">
                    <summary>Step Relationships</summary>
                    <table style="margin-top:8px;">
                      <thead>
                        <tr>
                          <th>From</th>
                          <th>To</th>
                          <th>Reason</th>
                          <th>Weight</th>
                        </tr>
                      </thead>
                      <tbody>
                        {% for rel in relationships %}
                          <tr>
                            <td>{{ rel.get('from_step') }}</td>
                            <td>{{ rel.get('to_step') }}</td>
                            <td>{{ rel.get('reason') }}</td>
                            <td>{{ '%.2f'|format(rel.get('weight', 0) or 0) }}</td>
                          </tr>
                        {% endfor %}
                      </tbody>
                    </table>
                  </details>
                {% endif %}

                {% set key_entities = recon.get('key_entities', {}) or {} %}
                {% if key_entities %}
                  <div style="margin-top:10px;">
                    <div style="font-weight:700;">Key Entities</div>
                    <div class="muted" style="margin-top:4px;">
                      {% if key_entities.get('src_ips') %}
                        <strong>IPs:</strong> {{ key_entities.get('src_ips') | join(', ') }}<br>
                      {% endif %}
                      {% if key_entities.get('users') %}
                        <strong>Users:</strong> {{ key_entities.get('users') | join(', ') }}<br>
                      {% endif %}
                      {% if key_entities.get('hosts') %}
                        <strong>Hosts:</strong> {{ key_entities.get('hosts') | join(', ') }}
                      {% endif %}
                    </div>
                  </div>
                {% endif %}

                {% set gaps = recon.get('gaps', []) or [] %}
                {% if gaps %}
                  <div style="margin-top:10px;">
                    <div style="font-weight:700;">Observed Gaps</div>
                    <ul style="margin-top:4px;">
                      {% for gap in gaps %}
                        <li>{{ gap }}</li>
                      {% endfor %}
                    </ul>
                  </div>
                {% endif %}

                {% set assumptions = recon.get('assumptions', []) or [] %}
                {% if assumptions %}
                  <div style="margin-top:10px;">
                    <div style="font-weight:700;">Assumptions</div>
                    <ul style="margin-top:4px;">
                      {% for assumption in assumptions %}
                        <li>{{ assumption }}</li>
                      {% endfor %}
                    </ul>
                  </div>
                {% endif %}
              </div>
            {% endif %}

            {% set related_hunts = c.get('related_hunts', []) %}
            {% if related_hunts and related_hunts|length > 0 %}
              <div class="card" style="margin-top:10px; border-left: 6px solid #7c3aed;">
                <div style="font-weight:900; margin-bottom:6px;">Related Hunt Findings</div>
                <table>
                  <thead>
                    <tr>
                      <th>Hunt</th>
                      <th>Summary</th>
                      <th>Severity</th>
                    </tr>
                  </thead>
                  <tbody>
                    {% for h in related_hunts %}
                      <tr>
                        <td>{{ h.get('title', '') }}</td>
                        <td>{{ h.get('summary', '') }}</td>
                        <td>{{ h.get('severity', '')|upper }}</td>
                      </tr>
                    {% endfor %}
                  </tbody>
                </table>
              </div>
            {% endif %}

            <div class="card case-card" style="margin:10px 0;">
              <div class="card-head">
                <div class="h">
                  <div class="left">
                    <span class="badge {{ h.get('severity','')|lower }}">{{ h.get('severity','') }}</span>
                    <strong>{{ h.get('title','') }}</strong>
                  </div>
                  <div class="right">
                    <span>Case: <span class="mono">{{ c.correlation_id }}</span></span>
                    <span>Time: <span class="mono">{{ h.get('timestamp','') }}</span></span>
                    <span>Score: <span class="mono">{{ cr.get('case_score', 0) }}</span></span>
                    <span>Threat: <span class="badge {{ cr.get('case_threat_level','low') }}">{{ cr.get('case_threat_level','low') }}</span></span>
                  </div>
                </div>
              </div>

              {% if c.get('story') %}
                {% set risk_level = ((c.get('header', {}).get('details', {}).get('case_risk', {}) or {}).get('level', 'low'))|lower %}

                {% if risk_level == 'critical' %}
                  {% set border_color = '#dc2626' %}
                {% elif risk_level == 'high' %}
                  {% set border_color = '#ea580c' %}
                {% elif risk_level == 'medium' %}
                  {% set border_color = '#ca8a04' %}
                {% else %}
                  {% set border_color = '#2563eb' %}
                {% endif %}

                <div class="card" style="
                  margin-top:12px;
                  padding:14px;
                  border-left: 6px solid {{ border_color }};
                  background: rgba(255,255,255,0.02);
                ">
                  <div style="display:flex; justify-content:space-between; align-items:center;">
                    <div style="font-weight:900; font-size:1.05rem;">
                      Investigation Story
                    </div>
                    <div class="badge">{{ risk_level|upper }}</div>
                  </div>

                  <div class="muted" style="margin-top:10px; line-height:1.7; font-size:0.95rem;">
                    {{ c.get('story') }}
                  </div>
                </div>
              {% endif %}

              <div class="card-body">
                {# --- Attack Chain --- #}
                {% set chain = c.get('attack_chain', {}) %}
                {% set tactics = chain.get('tactics', []) %}
                {% if tactics and tactics|length > 0 %}
                  <div style="margin-top:10px;">
                    <div class="muted" style="font-weight:900;">Attack Chain</div>

                    <div class="chain">
                      {% for t in tactics %}
                        <span class="node">{{ t }}</span>
                        {% if not loop.last %}<span class="arrow">-></span>{% endif %}
                      {% endfor %}
                    </div>

                    <details>
                      <summary>Why these stages?</summary>
                      <table>
                        <thead>
                          <tr>
                            <th>Tactic</th>
                            <th>First Seen</th>
                            <th>Description</th>
                            <th>Evidence</th>
                          </tr>
                        </thead>
                        <tbody>
                          {% for t in tactics %}
                            {% set bt = (chain.get('by_tactic', {}) or {}).get(t, {}) %}
                            <tr>
                              <td class="muted"><strong>{{ t }}</strong></td>
                              <td class="mono muted">{{ bt.get('first_seen', '') }}</td>
                              <td class="muted">{{ bt.get('description', '') }}</td>
                              <td>
                                {% set events = bt.get('events', []) %}
                                {% if events and events|length > 0 %}
                                  <ul style="margin:0; padding-left:18px;">
                                    {% for e in events %}
                                      <li class="muted">
                                        <span class="mono">{{ e.get('timestamp', '') }}</span> -
                                        <span class="mono">{{ e.get('rule_id', '') }}</span> -
                                        {{ e.get('title', '') }}
                                      </li>
                                    {% endfor %}
                                  </ul>
                                {% else %}
                                  <span class="muted">No evidence rows</span>
                                {% endif %}
                              </td>
                            </tr>
                          {% endfor %}
                        </tbody>
                      </table>
                    </details>
                  </div>
                {% endif %}
                {% if c.attack_flow %}
                  <div class="case-section">
                    <h3>Attack Flow</h3>
                    <div class="attack-flow">
                      {% for step in c.attack_flow %}
                        <div class="flow-step">
                          <div class="flow-label">{{ step.label }}</div>

                          {% if step.mitre_ids %}
                            <div class="flow-mitre">
                              {% for mid in step.mitre_ids %}
                                <span class="mitre-tag mono">{{ mid }}</span>
                              {% endfor %}
                            </div>
                          {% endif %}

                          <div class="flow-meta">
                            <span class="badge {{ step.severity }}">{{ step.severity }}</span>
                            <span class="mono">{{ step.timestamp }}</span>
                          </div>
                        </div>

                        {% if not loop.last %}
                          <div class="flow-arrow">-></div>
                        {% endif %}
                      {% endfor %}
                    </div>
                  </div>
                {% endif %}

                {% if mitre_coverage and mitre_coverage|length > 0 %}
                  <div class="mitre-panel">
                    <div style="font-weight:900; font-size:18px;">MITRE Coverage</div>
                    <div class="muted" style="margin-top:4px;">
                      Tactic distribution across matched detections in this investigation.
                    </div>

                    {% set max_count = mitre_coverage[0][1] %}

                    {% for tactic, count in mitre_coverage %}
                      {% set width_pct = (count * 100 / max_count)|int %}
                      <div class="mitre-row">
                        <div class="mitre-label">{{ tactic }}</div>
                        <div class="mitre-bar-wrap">
                          <div class="mitre-bar" style="width: {{ width_pct }}%;"></div>
                        </div>
                        <div class="mitre-count">{{ count }}</div>
                      </div>
                    {% endfor %}
                  </div>
                {% endif %}


                {% set path = (h.get('details', {}) or {}).get('attack_path', []) %}

                {% if path and path|length > 0 %}
                  <div class="panel">
                    <div style="font-weight:900; font-size:18px;">Attack Graph</div>
                    <div class="muted" style="margin-top:4px;">
                      Relationship path between source, identity, host, and attacker actions.
                    </div>

                    <div class="investigation-graph">
                      {% for node in path %}
                        <div class="graph-node {{ node['type'] }}">
                          <div class="graph-node-kind">{{ node.type|upper }}</div>
                          <div class="graph-node-value">{{ node.label }}</div>
                        </div>
                        {% if not loop.last %}
                          <div class="graph-arrow">v</div>
                        {% endif %}
                      {% endfor %}
                    </div>
                  </div>
                {% endif %}



                {# Phase 5: Analyst Summary #}
                {% set analyst_summary = (h.get('details', {}) or {}).get('analyst_summary', '') %}
                {% if analyst_summary %}
                  <div style="margin-bottom:10px;">
                    <div class="muted" style="font-weight:900;">Analyst Summary</div>
                    <div style="margin-top:6px;">{{ analyst_summary }}</div>
                  </div>
                {% endif %}

                {% set case_quality = (h.get('details', {}) or {}).get('case_quality', {}) %}
                {% if case_quality %}
                  <div class="case-section" style="margin-top:12px;">
                    <h3>Case Quality Brief</h3>
                    {% if case_quality.get('executive_summary') %}
                      <div style="margin-top:6px; line-height:1.65;">{{ case_quality.get('executive_summary') }}</div>
                    {% endif %}
                    <div class="case-meta">
                      <span class="badge">Quality {{ case_quality.get('quality_score', 0) }}/100</span>
                    </div>

                    {% if case_quality.get('key_findings') %}
                      <div style="margin-top:10px; font-weight:900;">Key Findings</div>
                      <ul style="margin-top:6px;">
                        {% for finding in case_quality.get('key_findings', []) %}
                          <li class="muted">{{ finding }}</li>
                        {% endfor %}
                      </ul>
                    {% endif %}

                    {% if case_quality.get('containment_guidance') %}
                      <div style="margin-top:10px; font-weight:900;">Containment Guidance</div>
                      <ul style="margin-top:6px;">
                        {% for action in case_quality.get('containment_guidance', []) %}
                          <li class="muted">{{ action }}</li>
                        {% endfor %}
                      </ul>
                    {% endif %}

                    {% if case_quality.get('quality_gaps') %}
                      <details>
                        <summary>Case quality gaps</summary>
                        <ul>
                          {% for gap in case_quality.get('quality_gaps', []) %}
                            <li class="muted">{{ gap }}</li>
                          {% endfor %}
                        </ul>
                      </details>
                    {% endif %}
                  </div>
                {% endif %}

                {# Phase 5: IOCs #}
                {% set iocs = (h.get('details', {}) or {}).get('iocs', {}) %}
                <div style="margin-top:10px;">
                  <div class="muted" style="font-weight:900;">Indicators (IOCs)</div>
                  <table>
                    <thead><tr><th>Type</th><th>Values</th></tr></thead>
                    <tbody>
                      <tr>
                        <td class="muted">IPs</td>
                        <td class="mono muted">
                          {% set ips = iocs.get('ips', []) %}
                          {% if ips and ips|length > 0 %}{{ ips|join(', ') }}{% else %}None observed{% endif %}
                        </td>
                      </tr>
                      <tr>
                        <td class="muted">Hosts</td>
                        <td class="mono muted">
                          {% set hosts = iocs.get('hosts', []) %}
                          {% if hosts and hosts|length > 0 %}{{ hosts|join(', ') }}{% else %}None observed{% endif %}
                        </td>
                      </tr>
                      <tr>
                        <td class="muted">Users</td>
                        <td class="mono muted">
                          {% set users = iocs.get('users', []) %}
                          {% if users and users|length > 0 %}{{ users|join(', ') }}{% else %}None observed{% endif %}
                        </td>
                      </tr>
                    </tbody>
                  </table>
                </div>

                {# Phase 5: Timeline #}
                {% set timeline = (h.get('details', {}) or {}).get('timeline', []) %}
                {% if timeline and timeline|length > 0 %}
                  <details>
                    <summary>Timeline ({{ timeline|length }} events)</summary>
                    <table>
                      <thead><tr><th>Timestamp</th><th>Rule</th><th>Title</th><th>Severity</th></tr></thead>
                      <tbody>
                        {% for t in timeline %}
                          <tr>
                            <td class="mono muted">{{ t.get('timestamp','') }}</td>
                            <td class="mono muted">{{ t.get('rule_id','') }}</td>
                            <td>{{ t.get('title','') }}</td>
                            <td><span class="badge {{ t.get('severity','')|lower }}">{{ t.get('severity','') }}</span></td>
                          </tr>
                        {% endfor %}
                      </tbody>
                    </table>
                  </details>
                {% endif %}

                {# Existing: Evidence #}
                {% if c.evidence %}
                  <div class="case-section">
                    <h3>Evidence</h3>
                    <div class="evidence-list">
                      {% for ev in c.evidence %}
                        <div class="evidence-item">
                          <div class="evidence-head">
                            <span class="mono">{{ ev.timestamp }}</span>
                            <span class="badge {{ ev.severity|lower }}">{{ ev.severity }}</span>
                            <strong>{{ ev.rule_id }}</strong>
                            <span>{{ ev.title }}</span>
                          </div>

                          {% if ev.fields %}
                            <div class="evidence-fields">
                              {% for label, value in ev.fields %}
                                <span class="kv">
                                  <span class="k">{{ label }}</span>
                                  <span class="v mono">{{ value }}</span>
                                </span>
                              {% endfor %}
                            </div>
                          {% endif %}
                        </div>
                      {% endfor %}
                    </div>
                  </div>
                {% endif %}

                {# Per-case scoring reasons (moved INSIDE loop so no undefined vars) #}
                {% if cr and cr.get('reasons') %}
                  <details>
                    <summary>Case scoring reasons</summary>
                    <ul>
                      {% for r in cr.get('reasons') %}
                        <li class="muted">{{ r }}</li>
                      {% endfor %}
                    </ul>
                  </details>
                {% endif %}

                <div class="muted" style="margin-top:10px;font-weight:900;">Alerts in this case</div>
                <table>
                  <thead>
                    <tr><th>Time</th><th>Severity</th><th>Rule</th><th>Title</th><th>Score</th></tr>
                  </thead>
                  <tbody>
                    {% for a in c.alerts %}
                      <tr data-sev="{{ a.get('severity','')|lower }}">
                        <td class="mono muted">{{ a.get('timestamp','') }}</td>
                        <td><span class="badge {{ a.get('severity','')|lower }}">{{ a.get('severity','') }}</span></td>
                        <td class="mono muted">{{ a.get('rule_id','') }}</td>
                        <td>{{ a.get('title','') }}</td>
                        <td class="mono muted"><strong>{{ a.get('score',0) }}</strong></td>
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

    {% if standalone and standalone|length > 0 %}
      <div class="card standalone-card">
        <div class="card-head">
          <div class="h">
            <div class="left"><strong>Standalone Alerts</strong></div>
            <div class="right"><span class="muted">No correlation_id</span></div>
          </div>
        </div>
        <div class="card-body">
          <table>
            <thead>
              <tr><th>Time</th><th>Severity</th><th>Rule</th><th>Title</th><th>Score</th></tr>
            </thead>
            <tbody>
              {% for a in standalone %}
                <tr data-sev="{{ a.get('severity','')|lower }}">
                  <td class="mono muted">{{ a.get('timestamp','') }}</td>
                  <td><span class="badge {{ a.get('severity','')|lower }}">{{ a.get('severity','') }}</span></td>
                  <td class="mono muted">{{ a.get('rule_id','') }}</td>
                  <td>{{ a.get('title','') }}</td>
                  <td class="mono muted"><strong>{{ a.get('score',0) }}</strong></td>
                </tr>
              {% endfor %}
            </tbody>
          </table>
        </div>
      </div>
    {% endif %}

  {% endif %}

  <details class="appendix">
    <summary>Appendix: metrics, MITRE coverage, correlations, and hunt findings</summary>
    <div class="appendix-note">Supporting detail is still available here without crowding the incident narrative.</div>

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

  <div class="card">
    <div class="card-head">
      <div class="h">
        <div class="left"><strong>MITRE Coverage</strong></div>
      </div>
    </div>
    <div class="card-body">
      {% if mitre_coverage and mitre_coverage|length > 0 %}
        <table>
          <thead>
            <tr><th>Tactic</th><th>Rule Count</th></tr>
          </thead>
          <tbody>
            {% for tactic, count in mitre_coverage %}
              <tr><td>{{ tactic }}</td><td>{{ count }}</td></tr>
            {% endfor %}
          </tbody>
        </table>
      {% else %}
        <p class="muted">No MITRE tactics found in loaded rules.</p>
      {% endif %}
    </div>
  </div>

  <div class="card">
    <div class="card-head">
      <div class="h">
        <div class="left"><strong>Risk Overview</strong></div>
      </div>
    </div>
    <div class="card-body">
      <div style="font-size:1.25rem; font-weight:900;">
        {{ risk_summary.level|upper }} ({{ risk_summary.overall_score }})
      </div>
      <div class="muted" style="margin-top:6px;">
        Alerts: {{ risk_summary.alerts }} |
        Hunts: {{ risk_summary.hunts }} |
        Correlations: {{ risk_summary.correlations }}
      </div>
    </div>
  </div>

  <div class="card">
    <div class="card-head">
      <div class="h">
        <div class="left"><strong>Correlation Summary</strong></div>
      </div>
    </div>
    <div class="card-body">
      {% if corr_summary.total > 0 %}
        <p><strong>Correlated alerts:</strong> {{ corr_summary.total }}</p>
        <table>
          <thead>
            <tr><th>Correlation Rule</th><th>Count</th></tr>
          </thead>
          <tbody>
            {% for rid, count in corr_summary.by_rule %}
              <tr><td class="mono muted">{{ rid }}</td><td>{{ count }}</td></tr>
            {% endfor %}
          </tbody>
        </table>
      {% else %}
        <p class="muted">No correlated alerts in this run.</p>
      {% endif %}
    </div>
  </div>

  <div class="card">
    <div class="card-head">
      <div class="h">
        <div class="left"><strong>Threat Hunting Findings</strong></div>
      </div>
    </div>
    <div class="card-body">
      <div class="muted" style="margin-bottom:10px;">
        Hunt count: {{ hunt_findings|length }}
      </div>

      {% if hunt_findings and hunt_findings|length > 0 %}
        {% for h in hunt_findings %}
          <div class="card" style="margin-top:12px; border-left: 6px solid #7c3aed; padding:12px;">
            <div style="font-weight:900; font-size:1.05rem;">{{ h.title }}</div>
            <div class="muted" style="margin-top:4px;">{{ h.summary }}</div>

            <div style="margin-top:8px;">
              <span class="hunt-badge">{{ h.hunt_id }}</span>
              <span class="hunt-badge">{{ h.severity|upper }}</span>
              <span class="hunt-badge">{{ h.category }}</span>
              <span class="hunt-badge">confidence: {{ h.confidence }}</span>
            </div>

            {% if h.entities %}
              <table style="margin-top:10px;">
                <thead>
                  <tr>
                    <th>Entity</th>
                    <th>Value</th>
                  </tr>
                </thead>
                <tbody>
                  {% for key, value in h.entities.items() %}
                    <tr>
                      <td>{{ key }}</td>
                      <td>
                        {% if value is iterable and value is not string and value is not mapping %}
                          {{ value|join(', ') }}
                        {% else %}
                          {{ value }}
                        {% endif %}
                      </td>
                    </tr>
                  {% endfor %}
                </tbody>
              </table>
            {% endif %}
          </div>
        {% endfor %}
      {% else %}
        <p class="muted">No threat hunting findings.</p>
      {% endif %}
    </div>
  </div>
  </details>

  <div class="footer">SOC-Forge &middot; Incident report view</div>

</div>

<script>
  function setFilter(level) {
    document.querySelectorAll(".btn").forEach(b => b.classList.remove("active"));
    const btn = document.querySelector(`.btn[data-level="${level}"]`);
    if (btn) btn.classList.add("active");

    // Filter rows
    document.querySelectorAll("tr[data-sev]").forEach(tr => {
      const sev = (tr.getAttribute("data-sev") || "").toLowerCase();
      const show = (level === "all" || sev === level);
      tr.classList.toggle("hidden", !show);
    });

    // Show/hide case cards based on visible rows
    document.querySelectorAll(".case-card").forEach(card => {
      if (level === "all") {
        card.classList.remove("hidden");
        return;
      }
      const visibleRows = card.querySelectorAll("tr[data-sev]:not(.hidden)");
      card.classList.toggle("hidden", visibleRows.length === 0);
    });

    // Same for standalone card
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

def build_cases(alerts: List[Dict[str, Any]], input_name: str) -> List[Dict[str, Any]]:
    from soc_forge.cases.builder import build_cases as _build_cases

    return _build_cases(alerts, input_name)
def write_html_report(
    alerts: List[Dict[str, Any]],
    output_path: Path,
    input_name: str,
    mitre_coverage: List[Tuple[str, int]] | None = None,
    corr_summary: Dict[str, Any] | None = None,
    reconstructions: List[Dict[str, Any]] | None = None,
    hunt_findings=None,
    risk_summary=None,
    cases=None,
) -> None:

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

    # -------------------------
    # Group standalone alerts
    # -------------------------
    standalone: List[Dict[str, Any]] = []
    for a in alerts_sorted:
        cid = a.get("correlation_id")
        if not cid:
            standalone.append(a)

    cases = cases or []

    recon_by_case = {
      r.get("case_id"): r
      for r in (reconstructions or [])
      if r.get("case_id")
    }

    html = HTML_TEMPLATE.render(
        cases=cases,
        standalone=standalone,
        stats=stats,
        input_name=input_name,
        mitre_coverage=mitre_coverage or [],
        corr_summary=corr_summary or {"total": 0, "by_rule": []},
        reconstructions=reconstructions or [],
        recon_by_case=recon_by_case,
        hunt_findings=hunt_findings or [],
        risk_summary=risk_summary or{
            "overall_score": 0,
            "level": "low",
            "alerts": 0,
            "hunts": 0,
            "correlations": 0,
        },
        version=__version__,
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
    )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html, encoding="utf-8")
