from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Tuple

from jinja2 import Template

from soc_forge import __version__
from soc_forge.scoring.risk import score_case


# -------------------------
# Phase 5 helpers
# -------------------------
def _safe_str(x: Any) -> str:
    if x is None:
        return ""
    return str(x).strip()


def _get_details(a: Dict[str, Any]) -> Dict[str, Any]:
    d = a.get("details")
    return d if isinstance(d, dict) else {}


def build_case_timeline(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Timeline is oldest -> newest.
    """
    rows: List[Dict[str, Any]] = []
    for a in items:
        rows.append(
            {
                "timestamp": _safe_str(a.get("timestamp")),
                "rule_id": _safe_str(a.get("rule_id")),
                "title": _safe_str(a.get("title")),
                "severity": _safe_str(a.get("severity")).lower(),
                "score": a.get("score", 0),
            }
        )

    # Sort by timestamp asc; blanks go last
    rows.sort(key=lambda r: (r.get("timestamp") == "", r.get("timestamp", "")))
    return rows


def extract_case_iocs(items: List[Dict[str, Any]]) -> Dict[str, List[str]]:
    ips, users, hosts = set(), set(), set()

    for a in items:
        d = _get_details(a)
        ip = _safe_str(d.get("ip"))
        user = _safe_str(d.get("username"))
        host = _safe_str(d.get("host"))

        if ip:
            ips.add(ip)
        if user:
            users.add(user)
        if host:
            hosts.add(host)

    return {"ips": sorted(ips), "hosts": sorted(hosts), "users": sorted(users)}


def build_analyst_summary(items: List[Dict[str, Any]]) -> str:
    """
    Deterministic SOC-style narrative based on what is present in the case.
    """
    rule_ids = {_safe_str(a.get("rule_id")) for a in items if _safe_str(a.get("rule_id"))}
    titles = " ".join(_safe_str(a.get("title")).lower() for a in items)

    has_rdp = "SOCF-006" in rule_ids or ("rdp" in titles and "logon" in titles)
    has_schtask = "SOCF-005" in rule_ids or ("scheduled task" in titles)
    has_new_admin = "SOCF-003" in rule_ids or ("new admin" in titles) or ("administrators" in titles and "added" in titles)
    has_lockout = "SOCF-002" in rule_ids or ("lockout" in titles)
    has_bruteforce = "SOCF-001" in rule_ids or ("brute" in titles and "force" in titles)
    has_corr = any(rid.startswith("SOCF-CORR") for rid in rule_ids)

    iocs = extract_case_iocs(items)
    ctx_bits = []
    if iocs["users"]:
        ctx_bits.append(f"user {iocs['users'][0]}")
    if iocs["hosts"]:
        ctx_bits.append(f"host {iocs['hosts'][0]}")
    if iocs["ips"]:
        ctx_bits.append(f"ip {iocs['ips'][0]}")

    ctx = f" (e.g., {', '.join(ctx_bits[:3])})" if ctx_bits else ""
    corr_note = " A correlation rule fired, increasing confidence that these events are related." if has_corr else ""

    if has_rdp and has_schtask:
        base = (
            "This case shows RDP interactive access followed by scheduled task activity, "
            "which is consistent with post-compromise persistence and operator automation."
        )
        next_steps = (
            "Validate whether the task is authorized, confirm the source of the RDP session, "
            "and review endpoint telemetry around the first RDP logon time."
        )
    elif has_rdp and has_new_admin:
        base = (
            "This case shows RDP access combined with administrative account or group changes, "
            "which suggests potential privilege escalation or account takeover."
        )
        next_steps = (
            "Confirm who initiated the admin change, review authentication context for the RDP logon, "
            "and hunt for additional persistence mechanisms."
        )
    elif has_bruteforce and has_lockout:
        base = (
            "This case indicates repeated authentication failures followed by account lockout, "
            "consistent with an active credential attack."
        )
        next_steps = (
            "Identify targeted accounts, block or rate-limit offending sources, "
            "and review password reset and MFA coverage for impacted users."
        )
    elif has_schtask:
        base = "This case includes scheduled task creation, which can indicate persistence or automation."
        next_steps = "Confirm task legitimacy, inspect task command/arguments on the endpoint, and correlate with prior logons."
    elif has_rdp:
        base = "This case includes RDP logon activity that may indicate lateral movement or remote access."
        next_steps = "Validate source IP and user, confirm business justification, and correlate with endpoint process execution."
    else:
        base = "This case contains multiple related alerts that warrant review and correlation."
        next_steps = "Review the timeline progression, validate user/host context, and pivot to endpoint telemetry for confirmation."

    return f"{base}{corr_note}{ctx} {next_steps}"

# -------------------------
# Phase 6: Attack Chain helpers
# -------------------------

TACTIC_ORDER = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]

# Keywords -> tactic (fallback if alerts don't carry MITRE tags)
TACTIC_KEYWORDS = [
    ("rdp", "Lateral Movement"),
    ("remote desktop", "Lateral Movement"),
    ("logon type 10", "Lateral Movement"),
    ("scheduled task", "Persistence"),
    ("new service", "Persistence"),
    ("service installed", "Persistence"),
    ("new admin", "Privilege Escalation"),
    ("administrators", "Privilege Escalation"),
    ("brute", "Credential Access"),
    ("password spray", "Credential Access"),
    ("lockout", "Credential Access"),
]

def _extract_tactics_from_alert(a: Dict[str, Any]) -> List[str]:
    """
    Try to extract MITRE tactics from alert fields.
    Supports a few shapes, then falls back to keyword inference from title.
    """
    tactics: List[str] = []

    # 1) If you have `a["mitre"]` as list of strings (tactics or techniques)
    m = a.get("mitre")
    if isinstance(m, list):
        for x in m:
            s = _safe_str(x)
            # If it's already one of our tactic names, use it
            if s in TACTIC_ORDER:
                tactics.append(s)

    # 2) Some rules store mitre metadata in details (optional)
    d = _get_details(a)
    dm = d.get("mitre")
    if isinstance(dm, list):
        for x in dm:
            s = _safe_str(x)
            if s in TACTIC_ORDER:
                tactics.append(s)

    # 3) Fallback: infer from title text
    if not tactics:
        title = _safe_str(a.get("title")).lower()
        for kw, tact in TACTIC_KEYWORDS:
            if kw in title:
                tactics.append(tact)

    # Dedup while preserving order
    out: List[str] = []
    seen = set()
    for t in tactics:
        if t not in seen:
            seen.add(t)
            out.append(t)
    return out


def build_attack_chain(items: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Build an ordered list of tactics (attack chain) + per-tactic contributing rules.
    Ordering logic:
      - determine first-seen timestamp for each tactic in the case
      - sort by first-seen time, then by MITRE tactic order
    """
    first_seen: Dict[str, str] = {}
    contrib: Dict[str, List[Dict[str, str]]] = {}  # tactic -> [{"rule_id":..., "title":..., "timestamp":...}]

    for a in items:
        ts = _safe_str(a.get("timestamp"))
        rid = _safe_str(a.get("rule_id"))
        title = _safe_str(a.get("title"))
        for tact in _extract_tactics_from_alert(a):
            if tact not in first_seen or (ts and ts < first_seen[tact]):
                first_seen[tact] = ts or first_seen.get(tact, "")
            contrib.setdefault(tact, []).append({"rule_id": rid, "title": title, "timestamp": ts})

    # Nothing found
    if not first_seen:
        return {"tactics": [], "by_tactic": {}}

    def tactic_rank(t: str) -> int:
        try:
            return TACTIC_ORDER.index(t)
        except ValueError:
            return 999

    # Sort tactics by first-seen timestamp, then by MITRE order for stability
    tactics_sorted = sorted(first_seen.keys(), key=lambda t: (first_seen.get(t, "") == "", first_seen.get(t, ""), tactic_rank(t)))

    # Dedup contrib rows per tactic (rule_id, timestamp)
    by_tactic: Dict[str, Any] = {}
    for t in tactics_sorted:
        seen = set()
        rows = []
        for r in contrib.get(t, []):
            key = (r.get("rule_id", ""), r.get("timestamp", ""))
            if key in seen:
                continue
            seen.add(key)
            rows.append(r)
        # sort rows oldest->newest
        rows.sort(key=lambda x: (x.get("timestamp", "") == "", x.get("timestamp", "")))
        by_tactic[t] = {"first_seen": first_seen.get(t, ""), "events": rows}

    return {"tactics": tactics_sorted, "by_tactic": by_tactic}


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
{% set h = {} %}

  <div class="header">
    <div>
      <div class="title">SOC-Forge Report</div>
      <div class="meta">
        Input: <span class="mono">{{ input_name }}</span> • Generated: {{ generated_at }} • Version: {{ version }}
      </div>
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
            <div class="left"><strong>Cases</strong></div>
            <div class="right"><span class="muted">Grouped by correlation_id</span></div>
          </div>
        </div>
        <div class="card-body">

          {% for c in cases %}
            {% set h = c.header %}
            {% set cr = (h.get('details', {}) or {}).get('case_risk', {}) %}

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
                    <span>Score: <span class="mono">{{ h.get('score',0) }}</span></span>
                    <span>Case Score: <span class="mono">{{ cr.get('case_score', 0) }}</span></span>
                    <span>Threat: <span class="badge {{ cr.get('case_threat_level','low') }}">{{ cr.get('case_threat_level','low') }}</span></span>
                  </div>
                </div>
              </div>

              <div class="card-body">
                {# --- Phase 6: Attack Chain --- #}
                {% set chain = (h.get('details', {}) or {}).get('attack_chain', {}) %}
                {% set tactics = chain.get('tactics', []) %}
                {% if tactics and tactics|length > 0 %}
                  <div style="margin-top:10px;">
                    <div class="muted" style="font-weight:900;">Attack Chain</div>

                    <div class="chain">
                      {% for t in tactics %}
                        <span class="node">{{ t }}</span>
                      {% if not loop.last %}<span class="arrow">→</span>{% endif %}
                      {% endfor %}
                    </div>

                    <details>
                      <summary>Why these stages?</summary>
                      <table>
                        <thead><tr><th>Tactic</th><th>First Seen</th><th>Evidence</th></tr></thead>
                        <tbody>
                          {% for t in tactics %}
                            {% set bt = (chain.get('by_tactic', {}) or {}).get(t, {}) %}
                            <tr>
                              <td class="muted"><strong>{{ t }}</strong></td>
                              <td class="mono muted">{{ bt.get('first_seen','') }}</td>
                              <td>
                                {% set events = bt.get('events', []) %}
                                {% if events and events|length > 0 %}
                                  <ul style="margin:0; padding-left:18px;">
                                    {% for e in events %}
                                      <li class="muted">
                                        <span class="mono">{{ e.get('timestamp','') }}</span> —
                                        <span class="mono">{{ e.get('rule_id','') }}</span> —
                                        {{ e.get('title','') }}
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

                {# Phase 5: Analyst Summary #}
                {% set analyst_summary = (h.get('details', {}) or {}).get('analyst_summary', '') %}
                {% if analyst_summary %}
                  <div style="margin-bottom:10px;">
                    <div class="muted" style="font-weight:900;">Analyst Summary</div>
                    <div style="margin-top:6px;">{{ analyst_summary }}</div>
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
                {% set evidence = (h.get('details', {}) or {}).get('evidence', []) %}
                {% if evidence and evidence|length > 0 %}
                  <details>
                    <summary>Evidence (click to expand)</summary>
                    <table>
                      <thead><tr><th>Rule</th><th>Timestamp</th></tr></thead>
                      <tbody>
                        {% for ev in evidence %}
                          <tr>
                            <td class="mono muted">{{ ev.get('rule_id','') }}</td>
                            <td class="mono muted">{{ ev.get('timestamp','') }}</td>
                          </tr>
                        {% endfor %}
                      </tbody>
                    </table>
                  </details>
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

  <div class="footer">SOC-Forge • Case-based report view</div>

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


def write_html_report(
    alerts: List[Dict[str, Any]],
    output_path: Path,
    input_name: str,
    mitre_coverage: List[Tuple[str, int]] | None = None,
    corr_summary: Dict[str, Any] | None = None,
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
    # Group into cases + standalone
    # -------------------------
    cases_map: Dict[str, List[Dict[str, Any]]] = {}
    standalone: List[Dict[str, Any]] = []

    for a in alerts_sorted:
        cid = a.get("correlation_id")
        if cid:
            cases_map.setdefault(str(cid), []).append(a)
        else:
            standalone.append(a)

    # -------------------------
    # Build cases (dedup + risk scoring + Phase 5 enrich)
    # -------------------------
    cases: List[Dict[str, Any]] = []

    for cid, items in cases_map.items():
        seen = set()
        dedup: List[Dict[str, Any]] = []
        for a in items:
            key = (a.get("rule_id"), a.get("timestamp"))
            if key in seen:
                continue
            seen.add(key)
            dedup.append(a)

        # Keep case alerts newest-first for the alerts table
        items_sorted = sorted(dedup, key=lambda x: x.get("timestamp", ""), reverse=True)

        header = next(
            (x for x in items_sorted if str(x.get("rule_id", "")).startswith("SOCF-CORR")),
            items_sorted[0],
        )

        case_risk = score_case(items_sorted)

        header = dict(header)
        header.setdefault("details", {})
        header["details"]["case_risk"] = case_risk

        # -------------------------
        # Phase 5 additions
        # -------------------------
        header["details"]["timeline"] = build_case_timeline(items_sorted)
        header["details"]["iocs"] = extract_case_iocs(items_sorted)
        header["details"]["analyst_summary"] = build_analyst_summary(items_sorted)
        header["details"]["attack_chain"] = build_attack_chain(items_sorted)

        cases.append({"correlation_id": cid, "header": header, "alerts": items_sorted})

    cases = sorted(cases, key=lambda c: c["header"].get("timestamp", ""), reverse=True)

    html = HTML_TEMPLATE.render(
        cases=cases,
        standalone=standalone,
        stats=stats,
        input_name=input_name,
        mitre_coverage=mitre_coverage or [],
        corr_summary=corr_summary or {"total": 0, "by_rule": []},
        version=__version__,
        generated_at=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
    )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html, encoding="utf-8")