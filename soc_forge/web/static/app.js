const state = {
  workspace: null,
  activeCaseId: null,
  view: "overview",
  search: "",
  runningScenario: false,
  demo: { active: false, step: 0 },
};

const demoSteps = [
  { label: 'Generate', title: 'Generate Scenario', view: 'overview' },
  { label: 'Dashboard', title: 'Review Dashboard', view: 'overview' },
  { label: 'Case', title: 'Open Highest-Risk Case', view: 'cases' },
  { label: 'Graph', title: 'Review Entity Graph', view: 'graph' },
  { label: 'Scorecard', title: 'Review Detection Scorecard', view: 'scorecard' },
  { label: 'Report', title: 'Open Incident Report', view: 'overview', report: true },
];

const $ = (selector) => document.querySelector(selector);
const escapeHtml = (value) => String(value ?? "").replace(/[&<>'"]/g, (char) => ({"&":"&amp;","<":"&lt;",">":"&gt;","'":"&#39;",'"':"&quot;"}[char]));
const asArray = (value) => Array.isArray(value) ? value : [];

function severityClass(value) { return String(value || "low").toLowerCase(); }
function caseRisk(caseItem) { return Number(caseItem.risk_score || caseItem.risk || 0); }
function qualityScore(caseItem) { return Number((caseItem.case_quality || {}).quality_score || 0); }
function matchesSearch(item) { return JSON.stringify(item).toLowerCase().includes(state.search.toLowerCase()); }

async function loadWorkspace() {
  const response = await fetch('/api/workspace');
  if (!response.ok) throw new Error('Unable to load workspace');
  state.workspace = await response.json();
  if (!state.activeCaseId && state.workspace.cases.length) state.activeCaseId = state.workspace.cases[0].case_id;
  render();
}

async function runScenario() {
  const scenario = $('#scenarioSelect').value;
  state.runningScenario = true;
  renderScenarioButton();
  try {
    const response = await fetch('/api/scenario', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ scenario }),
    });
    const contentType = response.headers.get('content-type') || '';
    const payload = contentType.includes('application/json') ? await response.json() : { error: await response.text() };
    if (!response.ok) {
      const message = payload.error || 'Unable to run demo scenario';
      if (message.includes('<!DOCTYPE') || message.includes('<html')) {
        throw new Error('The web server needs to be restarted so the new demo switcher endpoint is available.');
      }
      throw new Error(message);
    }
    state.workspace = payload.workspace;
    state.activeCaseId = state.workspace.cases[0]?.case_id || null;
    render();
  } finally {
    state.runningScenario = false;
    renderScenarioButton();
  }
}

function renderScenarioButton() {
  const button = $('#runScenarioButton');
  const startButton = $('#startDemoButton');
  if (button) {
    button.disabled = state.runningScenario;
    button.textContent = state.runningScenario ? 'Running...' : 'Run Demo';
  }
  if (startButton) {
    startButton.disabled = state.runningScenario;
    startButton.textContent = state.runningScenario ? 'Running...' : 'Start Demo';
  }
}

function scenarioLabel() {
  const selected = $('#scenarioSelect')?.selectedOptions?.[0]?.textContent;
  return selected || state.workspace?.scenario_label || 'Demo';
}

function renderDemoGuide() {
  const guide = $('#demoGuide');
  if (!guide) return;
  guide.hidden = !state.demo.active;
  if (!state.demo.active) return;
  const activeStep = demoSteps[state.demo.step] || demoSteps[0];
  $('#demoGuideTitle').textContent = `${scenarioLabel()} | ${activeStep.title}`;
  $('#demoSteps').innerHTML = demoSteps.map((step, index) => {
    const status = index < state.demo.step ? 'done' : index === state.demo.step ? 'active' : '';
    return `
      <button class="demo-step ${status}" data-demo-step="${index}" type="button">
        <span class="demo-step-number mono">${index + 1}</span>
        <span>${escapeHtml(step.label)}</span>
      </button>`;
  }).join('');
  $('#nextDemoStepButton').textContent = state.demo.step >= demoSteps.length - 1 ? 'Open Report' : 'Next';
  document.querySelectorAll('.demo-step').forEach((button) => button.addEventListener('click', () => goToDemoStep(Number(button.dataset.demoStep))));
}

function highestRiskCaseId() {
  const cases = asArray(state.workspace?.cases);
  const topCase = [...cases].sort((a, b) => caseRisk(b) - caseRisk(a))[0];
  return topCase?.case_id || null;
}

function goToDemoStep(stepIndex) {
  state.demo.step = Math.max(0, Math.min(stepIndex, demoSteps.length - 1));
  const step = demoSteps[state.demo.step];
  if (step.view === 'cases' || step.view === 'graph') {
    state.activeCaseId = highestRiskCaseId() || state.activeCaseId;
  }
  setView(step.view);
  render();
}

async function startGuidedDemo() {
  state.demo.active = true;
  state.demo.step = 0;
  renderDemoGuide();
  await runScenario();
  goToDemoStep(1);
}

function advanceGuidedDemo() {
  if (!state.demo.active) return;
  if (state.demo.step >= demoSteps.length - 1) {
    window.open('/artifact?file=report.html', '_blank', 'noopener');
    state.demo.active = false;
    render();
    return;
  }
  goToDemoStep(state.demo.step + 1);
}

function setView(view) {
  state.view = view;
  document.querySelectorAll('.nav-tab').forEach((button) => button.classList.toggle('active', button.dataset.view === view));
  document.querySelectorAll('.view').forEach((section) => section.classList.remove('active'));
  $(`#${view}View`).classList.add('active');
}

function renderMetrics(summary) {
  const metrics = [
    ['Cases', summary.case_count],
    ['Alerts', summary.alert_count],
    ['Correlations', summary.correlated_alert_count],
    ['Hunts', summary.hunt_count],
    ['Avg Quality', `${summary.average_case_quality}/100`],
  ];
  $('#metrics').innerHTML = metrics.map(([label, value]) => `<div class="metric"><div class="metric-label">${label}</div><div class="metric-value">${value}</div></div>`).join('');
}

function renderBars(target, rows, labelKey) {
  const max = Math.max(1, ...rows.map((row) => Number(row.count || 0)));
  target.innerHTML = rows.length ? rows.map((row) => `
    <div class="bar-item">
      <div class="mono">${escapeHtml(row[labelKey])}</div>
      <div class="bar-track"><div class="bar-fill" style="width:${Math.max(6, Number(row.count || 0) * 100 / max)}%"></div></div>
      <div class="mono muted">${row.count}</div>
    </div>`).join('') : '<div class="muted">No data available.</div>';
}

function renderOverview() {
  const { summary, cases } = state.workspace;
  renderMetrics(summary);
  const top = cases.find((caseItem) => caseItem.case_id === summary.top_case_id) || cases[0];
  $('#topCase').innerHTML = top ? `
    <div class="case-brief">
      <div>
        <h3>${escapeHtml(top.title)}</h3>
        <div class="pill-row" style="margin-top:10px;">
          <span class="pill ${severityClass(top.severity)}">${escapeHtml(top.severity || 'case')}</span>
          <span class="pill">Risk ${caseRisk(top)}</span>
          <span class="pill">Quality ${qualityScore(top)}/100</span>
          <span class="pill mono">${escapeHtml(top.case_id)}</span>
        </div>
      </div>
      <p>${escapeHtml((top.case_quality || {}).executive_summary || top.summary || 'No summary available.')}</p>
    </div>` : '<div class="muted">No cases found. Generate SOC-Forge output first.</div>';
  renderBars($('#ruleCounts'), summary.rule_counts || [], 'rule_id');
  renderBars($('#tacticCounts'), summary.tactic_counts || [], 'tactic');
}

function sortedCases() {
  const sort = $('#caseSort')?.value || 'risk';
  let cases = asArray(state.workspace.cases).filter(matchesSearch);
  if (sort === 'quality') cases.sort((a, b) => qualityScore(b) - qualityScore(a));
  else if (sort === 'time') cases.sort((a, b) => String(b.created_at || '').localeCompare(String(a.created_at || '')));
  else cases.sort((a, b) => caseRisk(b) - caseRisk(a));
  return cases;
}

function renderEntityChips(caseItem) {
  const iocs = caseItem.iocs || {};
  const chips = [
    ...asArray(iocs.users).map((value) => ['User', value]),
    ...asArray(iocs.hosts).map((value) => ['Host', value]),
    ...asArray(iocs.ips).map((value) => ['IP', value]),
  ];
  return chips.length ? `<div class="entity-chips">${chips.map(([label, value]) => `<span class="entity-chip"><span>${label}</span>${escapeHtml(value)}</span>`).join('')}</div>` : '';
}

function renderInsightList(items, emptyText) {
  const rows = asArray(items);
  return rows.length ? `<div class="insight-list">${rows.map((item) => `<div class="insight-card">${escapeHtml(item)}</div>`).join('')}</div>` : `<div class="muted">${escapeHtml(emptyText)}</div>`;
}

function renderCaseStats(caseItem, quality) {
  const timelineCount = asArray(caseItem.timeline).length;
  const evidenceCount = asArray(quality.key_evidence).length || asArray(caseItem.evidence).length;
  const entityCount = asArray((caseItem.iocs || {}).users).length + asArray((caseItem.iocs || {}).hosts).length + asArray((caseItem.iocs || {}).ips).length;
  return `
    <div class="case-stat-grid">
      <div><span>Risk</span><strong>${caseRisk(caseItem)}</strong></div>
      <div><span>Quality</span><strong>${qualityScore(caseItem)}/100</strong></div>
      <div><span>Evidence</span><strong>${evidenceCount}</strong></div>
      <div><span>Timeline</span><strong>${timelineCount}</strong></div>
      <div><span>Entities</span><strong>${entityCount}</strong></div>
    </div>`;
}

function renderCases() {
  const cases = sortedCases();
  if (!cases.some((caseItem) => caseItem.case_id === state.activeCaseId) && cases.length) state.activeCaseId = cases[0].case_id;
  $('#caseList').innerHTML = cases.length ? cases.map((caseItem) => `
    <button class="case-row ${caseItem.case_id === state.activeCaseId ? 'active' : ''}" data-case-id="${escapeHtml(caseItem.case_id)}">
      <div class="case-title">${escapeHtml(caseItem.title)}</div>
      <div class="case-meta">
        <span class="pill ${severityClass(caseItem.severity)}">${escapeHtml(caseItem.severity)}</span>
        <span class="pill">Risk ${caseRisk(caseItem)}</span>
        <span class="pill">Quality ${qualityScore(caseItem)}/100</span>
        <span class="pill mono">${escapeHtml(caseItem.case_id)}</span>
      </div>
    </button>`).join('') : '<div class="empty-state">No matching cases.</div>';
  document.querySelectorAll('.case-row').forEach((button) => button.addEventListener('click', () => { state.activeCaseId = button.dataset.caseId; renderCases(); }));
  renderCaseDetail(cases.find((caseItem) => caseItem.case_id === state.activeCaseId));
}

function renderCaseDetail(caseItem) {
  if (!caseItem) {
    $('#caseDetail').innerHTML = '<div class="empty-state">Select a case to review.</div>';
    return;
  }
  const quality = caseItem.case_quality || {};
  const findings = renderInsightList(quality.key_findings, 'No key findings generated.');
  const guidance = renderInsightList(quality.containment_guidance || caseItem.containment_guidance, 'No containment guidance generated.');
  const evidence = asArray(quality.key_evidence).map((item) => `
    <div class="evidence-row">
      <div class="evidence-head">
        <span class="pill mono">${escapeHtml(item.rule_id)}</span>
        <span class="pill ${severityClass(item.severity)}">${escapeHtml(item.severity)}</span>
        <span class="mono muted">${escapeHtml(item.timestamp)}</span>
      </div>
      <strong>${escapeHtml(item.title)}</strong>
      <p>${escapeHtml(item.why_it_matters)}</p>
    </div>`).join('');
  const timeline = asArray(caseItem.timeline).map((item, index) => `
    <div class="timeline-item">
      <div class="timeline-index mono">${index + 1}</div>
      <div>
        <div class="timeline-head">
          <span class="mono muted">${escapeHtml(item.timestamp)}</span>
          <span class="pill ${severityClass(item.severity)}">${escapeHtml(item.severity)}</span>
          <span class="pill mono">${escapeHtml(item.rule_id)}</span>
        </div>
        <strong>${escapeHtml(item.title)}</strong>
      </div>
    </div>`).join('');
  $('#caseDetail').innerHTML = `
    <div class="case-brief">
      <div class="case-detail-hero">
        <div>
          <h2>${escapeHtml(caseItem.title)}</h2>
          <div class="pill-row" style="margin-top:10px;"><span class="pill mono">${escapeHtml(caseItem.case_id)}</span><span class="pill ${severityClass(caseItem.severity)}">${escapeHtml(caseItem.severity)}</span><span class="pill">${escapeHtml(caseItem.status || 'New')}</span></div>
        </div>
        ${renderEntityChips(caseItem)}
      </div>
      ${renderCaseStats(caseItem, quality)}
      <section class="brief-section"><h3>Executive Summary</h3><p class="summary-copy">${escapeHtml(quality.executive_summary || caseItem.summary || 'No executive summary available.')}</p></section>
      <section class="brief-grid">
        <div class="brief-section"><h3>Key Findings</h3>${findings}</div>
        <div class="brief-section"><h3>Containment Guidance</h3>${guidance}</div>
      </section>
      <section class="brief-section"><h3>Key Evidence</h3><div class="evidence-list">${evidence || '<div class="muted">No key evidence available.</div>'}</div></section>
      <section class="brief-section"><h3>Timeline</h3><div class="timeline-list">${timeline || '<div class="muted">No timeline available.</div>'}</div></section>
    </div>`;
}

function nodeTypeLabel(type) {
  return String(type || 'entity').replace(/_/g, ' ');
}

function relationshipLabel(value) {
  return String(value || 'related').replace(/_/g, ' ');
}

function graphNodeLabel(value) {
  const label = String(value || 'unknown');
  return label.length > 16 ? `${label.slice(0, 15)}...` : label;
}

function graphCase() {
  const selected = $('#graphCaseSelect')?.value || state.activeCaseId;
  return asArray(state.workspace.cases).find((caseItem) => caseItem.case_id === selected) || asArray(state.workspace.cases)[0];
}

function renderGraphCaseSelect() {
  const select = $('#graphCaseSelect');
  if (!select) return;
  const cases = asArray(state.workspace.cases);
  select.innerHTML = cases.map((caseItem) => `<option value="${escapeHtml(caseItem.case_id)}">${escapeHtml(caseItem.title)}</option>`).join('');
  if (cases.some((caseItem) => caseItem.case_id === state.activeCaseId)) select.value = state.activeCaseId;
}

function graphLayout(nodes) {
  const order = ['ip', 'user', 'host', 'scheduled_task', 'service', 'group'];
  const fallback = 'entity';
  const grouped = {};
  nodes.forEach((node) => {
    const type = order.includes(node.type) ? node.type : fallback;
    grouped[type] = grouped[type] || [];
    grouped[type].push(node);
  });
  const columns = order.filter((type) => grouped[type]?.length);
  if (grouped[fallback]?.length) columns.push(fallback);
  const positions = {};
  columns.forEach((type, columnIndex) => {
    const group = grouped[type];
    const x = columns.length === 1 ? 450 : 90 + columnIndex * (720 / Math.max(1, columns.length - 1));
    group.forEach((node, index) => {
      const y = group.length === 1 ? 170 : 80 + index * (220 / Math.max(1, group.length - 1));
      positions[node.id] = { x, y };
    });
  });
  return positions;
}

function renderGraph() {
  renderGraphCaseSelect();
  const caseItem = graphCase();
  if (!caseItem) {
    $('#graphWorkspace').innerHTML = '<div class="empty-state">No cases available for graph review.</div>';
    return;
  }
  const graph = caseItem.web_graph || {};
  const nodes = Object.values(graph.nodes || {});
  const edges = asArray(graph.edges);
  const summary = graph.summary || {};
  const primaryPath = asArray(graph.primary_path);
  const primaryPairs = new Set(primaryPath.slice(0, -1).map((node, index) => `${node}->${primaryPath[index + 1]}`));
  const positions = graphLayout(nodes);
  const edgeLines = edges.map((edge) => {
    const source = positions[edge.source];
    const target = positions[edge.target];
    if (!source || !target) return '';
    const midX = (source.x + target.x) / 2;
    const midY = (source.y + target.y) / 2;
    const primary = primaryPairs.has(`${edge.source}->${edge.target}`);
    const severity = severityClass(edge.severity);
    return `<g><line x1="${source.x}" y1="${source.y}" x2="${target.x}" y2="${target.y}" class="graph-edge graph-edge-${severity} ${primary ? 'graph-edge-primary' : ''}" /><text x="${midX}" y="${midY - 6}" class="graph-edge-label">${escapeHtml(relationshipLabel(edge.relationship))}</text></g>`;
  }).join('');
  const nodeMarks = nodes.map((node) => {
    const pos = positions[node.id] || { x: 450, y: 170 };
    const risk = Number(node.risk || 0);
    const safeType = String(node.type || 'entity').replace(/[^a-z0-9_-]/gi, '-').toLowerCase();
    const primary = primaryPath.includes(node.id);
    return `<g class="graph-node graph-node-${safeType} ${primary ? 'graph-node-primary' : ''}" transform="translate(${pos.x}, ${pos.y})">
      <circle r="30"></circle>
      <text y="-4" text-anchor="middle" class="graph-node-label">${escapeHtml(graphNodeLabel(node.id))}</text>
      <text y="13" text-anchor="middle" class="graph-node-type">${escapeHtml(nodeTypeLabel(node.type))} | risk ${risk}</text>
    </g>`;
  }).join('');
  const primaryPathMarkup = primaryPath.length ? `<div class="graph-path mono">${primaryPath.map((node) => `<span>${escapeHtml(node)}</span>`).join('<b>-></b>')}</div>` : '<div class="muted">No primary path available.</div>';
  const relationshipRows = edges.map((edge) => `
    <div class="relationship-row relationship-${severityClass(edge.severity)}">
      <div class="relationship-route"><span class="pill mono">${escapeHtml(edge.source)}</span> <span class="muted">-></span> <span class="pill mono">${escapeHtml(edge.target)}</span></div>
      <div class="relationship-title"><strong>${escapeHtml(relationshipLabel(edge.relationship))}</strong><span class="pill ${severityClass(edge.severity)}">${escapeHtml(edge.severity || 'medium')}</span><span class="pill">Confidence ${escapeHtml(edge.confidence ?? 0)}%</span></div>
      <p>${escapeHtml(edge.evidence || 'Case relationship evidence')}</p>
    </div>`).join('');
  const hasGraph = Boolean(((caseItem.web_graph || {}).summary || {}).total_nodes);
  $('#graphWorkspace').innerHTML = `
    <div class="graph-header">
      <div>
        <h3>${escapeHtml(caseItem.title)}</h3>
        <p>${hasGraph ? 'Primary path highlights the strongest entity chain SOC-Forge reconstructed from indicators, alerts, and timeline evidence.' : 'No graph data available for this case.'}</p>
      </div>
      <div class="graph-stat-row">
        <span class="pill">Entities ${summary.total_nodes || 0}</span>
        <span class="pill">Relationships ${summary.total_edges || 0}</span>
        <span class="pill">Timeline ${graph.timeline_count || 0}</span>
        <span class="pill">Alerts ${graph.alert_count || 0}</span>
      </div>
    </div>
    <div class="graph-path-panel">
      <div class="metric-label">Primary Investigation Path</div>
      ${primaryPathMarkup}
    </div>
    <div class="graph-layout">
      <svg class="graph-canvas" viewBox="0 0 900 340" role="img" aria-label="Investigation entity relationship graph">
        ${edgeLines}
        ${nodeMarks}
      </svg>
      <div class="relationship-list">
        <h3>Relationship Evidence</h3>
        ${relationshipRows || '<div class="muted">No relationships found for this case.</div>'}
      </div>
    </div>`;
}

function renderScorecard() {
  const scorecard = state.workspace.detection_scorecard || {};
  const categories = asArray(scorecard.categories);
  const severityRows = asArray(scorecard.severity_balance);
  const tactics = asArray((scorecard.coverage || {}).tactics);
  $('#scorecardWorkspace').innerHTML = `
    <div class="scorecard-hero">
      <div>
        <div class="metric-label">Overall Detection Program Score</div>
        <div class="scorecard-grade">${escapeHtml(scorecard.grade || 'N/A')}</div>
      </div>
      <div class="scorecard-score mono">${escapeHtml(scorecard.overall_score ?? 0)}/100</div>
      <div class="scorecard-facts">
        <span class="pill">Rules ${escapeHtml(scorecard.enabled_rule_count ?? 0)}/${escapeHtml(scorecard.rule_count ?? 0)}</span>
        <span class="pill">Quality ${scorecard.quality_gate ? 'Pass' : 'Review'}</span>
        <span class="pill">Correlations ${escapeHtml(scorecard.correlation_alert_count ?? 0)}</span>
      </div>
    </div>
    <div class="scorecard-grid">
      ${categories.map((item) => `
        <div class="scorecard-card">
          <div class="scorecard-card-head">
            <h3>${escapeHtml(item.name)}</h3>
            <span class="pill">${escapeHtml(item.grade)} ${escapeHtml(item.score)}/100</span>
          </div>
          <div class="score-track"><div class="score-fill" style="width:${Math.max(4, Number(item.score || 0))}%"></div></div>
          <p>${escapeHtml(item.detail)}</p>
        </div>`).join('')}
    </div>
    <div class="scorecard-lower">
      <div class="scorecard-card">
        <h3>MITRE Tactics Covered</h3>
        <div class="tag-cloud">${tactics.map((tactic) => `<span class="pill">${escapeHtml(tactic)}</span>`).join('') || '<span class="muted">No tactics mapped.</span>'}</div>
      </div>
      <div class="scorecard-card">
        <h3>Rule Severity Balance</h3>
        <div class="bar-list">${severityRows.map((row) => `
          <div class="bar-item">
            <div class="mono">${escapeHtml(row.severity)}</div>
            <div class="bar-track"><div class="bar-fill" style="width:${Math.max(8, Number(row.count || 0) * 100 / Math.max(1, scorecard.enabled_rule_count || 1))}%"></div></div>
            <div class="mono muted">${escapeHtml(row.count)}</div>
          </div>`).join('') || '<div class="muted">No severity data.</div>'}</div>
      </div>
    </div>`;
}

function renderAlerts() {
  const alerts = asArray(state.workspace.alerts).filter(matchesSearch);
  $('#alertsTable').innerHTML = `<div class="table-wrap"><table><thead><tr><th>Time</th><th>Severity</th><th>Rule</th><th>Title</th><th>Score</th><th>Correlation</th></tr></thead><tbody>${alerts.map((alert) => `<tr><td class="mono muted">${escapeHtml(alert.timestamp)}</td><td><span class="pill ${severityClass(alert.severity)}">${escapeHtml(alert.severity)}</span></td><td class="mono">${escapeHtml(alert.rule_id)}</td><td>${escapeHtml(alert.title)}</td><td class="mono muted">${escapeHtml(alert.score)}</td><td class="mono muted">${escapeHtml(alert.correlation_id || '')}</td></tr>`).join('') || '<tr><td colspan="6" class="muted">No matching alerts.</td></tr>'}</tbody></table></div>`;
}

function renderHunts() {
  const hunts = asArray(state.workspace.hunts).filter(matchesSearch);
  $('#huntsList').innerHTML = hunts.length ? hunts.map((hunt) => `<div class="evidence-row"><div class="evidence-head"><span class="pill mono">${escapeHtml(hunt.hunt_id)}</span><span class="pill ${severityClass(hunt.severity)}">${escapeHtml(hunt.severity)}</span><span class="pill">${escapeHtml(hunt.confidence || 'confidence n/a')}</span></div><strong>${escapeHtml(hunt.title)}</strong><p>${escapeHtml(hunt.summary || '')}</p></div>`).join('') : '<div class="empty-state">No matching hunt findings.</div>';
}

function render() {
  if (!state.workspace) return;
  renderScenarioButton();
  renderDemoGuide();
  renderOverview();
  renderCases();
  renderGraph();
  renderScorecard();
  renderAlerts();
  renderHunts();
  setView(state.view);
}

document.querySelectorAll('.nav-tab').forEach((button) => button.addEventListener('click', () => setView(button.dataset.view)));
$('#refreshButton').addEventListener('click', loadWorkspace);
$('#runScenarioButton').addEventListener('click', () => runScenario().catch((error) => { state.runningScenario = false; renderScenarioButton(); alert(error.message); }));
$('#startDemoButton').addEventListener('click', () => startGuidedDemo().catch((error) => { state.runningScenario = false; renderScenarioButton(); alert(error.message); }));
$('#nextDemoStepButton').addEventListener('click', advanceGuidedDemo);
$('#closeDemoButton').addEventListener('click', () => { state.demo.active = false; render(); });
$('#searchInput').addEventListener('input', (event) => { state.search = event.target.value; render(); });
$('#caseSort').addEventListener('change', renderCases);
if ($('#graphCaseSelect')) $('#graphCaseSelect').addEventListener('change', (event) => { state.activeCaseId = event.target.value; renderCases(); renderGraph(); });

loadWorkspace().catch((error) => {
  document.body.innerHTML = `<main class="main"><section class="panel"><h1>Unable to load SOC-Forge output</h1><p>${escapeHtml(error.message)}</p></section></main>`;
});
