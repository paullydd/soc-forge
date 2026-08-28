function infoNode(tag, text, className) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = String(text);
  return node;
}

function infoLabel(value) {
  return String(value ?? 'Unknown').replaceAll('_', ' ');
}

function infoEmpty(title, detail) {
  const node = infoNode('div', undefined, 'empty-state');
  node.append(infoNode('strong', title), infoNode('p', detail));
  return node;
}

function infoMetric(label, value) {
  const node = infoNode('div', undefined, 'information-metric');
  node.append(infoNode('span', label, 'metric-label'), infoNode('strong', value, 'metric-value'));
  return node;
}

function infoTime(value, fallback) {
  return presentationTime(value, fallback || 'Time unavailable');
}

function infoFacts(entries, className) {
  const list = infoNode('dl', undefined, className || 'information-facts');
  entries.forEach(([label, value]) => {
    list.append(infoNode('dt', label), infoNode('dd', value ?? 'Unknown'));
  });
  return list;
}

function informationStatus(stateValue) {
  const stateText = String(stateValue || 'unknown').toLowerCase();
  return 'status-indicator system-state-' + stateText;
}

async function loadReportingWorkspace() {
  const response = await fetch('/api/reporting', { cache: 'no-store' });
  const payload = await response.json();
  if (!response.ok) throw new Error(payload.error || 'Unable to load Reporting');
  state.reporting = payload;
  renderReportingWorkspace();
}

async function loadSystemWorkspace() {
  const response = await fetch('/api/system', { cache: 'no-store' });
  const payload = await response.json();
  if (!response.ok) throw new Error(payload.error || 'Unable to load System');
  state.systemWorkspace = payload;
  renderSystemWorkspace();
}

function setInformationTab(kind, tab) {
  state[kind + 'Tab'] = tab;
  document.querySelectorAll('[data-' + kind + '-tab]').forEach((button) => {
    const active = button.dataset[kind + 'Tab'] === tab;
    button.classList.toggle('active', active);
    button.setAttribute('aria-selected', String(active));
    button.setAttribute('aria-controls', kind + '-panel-' + button.dataset[kind + 'Tab']);
    button.tabIndex = active ? 0 : -1;
  });
  document.querySelectorAll('[data-' + kind + '-panel]').forEach((panel) => {
    panel.id = kind + '-panel-' + panel.dataset[kind + 'Panel'];
    panel.setAttribute('role', 'tabpanel');
    panel.setAttribute('aria-labelledby', kind + '-tab-' + panel.dataset[kind + 'Panel']);
    panel.hidden = panel.dataset[kind + 'Panel'] !== tab;
  });
}

function bindInformationTabs(kind) {
  document.querySelectorAll('[data-' + kind + '-tab]').forEach((button) => {
    button.id = kind + '-tab-' + button.dataset[kind + 'Tab'];
    button.addEventListener('click', () => setInformationTab(kind, button.dataset[kind + 'Tab']));
    button.addEventListener('keydown', (event) => {
      const tabs = [...document.querySelectorAll('[data-' + kind + '-tab]')];
      let index = tabs.indexOf(button);
      if (event.key === 'ArrowRight') index = (index + 1) % tabs.length;
      else if (event.key === 'ArrowLeft') index = (index - 1 + tabs.length) % tabs.length;
      else if (event.key === 'Home') index = 0;
      else if (event.key === 'End') index = tabs.length - 1;
      else return;
      event.preventDefault(); tabs[index].focus(); setInformationTab(kind, tabs[index].dataset[kind + 'Tab']);
    });
  });
}

function renderReportingMode() {
  const executive = state.reporting?.executive;
  const target = document.querySelector('#reportingMode');
  if (!target || !executive) return;
  target.className = 'status-indicator ' + (executive.mode === 'full' ? 'status-available' : 'status-neutral');
  target.replaceChildren(infoNode('span'));
  target.append(document.createTextNode(executive.mode === 'full' ? 'FULL · machine + analyst' : 'OFFLINE · durable analyst state'));
}

function renderReportingOverview() {
  const target = document.querySelector('#reportingOverview');
  const reporting = state.reporting;
  if (!target || !reporting) return;
  target.replaceChildren();
  const metrics = infoNode('div', undefined, 'information-metrics');
  const availableExports = reporting.exports.filter((row) => row.available).length;
  metrics.append(
    infoMetric('Existing reports', reporting.reports.length),
    infoMetric('Investigation reports', reporting.investigations.length),
    infoMetric('Supported artifacts', availableExports),
    infoMetric('Attention items', reporting.executive.attention_items),
  );
  const grid = infoNode('div', undefined, 'reporting-overview-grid');
  const sources = infoNode('section', undefined, 'panel information-section');
  sources.append(infoNode('h3', 'Output ownership'));
  [
    ['Current analysis artifacts', 'Existing generated HTML and allowlisted JSON artifacts.'],
    ['Investigation Report', 'A human-readable projection of durable analyst state.'],
    ['Investigation Handoff', 'An operational transfer artifact owned by Investigations; not rebuilt here.'],
  ].forEach(([title, detail]) => {
    const row = infoNode('div', undefined, 'information-row');
    row.append(infoNode('strong', title), infoNode('span', detail, 'muted'));
    sources.append(row);
  });
  const availability = infoNode('section', undefined, 'panel information-section');
  availability.append(infoNode('h3', 'Source availability'), infoNode('p', reporting.executive.machine_context_available
    ? 'Current machine analysis and durable analyst state are available.'
    : 'Machine context unavailable. Durable Investigation reporting and analyst state remain available.'));
  grid.append(sources, availability);
  target.append(metrics, grid);
}

function reportLink(filename, label) {
  const link = infoNode('a', label || 'Open artifact', 'information-link');
  link.href = '/artifact?file=' + encodeURIComponent(filename);
  link.target = '_blank';
  link.rel = 'noreferrer';
  return link;
}

function renderReportCenter() {
  const target = document.querySelector('#reportCenter');
  const reports = state.reporting?.reports || [];
  if (!target) return;
  target.replaceChildren();
  const head = infoNode('div', undefined, 'section-heading');
  head.append(infoNode('div'));
  head.firstChild.append(infoNode('div', 'Existing human-readable artifacts', 'eyebrow'), infoNode('h3', 'Report Center'));
  target.append(head);
  if (!reports.length) {
    target.append(infoEmpty('No existing Analysis reports', 'No known HTML report artifact is currently available.'));
    return;
  }
  const list = infoNode('div', undefined, 'information-list');
  reports.forEach((report) => {
    const row = infoNode('article', undefined, 'information-record');
    row.append(infoNode('div', report.report_type, 'eyebrow'), infoNode('h3', report.filename), infoTime(report.modified_at, 'Modified time unavailable'), reportLink(report.filename, 'Open report'));
    const details = infoNode('details');
    details.append(infoNode('summary', 'Technical details'), infoNode('div', report.path, 'technical-id information-path'));
    row.append(details); list.append(row);
  });
  target.append(list);
}

async function loadInvestigationReport(investigationId) {
  const response = await fetch('/api/reporting/investigations/' + encodeURIComponent(investigationId), { cache: 'no-store' });
  const payload = await response.json();
  if (!response.ok) throw new Error(payload.error || 'Unable to load Investigation Report');
  state.investigationReport = payload;
  renderInvestigationReport();
}

function renderInvestigationReport() {
  const target = document.querySelector('#investigationReport');
  if (!target || !state.reporting) return;
  target.replaceChildren();
  const toolbar = infoNode('div', undefined, 'information-toolbar');
  const label = infoNode('label', 'Investigation');
  const select = infoNode('select');
  const prompt = infoNode('option', 'Select an Investigation'); prompt.value = '';
  select.append(prompt);
  state.reporting.investigations.forEach((row) => {
    const option = infoNode('option', row.title + ' · ' + row.investigation_id);
    option.value = row.investigation_id; select.append(option);
  });
  select.addEventListener('change', () => {
    if (select.value) loadInvestigationReport(select.value).catch(showReportingError);
  });
  label.append(select); toolbar.append(label);
  const boundary = infoNode('div', undefined, 'reporting-handoff-boundary');
  boundary.append(infoNode('strong', 'Investigation Report ≠ Investigation Handoff'), infoNode('span', 'This is a presentation view. Structured operational transfer remains in the Investigation Workspace.'));
  target.append(toolbar, boundary);
  const report = state.investigationReport;
  if (!report) {
    target.append(infoEmpty('Select an Investigation', 'Review its durable reporting projection without changing Investigation state.'));
    return;
  }
  select.value = report.investigation_id;
  const identity = infoNode('section', undefined, 'panel information-section');
  identity.append(infoNode('h3', report.title), infoFacts([
    ['Investigation ID', report.investigation_id], ['Status', infoLabel(report.status)],
    ['Owner', report.owner || 'Unassigned'], ['Revision', report.revision],
    ['Source mode', report.mode.toUpperCase()], ['Updated', formatUtcTimestamp(report.updated_at, 'Unknown')],
  ]));
  const assessment = infoNode('section', undefined, 'panel information-section');
  assessment.append(infoNode('h3', 'Analyst assessment'));
  [...report.active_findings, ...report.historical_findings].forEach((finding) => {
    const row = infoNode('div', undefined, 'information-row');
    row.append(infoNode('strong', finding.title), infoNode('span', finding.finding_id + ' · ' + infoLabel(finding.status) + ' · ' + infoLabel(finding.confidence), 'muted'), infoNode('p', finding.conclusion));
    assessment.append(row);
  });
  if (!report.active_findings.length && !report.historical_findings.length) assessment.append(infoEmpty('No Findings', 'No durable Findings are recorded for this Investigation.'));
  const facts = infoNode('section', undefined, 'panel information-section');
  facts.append(infoNode('h3', 'Reporting context'), infoFacts([
    ['Evidence references', report.evidence_count], ['Hypotheses', report.hypotheses.length],
    ['Decisions', report.decisions.length], ['Annotations', report.annotations.length],
    ['Response Actions', report.response_actions.length],
    ['ATT&CK tactics', report.attack_tactics.join(', ') || 'None explicit'],
    ['ATT&CK techniques', report.attack_techniques.join(', ') || 'None explicit'],
  ]), infoNode('p', 'Protected evidence values are not revealed in this report.', 'muted'));
  target.append(identity, assessment, facts);
}

function renderExecutiveSummary() {
  const target = document.querySelector('#executiveSummary');
  const summary = state.reporting?.executive;
  if (!target || !summary) return;
  target.replaceChildren();
  const hero = infoNode('section', undefined, 'executive-hero');
  hero.append(infoNode('div', 'Leadership view', 'eyebrow'), infoNode('h3', 'Current security situation'), infoNode('p', summary.machine_context_available
    ? 'Current machine analysis and durable analyst state are represented.'
    : 'Machine context is unavailable; this summary reflects durable analyst state only.'));
  const metrics = infoNode('div', undefined, 'information-metrics');
  metrics.append(infoMetric('Investigations', summary.investigation_count), infoMetric('Active findings', summary.active_findings), infoMetric('Open response work', summary.open_response_actions), infoMetric('Attention items', summary.attention_items));
  const context = infoNode('section', undefined, 'panel information-section');
  context.append(infoNode('h3', 'Observed ATT&CK context'));
  const tactics = summary.observed_attack_tactics.map((row) => row.tactic || row.value).filter(Boolean).slice(0, 5);
  context.append(infoNode('p', tactics.join(', ') || 'No explicit ATT&CK tactics are recorded.'));
  if (summary.top_attention) context.append(infoNode('h3', 'Top operational attention'), infoNode('p', summary.top_attention.reason || 'Open authoritative attention item.'));
  context.append(infoNode('p', 'For technical evidence and lifecycle details, open the authoritative Investigation or Operations workspace.', 'muted'));
  target.append(hero, metrics, context);
}

function renderExportCenter() {
  const target = document.querySelector('#exportCenter');
  if (!target || !state.reporting) return;
  target.replaceChildren();
  const notice = infoNode('div', undefined, 'reporting-handoff-boundary');
  notice.append(infoNode('strong', 'Existing artifacts only'), infoNode('span', 'Reporting does not transform, regenerate, or create a second Investigation Handoff.'));
  const list = infoNode('div', undefined, 'information-list');
  state.reporting.exports.forEach((artifact) => {
    const row = infoNode('div', undefined, 'information-record');
    row.append(infoNode('h3', artifact.filename), infoNode('span', artifact.available ? 'Available' : 'Unavailable', artifact.available ? 'state-ready' : 'state-unknown'));
    if (artifact.available) row.append(reportLink(artifact.filename, 'Open artifact'));
    list.append(row);
  });
  const handoff = infoNode('div', undefined, 'information-record');
  handoff.append(infoNode('h3', 'Investigation Handoff'), infoNode('p', 'Open an Investigation to preview or export its authoritative structured Handoff.'));
  const button = infoNode('button', 'Open Investigations'); button.type = 'button'; button.addEventListener('click', () => setView('investigations'));
  handoff.append(button); list.append(handoff);
  target.append(notice, list);
}

function renderReportingWorkspace() {
  if (!state.reporting) return;
  renderReportingMode(); renderReportingOverview(); renderReportCenter();
  renderInvestigationReport(); renderExecutiveSummary(); renderExportCenter();
  setInformationTab('reporting', state.reportingTab);
}

function renderSystemStatus() {
  const target = document.querySelector('#systemStatus');
  const status = state.systemWorkspace?.status;
  const overall = document.querySelector('#systemOverallStatus');
  if (!target || !status || !overall) return;
  overall.className = informationStatus(status.overall_state);
  overall.replaceChildren(infoNode('span'));
  overall.append(document.createTextNode(status.overall_state.toUpperCase()));
  target.replaceChildren();
  const groups = infoNode('div', undefined, 'system-status-groups');
  [['Required components', false], ['Optional components', true]].forEach(([title, optional]) => {
    const section = infoNode('section', undefined, 'panel information-section');
    section.append(infoNode('h3', title));
    status.components.filter((row) => Boolean(!row.required) === optional).forEach((row) => {
      const item = infoNode('div', undefined, 'system-status-row');
      item.append(infoNode('span', row.state.toUpperCase(), 'system-state-text state-' + row.state), infoNode('strong', row.title), infoNode('span', row.detail, 'muted'));
      section.append(item);
    });
    groups.append(section);
  });
  target.append(groups, infoNode('p', 'UNKNOWN means the state could not be determined; it is not converted to failure.', 'muted'));
}

function renderSystemConfiguration() {
  const target = document.querySelector('#systemConfiguration');
  const config = state.systemWorkspace?.configuration;
  if (!target || !config) return;
  target.replaceChildren(infoNode('div', 'Read-only effective configuration', 'eyebrow'), infoNode('h3', config.loaded ? 'Configured values' : 'Effective defaults'));
  target.append(infoNode('p', config.detail));
  target.append(infoFacts(config.values.length ? config.values : [['Configuration', 'Unavailable']]));
}

function renderSystemHealth() {
  const target = document.querySelector('#systemHealth');
  const health = state.systemWorkspace?.health;
  if (!target || !health) return;
  target.replaceChildren();
  const notice = infoNode('div', undefined, 'system-boundary');
  notice.append(infoNode('strong', 'Asset loadability, not Detection Coverage'), infoNode('span', 'No ATT&CK completeness or rule effectiveness is calculated here.'));
  target.append(notice, infoFacts([
    ['Rule files discovered', health.rules_discovered], ['Rules loaded', health.rules_loaded],
    ['Rule parse failures', health.parse_failures.length], ['Web assets', infoLabel(health.web_assets_state)],
    ['Reporting assets', infoLabel(health.report_assets_state)],
  ]));
  health.parse_failures.forEach((failure) => target.append(infoNode('p', failure, 'notice notice-error')));
}

function renderSystemStorage() {
  const target = document.querySelector('#systemStorage');
  const storage = state.systemWorkspace?.storage;
  if (!target || !storage) return;
  target.replaceChildren(infoNode('div', 'Bounded known-path inspection', 'eyebrow'), infoNode('h3', 'Repository & Storage'));
  target.append(infoFacts([
    ['Investigation repository', storage.repository_exists ? 'Available' : 'Unavailable'],
    ['Repository readable', storage.repository_readable ? 'Yes' : 'No'],
    ['Repository writable capability', storage.repository_writable ? 'Yes' : 'No'],
    ['Investigations', storage.investigation_count ?? 'Unknown'],
    ['Output storage', storage.output_exists ? 'Available' : 'Unavailable'],
    ['Snapshot location', storage.snapshot_exists ? 'Available' : 'Unavailable'],
    ['Known analysis reports', storage.analysis_report_count], ['Inspection', storage.detail],
  ]));
  const details = infoNode('details');
  details.append(infoNode('summary', 'Known technical paths'), infoFacts([
    ['Repository', storage.repository_path], ['Output', storage.output_path], ['Snapshots', storage.snapshot_path],
  ], 'information-facts technical-paths'));
  target.append(details);
}

function renderSystemEnvironment() {
  const target = document.querySelector('#systemEnvironment');
  const environment = state.systemWorkspace?.environment;
  if (!target || !environment) return;
  target.replaceChildren(infoNode('div', 'Bounded Python-native inspection', 'eyebrow'), infoNode('h3', 'Environment'));
  target.append(infoFacts([
    ['SOC-Forge version', environment.soc_forge_version], ['Python', environment.python_version],
    ['Platform', environment.platform_name], ['Architecture', environment.architecture],
    ['Virtual environment', environment.virtual_environment], ['Terminal', environment.terminal],
    ['Color', environment.color],
  ]));
  const details = infoNode('details');
  details.append(infoNode('summary', 'Runtime paths'), infoFacts([
    ['Executable', environment.executable], ['Working directory', environment.working_directory],
  ], 'information-facts technical-paths'));
  target.append(details);
}

function renderSystemAbout() {
  const target = document.querySelector('#systemAbout');
  const about = state.systemWorkspace?.about;
  if (!target || !about) return;
  target.replaceChildren(infoNode('div', about.product, 'eyebrow'), infoNode('h3', about.description), infoNode('div', 'Version ' + about.version, 'technical-id'));
  const list = infoNode('ul', undefined, 'about-capabilities');
  about.capabilities.forEach((value) => list.append(infoNode('li', value)));
  target.append(list, infoNode('p', about.remediation_boundary, 'system-remediation-boundary'));
}

function renderSystemWorkspace() {
  if (!state.systemWorkspace) return;
  renderSystemStatus(); renderSystemConfiguration(); renderSystemHealth();
  renderSystemStorage(); renderSystemEnvironment(); renderSystemAbout();
  setInformationTab('system', state.systemTab);
}

function showReportingError(error) {
  const target = document.querySelector('#reportingStatus');
  if (target) target.textContent = error.message;
}

function showSystemError(error) {
  const target = document.querySelector('#systemMessage');
  if (target) target.textContent = error.message;
}

function bindReportingSystem() {
  bindInformationTabs('reporting');
  bindInformationTabs('system');
}
