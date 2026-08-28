function analysisNode(tag, text, className) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = String(text);
  return node;
}

function analysisLabel(value) {
  return String(value || 'unknown').replaceAll('_', ' ');
}

function analysisEmpty(title, detail) {
  const empty = analysisNode('div', undefined, 'empty-state');
  empty.append(analysisNode('strong', title), analysisNode('p', detail));
  return empty;
}

function analysisPill(value, className) {
  return analysisNode('span', analysisLabel(value), 'pill ' + (className || ''));
}

function analysisMetric(label, value, unavailable) {
  const metric = analysisNode('div', undefined, 'analysis-metric');
  metric.append(
    analysisNode('span', label, 'metric-label'),
    analysisNode('strong', unavailable ? 'Unavailable' : value, 'metric-value'),
  );
  return metric;
}

async function loadSecurityAnalysis() {
  const [response, entitiesResponse] = await Promise.all([
    fetch('/api/security-analysis', { cache: 'no-store' }),
    fetch('/api/security-analysis/entities', { cache: 'no-store' }),
  ]);
  const [payload, entityDiscovery] = await Promise.all([
    response.json(), entitiesResponse.json(),
  ]);
  if (!response.ok) throw new Error(payload.error || 'Unable to load Security Analysis');
  if (!entitiesResponse.ok) throw new Error(entityDiscovery.error || 'Unable to load observed entities');
  state.securityAnalysis = payload;
  state.analysisEntityDiscovery = entityDiscovery;
  renderSecurityAnalysis();
}

function setAnalysisTab(tab) {
  state.analysisTab = tab;
  document.querySelectorAll('[data-analysis-tab]').forEach((button) => {
    const active = button.dataset.analysisTab === tab;
    button.classList.toggle('active', active);
    button.setAttribute('aria-selected', String(active));
    button.setAttribute('aria-controls', 'analysis-panel-' + button.dataset.analysisTab);
    button.tabIndex = active ? 0 : -1;
  });
  document.querySelectorAll('[data-analysis-panel]').forEach((panel) => {
    panel.id = 'analysis-panel-' + panel.dataset.analysisPanel;
    panel.setAttribute('role', 'tabpanel');
    panel.setAttribute('aria-labelledby', 'analysis-tab-' + panel.dataset.analysisPanel);
    panel.hidden = panel.dataset.analysisPanel !== tab;
  });
}

function renderAnalysisMode() {
  const mode = state.securityAnalysis?.overview?.mode || 'offline';
  const target = document.querySelector('#analysisMode');
  if (!target) return;
  target.className = 'status-indicator ' + (mode === 'full' ? 'status-available' : 'status-neutral');
  target.replaceChildren(analysisNode('span'));
  target.append(document.createTextNode(mode === 'full' ? 'FULL · machine + analyst' : 'OFFLINE · durable analyst state'));
}

function renderAnalysisOverview() {
  const target = document.querySelector('#analysisOverview');
  const overview = state.securityAnalysis?.overview;
  if (!target || !overview) return;
  target.replaceChildren();
  const context = analysisNode('div', undefined, 'analysis-context-strip');
  context.append(
    analysisNode('strong', overview.mode === 'full' ? 'Current machine context available' : 'Machine context unavailable'),
    analysisNode('span', overview.mode === 'full'
      ? 'FULL combines current machine analysis with durable analyst state.'
      : 'OFFLINE is a valid durable-state view; machine counts are intentionally unavailable.'),
  );
  const metrics = analysisNode('div', undefined, 'analysis-metrics');
  metrics.append(
    analysisMetric('Investigations', overview.investigation_count),
    analysisMetric('Active findings', overview.active_finding_count),
    analysisMetric('Open actions', overview.open_response_action_count),
    analysisMetric('Machine alerts', overview.alert_count, overview.alert_count === null),
    analysisMetric('Pipeline Hunts', overview.hunt_count, overview.hunt_count === null),
  );
  const grid = analysisNode('div', undefined, 'analysis-overview-grid');
  const attack = analysisNode('section', undefined, 'panel analysis-summary-panel');
  attack.append(analysisNode('h3', 'Observed ATT&CK activity'));
  const attackFacts = analysisNode('div', undefined, 'analysis-fact-list');
  const summary = state.securityAnalysis.attack;
  [
    ['Observations', summary.observation_count], ['Tactics', summary.tactic_count],
    ['Techniques', summary.technique_count], ['Analyst', summary.analyst_observation_count],
    ['Machine', summary.mode === 'full' ? summary.machine_observation_count : 'Unavailable'],
  ].forEach(([label, value]) => attackFacts.append(analysisNode('span', label + ' ' + value)));
  attack.append(attackFacts, analysisNode('p', 'Observed or recorded mappings only. Detection owns rule coverage.'));
  const recent = analysisNode('section', undefined, 'panel analysis-summary-panel');
  recent.append(analysisNode('h3', 'Recent recorded activity'));
  if (!overview.recent_activity.length) recent.append(analysisEmpty('No recent activity', 'No timed analyst or machine observations are available.'));
  overview.recent_activity.slice(0, 6).forEach((row) => {
    const item = analysisNode('div', undefined, 'analysis-compact-row');
    item.append(analysisPill(row.origin, 'attribution-' + row.origin), analysisNode('span', row.timestamp, 'mono'), analysisNode('strong', row.description));
    recent.append(item);
  });
  grid.append(attack, recent);
  target.append(context, metrics, grid);
}

function investigationButton(investigationId) {
  const button = analysisNode('button', investigationId, 'link-button mono');
  button.type = 'button';
  button.addEventListener('click', () => {
    openInvestigation(investigationId).then(() => {
      setView('investigations');
      setInvestigationTab('summary');
    }).catch(showAnalysisError);
  });
  return button;
}

function attackPivot(value) {
  const button = analysisNode('button', value, 'link-button mono');
  button.type = 'button';
  button.addEventListener('click', () => {
    state.analysisTechniqueQuery = String(value).match(/T[0-9]{4}(?:\.[0-9]{3})?/i)?.[0] || value;
    setAnalysisTab('hunts');
    renderAnalysisHunts();
  });
  return button;
}

async function searchAnalysisEntity(entityType, value) {
  const params = new URLSearchParams({ type: entityType, value });
  const response = await fetch('/api/security-analysis/entity?' + params, { cache: 'no-store' });
  const payload = await response.json();
  if (!response.ok) throw new Error(payload.error || 'Unable to explore entity');
  state.analysisEntityResult = payload;
  renderAnalysisEntity();
}

function selectDiscoveredEntity(entity) {
  const type = document.querySelector('#analysisEntityType');
  const value = document.querySelector('#analysisEntityValue');
  if (type) type.value = entity.entity_type;
  if (value) value.value = entity.display_value;
  searchAnalysisEntity(entity.entity_type, entity.display_value).catch(showAnalysisError);
}

function renderAnalysisEntityDiscovery() {
  const target = document.querySelector('#analysisEntityDiscovery');
  const discovery = state.analysisEntityDiscovery;
  if (!target) return;
  target.replaceChildren();
  if (!discovery) return;
  const section = analysisNode('section', undefined, 'analysis-entity-discovery');
  const head = analysisNode('div', undefined, 'analysis-entity-discovery-head');
  head.append(
    analysisNode('div', undefined),
    analysisNode('span', discovery.mode === 'full'
      ? 'Current machine + analyst observations'
      : 'OFFLINE · machine context unavailable', 'muted'),
  );
  head.firstChild.append(
    analysisNode('div', 'Exact normalized values', 'eyebrow'),
    analysisNode('h3', 'Observed entities'),
  );
  section.append(head);
  if (!discovery.entities.length) {
    section.append(analysisEmpty(
      'No authoritative entity values are discoverable',
      discovery.machine_context_available
        ? 'Current machine and analyst projections contain no structured entity values.'
        : 'Machine context is unavailable. Persisted Investigation state does not contain standalone entity values that can be safely reconstructed offline.',
    ));
    target.append(section);
    return;
  }
  const groups = analysisNode('div', undefined, 'analysis-entity-groups');
  const labels = { host: 'Hosts', user: 'Users', ip: 'IP addresses', process: 'Processes' };
  ['host', 'user', 'ip', 'process'].forEach((entityType) => {
    const entities = discovery.entities.filter((entity) => entity.entity_type === entityType);
    if (!entities.length) return;
    const group = analysisNode('div', undefined, 'analysis-entity-group');
    group.append(analysisNode('h4', labels[entityType]));
    entities.forEach((entity) => {
      const button = analysisNode('button', undefined, 'analysis-entity-option');
      button.type = 'button';
      button.append(
        analysisNode('strong', entity.display_value, 'mono'),
        analysisNode('span', entity.observation_count + ' observations', 'muted'),
        analysisNode('span', 'Machine ' + entity.machine_observation_count + ' · Analyst ' + entity.analyst_observation_count, 'analysis-entity-attribution'),
      );
      button.addEventListener('click', () => selectDiscoveredEntity(entity));
      group.append(button);
    });
    groups.append(group);
  });
  section.append(groups);
  target.append(section);
}

function renderAnalysisEntity() {
  const target = document.querySelector('#analysisEntityResult');
  const result = state.analysisEntityResult;
  if (!target) return;
  target.replaceChildren();
  if (!result) {
    target.append(analysisEmpty('Explore an exact entity', 'Select host, user, IP address, or process and enter an exact value.'));
    return;
  }
  const context = analysisNode('div', undefined, 'analysis-context-strip');
  context.append(analysisNode('strong', result.query), analysisNode('span', result.mode.toUpperCase() + ' · exact normalized match · ' + result.observation_count + ' observations'));
  const grid = analysisNode('div', undefined, 'analysis-browser');
  const list = analysisNode('div', undefined, 'analysis-list');
  if (!result.observations.length) list.append(analysisEmpty('No exact observations', result.mode === 'offline' ? 'Machine context is unavailable and durable state has no exact match.' : 'No structured observation exactly matches this entity.'));
  result.observations.forEach((row) => {
    const item = analysisNode('article', undefined, 'analysis-list-row');
    item.append(analysisPill(row.origin, 'attribution-' + row.origin), analysisNode('strong', row.title), analysisNode('span', analysisLabel(row.source_type) + ' · ' + row.source_id, 'mono muted'));
    if (row.investigation_id) item.append(investigationButton(row.investigation_id));
    list.append(item);
  });
  const detail = analysisNode('aside', undefined, 'analysis-detail');
  detail.append(analysisNode('h3', 'Related structured context'));
  const related = analysisNode('div', undefined, 'analysis-fact-list');
  result.related_entities.forEach((row) => related.append(analysisNode('span', analysisLabel(row.entity_type) + ': ' + row.entity_value + ' · ' + row.observation_count)));
  detail.append(analysisNode('h4', 'Related entities'), related);
  const techniques = analysisNode('div', undefined, 'analysis-pivots');
  result.attack_techniques.forEach((row) => techniques.append(attackPivot(row.value)));
  detail.append(analysisNode('h4', 'Explicit ATT&CK mappings'), techniques);
  grid.append(list, detail);
  target.append(context, grid);
}

function renderAnalysisAttack() {
  const target = document.querySelector('#analysisAttack');
  const summary = state.securityAnalysis?.attack;
  if (!target || !summary) return;
  target.replaceChildren();
  const notice = analysisNode('div', undefined, 'analysis-semantic-notice');
  notice.append(analysisNode('strong', 'Observed activity, not Detection Coverage'), analysisNode('span', 'Only explicit machine or analyst ATT&CK mappings appear here.'));
  const browser = analysisNode('div', undefined, 'analysis-browser');
  const tactics = analysisNode('section', undefined, 'analysis-list');
  tactics.append(analysisNode('h3', 'By tactic'));
  summary.tactics.forEach((row) => {
    const item = analysisNode('div', undefined, 'analysis-list-row');
    item.append(analysisNode('strong', row.tactic), analysisNode('span', row.observation_count + ' observations · machine ' + row.machine_observation_count + ' · analyst ' + row.analyst_observation_count, 'muted'));
    tactics.append(item);
  });
  const techniques = analysisNode('section', undefined, 'analysis-list');
  techniques.append(analysisNode('h3', 'By technique'));
  summary.techniques.forEach((row) => {
    const item = analysisNode('div', undefined, 'analysis-list-row');
    item.append(attackPivot(row.technique_key), analysisNode('span', row.observation_count + ' observations · ' + row.investigation_count + ' investigations', 'muted'));
    techniques.append(item);
  });
  if (!summary.observation_count) tactics.append(analysisEmpty('No recorded mappings', 'No explicit ATT&CK observations are available.'));
  browser.append(tactics, techniques);
  target.append(notice, browser);
}

function renderRelationshipDetail(row, target) {
  target.replaceChildren();
  target.append(analysisPill(row.relationship_type), analysisNode('h3', row.display_value), analysisNode('p', row.explanation));
  const facts = analysisNode('div', undefined, 'analysis-fact-list');
  facts.append(analysisNode('span', row.observation_count + ' supporting observations'), analysisNode('span', row.machine_observation_count + ' machine'), analysisNode('span', row.analyst_observation_count + ' analyst'));
  target.append(facts, analysisNode('h4', 'Participating Investigations'));
  const pivots = analysisNode('div', undefined, 'analysis-pivots');
  row.investigation_ids.forEach((id) => pivots.append(investigationButton(id)));
  target.append(pivots, analysisNode('h4', 'Supporting observations'));
  row.recent_observations.forEach((observation) => {
    const item = analysisNode('div', undefined, 'analysis-compact-row');
    item.append(analysisPill(observation.attribution, 'attribution-' + observation.attribution), analysisNode('strong', observation.title), analysisNode('span', observation.source_id, 'mono muted'));
    target.append(item);
  });
}

function renderAnalysisRelationships() {
  const target = document.querySelector('#analysisRelationships');
  const summary = state.securityAnalysis?.relationships;
  if (!target || !summary) return;
  target.replaceChildren();
  const caution = analysisNode('div', undefined, 'analysis-semantic-notice caution');
  caution.append(analysisNode('strong', 'Shared observations do not establish identity or cause'), analysisNode('span', 'Overlap does not establish the same attacker, attack, campaign, or cause.'));
  const browser = analysisNode('div', undefined, 'analysis-browser');
  const list = analysisNode('div', undefined, 'analysis-list');
  const detail = analysisNode('aside', undefined, 'analysis-detail');
  if (!summary.relationships.length) {
    list.append(analysisEmpty('No cross-Investigation overlap', 'No exact shared entities or explicit ATT&CK mappings span two Investigations.'));
    detail.append(analysisEmpty('Select a relationship', 'Supporting observations and attribution appear here.'));
  }
  summary.relationships.forEach((row, index) => {
    const button = analysisNode('button', undefined, 'analysis-list-row');
    button.type = 'button';
    button.append(analysisPill(row.relationship_type), analysisNode('strong', row.display_value), analysisNode('span', row.investigation_ids.length + ' investigations · ' + row.observation_count + ' observations', 'muted'));
    button.addEventListener('click', () => renderRelationshipDetail(row, detail));
    list.append(button);
    if (index === 0) renderRelationshipDetail(row, detail);
  });
  browser.append(list, detail);
  target.append(caution, browser);
}

function renderAnalysisTimeline() {
  const target = document.querySelector('#analysisTimeline');
  const timeline = state.securityAnalysis?.timeline;
  if (!target || !timeline) return;
  target.replaceChildren();
  const notice = analysisNode('div', undefined, 'analysis-semantic-notice');
  notice.append(analysisNode('strong', 'Chronology is not causality'), analysisNode('span', 'Ordering recorded activity does not establish a shared attack, campaign, or causal relationship.'));
  const filters = analysisNode('div', undefined, 'analysis-filter-bar');
  const definitions = [
    ['Investigation', 'investigation_id'], ['Source type', 'source_type'],
    ['ATT&CK tactic', 'attack_tactics'], ['ATT&CK technique', 'attack_techniques'],
  ];
  definitions.forEach(([label, key]) => {
    const wrapper = analysisNode('label', label);
    const select = analysisNode('select');
    const all = analysisNode('option', 'All'); all.value = '';
    select.append(all);
    const values = new Set();
    [...timeline.entries, ...timeline.untimed_entries].forEach((row) => {
      const value = row[key];
      (Array.isArray(value) ? value : [value]).filter(Boolean).forEach((entry) => values.add(entry));
    });
    [...values].sort().forEach((value) => { const option = analysisNode('option', value); option.value = value; select.append(option); });
    select.addEventListener('change', (event) => { state.analysisTimelineFilters[key] = event.target.value; renderAnalysisTimeline(); });
    select.value = state.analysisTimelineFilters[key] || '';
    wrapper.append(select); filters.append(wrapper);
  });
  const matches = (row) => Object.entries(state.analysisTimelineFilters).every(([key, value]) => !value || (Array.isArray(row[key]) ? row[key].includes(value) : row[key] === value));
  const rows = timeline.entries.filter(matches);
  const list = analysisNode('div', undefined, 'analysis-timeline-list');
  if (!rows.length) list.append(analysisEmpty('No timed activity', 'No chronological entries match the current filters.'));
  rows.forEach((row) => {
    const item = analysisNode('div', undefined, 'analysis-timeline-row');
    item.append(analysisNode('time', row.timestamp, 'mono'), analysisPill(row.attribution, 'attribution-' + row.attribution), analysisNode('span', analysisLabel(row.category)), analysisNode('strong', row.title), analysisNode('span', row.source_id, 'mono muted'));
    if (row.investigation_id) item.append(investigationButton(row.investigation_id));
    list.append(item);
  });
  const untimed = analysisNode('details', undefined, 'analysis-untimed');
  untimed.append(analysisNode('summary', 'Untimed activity · ' + timeline.untimed_entries.filter(matches).length));
  timeline.untimed_entries.filter(matches).forEach((row) => untimed.append(analysisNode('div', row.title + ' · ' + row.source_id, 'analysis-compact-row')));
  target.append(notice, filters, list, untimed);
}

function renderAnalysisHunts() {
  const target = document.querySelector('#analysisHunts');
  const summary = state.securityAnalysis?.hunts;
  if (!target || !summary) return;
  target.replaceChildren();
  const context = analysisNode('div', undefined, 'analysis-context-strip');
  context.append(analysisNode('strong', summary.mode === 'full' ? 'Existing pipeline Hunts' : 'Existing Hunts unavailable'), analysisNode('span', summary.mode === 'full' ? summary.hunt_count + ' current Hunt findings; exploration results remain ephemeral.' : 'OFFLINE preserves analyst projections but current pipeline Hunts require machine context.'));
  const modes = analysisNode('div', undefined, 'analysis-hunt-modes');
  ['Existing Hunts', 'Hunt by Entity', 'Hunt by ATT&CK Technique', 'Hunt by Investigation'].forEach((label) => modes.append(analysisNode('span', label, 'pill')));
  const list = analysisNode('div', undefined, 'analysis-list');
  if (summary.mode === 'offline') list.append(analysisEmpty('Machine context unavailable', 'Existing pipeline Hunt findings are unavailable, not zero. Entity, technique, and Investigation projections remain read-only and ephemeral.'));
  summary.hunts.forEach((hunt) => {
    const item = analysisNode('article', undefined, 'analysis-list-row');
    item.append(analysisNode('strong', hunt.title), analysisNode('span', hunt.hunt_id + ' · ' + analysisLabel(hunt.severity) + ' · ' + hunt.evidence_count + ' evidence', 'mono muted'), analysisNode('p', hunt.summary));
    list.append(item);
  });
  if (state.analysisTechniqueQuery) {
    const matches = state.securityAnalysis.attack.techniques.filter((row) => (row.technique_id || '').toLowerCase() === String(state.analysisTechniqueQuery).toLowerCase());
    const projection = analysisNode('section', undefined, 'analysis-projection');
    projection.append(analysisNode('h3', 'Ephemeral technique projection · ' + state.analysisTechniqueQuery));
    if (!matches.length) projection.append(analysisEmpty('No explicit technique observations', 'This search was not saved and did not rerun detection.'));
    matches.forEach((row) => projection.append(analysisNode('p', row.technique_key + ' · ' + row.observation_count + ' observations')));
    target.append(context, modes, projection, list);
    return;
  }
  target.append(context, modes, list);
}

function renderSecurityAnalysis() {
  if (!state.securityAnalysis) return;
  renderAnalysisMode();
  renderAnalysisOverview();
  renderAnalysisEntityDiscovery();
  renderAnalysisEntity();
  renderAnalysisAttack();
  renderAnalysisRelationships();
  renderAnalysisTimeline();
  renderAnalysisHunts();
  setAnalysisTab(state.analysisTab);
}

function showAnalysisError(error) {
  const target = document.querySelector('#analysisStatus');
  if (target) target.textContent = error.message;
}

function bindSecurityAnalysis() {
  document.querySelectorAll('[data-analysis-tab]').forEach((button) => {
    button.id = 'analysis-tab-' + button.dataset.analysisTab;
    button.addEventListener('click', () => setAnalysisTab(button.dataset.analysisTab));
    button.addEventListener('keydown', (event) => {
      const tabs = [...document.querySelectorAll('[data-analysis-tab]')];
      let index = tabs.indexOf(button);
      if (event.key === 'ArrowRight') index = (index + 1) % tabs.length;
      else if (event.key === 'ArrowLeft') index = (index - 1 + tabs.length) % tabs.length;
      else if (event.key === 'Home') index = 0;
      else if (event.key === 'End') index = tabs.length - 1;
      else return;
      event.preventDefault(); tabs[index].focus(); setAnalysisTab(tabs[index].dataset.analysisTab);
    });
  });
  document.querySelector('#entityExplorerForm')?.addEventListener('submit', (event) => {
    event.preventDefault();
    searchAnalysisEntity(document.querySelector('#analysisEntityType').value, document.querySelector('#analysisEntityValue').value).catch(showAnalysisError);
  });
}
