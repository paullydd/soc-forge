const queryWorkbench = { filters: {}, revision: null };
const queryFilterFields = [
  ['start_time', 'Start time'], ['end_time', 'End time'],
  ['entry_type', 'Entry type'], ['host', 'Host'], ['user', 'User'],
  ['ip', 'IP'], ['process', 'Process'], ['rule_id', 'Rule ID'],
  ['attack_tactic', 'ATT&CK tactic'],
  ['attack_technique', 'ATT&CK technique'], ['severity', 'Severity'],
  ['evidence_classification', 'Evidence classification'],
  ['hypothesis_id', 'Hypothesis ID'], ['case_id', 'Case ID'],
];
const queryControlledFilters = {
  entry_type: [
    'event', 'alert', 'case', 'reconstruction_step',
    'analyst_evidence_selection', 'hypothesis_created',
    'hypothesis_assessed', 'hypothesis_reopened',
    'analyst_decision', 'annotation',
  ],
  severity: ['critical', 'high', 'medium', 'low'],
  evidence_classification: ['supporting', 'contradicting', 'context'],
};

function queryNode(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined && text !== null) node.textContent = String(text);
  return node;
}

function queryBase() {
  const id = state.activeInvestigation?.investigation?.investigation_id;
  if (!id) throw new Error('Open an investigation first');
  return `/api/investigations/${encodeURIComponent(id)}`;
}

async function queryGet(path) {
  const response = await fetch(path, { cache: 'no-store' });
  const payload = await response.json();
  if (!response.ok) {
    const error = new Error(
      investigationErrorMessage(payload, 'Timeline and pivot workbench unavailable'),
    );
    error.code = payload?.error?.code;
    throw error;
  }
  queryWorkbench.revision = payload.revision;
  const warning = $('#workbenchStaleWarning');
  if (warning) {
    warning.textContent = payload.revision !== state.activeInvestigation?.revision
      ? 'Workbench data may be stale. Refresh to use the latest investigation revision.'
      : '';
  }
  return payload;
}

function showQueryError(error) {
  const status = $('#workbenchStatus');
  if (!status) return;
  status.textContent = error.code === 'analysis_provenance_mismatch'
    ? 'The active analysis no longer matches this investigation. Reopen with the matching analysis.'
    : error.message;
}

function bindInvestigationWorkbench() {
  const actions = [
    ['#openTimelineWorkbenchButton', openQueryTimeline],
    ['#browseWorkbenchEntitiesButton', browseQueryEntities],
    ['#refreshWorkbenchButton', refreshQueryWorkbench],
  ];
  actions.forEach(([selector, handler]) => {
    const button = $(selector);
    if (button) button.addEventListener('click', () => handler().catch(showQueryError));
  });
  renderQueryFilters();
}

function renderQueryFilters() {
  const target = $('#workbenchFilters');
  if (!target) return;
  target.replaceChildren();
  const controls = queryNode('div', 'workbench-filter-grid');
  queryFilterFields.forEach(([field, label]) => {
    const wrapper = queryNode('label', 'workbench-filter');
    wrapper.append(queryNode('span', '', label));
    const options = queryControlledFilters[field];
    const input = queryNode(options ? 'select' : 'input');
    if (options) {
      const empty = queryNode('option', '', 'Any');
      empty.value = '';
      input.append(empty);
      options.forEach((value) => {
        const option = queryNode('option', '', value.replaceAll('_', ' '));
        option.value = value;
        input.append(option);
      });
    } else {
      input.type = 'text';
    }
    input.dataset.queryFilter = field;
    input.value = queryWorkbench.filters[field] || '';
    wrapper.append(input);
    controls.append(wrapper);
  });
  const actions = queryNode('div', 'workspace-actions');
  const apply = queryNode('button', 'primary-button', 'Apply Filters');
  apply.type = 'button';
  apply.addEventListener('click', () => {
    queryWorkbench.filters = {};
    target.querySelectorAll('[data-query-filter]').forEach((input) => {
      if (input.value.trim()) queryWorkbench.filters[input.dataset.queryFilter] = input.value.trim();
    });
    openQueryTimeline().catch(showQueryError);
  });
  const clear = queryNode('button', '', 'Clear Filters');
  clear.type = 'button';
  clear.addEventListener('click', () => {
    queryWorkbench.filters = {};
    renderQueryFilters();
    openQueryTimeline().catch(showQueryError);
  });
  actions.append(apply, clear);
  target.append(controls, actions);
  renderActiveQueryFilters();
}

function renderActiveQueryFilters() {
  const target = $('#workbenchActiveFilters');
  if (!target) return;
  target.replaceChildren(queryNode('strong', '', 'Active Filters'));
  const values = Object.entries(queryWorkbench.filters);
  if (!values.length) target.append(queryNode('span', 'muted', 'None'));
  values.forEach(([field, value]) => {
    const label = queryFilterFields.find(([key]) => key === field)?.[1] || field;
    target.append(queryNode('span', 'pill', `${label}: ${value}`));
  });
}

async function openQueryTimeline() {
  renderActiveQueryFilters();
  const query = new URLSearchParams(queryWorkbench.filters).toString();
  const payload = await queryGet(`${queryBase()}/timeline${query ? `?${query}` : ''}`);
  renderQueryTimeline(payload);
}

function renderQueryTimeline(payload) {
  const target = $('#workbenchContent');
  target.replaceChildren(queryNode('h4', '', 'Chronological Activity'));
  asArray(payload.timed_entries).forEach((entry) => target.append(queryTimelineRow(entry)));
  if (!asArray(payload.timed_entries).length) target.append(queryNode('div', 'muted', 'No timed entries.'));
  target.append(queryNode('h4', '', 'Untimed Investigation Context'));
  asArray(payload.untimed_entries).forEach((entry) => target.append(queryTimelineRow(entry, true)));
  if (!asArray(payload.untimed_entries).length) target.append(queryNode('div', 'muted', 'No untimed entries.'));
}

function queryTimelineRow(entry, untimed = false) {
  const row = queryNode('button', 'workbench-row');
  row.type = 'button';
  row.append(
    queryNode('strong', '', `${untimed ? 'Untimed' : entry.timestamp} | ${entry.entry_type} | ${entry.title}`),
    queryNode('span', 'muted', [entry.context_kind, entry.host, entry.user, entry.rule_id, ...asArray(entry.case_ids)].filter(Boolean).join(' | ')),
  );
  if (entry.evidence_classification) row.append(queryNode('span', 'pill', `Analyst evidence: ${entry.evidence_classification}`));
  if (asArray(entry.hypothesis_overlays).length) row.append(queryNode('span', 'pill', 'Hypothesis overlay'));
  if (asArray(entry.sensitive_fields).length) row.append(queryNode('span', 'evidence-warning', 'Sensitive fields present'));
  row.addEventListener('click', () => openQueryEntry(entry.entry_id).catch(showQueryError));
  return row;
}

async function openQueryEntry(entryId) {
  const payload = await queryGet(`${queryBase()}/timeline/${encodeURIComponent(entryId)}`);
  const target = $('#workbenchContent');
  target.replaceChildren(queryNode('h4', '', 'Timeline Entry Details'));
  const entry = payload.entry;
  [
    ['Entry ID', entry.entry_id], ['Timestamp', entry.timestamp || 'Untimed'],
    ['Type', entry.entry_type], ['Source ID', entry.source_id],
    ['Source analysis ID', entry.source_analysis_id],
    ['Cases', asArray(entry.case_ids).join(', ') || 'None'],
    ['Title', entry.title], ['Summary', entry.summary], ['Host', entry.host],
    ['User', entry.user], ['IP', entry.ip], ['Process', entry.process],
    ['Rule', entry.rule_id], ['Severity', entry.severity],
    ['ATT&CK tactic', entry.attack_tactic],
    ['ATT&CK technique', entry.attack_technique],
    ['Why this entry is present', entry.relationship_reason],
  ].forEach(([label, value]) => {
    const line = queryNode('div', 'workbench-detail-row');
    line.append(queryNode('span', 'muted', label), queryNode('strong', '', value || 'None'));
    target.append(line);
  });
  const actions = queryNode('div', 'workspace-actions');
  if (payload.navigation.evidence_id) {
    const button = queryNode('button', '', 'View Evidence');
    button.addEventListener('click', () => inspectEvidence(payload.navigation.evidence_id, false).catch(showEvidenceError));
    actions.append(button);
  }
  asArray(payload.navigation.hypothesis_ids).forEach((id) => {
    const button = queryNode('button', '', `View Hypothesis ${id}`);
    button.addEventListener('click', () => showWebHypothesis(id).catch(showReasoningError));
    actions.append(button);
  });
  asArray(payload.navigation.decision_ids).forEach((id) => {
    const button = queryNode('button', '', `View Decision ${id}`);
    button.addEventListener('click', () => showQueryDecision(id).catch(showReasoningError));
    actions.append(button);
  });
  target.append(actions);
}

async function showQueryDecision(id) {
  const payload = await reasoningGet(`${activeReasoningBase()}/reasoning/decisions/${encodeURIComponent(id)}`);
  $('#reasoningWorkspace').replaceChildren(renderWebDecision(payload.decision));
}

async function browseQueryEntities(type = '') {
  const payload = await queryGet(`${queryBase()}/entities${type ? `?type=${encodeURIComponent(type)}` : ''}`);
  const target = $('#workbenchContent');
  target.replaceChildren(queryNode('h4', '', 'Normalized Entities'));
  const select = queryNode('select');
  ['', 'host', 'user', 'ip', 'process', 'service', 'rule', 'attack_technique', 'case', 'evidence', 'hypothesis'].forEach((value) => {
    const option = queryNode('option', '', value || 'All entity types');
    option.value = value;
    select.append(option);
  });
  select.value = type;
  select.addEventListener('change', () => browseQueryEntities(select.value).catch(showQueryError));
  target.append(select);
  asArray(payload.entities).forEach((entity) => {
    const row = queryNode('div', 'workbench-row');
    row.append(
      queryNode('strong', '', `${entity.entity_type}: ${entity.display_value}`),
      queryNode('span', 'muted', `Normalized: ${entity.normalized_value}`),
      queryNode('span', '', `Events ${entity.observed_counts.events} | Alerts ${entity.observed_counts.alerts} | Cases ${entity.observed_counts.cases}`),
      queryNode('span', 'muted', `First ${entity.first_seen || 'Untimed'} | Last ${entity.last_seen || 'Untimed'}`),
    );
    const button = queryNode('button', '', 'Open Pivot');
    button.addEventListener('click', () => openQueryPivot(entity).catch(showQueryError));
    row.append(button);
    target.append(row);
  });
}

async function openQueryPivot(entity) {
  const root = `${queryBase()}/entities/${encodeURIComponent(entity.entity_id)}`;
  const categories = ['events', 'alerts', 'cases', 'evidence', 'hypotheses', 'related', 'timeline'];
  const payloads = await Promise.all(categories.map((name) => queryGet(`${root}/${name}`)));
  const target = $('#workbenchContent');
  target.replaceChildren(queryNode('h4', '', `${entity.entity_type}: ${entity.display_value}`));
  categories.forEach((category, index) => {
    const payload = payloads[index];
    target.append(queryNode('h5', '', category === 'related' ? 'Observed Relationships' : category));
    if (category === 'timeline') {
      asArray(payload.timed_entries).forEach((entry) => target.append(queryTimelineRow(entry)));
      asArray(payload.untimed_entries).forEach((entry) => target.append(queryTimelineRow(entry, true)));
      return;
    }
    const items = category === 'related' ? payload.relationships : payload.matches;
    asArray(items).forEach((item) => {
      const row = queryNode('div', 'workbench-pivot-row');
      const identity = category === 'related'
        ? `${item.entity.entity_type}: ${item.entity.display_value}`
        : `${item.source_type}: ${item.source_id}`;
      row.append(queryNode('strong', '', identity), queryNode('span', '', `Reason: ${item.relationship_reason}`));
      if (item.evidence_classification) row.append(queryNode('span', 'pill', `Analyst evidence: ${item.evidence_classification}`));
      if (item.evidence_id) {
        const evidence = queryNode('button', '', 'View Evidence');
        evidence.addEventListener('click', () => inspectEvidence(item.evidence_id, false).catch(showEvidenceError));
        row.append(evidence);
      }
      asArray(item.hypothesis_overlays).forEach((overlay) => {
        const hypothesis = queryNode('button', '', `Hypothesis ${overlay.hypothesis_id}: ${overlay.relationship} (${overlay.state})`);
        hypothesis.addEventListener('click', () => showWebHypothesis(overlay.hypothesis_id).catch(showReasoningError));
        row.append(hypothesis);
      });
      asArray(item.decision_overlays).forEach((overlay) => {
        const decision = queryNode('button', '', `Decision ${overlay.decision_id}: ${overlay.decision_type}`);
        decision.addEventListener('click', () => showQueryDecision(overlay.decision_id).catch(showReasoningError));
        row.append(decision);
      });
      target.append(row);
    });
  });
}

async function refreshQueryWorkbench() {
  const id = state.activeInvestigation.investigation.investigation_id;
  await openInvestigation(id);
  await openQueryTimeline();
}
