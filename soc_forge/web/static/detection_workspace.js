function detectionNode(tag, text, className) {
  const node = document.createElement(tag);
  if (text !== undefined && text !== null) node.textContent = String(text);
  if (className) node.className = className;
  return node;
}

function detectionArray(value) {
  return Array.isArray(value) ? value : [];
}

function detectionButton(label, handler, className) {
  const button = detectionNode('button', label, className);
  button.type = 'button';
  button.addEventListener('click', handler);
  return button;
}

function detectionSeverity(value) {
  const normalized = String(value || 'unknown').toLowerCase();
  return ['critical', 'high', 'medium', 'low'].includes(normalized)
    ? normalized : 'unknown';
}

function detectionBadge(value, extraClass = '') {
  const text = String(value || 'Unknown');
  return detectionNode(
    'span',
    text,
    `badge badge-${detectionSeverity(text)} ${extraClass}`.trim(),
  );
}

function detectionSection(eyebrow, title, description) {
  const section = detectionNode('section', null, 'panel detection-section');
  const head = detectionNode('div', null, 'panel-head');
  const copy = detectionNode('div');
  if (eyebrow) copy.appendChild(detectionNode('div', eyebrow, 'eyebrow'));
  copy.appendChild(detectionNode('h3', title));
  if (description) copy.appendChild(detectionNode('p', description, 'muted'));
  head.appendChild(copy);
  section.appendChild(head);
  return section;
}

function detectionMetric(label, value, primary = false) {
  const item = detectionNode('div', null, primary ? 'detection-metric primary' : 'detection-metric');
  item.append(
    detectionNode('span', label, 'metric-label'),
    detectionNode('strong', value, 'detection-metric-value'),
  );
  return item;
}

function detectionAlerts() {
  return detectionArray(state.workspace?.alerts);
}

function detectionRules() {
  return detectionArray(state.workspace?.detection_rules);
}

function detectionAlertKey(alert, index) {
  return `${alert.rule_id || 'unknown'}:${alert.timestamp || 'untimed'}:${index}`;
}

function detectionRuleCounts() {
  const counts = new Map();
  detectionAlerts().forEach((alert) => {
    const id = String(alert.rule_id || 'Unknown rule');
    counts.set(id, (counts.get(id) || 0) + 1);
  });
  return counts;
}

function detectionAttackMappings(values) {
  return detectionArray(values).filter((item) => item && typeof item === 'object');
}

function observedAttackMappings() {
  const counts = new Map();
  detectionAlerts().forEach((alert) => {
    detectionAttackMappings(alert.mitre).forEach((mapping) => {
      const tactic = String(mapping.tactic || '').trim();
      const techniqueId = String(mapping.technique_id || mapping.id || '').trim();
      const technique = String(mapping.technique || '').trim();
      if (!tactic && !techniqueId && !technique) return;
      const key = `${tactic}\u0000${techniqueId}\u0000${technique}`;
      const current = counts.get(key) || { tactic, technique_id: techniqueId, technique, count: 0 };
      current.count += 1;
      counts.set(key, current);
    });
  });
  return [...counts.values()].sort((a, b) => (
    b.count - a.count
    || a.tactic.localeCompare(b.tactic)
    || a.technique_id.localeCompare(b.technique_id)
  ));
}

function coverageAttackMappings() {
  const rulesByMapping = new Map();
  detectionRules().forEach((rule) => {
    detectionAttackMappings(rule.attack_mappings).forEach((mapping) => {
      const tactic = String(mapping.tactic || '').trim();
      const techniqueId = String(mapping.technique_id || '').trim();
      const technique = String(mapping.technique || '').trim();
      const key = `${tactic}\u0000${techniqueId}\u0000${technique}`;
      const current = rulesByMapping.get(key) || {
        tactic, technique_id: techniqueId, technique, rule_ids: [],
      };
      current.rule_ids.push(rule.rule_id);
      rulesByMapping.set(key, current);
    });
  });
  return [...rulesByMapping.values()].sort((a, b) => (
    a.tactic.localeCompare(b.tactic) || a.technique_id.localeCompare(b.technique_id)
  ));
}

function setDetectionTab(tab) {
  const allowed = new Set(['overview', 'alerts', 'rules', 'attack', 'health']);
  state.detectionTab = allowed.has(tab) ? tab : 'overview';
  document.querySelectorAll('[data-detection-tab]').forEach((button) => {
    const active = button.dataset.detectionTab === state.detectionTab;
    button.classList.toggle('active', active);
    button.setAttribute('aria-selected', String(active));
    button.setAttribute('aria-controls', 'detection-panel-' + button.dataset.detectionTab);
    button.tabIndex = active ? 0 : -1;
  });
  document.querySelectorAll('[data-detection-panel]').forEach((panel) => {
    panel.id = 'detection-panel-' + panel.dataset.detectionPanel;
    panel.setAttribute('role', 'tabpanel');
    panel.setAttribute('aria-labelledby', 'detection-tab-' + panel.dataset.detectionPanel);
    panel.hidden = panel.dataset.detectionPanel !== state.detectionTab;
  });
}

function bindDetectionWorkspace() {
  document.querySelectorAll('[data-detection-tab]').forEach((button) => {
    button.id = 'detection-tab-' + button.dataset.detectionTab;
    button.addEventListener('click', () => setDetectionTab(button.dataset.detectionTab));
    button.addEventListener('keydown', (event) => {
      if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return;
      const tabs = [...document.querySelectorAll('[data-detection-tab]')];
      const current = tabs.indexOf(button);
      const target = event.key === 'Home' ? 0
        : event.key === 'End' ? tabs.length - 1
          : (current + (event.key === 'ArrowRight' ? 1 : -1) + tabs.length) % tabs.length;
      event.preventDefault();
      tabs[target].focus();
      setDetectionTab(tabs[target].dataset.detectionTab);
    });
  });
}

function openDetectionAlert(key) {
  state.activeDetectionAlertId = key;
  setDetectionTab('alerts');
  renderDetectionAlerts();
}

function openDetectionRule(ruleId) {
  state.activeDetectionRuleId = ruleId;
  setDetectionTab('rules');
  renderDetectionRules();
}

function renderDetectionOverview() {
  const mount = document.querySelector('#detectionOverview');
  if (!mount) return;
  mount.replaceChildren();
  const alerts = detectionAlerts();
  const rules = detectionRules();
  const counts = detectionRuleCounts();
  const scorecard = state.workspace?.detection_scorecard || {};
  const highPriority = alerts.filter((item) => ['critical', 'high'].includes(detectionSeverity(item.severity)));

  const metrics = detectionNode('div', null, 'detection-overview-metrics');
  metrics.append(
    detectionMetric('Current alerts', alerts.length, true),
    detectionMetric('Critical / high', highPriority.length, true),
    detectionMetric('Triggered rules', counts.size, true),
    detectionMetric('Enabled rules', scorecard.enabled_rule_count ?? 'Unavailable'),
    detectionMetric('Program grade', scorecard.grade || 'Unknown'),
  );
  mount.appendChild(metrics);

  const grid = detectionNode('div', null, 'detection-overview-grid');
  const priority = detectionSection(
    'Priority alerts', 'Current machine detections',
    'Severity is textual and reflects the existing alert projection.',
  );
  const priorityList = detectionNode('div', null, 'detection-record-list');
  const indexed = alerts.map((alert, index) => ({ alert, key: detectionAlertKey(alert, index) }));
  indexed.slice(0, 6).forEach(({ alert, key }) => {
    const row = detectionButton('', () => openDetectionAlert(key), 'detection-record');
    row.setAttribute('aria-label', `Open ${alert.severity || 'unknown'} alert ${alert.title || alert.rule_id || ''}`);
    const head = detectionNode('div', null, 'detection-record-head');
    head.append(detectionBadge(alert.severity), detectionNode('span', alert.rule_id || 'Unknown rule', 'technical-id'));
    row.append(
      head,
      detectionNode('strong', alert.title || 'Untitled alert'),
      presentationTime(alert.timestamp, 'Unknown time'),
    );
    priorityList.appendChild(row);
  });
  if (!alerts.length) priorityList.appendChild(detectionNode('div', 'No machine-generated alerts are available in the current analysis.', 'empty-state'));
  priority.appendChild(priorityList);

  const activity = detectionSection(
    'Rule activity', 'Triggered rule summary',
    'Counts reflect alerts in the current analysis; they do not modify rule state.',
  );
  const ruleList = detectionNode('div', null, 'detection-compact-list');
  [...counts.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])).slice(0, 8)
    .forEach(([ruleId, count]) => {
      const ruleAvailable = rules.some((rule) => rule.rule_id === ruleId);
      const row = ruleAvailable
        ? detectionButton('', () => openDetectionRule(ruleId), 'detection-compact-row')
        : detectionNode('div', null, 'detection-compact-row');
      row.append(
        detectionNode('span', ruleId, 'technical-id'),
        detectionNode('strong', ruleAvailable
          ? `${count} alert${count === 1 ? '' : 's'}`
          : `${count} generated correlation alert${count === 1 ? '' : 's'}`),
      );
      ruleList.appendChild(row);
    });
  if (!counts.size) ruleList.appendChild(detectionNode('p', 'No rules triggered in the current analysis.', 'muted'));
  activity.appendChild(ruleList);
  grid.append(priority, activity);
  mount.appendChild(grid);

  const posture = detectionSection(
    'Detection posture', 'Program context',
    'Rule coverage and observed activity are reviewed separately in ATT&CK.',
  );
  const facts = detectionNode('div', null, 'detection-facts');
  facts.append(
    detectionMetric('Loaded rules', rules.length),
    detectionMetric('Quality gate', scorecard.quality_gate === true ? 'Pass' : scorecard.quality_gate === false ? 'Review' : 'Unknown'),
    detectionMetric('Correlation alerts', scorecard.correlation_alert_count ?? 'Unavailable'),
    detectionMetric('Observed ATT&CK mappings', observedAttackMappings().length),
  );
  posture.appendChild(facts);
  mount.appendChild(posture);
}

function alertContextRows(alert) {
  const details = alert.details && typeof alert.details === 'object' ? alert.details : {};
  const preferred = ['host', 'hostname', 'user', 'username', 'src_ip', 'source_ip', 'ip', 'process_name', 'service_name', 'target_user'];
  return preferred
    .map((key) => [key, alert[key] ?? details[key]])
    .filter(([, value]) => value !== undefined && value !== null && value !== '');
}

function renderAttackMappingList(mappings, emptyText) {
  const list = detectionNode('div', null, 'attack-mapping-list');
  mappings.forEach((mapping) => {
    const row = detectionNode('div', null, 'attack-mapping-row');
    row.append(
      detectionNode('strong', mapping.tactic || 'Tactic not specified'),
      detectionNode('span', [mapping.technique_id, mapping.technique].filter(Boolean).join(' — ') || 'Technique not specified', 'technical-id'),
    );
    if (mapping.count !== undefined) row.appendChild(detectionNode('span', `${mapping.count} alert${mapping.count === 1 ? '' : 's'}`, 'badge'));
    if (mapping.rule_ids) row.appendChild(detectionNode('span', `${mapping.rule_ids.length} rule${mapping.rule_ids.length === 1 ? '' : 's'}`, 'badge'));
    list.appendChild(row);
  });
  if (!mappings.length) list.appendChild(detectionNode('p', emptyText, 'muted'));
  return list;
}

function renderAlertDetail(alert) {
  const detail = detectionNode('article', null, 'detection-detail');
  if (!alert) {
    detail.appendChild(detectionNode('div', 'Select an alert to inspect its detection reason and context.', 'empty-state'));
    return detail;
  }
  const identity = detectionNode('div', null, 'detection-detail-head');
  const title = detectionNode('div');
  title.append(
    detectionNode('div', alert.rule_id || 'Unknown rule', 'technical-id'),
    detectionNode('h3', alert.title || 'Untitled alert'),
  );
  identity.append(title, detectionBadge(alert.severity));
  detail.append(identity);
  detail.appendChild(detectionNode('p', 'Machine-generated detection alert', 'detection-attribution'));

  const facts = detectionNode('dl', null, 'detection-detail-grid');
  [
    ['Timestamp', alert.timestamp || 'Unknown'],
    ['Score', alert.score ?? 'Unavailable'],
    ['Correlation ID', alert.correlation_id || 'None'],
  ].forEach(([label, value]) => {
    facts.append(detectionNode('dt', label), detectionNode('dd', value, label === 'Timestamp' || label === 'Correlation ID' ? 'technical-id' : ''));
  });
  detail.appendChild(facts);

  const details = alert.details && typeof alert.details === 'object' ? alert.details : {};
  detail.append(
    detectionNode('h4', 'Detection reason'),
    detectionNode('p', details.message || alert.message || alert.title || 'No additional detection reason was projected.'),
  );

  const context = alertContextRows(alert);
  detail.appendChild(detectionNode('h4', 'Affected entities and context'));
  if (context.length) {
    const contextList = detectionNode('dl', null, 'detection-detail-grid');
    context.forEach(([key, value]) => contextList.append(
      detectionNode('dt', key.replaceAll('_', ' ')),
      detectionNode('dd', value, 'technical-id'),
    ));
    detail.appendChild(contextList);
  } else detail.appendChild(detectionNode('p', 'No normalized entity context was projected for this alert.', 'muted'));

  detail.append(
    detectionNode('h4', 'Observed ATT&CK mapping'),
    detectionNode('p', 'Mappings are observed on this alert and do not prove attacker intent.', 'muted'),
    renderAttackMappingList(detectionAttackMappings(alert.mitre), 'No ATT&CK mapping is present on this alert.'),
  );

  const supporting = Object.entries(details).filter(([key]) => !['message'].includes(key));
  const disclosure = detectionNode('details', null, 'technical-disclosure');
  disclosure.appendChild(detectionNode('summary', 'Supporting metadata'));
  if (supporting.length) {
    const metadata = detectionNode('dl', null, 'detection-detail-grid');
    supporting.forEach(([key, value]) => metadata.append(
      detectionNode('dt', key.replaceAll('_', ' ')),
      detectionNode('dd', typeof value === 'object' ? JSON.stringify(value) : value, 'technical-id'),
    ));
    disclosure.appendChild(metadata);
  } else disclosure.appendChild(detectionNode('p', 'No supporting metadata was projected.', 'muted'));
  detail.appendChild(disclosure);
  if (detectionRules().some((rule) => rule.rule_id === alert.rule_id)) {
    detail.appendChild(detectionButton('Open Rule Explainability', () => openDetectionRule(alert.rule_id), 'primary-button'));
  }
  return detail;
}

function renderDetectionAlerts() {
  const mount = document.querySelector('#detectionAlerts');
  if (!mount) return;
  mount.replaceChildren();
  const toolbar = detectionNode('div', null, 'detection-toolbar');
  const heading = detectionNode('div');
  heading.append(detectionNode('div', 'Current analysis', 'eyebrow'), detectionNode('h3', 'Machine-generated alerts'));
  const filter = detectionNode('select');
  filter.setAttribute('aria-label', 'Filter alerts by severity');
  ['all', 'critical', 'high', 'medium', 'low'].forEach((value) => {
    const option = detectionNode('option', value === 'all' ? 'All severities' : value[0].toUpperCase() + value.slice(1));
    option.value = value;
    option.selected = state.detectionSeverity === value;
    filter.appendChild(option);
  });
  filter.addEventListener('change', () => {
    state.detectionSeverity = filter.value;
    state.activeDetectionAlertId = null;
    renderDetectionAlerts();
  });
  toolbar.append(heading, filter);
  mount.appendChild(toolbar);

  const all = detectionAlerts().map((alert, index) => ({ alert, key: detectionAlertKey(alert, index) }));
  const rows = all.filter(({ alert }) => (
    (state.detectionSeverity === 'all' || detectionSeverity(alert.severity) === state.detectionSeverity)
    && matchesSearch(alert)
  ));
  if (!rows.some((item) => item.key === state.activeDetectionAlertId)) {
    state.activeDetectionAlertId = rows[0]?.key || null;
  }
  const layout = detectionNode('div', null, 'detection-browser');
  const list = detectionNode('div', null, 'detection-record-list detection-browser-list');
  rows.forEach(({ alert, key }) => {
    const row = detectionButton('', () => openDetectionAlert(key), 'detection-record');
    row.classList.toggle('active', key === state.activeDetectionAlertId);
    row.setAttribute('aria-pressed', String(key === state.activeDetectionAlertId));
    const head = detectionNode('div', null, 'detection-record-head');
    head.append(detectionBadge(alert.severity), detectionNode('span', alert.rule_id || 'Unknown rule', 'technical-id'));
    row.append(head, detectionNode('strong', alert.title || 'Untitled alert'), presentationTime(alert.timestamp, 'Unknown time'));
    const context = alertContextRows(alert).slice(0, 3).map(([keyName, value]) => `${keyName.replaceAll('_', ' ')}: ${value}`).join(' · ');
    if (context) row.appendChild(detectionNode('span', context, 'muted'));
    list.appendChild(row);
  });
  if (!rows.length) list.appendChild(detectionNode('div', 'No alerts match the current severity and analysis filter.', 'empty-state'));
  const selected = rows.find((item) => item.key === state.activeDetectionAlertId)?.alert;
  layout.append(list, renderAlertDetail(selected));
  mount.appendChild(layout);
}

function renderRuleDetail(rule, count) {
  const detail = detectionNode('article', null, 'detection-detail');
  if (!rule) {
    detail.appendChild(detectionNode('div', 'Select a rule to inspect deterministic metadata and current trigger context.', 'empty-state'));
    return detail;
  }
  const head = detectionNode('div', null, 'detection-detail-head');
  const title = detectionNode('div');
  title.append(detectionNode('div', rule.rule_id, 'technical-id'), detectionNode('h3', rule.title));
  head.append(title, detectionBadge(rule.severity));
  detail.append(head, detectionNode('p', 'Deterministic loaded-rule metadata', 'detection-attribution'));
  detail.appendChild(detectionNode('p', rule.description || 'No rule description was provided.'));
  const facts = detectionNode('dl', null, 'detection-detail-grid');
  [
    ['State', rule.enabled ? 'Enabled' : 'Disabled'],
    ['Current triggers', count],
    ['Rule score', rule.score],
    ['Log source', rule.logsource || 'Not specified'],
    ['Author', rule.author || 'Not specified'],
    ['Created', rule.created || 'Not specified'],
  ].forEach(([label, value]) => facts.append(detectionNode('dt', label), detectionNode('dd', value)));
  detail.appendChild(facts);

  detail.append(
    detectionNode('h4', 'ATT&CK detection coverage'),
    detectionNode('p', 'These mappings describe what the loaded rule is designed to detect; they are not observed activity.', 'muted'),
    renderAttackMappingList(detectionAttackMappings(rule.attack_mappings), 'No ATT&CK mapping is defined for this rule.'),
  );

  detail.appendChild(detectionNode('h4', 'Why this rule fires'));
  const explanation = detectionNode('dl', null, 'detection-explainability');
  [
    ['Match conditions', rule.match_metadata],
    ['Emitted context', rule.emit_metadata],
    ['Aggregation / window', rule.aggregate_metadata],
    ['Score modifiers', rule.score_modifiers_metadata],
  ].forEach(([label, value]) => {
    explanation.append(detectionNode('dt', label), detectionNode('dd', value || 'None', 'technical-code'));
  });
  detail.appendChild(explanation);

  const related = detectionAlerts().map((alert, index) => ({ alert, key: detectionAlertKey(alert, index) }))
    .filter(({ alert }) => alert.rule_id === rule.rule_id);
  detail.appendChild(detectionNode('h4', 'Contributing current alerts'));
  if (related.length) {
    const list = detectionNode('div', null, 'detection-compact-list');
    related.slice(0, 10).forEach(({ alert, key }) => {
      const row = detectionButton('', () => openDetectionAlert(key), 'detection-compact-row');
      row.append(presentationTime(alert.timestamp, 'Unknown time'), detectionNode('strong', alert.title || rule.title));
      list.appendChild(row);
    });
    detail.appendChild(list);
  } else detail.appendChild(detectionNode('p', 'This rule did not trigger in the current analysis.', 'muted'));
  return detail;
}

function renderDetectionRules() {
  const mount = document.querySelector('#detectionRules');
  if (!mount) return;
  mount.replaceChildren();
  const counts = detectionRuleCounts();
  const toolbar = detectionNode('div', null, 'detection-toolbar');
  const heading = detectionNode('div');
  heading.append(detectionNode('div', 'Loaded catalog', 'eyebrow'), detectionNode('h3', 'Rules and explainability'));
  const filter = detectionNode('select');
  filter.setAttribute('aria-label', 'Filter detection rules');
  [
    ['all', 'All rules'], ['triggered', 'Triggered'], ['not_triggered', 'Not triggered'],
    ['critical', 'Critical'], ['high', 'High'], ['medium', 'Medium'], ['low', 'Low'],
  ].forEach(([value, label]) => {
    const option = detectionNode('option', label);
    option.value = value;
    option.selected = state.detectionRuleFilter === value;
    filter.appendChild(option);
  });
  filter.addEventListener('change', () => {
    state.detectionRuleFilter = filter.value;
    state.activeDetectionRuleId = null;
    renderDetectionRules();
  });
  toolbar.append(heading, filter);
  mount.appendChild(toolbar);

  const rules = detectionRules().filter((rule) => {
    const filterValue = state.detectionRuleFilter;
    const triggered = counts.has(rule.rule_id);
    const filterMatch = filterValue === 'all'
      || (filterValue === 'triggered' && triggered)
      || (filterValue === 'not_triggered' && !triggered)
      || detectionSeverity(rule.severity) === filterValue;
    return filterMatch && matchesSearch(rule);
  });
  if (!rules.some((rule) => rule.rule_id === state.activeDetectionRuleId)) {
    state.activeDetectionRuleId = rules[0]?.rule_id || null;
  }
  const layout = detectionNode('div', null, 'detection-browser');
  const list = detectionNode('div', null, 'detection-record-list detection-browser-list');
  rules.forEach((rule) => {
    const active = rule.rule_id === state.activeDetectionRuleId;
    const row = detectionButton('', () => openDetectionRule(rule.rule_id), 'detection-record');
    row.classList.toggle('active', active);
    row.setAttribute('aria-pressed', String(active));
    const head = detectionNode('div', null, 'detection-record-head');
    head.append(detectionBadge(rule.severity), detectionNode('span', rule.rule_id, 'technical-id'));
    row.append(
      head,
      detectionNode('strong', rule.title),
      detectionNode('span', `${rule.enabled ? 'Enabled' : 'Disabled'} · ${counts.get(rule.rule_id) || 0} current alerts`, 'muted'),
    );
    list.appendChild(row);
  });
  if (!rules.length) list.appendChild(detectionNode('div', 'No loaded rules match the current filter.', 'empty-state'));
  const selected = rules.find((rule) => rule.rule_id === state.activeDetectionRuleId);
  layout.append(list, renderRuleDetail(selected, selected ? counts.get(selected.rule_id) || 0 : 0));
  mount.appendChild(layout);
}

function renderDetectionAttack() {
  const mount = document.querySelector('#detectionAttack');
  if (!mount) return;
  mount.replaceChildren();
  const intro = detectionNode('div', null, 'notice detection-semantic-notice');
  intro.append(
    detectionNode('strong', 'Two different questions'),
    detectionNode('span', 'Detection Coverage describes loaded rule mappings. Observed ATT&CK Activity describes mappings present in the current analysis. Neither implies complete coverage or proves attacker intent.'),
  );
  mount.appendChild(intro);
  const grid = detectionNode('div', null, 'detection-attack-grid');
  const coverage = detectionSection(
    'Loaded rules', 'Detection Coverage',
    'What the enabled and disabled loaded rules are mapped to detect.',
  );
  coverage.appendChild(renderAttackMappingList(coverageAttackMappings(), 'No loaded rules contain ATT&CK mappings.'));
  const observed = detectionSection(
    'Current analysis', 'Observed ATT&CK Activity',
    'Mappings present on machine-generated alerts; observation is not proof of attacker intent.',
  );
  observed.appendChild(renderAttackMappingList(observedAttackMappings(), 'No ATT&CK activity was observed in current alerts.'));
  grid.append(coverage, observed);
  mount.appendChild(grid);
}

function renderDetectionHealth() {
  const mount = document.querySelector('#detectionHealth');
  if (!mount) return;
  mount.replaceChildren();
  const scorecard = state.workspace?.detection_scorecard || {};
  const hero = detectionNode('section', null, 'detection-health-hero');
  const grade = detectionNode('div');
  grade.append(detectionNode('span', 'Existing program grade', 'metric-label'), detectionNode('strong', scorecard.grade || 'Unknown', 'scorecard-grade'));
  const score = detectionNode('div');
  score.append(detectionNode('span', 'Existing program score', 'metric-label'), detectionNode('strong', scorecard.overall_score === undefined ? 'Unknown' : `${scorecard.overall_score}/100`, 'scorecard-score'));
  const facts = detectionNode('dl', null, 'detection-health-facts');
  [
    ['Quality gate', scorecard.quality_gate === true ? 'Pass' : scorecard.quality_gate === false ? 'Review' : 'Unknown'],
    ['Enabled rules', `${scorecard.enabled_rule_count ?? 'Unknown'} / ${scorecard.rule_count ?? 'Unknown'}`],
    ['Quality errors', scorecard.finding_counts?.errors ?? 'Unknown'],
    ['Quality warnings', scorecard.finding_counts?.warnings ?? 'Unknown'],
  ].forEach(([label, value]) => facts.append(detectionNode('dt', label), detectionNode('dd', value)));
  hero.append(grade, score, facts);
  mount.append(hero, detectionNode('p', 'This preserves the existing scorecard calculation. Unknown values are unavailable, not failures.', 'muted'));

  const categories = detectionSection('Authoritative components', 'Score components', 'Scores and details are unchanged from the existing Detection Scorecard projection.');
  const categoryGrid = detectionNode('div', null, 'detection-health-grid');
  detectionArray(scorecard.categories).forEach((item) => {
    const card = detectionNode('article', null, 'detection-health-card');
    const head = detectionNode('div', null, 'detection-record-head');
    head.append(detectionNode('strong', item.name), detectionNode('span', `${item.grade} ${item.score}/100`, 'badge'));
    const track = detectionNode('div', null, 'score-track');
    const fill = detectionNode('div', null, 'score-fill');
    fill.style.width = `${Math.max(0, Math.min(100, Number(item.score || 0)))}%`;
    track.appendChild(fill);
    card.append(head, track, detectionNode('p', item.detail, 'muted'));
    categoryGrid.appendChild(card);
  });
  if (!scorecard.categories?.length) categoryGrid.appendChild(detectionNode('div', 'Detection health is unavailable.', 'empty-state'));
  categories.appendChild(categoryGrid);
  mount.appendChild(categories);
}

function renderDetectionWorkspace() {
  if (!state.workspace) return;
  const status = document.querySelector('#detectionAnalysisStatus');
  if (status) {
    const hasAnalysis = detectionAlerts().length > 0 || detectionArray(state.workspace?.cases).length > 0;
    status.lastChild.textContent = hasAnalysis ? 'Current analysis loaded' : 'No generated analysis';
    status.classList.toggle('status-available', hasAnalysis);
  }
  renderDetectionOverview();
  renderDetectionAlerts();
  renderDetectionRules();
  renderDetectionAttack();
  renderDetectionHealth();
  setDetectionTab(state.detectionTab);
}
