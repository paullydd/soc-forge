function commandNode(tag, text, className) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined && text !== null) node.textContent = String(text);
  return node;
}

function commandMetric(label, value, destination, detectionTab) {
  const metric = commandNode(destination ? 'button' : 'div', undefined, 'metric command-metric');
  if (destination) {
    metric.type = 'button';
    metric.addEventListener('click', () => {
      if (detectionTab) setDetectionTab(detectionTab);
      setView(destination);
    });
  }
  metric.append(
    commandNode('div', label, 'metric-label'),
    commandNode('div', value, 'metric-value'),
  );
  return metric;
}

function renderCommandMetrics() {
  const target = document.querySelector('#metrics');
  if (!target) return;
  target.replaceChildren();
  const summary = state.workspace?.summary || {};
  const operations = state.operationsQueue?.operational_summary || {};
  const highCritical = Number(operations.critical_count || 0) + Number(operations.high_count || 0);
  [
    ['Investigations', state.investigations.length, 'investigations'],
    ['High / Critical Attention', highCritical, 'operations'],
    ['Open Response Actions', operations.response_action_count || 0, 'operations'],
    ['Alerts', summary.alert_count || 0, 'detection', 'alerts'],
    ['Hunts', summary.hunt_count || 0, 'hunts'],
  ].forEach(([label, value, destination, detectionTab]) => target.append(commandMetric(label, value, destination, detectionTab)));
}

function renderCommandAttention() {
  const target = document.querySelector('#commandTopAttention');
  if (!target) return;
  target.replaceChildren();
  const topItems = Array.isArray(state.operationsQueue?.operational_summary?.top_items)
    ? state.operationsQueue.operational_summary.top_items.slice(0, 4)
    : [];
  if (!topItems.length) {
    const empty = commandNode('div', undefined, 'empty-state compact-empty');
    empty.append(
      commandNode('strong', 'No items currently require Operations Queue attention.'),
      commandNode('p', 'This projection is derived from active Findings and open Response Actions.'),
    );
    target.append(empty);
    return;
  }
  topItems.forEach((item) => {
    const row = commandNode('article', undefined, 'attention-item');
    const head = commandNode('div', undefined, 'attention-item-head');
    head.append(
      operationsPill(item.priority, 'priority'),
      commandNode('span', item.item_type === 'response_action' ? 'Response Action' : 'Uncovered Finding', 'pill'),
      operationsPill(item.source_status, 'status'),
    );
    const identity = commandNode('div', undefined, 'attention-identity');
    identity.append(
      commandNode('strong', item.source_id, 'technical-id'),
      commandNode('span', item.investigation_id, 'technical-id muted'),
    );
    const reason = Array.isArray(item.priority_basis) && item.priority_basis.length
      ? item.priority_basis[0]
      : item.reason;
    const open = commandNode('button', item.item_type === 'response_action' ? 'Open Action' : 'Open Finding');
    open.type = 'button';
    open.addEventListener('click', () => openOperationsSource(item).catch((error) => {
      target.replaceChildren(commandNode('div', error.message, 'notice'));
    }));
    row.append(
      head,
      identity,
      commandNode('div', item.investigation_title, 'attention-title'),
      commandNode('p', reason || 'Authoritative Operations Queue attention item.', 'attention-reason'),
      commandNode('div', 'Updated ' + formatUtcTimestamp(item.updated_at, 'Unknown'), 'technical-id muted'),
      open,
    );
    target.append(row);
  });
}

function commandRecentActivity() {
  const alerts = Array.isArray(state.workspace?.alerts) ? state.workspace.alerts : [];
  const investigations = Array.isArray(state.investigations) ? state.investigations : [];
  const activity = [
    ...alerts.map((alert, alertIndex) => ({
      timestamp: alert.timestamp || alert.created_at || '',
      kind: 'Machine alert',
      id: alert.rule_id || alert.alert_id || 'Alert',
      description: alert.title || 'Detection alert observed',
      destination: 'detection',
      detectionTab: 'alerts',
      alertKey: detectionAlertKey(alert, alertIndex),
    })),
    ...investigations.map((investigation) => ({
      timestamp: investigation.updated_at || '',
      kind: 'Investigation',
      id: investigation.investigation_id,
      description: investigation.title || 'Durable Investigation updated',
      investigationId: investigation.investigation_id,
    })),
  ];
  return activity
    .sort((left, right) => String(right.timestamp).localeCompare(String(left.timestamp)) || String(left.id).localeCompare(String(right.id)))
    .slice(0, 7);
}

function renderCommandRecentActivity() {
  const target = document.querySelector('#commandRecentActivity');
  if (!target) return;
  target.replaceChildren();
  const activity = commandRecentActivity();
  if (!activity.length) {
    const empty = commandNode('div', undefined, 'empty-state compact-empty');
    empty.append(
      commandNode('strong', 'No current timestamped activity is available.'),
      commandNode('p', 'No generated alerts or durable Investigation updates are present.'),
    );
    target.append(empty);
    return;
  }
  activity.forEach((item) => {
    const row = commandNode('button', undefined, 'activity-item');
    row.type = 'button';
    row.append(
      commandNode('span', item.kind, 'activity-kind'),
      commandNode('strong', item.id, 'technical-id'),
      commandNode('span', item.description, 'activity-description'),
      presentationTime(item.timestamp, 'Timestamp unavailable'),
    );
    row.addEventListener('click', () => {
      if (item.investigationId) {
        openInvestigation(item.investigationId)
          .then(() => setView('investigations'))
          .catch((error) => target.replaceChildren(commandNode('div', error.message, 'notice')));
      } else {
        if (item.detectionTab) {
          state.activeDetectionAlertId = item.alertKey;
          setDetectionTab(item.detectionTab);
          renderDetectionAlerts();
        }
        setView(item.destination);
      }
    });
    target.append(row);
  });
}

function renderCommandSecurityActivity() {
  const target = document.querySelector('#commandSecurityActivity');
  if (!target) return;
  target.replaceChildren();
  const summary = state.workspace?.summary || {};
  const scorecard = state.workspace?.detection_scorecard || {};
  const hasMachineContext = Number(summary.alert_count || 0) > 0
    || Number(summary.case_count || 0) > 0
    || Number(summary.hunt_count || 0) > 0;
  if (!hasMachineContext) {
    target.append(commandNode('div', 'No current generated machine-analysis artifacts are available. Durable Investigation and Operations state remains separate.', 'notice'));
    return;
  }
  const facts = commandNode('div', undefined, 'security-facts');
  [
    ['Enabled rules', scorecard.enabled_rule_count ?? 'Unavailable'],
    ['Correlations', summary.correlated_alert_count ?? 'Unavailable'],
    ['Hunts', summary.hunt_count ?? 'Unavailable'],
    ['Cases', summary.case_count ?? 'Unavailable'],
  ].forEach(([label, value]) => {
    const fact = commandNode('div', undefined, 'security-fact');
    fact.append(commandNode('span', label), commandNode('strong', value));
    facts.append(fact);
  });
  const tactics = commandNode('div', undefined, 'tactic-summary');
  tactics.append(commandNode('strong', 'Top observed ATT&CK tactics'));
  const list = commandNode('ul');
  const rows = Array.isArray(summary.tactic_counts) ? summary.tactic_counts.slice(0, 5) : [];
  rows.forEach((row) => list.append(commandNode('li', row.tactic + ' — ' + row.count + ' observations')));
  if (!rows.length) list.append(commandNode('li', 'No explicit ATT&CK observations in current generated analysis.'));
  tactics.append(list, commandNode('p', 'Observed ATT&CK activity is not Detection Coverage.', 'muted'));
  target.append(facts, tactics);
}

function renderCommandCenter() {
  renderCommandMetrics();
  renderCommandAttention();
  renderCommandRecentActivity();
  renderCommandSecurityActivity();
}

function bindCommandCenter() {
  const openOperations = document.querySelector('#openOperationsButton');
  if (openOperations) openOperations.addEventListener('click', () => setView('operations'));
}
