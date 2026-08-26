function operationsNode(tag, text, className) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = String(text);
  return node;
}

async function loadOperationsQueue() {
  const response = await fetch('/api/operations-queue', { cache: 'no-store' });
  const payload = await response.json();
  if (!response.ok) throw new Error(payload.error || 'Unable to load analyst operations queue');
  state.operationsQueue = payload;
  renderOperationsQueue();
}

function operationsItems() {
  const items = Array.isArray(state.operationsQueue?.items) ? state.operationsQueue.items : [];
  if (state.operationsFilter === 'response_action') return items.filter((item) => item.item_type === 'response_action');
  if (state.operationsFilter === 'uncovered_finding') return items.filter((item) => item.item_type === 'uncovered_finding');
  if (state.operationsFilter === 'high_critical') return items.filter((item) => item.priority === 'critical' || item.priority === 'high');
  return items;
}

function renderOperationsSummary(summary) {
  const target = document.querySelector('#operationsSummary');
  if (!target) return;
  target.replaceChildren();
  [
    ['Attention Items', summary.total_attention_items],
    ['High / Critical', (summary.critical_count || 0) + (summary.high_count || 0)],
    ['Response Actions', summary.response_action_count],
    ['Uncovered Findings', summary.uncovered_finding_count],
    ['Investigations Represented', summary.investigations_represented],
  ].forEach(([label, value], index) => {
    const card = operationsNode('div', undefined, index === 0 ? 'metric operations-primary-metric' : 'metric');
    card.append(operationsNode('div', label, 'metric-label'), operationsNode('div', value || 0, 'metric-value'));
    target.append(card);
  });
}

function operationsPill(value, kind) {
  return operationsNode('span', String(value).replaceAll('_', ' ').toUpperCase(), 'pill response-' + kind + '-' + value);
}

function operationsTypeLabel(item) {
  return item.item_type === 'response_action' ? 'Response Action' : 'Uncovered Finding';
}

async function openOperationsSource(item) {
  await openInvestigation(item.investigation_id);
  setView('investigations');
  if (item.item_type === 'response_action') await openResponseAction(item.source_id);
  else await openFinding(item.source_id, item.investigation_id);
}

function operationsFact(label, value, className) {
  const row = operationsNode('div', undefined, 'operations-fact');
  row.append(operationsNode('dt', label), operationsNode('dd', value, className));
  return row;
}

function renderOperationsDetail(item) {
  const target = document.querySelector('#operationsDetail');
  if (!target) return;
  target.replaceChildren();
  if (!item) {
    target.append(operationsNode('div', 'Select an attention item to review its priority basis and authoritative destination.', 'empty-state'));
    return;
  }
  const head = operationsNode('div', undefined, 'operations-detail-head');
  const identity = operationsNode('div');
  identity.append(operationsNode('div', operationsTypeLabel(item), 'eyebrow'), operationsNode('h3', item.source_id, 'mono'));
  const pills = operationsNode('div', undefined, 'operations-row-pills');
  pills.append(operationsPill(item.priority, 'priority'), operationsPill(item.source_status, 'status'));
  head.append(identity, pills);

  const reason = operationsNode('section', undefined, 'operations-reason');
  reason.append(operationsNode('div', 'Why it needs attention', 'eyebrow'), operationsNode('p', item.reason));

  const basis = operationsNode('section', undefined, 'operations-priority-basis');
  basis.append(operationsNode('h4', 'Why this is prioritized:'));
  const basisList = operationsNode('ul');
  (Array.isArray(item.priority_basis) ? item.priority_basis : []).forEach((entry) => basisList.append(operationsNode('li', entry)));
  basis.append(basisList);

  const facts = operationsNode('dl', undefined, 'operations-facts');
  facts.append(
    operationsFact('Owning Investigation', item.investigation_title),
    operationsFact('Investigation ID', item.investigation_id, 'mono'),
    operationsFact('Work Type', operationsTypeLabel(item)),
    operationsFact('Operational State', item.operational_state.replaceAll('_', ' ')),
    operationsFact('Created', item.created_at),
    operationsFact('Updated', item.updated_at),
  );

  const destination = operationsNode('section', undefined, 'operations-destination');
  destination.append(
    operationsNode('div', 'Authoritative destination', 'eyebrow'),
    operationsNode('p', 'Open the owning Investigation and continue in the existing ' + operationsTypeLabel(item) + ' workflow.'),
  );
  const button = operationsNode(
    'button',
    item.item_type === 'response_action' ? 'Open Response Action' : 'Open Finding',
    'primary-button',
  );
  button.type = 'button';
  button.addEventListener('click', () => openOperationsSource(item).catch((error) => {
    const status = document.querySelector('#operationsStatus');
    if (status) status.textContent = error.message;
  }));
  destination.append(button);
  target.append(head, reason, basis, facts, destination);
}

function renderOperationsRow(item, rank) {
  const selected = item.queue_item_id === state.activeOperationsItemId;
  const button = operationsNode('button', undefined, 'operations-row' + (selected ? ' active' : ''));
  button.type = 'button';
  button.dataset.queueItemId = item.queue_item_id;
  button.setAttribute('aria-pressed', String(selected));
  const head = operationsNode('div', undefined, 'operations-row-head');
  const identity = operationsNode('span', undefined, 'operations-row-identity');
  identity.append(operationsNode('span', String(rank), 'operations-rank mono'), operationsNode('strong', item.source_id, 'mono'));
  const pills = operationsNode('span', undefined, 'operations-row-pills');
  pills.append(operationsPill(item.priority, 'priority'), operationsPill(item.source_status, 'status'));
  head.append(identity, pills);
  button.append(
    head,
    operationsNode('span', operationsTypeLabel(item), 'operations-row-type'),
    operationsNode('span', item.reason, 'operations-row-reason'),
    operationsNode('span', item.investigation_title + ' · ' + item.investigation_id, 'operations-row-owner'),
    operationsNode('span', 'Updated ' + item.updated_at, 'operations-row-time'),
  );
  button.addEventListener('click', () => {
    state.activeOperationsItemId = item.queue_item_id;
    renderOperationsQueue();
  });
  return button;
}

function renderOperationsTopItems(summary) {
  const target = document.querySelector('#operationsTopItems');
  if (target) target.replaceChildren();
}

function renderOperationsQueue() {
  const summary = state.operationsQueue?.operational_summary || {};
  renderOperationsSummary(summary);
  renderOperationsTopItems(summary);
  document.querySelectorAll('[data-operations-filter]').forEach((button) => {
    const active = button.dataset.operationsFilter === state.operationsFilter;
    button.classList.toggle('primary-button', active);
    button.setAttribute('aria-pressed', String(active));
  });
  const target = document.querySelector('#operationsItems');
  if (!target) return;
  target.replaceChildren();
  const items = operationsItems();
  if (!items.some((item) => item.queue_item_id === state.activeOperationsItemId)) {
    state.activeOperationsItemId = items[0]?.queue_item_id || null;
  }
  if (!items.length) {
    const empty = operationsNode('div', undefined, 'empty-state');
    empty.append(operationsNode('strong', 'No analyst attention items.'), operationsNode('p', 'This does not mean there are no alerts or investigations; no current Findings or open Response Actions meet Operations Queue rules.'));
    target.append(empty);
    renderOperationsDetail(null);
    return;
  }
  items.forEach((item, index) => target.append(renderOperationsRow(item, index + 1)));
  renderOperationsDetail(items.find((item) => item.queue_item_id === state.activeOperationsItemId));
}

function bindOperationsQueue() {
  document.querySelectorAll('[data-operations-filter]').forEach((button) => {
    button.addEventListener('click', () => {
      state.operationsFilter = button.dataset.operationsFilter;
      renderOperationsQueue();
    });
  });
  const refresh = document.querySelector('#refreshOperationsButton');
  if (refresh) refresh.addEventListener('click', () => loadOperationsQueue().catch((error) => {
    const status = document.querySelector('#operationsStatus');
    if (status) status.textContent = error.message;
  }));
}
