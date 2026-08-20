function operationsNode(tag, text, className) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = String(text);
  return node;
}

async function loadOperationsQueue() {
  const response = await fetch('/api/operations-queue', { cache: 'no-store' });
  const payload = await response.json();
  if (!response.ok) {
    throw new Error(payload.error || 'Unable to load analyst operations queue');
  }
  state.operationsQueue = payload;
  renderOperationsQueue();
}

function operationsItems() {
  const items = Array.isArray(state.operationsQueue?.items)
    ? state.operationsQueue.items
    : [];
  if (state.operationsFilter === 'response_action') {
    return items.filter((item) => item.item_type === 'response_action');
  }
  if (state.operationsFilter === 'uncovered_finding') {
    return items.filter((item) => item.item_type === 'uncovered_finding');
  }
  if (state.operationsFilter === 'high_critical') {
    return items.filter((item) => (
      item.priority === 'critical' || item.priority === 'high'
    ));
  }
  return items;
}

function renderOperationsSummary(summary) {
  const target = document.querySelector('#operationsSummary');
  if (!target) return;
  target.replaceChildren();
  [
    ["Attention Items", summary.total_attention_items],
    ["Investigations Represented", summary.investigations_represented],
    ['Critical', summary.critical_count],
    ['High', summary.high_count],
    ['Medium', summary.medium_count],
    ['Low', summary.low_count],
    ['Response Actions', summary.response_action_count],
    ['Uncovered Findings', summary.uncovered_finding_count],
    ['Proposed', summary.proposed_count],
    ['Approved', summary.approved_count],
    ['In Progress', summary.in_progress_count],
  ].forEach(([label, value]) => {
    const card = operationsNode('div', undefined, 'metric');
    card.append(
      operationsNode('div', label, 'metric-label'),
      operationsNode('div', value || 0, 'metric-value'),
    );
    target.append(card);
  });
}

function operationsPill(value, kind) {
  return operationsNode(
    'span',
    String(value).toUpperCase(),
    'pill response-' + kind + '-' + value,
  );
}

async function openOperationsSource(item) {
  await openInvestigation(item.investigation_id);
  setView('investigations');
  if (item.item_type === 'response_action') {
    await openResponseAction(item.source_id);
  } else {
    await openFinding(item.source_id);
  }
}

function renderOperationsCard(item) {
  const card = operationsNode('article', undefined, 'workspace-record');
  const head = operationsNode('div', undefined, 'record-head');
  head.append(
    operationsPill(item.priority, 'priority'),
    operationsNode(
      'span',
      item.item_type === 'response_action'
        ? 'RESPONSE ACTION'
        : 'UNCOVERED FINDING',
      'pill',
    ),
    operationsPill(item.source_status, 'status'),
  );
  card.append(head);
  card.append(operationsNode('strong', item.source_id, 'mono'));
  card.append(
    operationsNode(
      'p',
      'Investigation: ' + item.investigation_id,
    ),
  );
  card.append(operationsNode('p', item.investigation_title));
  const basis = operationsNode("div", undefined, "operations-priority-basis");
  basis.append(operationsNode("strong", "Why this is prioritized:"));
  const basisList = operationsNode("ul");
  (Array.isArray(item.priority_basis) ? item.priority_basis : []).forEach(
    (entry) => basisList.append(operationsNode("li", entry)),
  );
  basis.append(basisList);
  card.append(basis);
  card.append(operationsNode('p', item.reason));
  card.append(operationsNode('p', 'Updated: ' + item.updated_at, 'muted'));
  card.dataset.queueItemId = item.queue_item_id;
  const button = operationsNode(
    'button',
    item.item_type === 'response_action'
      ? 'Open Response Action'
      : 'Open Finding',
  );
  button.type = 'button';
  button.addEventListener('click', () => {
    openOperationsSource(item).catch((error) => {
      const status = document.querySelector('#operationsStatus');
      if (status) status.textContent = error.message;
    });
  });
  card.append(button);
  return card;
}

function renderOperationsTopItems(summary) {
  const target = document.querySelector("#operationsTopItems");
  if (!target) return;
  target.replaceChildren();
  const items = Array.isArray(summary.top_items) ? summary.top_items : [];
  if (!items.length) {
    const empty = operationsNode("div", undefined, "empty-state");
    empty.append(
      operationsNode("strong", "Top Attention: None"),
      operationsNode(
        "p", "There are no current operational attention items.",
      ),
    );
    target.append(empty);
    return;
  }
  items.forEach((item) => target.append(renderOperationsCard(item)));
}

function renderOperationsQueue() {
  const summary = state.operationsQueue?.operational_summary || {};
  renderOperationsSummary(summary);
  renderOperationsTopItems(summary);
  document.querySelectorAll('[data-operations-filter]').forEach((button) => {
    button.classList.toggle(
      'primary-button',
      button.dataset.operationsFilter === state.operationsFilter,
    );
  });
  const target = document.querySelector('#operationsItems');
  if (!target) return;
  target.replaceChildren();
  const items = operationsItems();
  if (!items.length) {
    const empty = operationsNode('div', undefined, 'empty-state');
    empty.append(
      operationsNode('strong', 'No analyst attention items.'),
      operationsNode(
        'p',
        'This does not mean there are no alerts or investigations; no current Findings or open Response Actions meet Operations Queue rules.',
      ),
    );
    target.append(empty);
    return;
  }
  items.forEach((item) => target.append(renderOperationsCard(item)));
}

function bindOperationsQueue() {
  document.querySelectorAll('[data-operations-filter]').forEach((button) => {
    button.addEventListener('click', () => {
      state.operationsFilter = button.dataset.operationsFilter;
      renderOperationsQueue();
    });
  });
  const refresh = document.querySelector('#refreshOperationsButton');
  if (refresh) {
    refresh.addEventListener('click', () => {
      loadOperationsQueue().catch((error) => {
        const status = document.querySelector('#operationsStatus');
        if (status) status.textContent = error.message;
      });
    });
  }
}
