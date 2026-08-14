function responseNode(tag, text, className) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = String(text);
  return node;
}

function responseBase() {
  const id = state.activeInvestigation?.investigation?.investigation_id;
  if (!id) throw new Error('Open an investigation first');
  return `/api/investigations/${encodeURIComponent(id)}/response-actions`;
}

function responseMessage(message, isError = false) {
  const target = $('#responseActionStatus');
  if (!target) return;
  target.textContent = message;
  target.classList.toggle('error-text', isError);
}

async function loadResponseActions() {
  if (!state.activeInvestigation) {
    state.responseActions = null;
    return;
  }
  const response = await fetch(responseBase(), { cache: 'no-store' });
  const payload = await response.json();
  if (!response.ok) throw new Error(investigationErrorMessage(payload, 'Unable to load response actions'));
  state.responseActions = payload;
}

function renderResponseActionCounts(counts = {}) {
  const target = $('#responseActionCounts');
  if (!target) return;
  target.replaceChildren();
  [
    ['Actions', counts.total || 0],
    ['Proposed', counts.proposed || 0],
    ['Approved', counts.approved || 0],
    ['In Progress', counts.in_progress || 0],
    ['Completed', counts.completed || 0],
    ['Dismissed', counts.dismissed || 0],
  ].forEach(([label, value]) => {
    const item = responseNode('div', undefined, 'evidence-count');
    item.append(responseNode('span', label, 'muted'));
    item.append(responseNode('strong', value));
    target.append(item);
  });
}

function responsePill(value, kind) {
  return responseNode('span', String(value).toUpperCase(), `pill response-${kind}-${value}`);
}

function renderResponseActionCard(target, action) {
  const card = responseNode('article', undefined, 'workspace-record');
  const head = responseNode('div', undefined, 'record-head');
  head.append(responseNode('strong', action.action_id, 'mono'));
  head.append(responsePill(action.status, 'status'));
  head.append(responsePill(action.priority, 'priority'));
  card.append(head);
  card.append(responseNode('h4', action.title));
  card.append(responseNode('p', `${action.action_type} | Owner: ${action.owner}`));
  card.append(responseNode('p', `Updated: ${action.updated_at} | Findings: ${action.finding_ids.length}`, 'muted'));
  const button = responseNode('button', 'Open Action');
  button.type = 'button';
  button.addEventListener('click', () => openResponseAction(action.action_id).catch((error) => responseMessage(error.message, true)));
  card.append(button);
  target.append(card);
}

async function listResponseActions() {
  await loadResponseActions();
  const target = $('#responseActionWorkspace');
  target.replaceChildren();
  const actions = state.responseActions?.actions || [];
  if (!actions.length) {
    target.append(responseNode('p', 'No response actions recorded.', 'muted'));
  } else {
    actions.forEach((action) => renderResponseActionCard(target, action));
  }
  renderResponseActionCounts(state.responseActions?.counts);
  responseMessage('Response Actions');
}

function responseField(form, label, name, options) {
  const wrapper = responseNode('label');
  wrapper.append(responseNode('span', label));
  let input;
  if (options) {
    input = document.createElement('select');
    options.forEach((value) => {
      const option = responseNode('option', value);
      option.value = value;
      input.append(option);
    });
  } else {
    input = document.createElement(name === 'description' || name === 'rationale' ? 'textarea' : 'input');
  }
  input.name = name;
  input.required = name !== 'action_id';
  wrapper.append(input);
  form.append(wrapper);
  return input;
}

function renderCreateResponseActionForm() {
  const target = $('#responseActionWorkspace');
  target.replaceChildren();
  const form = responseNode('form', undefined, 'workspace-form');
  responseField(form, 'Action ID (optional)', 'action_id');
  responseField(form, 'Title', 'title');
  responseField(form, 'Description', 'description');
  responseField(form, 'Action Type', 'action_type', ['containment', 'credential_action', 'host_action', 'network_action', 'collection', 'validation', 'monitoring', 'communication', 'other']);
  responseField(form, 'Priority', 'priority', ['', 'low', 'medium', 'high', 'critical']);
  responseField(form, 'Rationale', 'rationale');
  responseField(form, 'Owner', 'owner');
  responseField(form, 'Created By', 'created_by');
  const findings = responseNode('fieldset');
  findings.append(responseNode('legend', 'ACTIVE Findings'));
  (state.responseActions?.active_findings || []).forEach((finding) => {
    const label = responseNode('label');
    const input = document.createElement('input');
    input.type = 'checkbox';
    input.name = 'finding_ids';
    input.value = finding.finding_id;
    label.append(input, document.createTextNode(` ${finding.finding_id} | ${finding.title}`));
    findings.append(label);
  });
  form.append(findings);
  form.append(responseNode('p', 'SOC-Forge records analyst response workflow. It does not execute remediation.', 'evidence-warning'));
  const submit = responseNode('button', 'Create Action');
  submit.type = 'submit';
  form.append(submit);
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    const data = new FormData(form);
    const findingIds = data.getAll('finding_ids');
    if (!findingIds.length) {
      responseMessage('Select at least one ACTIVE Finding.', true);
      return;
    }
    const payload = Object.fromEntries(data.entries());
    payload.finding_ids = findingIds;
    payload.expected_revision = state.activeInvestigation.revision;
    if (!payload.action_id) delete payload.action_id;
    try {
      const created = await investigationRequest('POST', responseBase(), payload);
      state.activeInvestigation = created;
      await loadInvestigationSummaries();
      await loadResponseActions();
      renderInvestigations();
      responseMessage(`Action created: ${created.action.action_id}`);
    } catch (error) {
      responseMessage(error.message, true);
    }
  });
  target.append(form);
  responseMessage('Create Response Action');
}

function validResponseTransitions(status) {
  return {
    proposed: [['approved', 'Approve'], ['dismissed', 'Dismiss']],
    approved: [['in_progress', 'Start Work'], ['dismissed', 'Dismiss']],
    in_progress: [['completed', 'Complete'], ['dismissed', 'Dismiss']],
    completed: [],
    dismissed: [],
  }[status] || [];
}

async function openResponseAction(actionId) {
  const response = await fetch(`${responseBase()}/${encodeURIComponent(actionId)}`, { cache: 'no-store' });
  const payload = await response.json();
  if (!response.ok) throw new Error(investigationErrorMessage(payload, 'Unable to open response action'));
  const action = payload.action;
  const target = $('#responseActionWorkspace');
  target.replaceChildren();
  const detail = responseNode('article', undefined, 'workspace-record');
  detail.append(responseNode('h3', `${action.action_id}: ${action.title}`));
  [
    ['Status', action.status], ['Priority', action.priority], ['Type', action.action_type],
    ['Description', action.description], ['Rationale', action.rationale], ['Owner', action.owner],
    ['Created By', action.created_by], ['Created', action.created_at], ['Updated', action.updated_at],
  ].forEach(([label, value]) => detail.append(responseNode('p', `${label}: ${value}`)));
  detail.append(responseNode('p', 'RESPONSE ACTIONS RECORD ANALYST-CONTROLLED WORK. SOC-FORGE DOES NOT EXECUTE THIS ACTION.', 'evidence-warning'));
  const related = responseNode('section', undefined, 'workspace-record');
  related.append(responseNode('h4', 'Related Findings'));
  payload.related_findings.forEach((finding) => {
    const button = responseNode('button', `${finding.finding_id} | ${finding.lifecycle_state.toUpperCase()}`);
    button.type = 'button';
    button.addEventListener('click', () => openFinding(finding.finding_id).catch((error) => responseMessage(error.message, true)));
    related.append(button);
  });
  const history = responseNode('section', undefined, 'workspace-record');
  history.append(responseNode('h4', 'Transition History'));
  if (!action.transition_history.length) history.append(responseNode('p', 'No lifecycle transitions recorded.', 'muted'));
  action.transition_history.forEach((item) => {
    const record = responseNode('div', undefined, 'workspace-record');
    record.append(responseNode('strong', `${item.from_status} -> ${item.to_status}`));
    record.append(responseNode('p', `${item.author} | ${item.timestamp}`, 'muted'));
    record.append(responseNode('p', item.rationale));
    history.append(record);
  });
  const controls = responseNode('div', undefined, 'workspace-actions');
  validResponseTransitions(action.status).forEach(([targetStatus, label]) => {
    const button = responseNode('button', label);
    button.type = 'button';
    button.addEventListener('click', async () => {
      const author = window.prompt('Analyst/author');
      if (author === null) return;
      const rationale = window.prompt('Transition rationale');
      if (rationale === null) return;
      try {
        const updated = await investigationRequest(
          'POST', `${responseBase()}/${encodeURIComponent(action.action_id)}/transition`,
          { target_status: targetStatus, author, rationale, expected_revision: state.activeInvestigation.revision },
        );
        state.activeInvestigation = updated;
        await loadInvestigationSummaries();
        await loadResponseActions();
        await openResponseAction(action.action_id);
        renderResponseActionCounts(state.responseActions.counts);
        responseMessage(`Action moved from ${updated.transition.from_status} to ${updated.transition.to_status}.`);
      } catch (error) {
        responseMessage(error.message, true);
      }
    });
    controls.append(button);
  });
  if (!controls.children.length) controls.append(responseNode('p', 'Lifecycle is read-only for this terminal action.', 'muted'));
  target.append(detail, controls, related, history);
  responseMessage('Response Action Detail');
}

function bindResponseActionActions() {
  const view = $('#viewResponseActionsButton');
  const create = $('#createResponseActionButton');
  if (view) view.addEventListener('click', () => listResponseActions().catch((error) => responseMessage(error.message, true)));
  if (create) create.addEventListener('click', () => {
    if (!state.responseActions?.active_findings?.length) {
      responseMessage('No ACTIVE Findings are available for a response action.', true);
      return;
    }
    renderCreateResponseActionForm();
  });
}