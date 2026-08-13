function findingNode(tag, text, className) {
  const node = document.createElement(tag);
  if (text !== undefined && text !== null) node.textContent = String(text);
  if (className) node.className = className;
  return node;
}

function findingBase() {
  return `/api/investigations/${encodeURIComponent(state.activeInvestigation.investigation.investigation_id)}/findings`;
}

function findingMessage(message, isError) {
  const target = document.querySelector('#findingStatus');
  if (!target) return;
  target.textContent = message;
  target.className = isError ? 'error' : 'muted evidence-status';
}

function selectedFindingValues(container, name) {
  return Array.from(container.querySelectorAll(`input[name="${name}"]:checked`))
    .map((item) => item.value);
}

function findingChecks(container, legend, name, records, idField, label) {
  const fieldset = findingNode('fieldset');
  fieldset.appendChild(findingNode('legend', legend));
  if (!records.length) fieldset.appendChild(findingNode('p', 'No available references.'));
  records.forEach((record) => {
    const row = findingNode('label', null, 'finding-check');
    const checkbox = document.createElement('input');
    checkbox.type = 'checkbox';
    checkbox.name = name;
    checkbox.value = record[idField];
    row.appendChild(checkbox);
    row.appendChild(document.createTextNode(` ${record[idField]} | ${label(record)}`));
    fieldset.appendChild(row);
  });
  container.appendChild(fieldset);
}

async function loadFindings() {
  if (!state.activeInvestigation) return;
  const payload = await investigationRequest('GET', findingBase());
  state.findings = payload;
  renderFindingCounts(payload.counts);
}

function renderFindingCounts(counts) {
  const target = document.querySelector('#findingCounts');
  if (!target) return;
  target.replaceChildren();
  [
    ['Findings', counts.total],
    ['Active', counts.active],
    ['Superseded', counts.superseded],
    ['Draft', counts.draft],
    ['Substantiated', counts.substantiated],
    ['Unsubstantiated', counts.unsubstantiated],
    ['Inconclusive', counts.inconclusive],
  ].forEach(([label, value]) => {
    const item = findingNode('div', null, 'evidence-count');
    item.appendChild(findingNode('strong', value));
    item.appendChild(findingNode('span', label));
    target.appendChild(item);
  });
}

function renderFindingListCard(target, finding) {
  const card = findingNode('article', null, 'workspace-record finding-lifecycle-record');
  card.appendChild(findingNode('strong', `${finding.finding_id}: ${finding.title}`));
  card.appendChild(findingNode('span', finding.lifecycle_state.toUpperCase(), 'badge'));
  card.appendChild(findingNode('p', `${finding.status} | analyst confidence: ${finding.confidence} | ${finding.author}`));
  card.appendChild(findingNode('p', `Updated: ${finding.updated_at}`));
  card.appendChild(findingNode('p', `Basis: ${finding.evidence_ids.length} evidence, ${finding.hypothesis_ids.length} hypotheses, ${finding.decision_ids.length} decisions`));
  const open = findingNode('button', 'Open Finding');
  open.type = 'button';
  open.addEventListener('click', () => openFinding(finding.finding_id).catch((error) => findingMessage(error.message, true)));
  card.appendChild(open);
  target.appendChild(card);
}

async function listFindings() {
  await loadFindings();
  const target = document.querySelector('#findingWorkspace');
  target.replaceChildren();
  const controls = findingNode('div', null, 'workspace-actions');
  const activeButton = findingNode('button', 'View Active');
  const historyButton = findingNode('button', 'View History');
  activeButton.type = historyButton.type = 'button';
  controls.appendChild(activeButton);
  controls.appendChild(historyButton);
  target.appendChild(controls);
  const renderGroup = (lifecycle) => {
    Array.from(target.querySelectorAll('.finding-lifecycle-record')).forEach((item) => item.remove());
    state.findings.findings.filter((item) => item.lifecycle_state === lifecycle).forEach((finding) => renderFindingListCard(target, finding));
    if (!state.findings.findings.some((item) => item.lifecycle_state === lifecycle)) {
      const empty = findingNode('p', lifecycle === 'active' ? 'No active findings.' : 'No superseded findings.', 'finding-lifecycle-record');
      target.appendChild(empty);
    }
  };
  activeButton.addEventListener('click', () => renderGroup('active'));
  historyButton.addEventListener('click', () => renderGroup('superseded'));
  const findings = state.findings.findings;
  if (!findings.length) {
    target.appendChild(findingNode('p', 'No analyst-authored findings.'));
    return;
  }
  findings.filter((item) => item.lifecycle_state === 'active').forEach((finding) => renderFindingListCard(target, finding));
}

function findingTextInput(form, label, name, value, multiline) {
  const wrapper = findingNode('label', label);
  const input = document.createElement(multiline ? 'textarea' : 'input');
  input.name = name;
  input.value = value || '';
  wrapper.appendChild(input);
  form.appendChild(wrapper);
  return input;
}

function findingSelect(form, label, name, values, selected) {
  const wrapper = findingNode('label', label);
  const select = document.createElement('select');
  select.name = name;
  select.required = true;
  if (!selected) {
    const prompt = findingNode('option', 'Select confidence');
    prompt.value = '';
    prompt.disabled = true;
    prompt.selected = true;
    select.appendChild(prompt);
  }
  values.forEach((value) => {
    const option = findingNode('option', value);
    option.value = value;
    option.selected = value === selected;
    select.appendChild(option);
  });
  wrapper.appendChild(select);
  form.appendChild(wrapper);
}

function renderFindingForm(existing) {
  const target = document.querySelector('#findingWorkspace');
  target.replaceChildren();
  const form = findingNode('form', null, 'finding-form');
  const investigation = state.activeInvestigation.investigation;
  const id = findingTextInput(form, 'Finding ID', 'finding_id', existing?.finding_id);
  id.disabled = Boolean(existing);
  findingTextInput(form, 'Title', 'title', existing?.title);
  findingTextInput(form, 'Conclusion', 'conclusion', existing?.conclusion, true);
  findingSelect(form, 'Status', 'status', ['draft', 'substantiated', 'unsubstantiated', 'inconclusive'], existing?.status || 'draft');
  findingSelect(form, 'Confidence', 'confidence', ['low', 'medium', 'high'], existing?.confidence || '');
  findingTextInput(form, 'Author', 'author', existing?.author);
  findingTextInput(form, 'ATT&CK tactics (comma-separated)', 'attack_tactics', existing?.attack_tactics.join(', '));
  findingTextInput(form, 'ATT&CK techniques (comma-separated)', 'attack_techniques', existing?.attack_techniques.join(', '));
  findingTextInput(form, 'Limitations (one per line)', 'limitations', existing?.limitations.join('\n'), true);
  const evidence = investigation.evidence_references.filter((item) => item.origin === 'analyst_selection');
  findingChecks(form, 'Evidence', 'evidence_ids', evidence, 'reference_id', (item) => `${item.evidence_type} | ${item.classification}`);
  findingChecks(form, 'Hypotheses', 'hypothesis_ids', investigation.hypotheses, 'hypothesis_id', (item) => `${item.state} | ${item.statement}`);
  findingChecks(form, 'Decisions', 'decision_ids', investigation.decisions, 'decision_id', (item) => `${item.decision_type} | ${item.outcome}`);
  if (existing) {
    ['evidence_ids', 'hypothesis_ids', 'decision_ids'].forEach((name) => {
      new Set(existing[name]).forEach((value) => {
        const box = form.querySelector(`input[name="${name}"][value="${CSS.escape(value)}"]`);
        if (box) box.checked = true;
      });
    });
  }
  const submit = findingNode('button', existing ? 'Update Finding' : 'Create Finding');
  submit.type = 'submit';
  form.appendChild(submit);
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    const data = new FormData(form);
    const comma = (name) => String(data.get(name) || '').split(',').map((x) => x.trim()).filter(Boolean);
    const payload = {
      title: data.get('title'), conclusion: data.get('conclusion'),
      status: data.get('status'), confidence: data.get('confidence'),
      author: data.get('author'),
      evidence_ids: selectedFindingValues(form, 'evidence_ids'),
      hypothesis_ids: selectedFindingValues(form, 'hypothesis_ids'),
      decision_ids: selectedFindingValues(form, 'decision_ids'),
      attack_tactics: comma('attack_tactics'),
      attack_techniques: comma('attack_techniques'),
      limitations: String(data.get('limitations') || '').split('\n').map((x) => x.trim()).filter(Boolean),
      expected_revision: state.activeInvestigation.revision,
    };
    if (!existing) payload.finding_id = data.get('finding_id');
    try {
      const result = await investigationRequest(existing ? 'PUT' : 'POST', existing ? `${findingBase()}/${encodeURIComponent(existing.finding_id)}` : findingBase(), payload);
      state.activeInvestigation = result;
      await loadFindings();
      renderInvestigations();
      findingMessage(existing ? 'Finding updated.' : 'Finding created.', false);
    } catch (error) {
      findingMessage(error.message, true);
    }
  });
  target.appendChild(form);
}

function renderSupersedeFindingForm(finding) {
  const target = document.querySelector('#findingWorkspace');
  target.replaceChildren();
  const form = findingNode('form', null, 'finding-form');
  const replacement = findingSelect(form, 'Replacement Finding', 'replacement_finding_id', state.findings.findings.filter((item) => item.lifecycle_state === 'active' && item.finding_id !== finding.finding_id).map((item) => item.finding_id), '');
  findingTextInput(form, 'Reason', 'reason', '', true);
  findingTextInput(form, 'Author', 'author', '');
  const submit = findingNode('button', 'Confirm Supersession');
  submit.type = 'submit';
  form.appendChild(submit);
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    const data = new FormData(form);
    if (!window.confirm(`Supersede ${finding.finding_id} with the selected Finding?`)) return;
    try {
      const result = await investigationRequest('POST', `${findingBase()}/${encodeURIComponent(finding.finding_id)}/supersede`, {
        replacement_finding_id: data.get('replacement_finding_id'),
        reason: data.get('reason'), author: data.get('author'),
        expected_revision: state.activeInvestigation.revision,
      });
      state.activeInvestigation = result;
      await loadFindings();
      renderInvestigations();
      findingMessage('Finding superseded.', false);
    } catch (error) {
      findingMessage(error.message, true);
    }
  });
  target.appendChild(form);
}

async function openFinding(findingId) {
  const payload = await investigationRequest('GET', `${findingBase()}/${encodeURIComponent(findingId)}`);
  const finding = payload.finding;
  const target = document.querySelector('#findingWorkspace');
  target.replaceChildren();
  const detail = findingNode('article', null, 'workspace-record');
  detail.appendChild(findingNode('h3', 'ANALYST-AUTHORED FINDING'));
  detail.appendChild(findingNode('p', 'Confidence reflects analyst assessment and does not represent machine certainty.'));
  [
    ['Finding ID', finding.finding_id], ['Title', finding.title],
    ['Conclusion', finding.conclusion], ['Status', finding.status],
    ['Lifecycle', finding.lifecycle_state.toUpperCase()],
    ['Supersedes', finding.supersedes_finding_id || 'None'],
    ['Superseded by', finding.superseded_by_finding_id || 'None'],
    ['Supersession reason', finding.supersession_reason || 'None'],
    ['Supersession author', finding.supersession_author || 'None'],
    ['Superseded at', finding.superseded_at || 'None'],
    ['Confidence', finding.confidence], ['Author', finding.author],
    ['Created', finding.created_at], ['Updated', finding.updated_at],
    ['Evidence IDs', finding.evidence_ids.join(', ') || 'None'],
    ['Hypothesis IDs', finding.hypothesis_ids.join(', ') || 'None'],
    ['Decision IDs', finding.decision_ids.join(', ') || 'None'],
    ['ATT&CK tactics', finding.attack_tactics.join(', ') || 'None'],
    ['ATT&CK techniques', finding.attack_techniques.join(', ') || 'None'],
    ['Limitations', finding.limitations.join('; ') || 'None'],
  ].forEach(([label, value]) => detail.appendChild(findingNode('p', `${label}: ${value}`)));
  if (finding.lifecycle_state === 'active') {
    const edit = findingNode('button', 'Edit Finding');
    edit.type = 'button';
    edit.addEventListener('click', () => renderFindingForm(finding));
    detail.appendChild(edit);
    const supersede = findingNode('button', 'Supersede Finding');
    supersede.type = 'button';
    supersede.addEventListener('click', () => renderSupersedeFindingForm(finding));
    detail.appendChild(supersede);
  } else {
    detail.appendChild(findingNode('p', 'Historical findings are read-only.', 'muted'));
  }
  finding.evidence_ids.forEach((id) => {
    const button = findingNode('button', `View Evidence ${id}`);
    button.type = 'button';
    button.addEventListener('click', () => inspectEvidence(id, false).catch((error) => findingMessage(error.message, true)));
    detail.appendChild(button);
  });
  finding.hypothesis_ids.forEach((id) => {
    const button = findingNode('button', `View Hypothesis ${id}`);
    button.type = 'button';
    button.addEventListener('click', () => showWebHypothesis(id).catch((error) => findingMessage(error.message, true)));
    detail.appendChild(button);
  });
  finding.decision_ids.forEach((id) => {
    const button = findingNode('button', `View Decision ${id}`);
    button.type = 'button';
    button.addEventListener('click', () => showQueryDecision(id).catch((error) => findingMessage(error.message, true)));
    detail.appendChild(button);
  });
  target.appendChild(detail);
}

function bindFindingActions() {
  const view = document.querySelector('#viewFindingsButton');
  const create = document.querySelector('#createFindingButton');
  if (view) view.addEventListener('click', () => listFindings().catch((error) => findingMessage(error.message, true)));
  if (create) create.addEventListener('click', () => renderFindingForm(null));
}
