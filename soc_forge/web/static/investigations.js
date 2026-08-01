function investigationErrorMessage(payload, fallback) {
  return payload?.error?.message || fallback;
}

async function investigationRequest(method, path, body) {
  const response = await fetch(path, {
    method,
    headers: { 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const payload = await response.json();
  if (response.status === 409 && payload.latest) {
    state.activeInvestigation = payload.latest;
    await loadInvestigationSummaries();
    renderInvestigations();
  }
  if (!response.ok) {
    throw new Error(
      investigationErrorMessage(payload, 'Investigation request failed'),
    );
  }
  return payload;
}

async function loadInvestigationSummaries() {
  const response = await fetch('/api/investigations');
  if (!response.ok) throw new Error('Unable to load investigations');
  state.investigations = await response.json();
}

async function openInvestigation(investigationId) {
  const response = await fetch(
    `/api/investigations/${encodeURIComponent(investigationId)}`,
  );
  const payload = await response.json();
  if (!response.ok) {
    throw new Error(
      investigationErrorMessage(payload, 'Unable to open investigation'),
    );
  }
  state.activeInvestigation = payload;
  state.evidenceCandidates = [];
  state.evidenceDraft = null;
  await loadEvidenceSelections();
  renderInvestigations();
}

async function createInvestigationFromCase(caseItem) {
  const investigationId = window.prompt('Investigation ID');
  if (investigationId === null) return;
  const title = window.prompt(
    'Title override (leave blank to use the case title)',
    '',
  );
  if (title === null) return;
  const owner = window.prompt('Owner (leave blank for unassigned)', '');
  if (owner === null) return;
  if (!window.confirm(`Create investigation ${investigationId}?`)) return;
  const created = await investigationRequest(
    'POST',
    '/api/investigations',
    {
      investigation_id: investigationId,
      case_ids: [caseItem.case_id],
      title,
      owner,
    },
  );
  state.activeInvestigation = created;
  state.evidenceCandidates = [];
  state.evidenceDraft = null;
  await loadEvidenceSelections();
  await loadInvestigationSummaries();
  setView('investigations');
  renderInvestigations();
}

async function updateActiveInvestigation(path, body, method = 'POST') {
  const current = state.activeInvestigation;
  if (!current) return;
  const investigationId = current.investigation.investigation_id;
  const updated = await investigationRequest(
    method,
    `/api/investigations/${encodeURIComponent(investigationId)}${path}`,
    { ...body, expected_revision: current.revision },
  );
  state.activeInvestigation = updated;
  await loadInvestigationSummaries();
  renderInvestigations();
}

function selectedCaseIds(investigation) {
  return asArray(investigation.evidence_references)
    .filter((reference) => (
      reference.origin === 'scope' && reference.source_type === 'case'
    ))
    .map((reference) => reference.source_id);
}

function renderInvestigations() {
  const list = $('#investigationList');
  const detail = $('#investigationDetail');
  if (!list || !detail) return;
  const activeId =
    state.activeInvestigation?.investigation?.investigation_id;
  list.innerHTML = state.investigations.length
    ? state.investigations.map((summary) => `
      <button class="case-row ${summary.investigation_id === activeId ? 'active' : ''}" data-investigation-id="${escapeHtml(summary.investigation_id)}">
        <div class="case-title">${escapeHtml(summary.title)}</div>
        <div class="case-meta">
          <span class="pill">${escapeHtml(summary.status)}</span>
          <span class="pill">${escapeHtml(summary.owner || 'Unassigned')}</span>
          <span class="pill mono">Revision ${escapeHtml(summary.revision)}</span>
        </div>
        <div class="mono muted compact-time">${escapeHtml(summary.updated_at)}</div>
      </button>`).join('')
    : '<div class="empty-state">No durable investigations yet. Open a case to create one.</div>';
  document.querySelectorAll('[data-investigation-id]').forEach((button) => {
    button.addEventListener('click', () => {
      openInvestigation(button.dataset.investigationId)
        .catch((error) => alert(error.message));
    });
  });

  if (!state.activeInvestigation) {
    detail.innerHTML =
      '<div class="empty-state">Open a durable investigation workspace.</div>';
    return;
  }
  const { investigation, revision } = state.activeInvestigation;
  const metadata = investigation.metadata || {};
  const annotations = asArray(investigation.annotations);
  const decisions = asArray(investigation.decisions);
  detail.innerHTML = `
    <div class="case-brief">
      <div class="workspace-heading">
        <div>
          <h2>${escapeHtml(metadata.title)}</h2>
          <div class="pill-row">
            <span class="pill mono">${escapeHtml(investigation.investigation_id)}</span>
            <span class="pill">${escapeHtml(metadata.status)}</span>
            <span class="pill">${escapeHtml(metadata.owner || 'Unassigned')}</span>
            <span class="pill mono">Revision ${escapeHtml(revision)}</span>
          </div>
        </div>
        <button id="deleteInvestigationButton" class="danger-button" type="button">Delete Workspace</button>
      </div>
      <div class="workspace-metadata">
        <div><span>Created</span><strong>${escapeHtml(metadata.created_at)}</strong></div>
        <div><span>Updated</span><strong>${escapeHtml(metadata.updated_at)}</strong></div>
        <div><span>Source Analysis</span><strong class="mono">${escapeHtml(investigation.analysis_id)}</strong></div>
        <div><span>Selected Cases</span><strong class="mono">${escapeHtml(selectedCaseIds(investigation).join(', ') || 'None')}</strong></div>
      </div>
      <div class="workspace-actions">
        <button id="assignOwnerButton" type="button">Assign Owner</button>
        <button id="clearOwnerButton" type="button">Clear Owner</button>
        ${metadata.status === 'closed'
          ? '<button id="reopenInvestigationButton" type="button">Reopen</button>'
          : '<button id="changeStatusButton" type="button">Change Status</button>'}
        <button id="addAnnotationButton" type="button">Add Annotation</button>
        <button id="recordDecisionButton" type="button">Record Decision</button>
      </div>
      <section class="brief-section evidence-section">
        <div class="panel-head">
          <h3>Evidence</h3>
          <span id="evidenceAvailability" class="muted"></span>
        </div>
        <div id="evidenceCounts" class="evidence-counts"></div>
        <div class="workspace-actions">
          <button id="browseEvidenceButton" type="button">Browse Evidence</button>
          <button id="viewSelectedEvidenceButton" type="button">View Selected Evidence</button>
          <select id="evidenceTypeFilter" aria-label="Evidence type filter">
            <option value="all">All</option>
            <option value="event">Events</option>
            <option value="alert">Alerts</option>
            <option value="case">Cases</option>
            <option value="reconstruction_step">Reconstruction steps</option>
          </select>
        </div>
        <div id="evidenceStatus" class="muted evidence-status"></div>
        <div id="evidenceWorkspace" class="workspace-records"></div>
      </section>
      <section class="brief-section">
        <h3>Analyst Annotations</h3>
        <div class="workspace-records">${annotations.map((annotation) => `
          <article class="workspace-record">
            <div class="record-head">
              <strong class="mono">${escapeHtml(annotation.annotation_id)}</strong>
              <span>${escapeHtml(annotation.created_by || 'Unknown')}</span>
              <span class="muted">${escapeHtml(annotation.updated_at || annotation.created_at)}</span>
            </div>
            <p>${escapeHtml(annotation.body)}</p>
            <div class="record-actions">
              <button data-edit-annotation="${escapeHtml(annotation.annotation_id)}" type="button">Edit</button>
              <button data-delete-annotation="${escapeHtml(annotation.annotation_id)}" type="button">Delete</button>
            </div>
          </article>`).join('') || '<div class="muted">No annotations.</div>'}</div>
      </section>
      <section class="brief-section">
        <h3>Analyst Decisions</h3>
        <div class="workspace-records">${decisions.map((decision) => `
          <article class="workspace-record">
            <div class="record-head">
              <strong class="mono">${escapeHtml(decision.decision_id)}</strong>
              <span>${escapeHtml(decision.decided_by || 'Unknown')}</span>
              <span class="pill">${escapeHtml(decision.decision_type)}: ${escapeHtml(decision.outcome)}</span>
            </div>
            <p>${escapeHtml(decision.rationale)}</p>
          </article>`).join('') || '<div class="muted">No analyst decisions.</div>'}</div>
      </section>
    </div>`;
  bindInvestigationActions(investigation);
  bindEvidenceActions();
  renderEvidenceSummary();
}

function bindInvestigationActions(investigation) {
  const bind = (selector, handler) => {
    const element = $(selector);
    if (element) {
      element.addEventListener('click', () => {
        handler().catch((error) => alert(error.message));
      });
    }
  };
  bind('#assignOwnerButton', async () => {
    const owner = window.prompt(
      'Owner label',
      investigation.metadata.owner || '',
    );
    if (owner === null) return;
    await updateActiveInvestigation('/owner', { owner });
  });
  bind('#clearOwnerButton', () =>
    updateActiveInvestigation('/owner', { owner: null }));
  bind('#changeStatusButton', async () => {
    const status = window.prompt(
      'Target status: in_progress, escalated, or closed',
    );
    if (status === null) return;
    await updateActiveInvestigation('/status', { status });
  });
  bind('#reopenInvestigationButton', () =>
    updateActiveInvestigation('/reopen', {}));
  bind('#addAnnotationButton', async () => {
    const annotationId = window.prompt('Annotation ID');
    if (annotationId === null) return;
    const author = window.prompt('Author label');
    if (author === null) return;
    const text = window.prompt('Annotation text');
    if (text === null) return;
    await updateActiveInvestigation('/annotations', {
      annotation_id: annotationId,
      author,
      text,
    });
  });
  bind('#recordDecisionButton', async () => {
    const decisionId = window.prompt('Decision ID');
    if (decisionId === null) return;
    const author = window.prompt('Author label');
    if (author === null) return;
    const decisionType = window.prompt('Decision type or disposition');
    if (decisionType === null) return;
    const outcome = window.prompt('Outcome');
    if (outcome === null) return;
    const rationale = window.prompt('Rationale');
    if (rationale === null) return;
    await updateActiveInvestigation('/decisions', {
      decision_id: decisionId,
      author,
      decision_type: decisionType,
      outcome,
      rationale,
      evidence_reference_ids: [],
      hypothesis_ids: [],
    });
  });
  bind('#deleteInvestigationButton', async () => {
    if (!window.confirm(
      `Delete workspace ${investigation.investigation_id}? Analysis artifacts will remain.`,
    )) return;
    await investigationRequest(
      'DELETE',
      `/api/investigations/${encodeURIComponent(investigation.investigation_id)}`,
      { expected_revision: state.activeInvestigation.revision },
    );
    state.activeInvestigation = null;
    await loadInvestigationSummaries();
    renderInvestigations();
  });
  document.querySelectorAll('[data-edit-annotation]').forEach((button) => {
    button.addEventListener('click', () => {
      const annotation = asArray(investigation.annotations)
        .find((item) => item.annotation_id === button.dataset.editAnnotation);
      const text = window.prompt('Annotation text', annotation?.body || '');
      if (text === null) return;
      updateActiveInvestigation(
        `/annotations/${encodeURIComponent(button.dataset.editAnnotation)}`,
        { text },
        'PUT',
      ).catch((error) => alert(error.message));
    });
  });
  document.querySelectorAll('[data-delete-annotation]').forEach((button) => {
    button.addEventListener('click', () => {
      if (!window.confirm(
        `Delete annotation ${button.dataset.deleteAnnotation}?`,
      )) return;
      updateActiveInvestigation(
        `/annotations/${encodeURIComponent(button.dataset.deleteAnnotation)}`,
        {},
        'DELETE',
      ).catch((error) => alert(error.message));
    });
  });
}


function evidenceElement(tag, className, text) {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (text !== undefined) element.textContent = String(text);
  return element;
}

function activeEvidenceBase() {
  const investigationId =
    state.activeInvestigation?.investigation?.investigation_id;
  if (!investigationId) throw new Error('Open an investigation first');
  return `/api/investigations/${encodeURIComponent(investigationId)}/evidence`;
}

async function evidenceGet(path) {
  const response = await fetch(path);
  const payload = await response.json();
  if (!response.ok) {
    const error = new Error(
      investigationErrorMessage(payload, 'Evidence request failed'),
    );
    error.code = payload?.error?.code;
    throw error;
  }
  return payload;
}

async function loadEvidenceSelections() {
  if (!state.activeInvestigation) return;
  state.evidenceSelections = await evidenceGet(
    `${activeEvidenceBase()}/selections`,
  );
}

function renderEvidenceSummary() {
  const target = $('#evidenceCounts');
  const workspace = $('#evidenceWorkspace');
  if (!target || !workspace) return;
  target.replaceChildren();
  const counts = state.evidenceSelections?.counts || {
    scope: asArray(state.activeInvestigation?.investigation?.evidence_references)
      .filter((item) => item.origin === 'scope').length,
    selected: 0,
    supporting: 0,
    contradicting: 0,
    context: 0,
  };
  [
    ['Scope references', counts.scope],
    ['Selected', counts.selected],
    ['Supporting', counts.supporting],
    ['Contradicting', counts.contradicting],
    ['Context', counts.context],
  ].forEach(([label, value]) => {
    const item = evidenceElement('div', 'evidence-count');
    item.append(
      evidenceElement('span', '', label),
      evidenceElement('strong', '', value),
    );
    target.append(item);
  });
  const filter = $('#evidenceTypeFilter');
  if (filter) filter.value = state.evidenceFilter;
}

function bindEvidenceActions() {
  const browse = $('#browseEvidenceButton');
  const selected = $('#viewSelectedEvidenceButton');
  const filter = $('#evidenceTypeFilter');
  if (browse) browse.addEventListener('click', () => {
    browseEvidence().catch(showEvidenceError);
  });
  if (selected) selected.addEventListener('click', () => {
    showSelectedEvidence().catch(showEvidenceError);
  });
  if (filter) filter.addEventListener('change', () => {
    state.evidenceFilter = filter.value;
    browseEvidence().catch(showEvidenceError);
  });
}

function showEvidenceError(error) {
  const status = $('#evidenceStatus');
  if (status) status.textContent = error.message;
  if (
    error.code === 'analysis_unavailable'
    || error.code === 'analysis_provenance_mismatch'
  ) {
    const availability = $('#evidenceAvailability');
    if (availability) {
      availability.textContent =
        'Source evidence details require the matching completed analysis to be active.';
    }
  }
}

async function browseEvidence() {
  const query = encodeURIComponent(state.evidenceFilter || 'all');
  const payload = await evidenceGet(
    `${activeEvidenceBase()}/candidates?type=${query}`,
  );
  state.evidenceCandidates = asArray(payload.candidates);
  const status = $('#evidenceStatus');
  if (status) {
    status.textContent = state.evidenceCandidates.length
      ? `${state.evidenceCandidates.length} case-scoped candidates`
      : 'No evidence candidates match this filter.';
  }
  renderEvidenceCandidates();
}

function renderEvidenceCandidates() {
  const target = $('#evidenceWorkspace');
  if (!target) return;
  target.replaceChildren();
  state.evidenceCandidates.forEach((candidate) => {
    const row = evidenceElement('article', 'workspace-record evidence-candidate');
    const head = evidenceElement('div', 'record-head');
    head.append(
      evidenceElement('span', 'pill', candidate.evidence_type),
      evidenceElement('strong', '', candidate.title),
      evidenceElement('span', 'mono muted', candidate.timestamp || 'Unknown'),
    );
    row.append(head);
    const facts = evidenceElement('div', 'evidence-facts');
    [
      ['Source', candidate.source_id],
      ['Cases', asArray(candidate.case_ids).join(', ') || 'None'],
      ['Rule', candidate.rule_id || 'None'],
    ].forEach(([label, value]) => {
      const fact = evidenceElement('span', 'mono');
      fact.append(
        evidenceElement('b', '', `${label}: `),
        document.createTextNode(String(value)),
      );
      facts.append(fact);
    });
    row.append(facts);
    if (asArray(candidate.sensitive_fields).length) {
      row.append(evidenceElement(
        'div',
        'evidence-warning',
        `Sensitive fields: ${candidate.sensitive_fields.join(', ')}`,
      ));
    }
    if (candidate.limitation_reason) {
      row.append(evidenceElement(
        'div', 'evidence-limitation', candidate.limitation_reason,
      ));
    }
    const actions = evidenceElement('div', 'record-actions');
    const inspect = evidenceElement('button', '', 'Inspect');
    inspect.type = 'button';
    inspect.addEventListener('click', () => {
      inspectEvidence(candidate.evidence_id, false).catch(showEvidenceError);
    });
    const select = evidenceElement('button', '', 'Select');
    select.type = 'button';
    select.disabled = !candidate.selectable;
    select.addEventListener('click', () => {
      selectEvidence(candidate).catch(showEvidenceError);
    });
    actions.append(inspect, select);
    row.append(actions);
    target.append(row);
  });
}

async function inspectEvidence(evidenceId, includeSensitive) {
  if (!/^evidence-[a-f0-9]+$/.test(evidenceId)) {
    throw new Error('Invalid evidence identifier');
  }
  const suffix = includeSensitive ? '?include_sensitive=true' : '';
  const payload = await evidenceGet(
    `${activeEvidenceBase()}/candidates/${encodeURIComponent(evidenceId)}${suffix}`,
  );
  renderEvidenceDetails(payload);
}

function renderEvidenceDetails(payload) {
  const target = $('#evidenceWorkspace');
  if (!target) return;
  target.replaceChildren();
  const candidate = payload.candidate;
  const panel = evidenceElement('article', 'workspace-record evidence-detail');
  panel.append(
    evidenceElement('h4', '', candidate.title),
    evidenceElement('div', 'mono muted', candidate.evidence_id),
    evidenceElement('p', '', candidate.summary),
  );
  const metadata = evidenceElement('div', 'evidence-detail-grid');
  [
    ['Type', candidate.evidence_type],
    ['Timestamp', candidate.timestamp || 'Unknown'],
    ['Source', candidate.source_id],
    ['Cases', asArray(candidate.case_ids).join(', ') || 'None'],
    ['Rule', candidate.rule_id || 'None'],
    ['ATT&CK tactic', candidate.tactic || 'None'],
    ['ATT&CK technique', candidate.technique || 'None'],
    ['Entities', asArray(candidate.entities).join(', ') || 'None'],
    ['Limitation', candidate.limitation_reason || 'None'],
  ].forEach(([label, value]) => {
    const item = evidenceElement('div', '');
    item.append(
      evidenceElement('span', '', label),
      evidenceElement('strong', '', value),
    );
    metadata.append(item);
  });
  panel.append(metadata);
  const fields = evidenceElement('div', 'workspace-records');
  asArray(payload.details?.fields).forEach((field) => {
    const item = evidenceElement('div', 'evidence-field');
    item.append(evidenceElement('strong', '', field.field_name));
    item.append(evidenceElement(
      'div',
      field.sensitive ? 'evidence-warning' : 'mono',
      field.value_hidden ? '[hidden - reveal required]' : field.value,
    ));
    const provenance = field.provenance || {};
    item.append(evidenceElement(
      'div',
      'muted',
      `Source ${provenance.source_type}:${provenance.source_id} field ${provenance.source_field} | ${provenance.source_kind} | Normalized: ${provenance.normalized ? 'yes' : 'no'} | Sensitive: ${field.sensitive ? 'yes' : 'no'}`,
    ));
    fields.append(item);
  });
  panel.append(fields);
  if (asArray(candidate.sensitive_fields).length) {
    panel.append(evidenceElement(
      'div',
      'evidence-warning',
      'Sensitive values may remain in browser history, developer tools, or screen captures.',
    ));
    const toggle = evidenceElement(
      'button',
      '',
      payload.sensitive_values_included ? 'Hide Sensitive Values' : 'Reveal Sensitive Values',
    );
    toggle.type = 'button';
    toggle.addEventListener('click', () => {
      if (
        !payload.sensitive_values_included
        && !window.confirm('Reveal bounded sensitive evidence values?')
      ) return;
      inspectEvidence(
        candidate.evidence_id,
        !payload.sensitive_values_included,
      ).catch(showEvidenceError);
    });
    panel.append(toggle);
  }
  const select = evidenceElement('button', 'primary-button', 'Select Evidence');
  select.type = 'button';
  select.disabled = !candidate.selectable;
  select.addEventListener('click', () => {
    selectEvidence(candidate).catch(showEvidenceError);
  });
  panel.append(select);
  target.append(panel);
}

function promptEvidenceClassification(currentValue) {
  const value = window.prompt(
    'Classification: supporting, contradicting, or context',
    currentValue || 'supporting',
  );
  if (value === null) return null;
  const normalized = value.trim().toLowerCase();
  if (!['supporting', 'contradicting', 'context'].includes(normalized)) {
    throw new Error('Choose supporting, contradicting, or context.');
  }
  return normalized;
}

async function selectEvidence(candidate) {
  const classification = promptEvidenceClassification(
    state.evidenceDraft?.classification,
  );
  if (classification === null) return;
  const rationale = window.prompt(
    'Analyst rationale',
    state.evidenceDraft?.rationale || '',
  );
  if (rationale === null) return;
  const author = window.prompt(
    'Author label',
    state.evidenceDraft?.author || '',
  );
  if (author === null) return;
  state.evidenceDraft = { classification, rationale, author };
  if (!window.confirm(
    'Save this analyst classification and rationale? Classification is not machine certainty.',
  )) return;
  try {
    const updated = await investigationRequest(
      'POST',
      `${activeEvidenceBase()}/selections`,
      {
        evidence_id: candidate.evidence_id,
        classification,
        rationale,
        author,
        expected_revision: state.activeInvestigation.revision,
      },
    );
    state.activeInvestigation = updated;
    state.evidenceDraft = null;
    await loadEvidenceSelections();
    await loadInvestigationSummaries();
    renderInvestigations();
    const status = $('#evidenceStatus');
    if (status) status.textContent = 'Evidence selected.';
  } catch (error) {
    renderInvestigations();
    showEvidenceError(error);
  }
}

async function showSelectedEvidence() {
  await loadEvidenceSelections();
  renderInvestigations();
  const target = $('#evidenceWorkspace');
  if (!target) return;
  target.replaceChildren();
  const scopeHeading = evidenceElement('h4', '', 'Investigation Scope References');
  target.append(scopeHeading);
  const scope = evidenceElement('div', 'workspace-records scope-evidence');
  asArray(state.evidenceSelections.scope_references).forEach((reference) => {
    const row = evidenceElement('div', 'workspace-record');
    row.append(
      evidenceElement('strong', '', `${reference.source_type}: ${reference.source_id}`),
      evidenceElement('p', '', 'Defines investigation case scope; not analyst-reviewed evidence.'),
    );
    scope.append(row);
  });
  if (!scope.children.length) {
    scope.append(evidenceElement('div', 'muted', 'No scope references.'));
  }
  target.append(scope, evidenceElement('h4', '', 'Analyst-Selected Evidence'));
  const selected = evidenceElement('div', 'workspace-records selected-evidence');
  asArray(state.evidenceSelections.analyst_selections).forEach((reference) => {
    const row = evidenceElement('article', 'workspace-record');
    row.append(
      evidenceElement('strong', '', `${reference.evidence_type}: ${reference.source_id}`),
      evidenceElement('span', 'pill', reference.classification),
      evidenceElement('p', '', reference.rationale),
      evidenceElement('div', 'muted', `${reference.selected_by} | ${reference.selected_at}`),
    );
    if (asArray(reference.provenance_fields).some(
      (name) => ['command_line', 'message', 'raw_message'].includes(name),
    )) {
      row.append(evidenceElement('div', 'evidence-warning', 'Contains sensitive fields'));
    }
    const actions = evidenceElement('div', 'record-actions');
    [
      ['Inspect', () => inspectEvidence(reference.reference_id, false)],
      ['Update', () => updateEvidenceSelection(reference)],
      ['Remove', () => removeEvidenceSelection(reference)],
    ].forEach(([label, handler]) => {
      const button = evidenceElement('button', '', label);
      button.type = 'button';
      button.addEventListener('click', () => handler().catch(showEvidenceError));
      actions.append(button);
    });
    row.append(actions);
    selected.append(row);
  });
  if (!selected.children.length) {
    selected.append(evidenceElement('div', 'muted', 'No analyst-selected evidence.'));
  }
  target.append(selected);
}

async function updateEvidenceSelection(reference) {
  const classification = promptEvidenceClassification(reference.classification);
  if (classification === null) return;
  const rationale = window.prompt('Analyst rationale', reference.rationale);
  if (rationale === null) return;
  const author = window.prompt('Author label', reference.selected_by);
  if (author === null) return;
  state.evidenceDraft = { classification, rationale, author };
  try {
    const updated = await investigationRequest(
      'PUT',
      `${activeEvidenceBase()}/selections/${encodeURIComponent(reference.reference_id)}`,
      {
        classification,
        rationale,
        author,
        expected_revision: state.activeInvestigation.revision,
      },
    );
    state.activeInvestigation = updated;
    state.evidenceDraft = null;
    await loadEvidenceSelections();
    await loadInvestigationSummaries();
    renderInvestigations();
    await showSelectedEvidence();
  } catch (error) {
    renderInvestigations();
    showEvidenceError(error);
  }
}

async function removeEvidenceSelection(reference) {
  if (!window.confirm(
    `Remove selected evidence ${reference.reference_id}? Referenced evidence cannot be removed.`,
  )) return;
  const updated = await investigationRequest(
    'DELETE',
    `${activeEvidenceBase()}/selections/${encodeURIComponent(reference.reference_id)}`,
    { expected_revision: state.activeInvestigation.revision },
  );
  state.activeInvestigation = updated;
  await loadEvidenceSelections();
  await loadInvestigationSummaries();
  renderInvestigations();
  await showSelectedEvidence();
}
