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
    .filter((reference) => reference.source_type === 'case')
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
