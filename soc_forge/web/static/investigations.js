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
  if (
    response.status === 409
    && payload?.error?.code === 'revision_conflict'
    && payload.error.investigation_id
  ) {
    await refreshInvestigationAfterConflict(payload.error.investigation_id);
  }
  if (!response.ok) {
    throw new Error(
      investigationErrorMessage(payload, 'Investigation request failed'),
    );
  }
  return payload;
}

async function refreshInvestigationAfterConflict(investigationId) {
  const response = await fetch(
    `/api/investigations/${encodeURIComponent(investigationId)}`,
    { cache: 'no-store' },
  );
  if (!response.ok) return;
  state.activeInvestigation = await response.json();
  await loadInvestigationSummaries();
  await loadEvidenceSelections();
  await loadReasoning();
  await loadFindings();
  await loadResponseActions();
  renderInvestigations();
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
  await loadReasoning();
  await loadFindings();
  await loadResponseActions();
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
  await loadReasoning();
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
  const sourceAnalysis = state.activeInvestigation.source_analysis || {};
  const sourceAvailable = sourceAnalysis.available === true;
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
      <section class="brief-section source-analysis-section">
        <div class="panel-head">
          <h3>Source Analysis</h3>
          <span id="sourceAnalysisAvailability" class="pill">${sourceAvailable ? 'Available' : 'Unavailable'}</span>
        </div>
        <p id="sourceAnalysisStatus" class="muted">${sourceAvailable
          ? 'Available in current server session'
          : 'Unavailable in current server session'}</p>
        ${sourceAvailable
          ? ''
          : '<button id="loadSourceAnalysisButton" type="button">Load Source Analysis</button>'}
      </section>
      <section class="brief-section investigation-summary-section">
        <div id="investigationSummary" class="workspace-records"></div>
      </section>
      <div class="workspace-actions">
        <button id="assignOwnerButton" type="button">Assign Owner</button>
        <button id="clearOwnerButton" type="button">Clear Owner</button>
        ${metadata.status === 'closed'
          ? '<button id="reopenInvestigationButton" type="button">Reopen</button>'
          : '<button id="changeStatusButton" type="button">Change Status</button>'}
        <button id="addAnnotationButton" type="button">Add Annotation</button>
      </div>
      <section class="brief-section handoff-section">
        <div class="panel-head">
          <h3>Investigation Handoff</h3>
          <span class="pill">Read Only</span>
        </div>
        <p class="muted">Read-only export of this investigation revision.</p>
        <div class="evidence-warning">
          This bundle may contain usernames, hosts, IPs, evidence rationales, hypothesis statements, decision rationale, annotations, and case metadata. Review the generated handoff before sharing it outside the intended environment.
        </div>
        <div class="workspace-actions">
          <button id="previewHandoffButton" type="button">Preview Handoff</button>
          <select id="handoffOutputRoot" aria-label="Handoff output root">
            <option value="handoffs">Analysis output / handoffs</option>
          </select>
          <label><input id="handoffSensitiveAcknowledgement" type="checkbox"> I reviewed the sensitive-data warning</label>
          <label><input id="handoffOverwrite" type="checkbox"> Replace existing handoff</label>
          <button id="exportHandoffButton" type="button">Export Handoff</button>
          <button id="inspectHandoffManifestButton" type="button">Inspect Manifest</button>
          <button id="validateHandoffButton" type="button">Validate Bundle</button>
        </div>
        <p class="muted">The existing handoff will be replaced only after a new bundle is fully staged and validated.</p>
        <div id="handoffStatus" class="muted evidence-status"></div>
        <div id="handoffWorkspace" class="workspace-records"></div>
      </section>
      <section class="brief-section reasoning-section">
        <div class="panel-head">
          <h3>Hypotheses and Decisions</h3>
          <span class="muted">Analyst-authored reasoning</span>
        </div>
        <p class="muted">States reflect analyst assessment of current evidence, not machine certainty.</p>
        <div id="reasoningCounts" class="evidence-counts"></div>
        <div class="workspace-actions">
          <button id="viewHypothesesButton" type="button">View Hypotheses</button>
          <button id="createHypothesisButton" type="button">Create Hypothesis</button>
          <button id="viewReasoningDecisionsButton" type="button">View Decisions</button>
          <button id="recordReasoningDecisionButton" type="button">Record Decision</button>
        </div>
        <div id="reasoningStatus" class="muted evidence-status"></div>
        <div id="reasoningWorkspace" class="workspace-records"></div>
      </section>
      <section class="brief-section response-actions-section">
        <div class="panel-head">
          <h3>Response Actions</h3>
          <span class="muted">Analyst-controlled response work</span>
        </div>
        <p class="muted">Creating or advancing a Response Action does not execute remediation.</p>
        <div id="responseActionCounts" class="evidence-counts"></div>
        <div class="workspace-actions">
          <button id="viewResponseActionsButton" type="button">View Actions</button>
          <button id="createResponseActionButton" type="button">Create Action</button>
        </div>
        <div id="responseActionStatus" class="muted evidence-status"></div>
        <div id="responseActionWorkspace" class="workspace-records"></div>
      </section>
      <section class="brief-section findings-section">
        <div class="panel-head">
          <h3>Investigation Findings</h3>
          <span class="muted">Analyst-authored conclusions</span>
        </div>
        <p class="muted">Confidence reflects analyst assessment, not machine certainty.</p>
        <div id="findingCounts" class="evidence-counts"></div>
        <div class="workspace-actions">
          <button id="viewFindingsButton" type="button">View Findings</button>
          <button id="createFindingButton" type="button">Create Finding</button>
        </div>
        <div id="findingStatus" class="muted evidence-status"></div>
        <div id="findingWorkspace" class="workspace-records"></div>
      </section>      <section class="brief-section workbench-section">
        <div class="panel-head">
          <h3>Timeline and Pivot Workbench</h3>
          <span class="pill">Read Only</span>
        </div>
        <p class="muted">Canonical chronology and explainable entity relationships from the matching completed analysis.</p>
        <div class="workspace-actions">
          <button id="openTimelineWorkbenchButton" type="button">Open Timeline</button>
          <button id="browseWorkbenchEntitiesButton" type="button">Browse Entities</button>
          <button id="refreshWorkbenchButton" type="button">Refresh</button>
        </div>
        <div id="workbenchStaleWarning" class="evidence-warning"></div>
        <div id="workbenchStatus" class="muted evidence-status"></div>
        <div id="workbenchFilters"></div>
        <div id="workbenchActiveFilters" class="pill-row"></div>
        <div id="workbenchContent" class="workbench-content"></div>
      </section>
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
  bindSourceAnalysisActions(investigation, sourceAvailable);
  bindHandoffActions();
  bindEvidenceActions();
  bindReasoningActions();
  bindFindingActions();
  bindResponseActionActions();
  bindInvestigationWorkbench();
  renderEvidenceSummary();
  renderReasoningSummary();
  if (state.findings) renderFindingCounts(state.findings.counts);
  if (state.responseActions) {
    renderResponseActionCounts(state.responseActions.counts);
  }
  loadInvestigationSummary().catch(showInvestigationSummaryError);
}

function bindSourceAnalysisActions(investigation, sourceAvailable) {
  const sourceDependent = [
    '#previewHandoffButton',
    '#exportHandoffButton',
    '#openTimelineWorkbenchButton',
    '#browseWorkbenchEntitiesButton',
    '#refreshWorkbenchButton',
    '#browseEvidenceButton',
  ];
  sourceDependent.forEach((selector) => {
    const element = $(selector);
    if (element) element.disabled = !sourceAvailable;
  });
  const button = $('#loadSourceAnalysisButton');
  if (!button) return;
  button.addEventListener('click', () => {
    button.disabled = true;
    const status = $('#sourceAnalysisStatus');
    if (status) status.textContent = 'Loading and validating source analysis...';
    investigationRequest(
      'POST',
      '/api/investigations/' + encodeURIComponent(investigation.investigation_id) + '/source-analysis/load',
      {},
    ).then(async (payload) => {
      state.activeInvestigation.source_analysis = {
        source_analysis_id: payload.source_analysis_id,
        available: true,
        status: 'available',
      };
      await loadEvidenceSelections();
      renderInvestigations();
      const updated = $('#sourceAnalysisStatus');
      if (updated) updated.textContent = payload.message;
    }).catch((error) => {
      button.disabled = false;
      if (status) status.textContent = error.message;
    });
  });
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
    const draft = state.investigationDraft?.kind === 'annotation'
      ? state.investigationDraft
      : {};
    const annotationId = window.prompt('Annotation ID', draft.annotation_id || '');
    if (annotationId === null) return;
    const author = window.prompt('Author label', draft.author || '');
    if (author === null) return;
    const text = window.prompt('Annotation text', draft.text || '');
    if (text === null) return;
    state.investigationDraft = {
      kind: 'annotation',
      annotation_id: annotationId,
      author,
      text,
    };
    await updateActiveInvestigation('/annotations', {
      annotation_id: annotationId,
      author,
      text,
    });
    state.investigationDraft = null;
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
      const text = window.prompt(
        'Annotation text',
        state.investigationDraft?.text || annotation?.body || '',
      );
      if (text === null) return;
      state.investigationDraft = { kind: 'annotation', text };
      updateActiveInvestigation(
        `/annotations/${encodeURIComponent(button.dataset.editAnnotation)}`,
        { text },
        'PUT',
      ).then(() => {
        state.investigationDraft = null;
      }).catch((error) => alert(error.message));
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


function handoffBase() {
  const investigationId =
    state.activeInvestigation?.investigation?.investigation_id;
  if (!investigationId) throw new Error('Open an investigation first');
  return `/api/investigations/${encodeURIComponent(investigationId)}/handoff`;
}

function renderHandoffPayload(title, payload) {
  const workspace = $('#handoffWorkspace');
  const status = $('#handoffStatus');
  if (!workspace || !status) return;
  workspace.replaceChildren();
  status.textContent = title;
  const record = evidenceElement('article', 'workspace-record');
  record.appendChild(evidenceElement('strong', null, title));
  Object.entries(payload).forEach(([key, value]) => {
    if (value === null || value === undefined) return;
    const row = evidenceElement('div', 'record-head');
    row.appendChild(evidenceElement('span', 'muted', key.replaceAll('_', ' ')));
    row.appendChild(evidenceElement(
      'span',
      Array.isArray(value) || typeof value === 'object' ? 'mono' : null,
      Array.isArray(value) || typeof value === 'object'
        ? JSON.stringify(value)
        : value,
    ));
    record.appendChild(row);
  });
  workspace.appendChild(record);
}

function renderHandoffPreview(payload) {
  renderHandoffPayload('Handoff Preview', payload);
  const workspace = $('#handoffWorkspace');
  if (!workspace) return;
  const section = evidenceElement('section', 'workspace-record');
  section.appendChild(evidenceElement('strong', null, 'Analyst Findings'));
  section.appendChild(evidenceElement(
    'p',
    'muted',
    'Findings are analyst-authored conclusions. Confidence reflects analyst assessment, not machine certainty.',
  ));
  if (!payload.findings.length) {
    section.appendChild(evidenceElement('p', null, 'No analyst-authored findings.'));
  }
  payload.findings.forEach((finding) => {
    const item = evidenceElement('article', 'workspace-record');
    item.appendChild(evidenceElement('strong', null, `${finding.finding_id}: ${finding.title}`));
    item.appendChild(evidenceElement('p', null, `${finding.status} | Analyst confidence: ${finding.confidence}`));
    item.appendChild(evidenceElement('p', null, finding.conclusion));
    item.appendChild(evidenceElement('p', null, `Basis: ${finding.evidence_count} evidence, ${finding.hypothesis_count} hypotheses, ${finding.decision_count} decisions`));
    item.appendChild(evidenceElement('p', 'muted', `Evidence IDs: ${finding.evidence_ids.join(', ') || 'None'}`));
    item.appendChild(evidenceElement('p', 'muted', `Hypothesis IDs: ${finding.hypothesis_ids.join(', ') || 'None'}`));
    item.appendChild(evidenceElement('p', 'muted', `Decision IDs: ${finding.decision_ids.join(', ') || 'None'}`));
    finding.limitations.forEach((value) => {
      item.appendChild(evidenceElement('p', 'muted', `Limitation: ${value}`));
    });
    section.appendChild(item);
  });
  workspace.appendChild(section);
}

async function handoffGet(action) {
  const response = await fetch(`${handoffBase()}/${action}`, {
    cache: 'no-store',
  });
  const payload = await response.json();
  if (!response.ok) {
    throw new Error(investigationErrorMessage(payload, 'Handoff request failed'));
  }
  return payload;
}

function bindHandoffActions() {
  const bind = (selector, handler) => {
    const element = $(selector);
    if (!element) return;
    element.addEventListener('click', () => {
      handler().catch((error) => {
        const status = $('#handoffStatus');
        if (status) status.textContent = error.message;
      });
    });
  };
  bind('#previewHandoffButton', async () => {
    renderHandoffPreview(await handoffGet('preview'));
  });
  bind('#exportHandoffButton', async () => {
    const overwrite = Boolean($('#handoffOverwrite')?.checked);
    const acknowledged = Boolean(
      $('#handoffSensitiveAcknowledgement')?.checked,
    );
    state.handoffDraft = {
      output_root: $('#handoffOutputRoot')?.value || 'handoffs',
      overwrite,
      sensitive_data_acknowledged: acknowledged,
    };
    if (!acknowledged) {
      throw new Error('Review and acknowledge the sensitive-data warning first.');
    }
    if (overwrite && !window.confirm(
      'Replace the existing handoff after a new bundle is staged and validated?',
    )) return;
    const result = await investigationRequest(
      'POST',
      `${handoffBase()}/export`,
      {
        expected_revision: state.activeInvestigation.revision,
        ...state.handoffDraft,
      },
    );
    renderHandoffPayload('Handoff Exported', result);
  });
  bind('#inspectHandoffManifestButton', async () => {
    renderHandoffPayload('Handoff Manifest', await handoffGet('manifest'));
  });
  bind('#validateHandoffButton', async () => {
    const result = await investigationRequest(
      'POST',
      `${handoffBase()}/validate`,
      {},
    );
    renderHandoffPayload(
      result.valid ? 'VALID' : 'INVALID',
      result,
    );
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

async function inspectEvidence(
  evidenceId,
  includeSensitive,
  targetSelector = '#evidenceWorkspace',
) {
  if (!/^evidence-[a-f0-9]+$/.test(evidenceId)) {
    throw new Error('Invalid evidence identifier');
  }
  const suffix = includeSensitive ? '?include_sensitive=true' : '';
  const payload = await evidenceGet(
    `${activeEvidenceBase()}/candidates/${encodeURIComponent(evidenceId)}${suffix}`,
  );
  renderEvidenceDetails(payload, targetSelector);
}

function renderEvidenceDetails(payload, targetSelector = '#evidenceWorkspace') {
  const target = $(targetSelector);
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
        targetSelector,
      ).catch(
        targetSelector === '#workbenchContent' ? showQueryError : showEvidenceError,
      );
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
  await loadReasoning();
  await loadFindings();
  await loadResponseActions();
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



function activeReasoningBase() {
  const investigationId =
    state.activeInvestigation?.investigation?.investigation_id;
  if (!investigationId) throw new Error('Open an investigation first');
  return `/api/investigations/${encodeURIComponent(investigationId)}`;
}

async function reasoningGet(path) {
  const response = await fetch(path, { cache: 'no-store' });
  const payload = await response.json();
  if (!response.ok) {
    throw new Error(
      investigationErrorMessage(payload, 'Reasoning request failed'),
    );
  }
  return payload;
}

async function loadReasoning() {
  if (!state.activeInvestigation) return;
  state.reasoningSummary = await reasoningGet(
    `${activeReasoningBase()}/reasoning`,
  );
}

function renderReasoningSummary() {
  const target = $('#reasoningCounts');
  if (!target) return;
  target.replaceChildren();
  const summary = state.reasoningSummary || {
    total_hypotheses: 0,
    open: 0,
    supported: 0,
    rejected: 0,
    inconclusive: 0,
    total_decisions: 0,
  };
  [
    ['Hypotheses', summary.total_hypotheses],
    ['Open', summary.open],
    ['Supported', summary.supported],
    ['Rejected', summary.rejected],
    ['Inconclusive', summary.inconclusive],
    ['Decisions', summary.total_decisions],
  ].forEach(([label, value]) => {
    const item = evidenceElement('div', 'evidence-count');
    item.append(
      evidenceElement('span', '', label),
      evidenceElement('strong', '', value),
    );
    target.append(item);
  });
}

async function refreshReasoning(updated) {
  if (updated?.investigation) state.activeInvestigation = updated;
  await loadReasoning();
  await loadEvidenceSelections();
  await loadInvestigationSummaries();
  renderInvestigations();
}

function showReasoningError(error) {
  const status = $('#reasoningStatus');
  if (status) {
    status.textContent = error.message.includes('another session')
      ? `${error.message} Draft values remain available in this browser session.`
      : error.message;
  }
}

function compatibleReasoningEvidence(classification, excluded = []) {
  const excludedIds = new Set(excluded);
  return asArray(
    state.evidenceSelections?.analyst_selections
      || state.activeInvestigation?.investigation?.evidence_references,
  )
    .filter((item) => (
      item.origin === 'analyst_selection'
      && item.classification === classification
      && !excludedIds.has(item.reference_id)
    ))
    .sort((left, right) => left.reference_id.localeCompare(right.reference_id));
}

function chooseReasoningItem(items, label) {
  if (!items.length) return null;
  const listing = items.map((item, index) => (
    `${index + 1}. ${item.hypothesis_id || item.reference_id}`
  )).join('\n');
  const value = window.prompt(`${label}\n${listing}\nNumber (blank for none)`, '');
  if (value === null || value.trim() === '') return null;
  const index = Number(value) - 1;
  if (!Number.isInteger(index) || index < 0 || index >= items.length) {
    throw new Error('Choose one of the displayed records.');
  }
  return items[index];
}

function selectedReasoningIds(items, label) {
  if (!items.length) return [];
  const selected = chooseReasoningItem(items, label);
  return selected
    ? [selected.hypothesis_id || selected.reference_id]
    : [];
}

async function createWebHypothesis() {
  const draft = state.reasoningDraft?.kind === 'hypothesis'
    ? state.reasoningDraft
    : {};
  const hypothesisId = window.prompt('Hypothesis ID', draft.hypothesis_id || '');
  if (hypothesisId === null) return;
  const statement = window.prompt(
    'Analyst hypothesis statement',
    draft.statement || '',
  );
  if (statement === null) return;
  const author = window.prompt('Analyst author label', draft.author || '');
  if (author === null) return;
  const supporting = selectedReasoningIds(
    compatibleReasoningEvidence('supporting'),
    'Choose optional supporting evidence',
  );
  const contradicting = selectedReasoningIds(
    compatibleReasoningEvidence('contradicting', supporting),
    'Choose optional contradicting evidence',
  );
  state.reasoningDraft = {
    kind: 'hypothesis',
    hypothesis_id: hypothesisId,
    statement,
    author,
  };
  if (!window.confirm(
    'Create this analyst-authored hypothesis? It is not a machine conclusion.',
  )) return;
  try {
    const updated = await investigationRequest(
      'POST',
      `${activeReasoningBase()}/hypotheses`,
      {
        hypothesis_id: hypothesisId,
        statement,
        author,
        supporting_evidence_ids: supporting,
        contradicting_evidence_ids: contradicting,
        expected_revision: state.activeInvestigation.revision,
      },
    );
    state.reasoningDraft = null;
    await refreshReasoning(updated);
    await showWebHypothesis(hypothesisId);
  } catch (error) {
    renderInvestigations();
    showReasoningError(error);
  }
}

async function listWebHypotheses() {
  const payload = await reasoningGet(
    `${activeReasoningBase()}/hypotheses`,
  );
  const target = $('#reasoningWorkspace');
  if (!target) return;
  target.replaceChildren();
  asArray(payload.hypotheses).forEach((hypothesis) => {
    const row = evidenceElement('article', 'workspace-record');
    const head = evidenceElement('div', 'record-head');
    head.append(
      evidenceElement('strong', 'mono', hypothesis.hypothesis_id),
      evidenceElement('span', 'pill', hypothesis.state),
      evidenceElement('span', 'muted', hypothesis.author || 'Unknown'),
    );
    row.append(
      head,
      evidenceElement('p', '', hypothesis.statement),
      evidenceElement(
        'div',
        'muted',
        `Updated ${hypothesis.updated_at || 'Unknown'} | Supporting ${hypothesis.supporting_evidence_count} | Contradicting ${hypothesis.contradicting_evidence_count}`,
      ),
    );
    const open = evidenceElement('button', '', 'Open');
    open.type = 'button';
    open.addEventListener('click', () => {
      showWebHypothesis(hypothesis.hypothesis_id).catch(showReasoningError);
    });
    row.append(open);
    target.append(row);
  });
  if (!target.children.length) {
    target.append(evidenceElement('div', 'muted', 'No analyst-authored hypotheses.'));
  }
}

function renderReasoningEvidence(reference, relationship, hypothesisId) {
  const row = evidenceElement('article', 'workspace-record');
  row.append(
    evidenceElement('strong', 'mono', reference.reference_id),
    evidenceElement(
      'div',
      '',
      `${reference.evidence_type || reference.source_type} | ${reference.classification}`,
    ),
    evidenceElement('p', '', reference.rationale || 'No rationale'),
    evidenceElement('div', 'muted', `Source: ${reference.source_id}`),
    evidenceElement(
      'div',
      'evidence-warning',
      'Evidence metadata and source values may be sensitive.',
    ),
  );
  const remove = evidenceElement('button', '', 'Remove from Hypothesis');
  remove.type = 'button';
  remove.addEventListener('click', () => {
    removeWebHypothesisEvidence(
      hypothesisId,
      relationship,
      reference.reference_id,
    ).catch(showReasoningError);
  });
  row.append(remove);
  return row;
}

async function showWebHypothesis(hypothesisId) {
  const payload = await reasoningGet(
    `${activeReasoningBase()}/hypotheses/${encodeURIComponent(hypothesisId)}`,
  );
  const target = $('#reasoningWorkspace');
  if (!target) return;
  target.replaceChildren();
  const hypothesis = payload.hypothesis;
  const detail = evidenceElement('article', 'workspace-record reasoning-detail');
  detail.append(
    evidenceElement('h4', '', hypothesis.statement),
    evidenceElement('div', 'mono muted', hypothesis.hypothesis_id),
    evidenceElement('span', 'pill', hypothesis.state),
    evidenceElement('div', '', `Author: ${hypothesis.author || 'Unknown'}`),
    evidenceElement(
      'div',
      'muted',
      `Created ${hypothesis.created_at || 'Unknown'} | Updated ${hypothesis.updated_at || 'Unknown'}`,
    ),
  );
  const actions = evidenceElement('div', 'record-actions');
  if (hypothesis.state === 'open') {
    const edit = evidenceElement('button', '', 'Edit Statement');
    edit.type = 'button';
    edit.addEventListener('click', () => {
      editWebHypothesis(hypothesis).catch(showReasoningError);
    });
    actions.append(edit);
    const assess = evidenceElement('button', 'primary-button', 'Assess');
    assess.type = 'button';
    assess.addEventListener('click', () => {
      assessWebHypothesis(hypothesis).catch(showReasoningError);
    });
    actions.append(assess);
  } else {
    const reopen = evidenceElement('button', '', 'Reopen');
    reopen.type = 'button';
    reopen.addEventListener('click', () => {
      reopenWebHypothesis(hypothesis).catch(showReasoningError);
    });
    actions.append(reopen);
  }
  [
    ['supporting', hypothesis.supporting_evidence_reference_ids],
    ['contradicting', hypothesis.contradicting_evidence_reference_ids],
  ].forEach(([relationship, ids]) => {
    const add = evidenceElement('button', '', `Add ${relationship} evidence`);
    add.type = 'button';
    add.addEventListener('click', () => {
      addWebHypothesisEvidence(hypothesis, relationship).catch(showReasoningError);
    });
    actions.append(add);
  });
  detail.append(actions);
  target.append(detail, evidenceElement('h4', '', 'Supporting Evidence'));
  asArray(payload.supporting_evidence).forEach((item) => {
    target.append(renderReasoningEvidence(item, 'supporting', hypothesisId));
  });
  target.append(evidenceElement('h4', '', 'Contradicting Evidence'));
  asArray(payload.contradicting_evidence).forEach((item) => {
    target.append(renderReasoningEvidence(item, 'contradicting', hypothesisId));
  });
  target.append(evidenceElement('h4', '', 'Append-only Assessment History'));
  asArray(payload.related_decisions).forEach((item) => {
    target.append(renderWebDecision(item));
  });
  if (!payload.source_details_available) {
    target.append(evidenceElement(
      'div',
      'muted',
      'Persisted reasoning remains available. Source details require the matching active analysis in the evidence workspace.',
    ));
  }
}

async function editWebHypothesis(hypothesis) {
  const statement = window.prompt('Hypothesis statement', hypothesis.statement);
  if (statement === null) return;
  state.reasoningDraft = { kind: 'statement', statement };
  const updated = await investigationRequest(
    'PUT',
    `${activeReasoningBase()}/hypotheses/${encodeURIComponent(hypothesis.hypothesis_id)}`,
    { statement, expected_revision: state.activeInvestigation.revision },
  );
  state.reasoningDraft = null;
  await refreshReasoning(updated);
  await showWebHypothesis(hypothesis.hypothesis_id);
}

async function addWebHypothesisEvidence(hypothesis, relationship) {
  const excluded = [
    ...asArray(hypothesis.supporting_evidence_reference_ids),
    ...asArray(hypothesis.contradicting_evidence_reference_ids),
  ];
  const evidence = chooseReasoningItem(
    compatibleReasoningEvidence(relationship, excluded),
    `Choose ${relationship} analyst-selected evidence`,
  );
  if (!evidence) return;
  const updated = await investigationRequest(
    'POST',
    `${activeReasoningBase()}/hypotheses/${encodeURIComponent(hypothesis.hypothesis_id)}/${relationship}-evidence`,
    {
      evidence_id: evidence.reference_id,
      expected_revision: state.activeInvestigation.revision,
    },
  );
  await refreshReasoning(updated);
  await showWebHypothesis(hypothesis.hypothesis_id);
}

async function removeWebHypothesisEvidence(
  hypothesisId,
  relationship,
  evidenceId,
) {
  if (!window.confirm(
    'Remove only this hypothesis relationship? Selected evidence will remain.',
  )) return;
  const updated = await investigationRequest(
    'DELETE',
    `${activeReasoningBase()}/hypotheses/${encodeURIComponent(hypothesisId)}/${relationship}-evidence/${encodeURIComponent(evidenceId)}`,
    { expected_revision: state.activeInvestigation.revision },
  );
  await refreshReasoning(updated);
  await showWebHypothesis(hypothesisId);
}

async function assessWebHypothesis(hypothesis) {
  const stateValue = window.prompt(
    'Assessment: supported, rejected, or inconclusive',
    'inconclusive',
  );
  if (stateValue === null) return;
  const rationale = window.prompt(
    'Assessment rationale',
    state.reasoningDraft?.rationale || '',
  );
  if (rationale === null) return;
  const author = window.prompt('Analyst author label', '');
  if (author === null) return;
  const decisionId = window.prompt('Assessment decision ID', '');
  if (decisionId === null) return;
  state.reasoningDraft = { kind: 'assessment', rationale };
  if (!window.confirm(
    'This records an analyst assessment. It does not verify the hypothesis as objective fact.',
  )) return;
  const updated = await investigationRequest(
    'POST',
    `${activeReasoningBase()}/hypotheses/${encodeURIComponent(hypothesis.hypothesis_id)}/assess`,
    {
      state: stateValue,
      rationale,
      author,
      decision_id: decisionId,
      expected_revision: state.activeInvestigation.revision,
    },
  );
  state.reasoningDraft = null;
  await refreshReasoning(updated);
  await showWebHypothesis(hypothesis.hypothesis_id);
}

async function reopenWebHypothesis(hypothesis) {
  const rationale = window.prompt(
    'Rationale for reopening',
    state.reasoningDraft?.rationale || '',
  );
  if (rationale === null) return;
  const author = window.prompt('Analyst author label', '');
  if (author === null) return;
  const decisionId = window.prompt('Reopening decision ID', '');
  if (decisionId === null) return;
  state.reasoningDraft = { kind: 'reopen', rationale };
  if (!window.confirm('Reopen for further investigation?')) return;
  const updated = await investigationRequest(
    'POST',
    `${activeReasoningBase()}/hypotheses/${encodeURIComponent(hypothesis.hypothesis_id)}/reopen`,
    {
      rationale,
      author,
      decision_id: decisionId,
      expected_revision: state.activeInvestigation.revision,
    },
  );
  state.reasoningDraft = null;
  await refreshReasoning(updated);
  await showWebHypothesis(hypothesis.hypothesis_id);
}

function renderWebDecision(decision) {
  const row = evidenceElement('article', 'workspace-record');
  row.append(
    evidenceElement('strong', 'mono', decision.decision_id),
    evidenceElement('span', 'pill', decision.decision_type),
    evidenceElement('div', '', `Outcome: ${decision.outcome}`),
    evidenceElement('p', '', decision.rationale),
    evidenceElement(
      'div',
      'muted',
      `${decision.decided_by || decision.author || 'Unknown'} | ${decision.decided_at || 'Unknown'}`,
    ),
    evidenceElement(
      'div',
      'mono muted',
      `Hypotheses: ${asArray(decision.hypothesis_ids).join(', ') || 'None'} | Evidence: ${asArray(decision.evidence_reference_ids).join(', ') || 'None'}`,
    ),
  );
  return row;
}

async function listWebDecisions() {
  const payload = await reasoningGet(
    `${activeReasoningBase()}/reasoning/decisions`,
  );
  const target = $('#reasoningWorkspace');
  if (!target) return;
  target.replaceChildren();
  for (const summary of asArray(payload.decisions)) {
    const row = evidenceElement("article", "workspace-record");
    row.append(
      evidenceElement("strong", "mono", summary.decision_id),
      evidenceElement("span", "pill", summary.decision_type),
      evidenceElement("div", "", "Outcome: " + summary.outcome),
      evidenceElement("p", "", summary.rationale_summary),
      evidenceElement("div", "muted", (summary.author || "Unknown") + " | " + (summary.decided_at || "Unknown")),
      evidenceElement("div", "muted", "Hypotheses: " + summary.related_hypothesis_count + " | Evidence: " + summary.related_evidence_count),
    );
    const details = evidenceElement("button", "", "View Details");
    details.type = "button";
    details.addEventListener("click", async () => {
      const detail = await reasoningGet(
        activeReasoningBase() + "/reasoning/decisions/" + encodeURIComponent(summary.decision_id),
      );
      target.replaceChildren(renderWebDecision(detail.decision));
    });
    row.append(details);
    target.append(row);
  }
  if (!target.children.length) {
    target.append(evidenceElement('div', 'muted', 'No analyst decisions.'));
  }
}

async function recordWebDecision() {
  const decisionId = window.prompt('Decision ID', '');
  if (decisionId === null) return;
  const decisionType = window.prompt(
    'Decision type: escalation, containment_recommendation, closure_rationale, or investigative_conclusion',
    'escalation',
  );
  if (decisionType === null) return;
  const rationale = window.prompt(
    'Decision rationale',
    state.reasoningDraft?.rationale || '',
  );
  if (rationale === null) return;
  const author = window.prompt('Analyst author label', '');
  if (author === null) return;
  const hypotheses = asArray(
    state.activeInvestigation.investigation.hypotheses,
  ).sort((left, right) => left.hypothesis_id.localeCompare(right.hypothesis_id));
  const hypothesisIds = selectedReasoningIds(
    hypotheses,
    'Choose an optional related hypothesis',
  );
  const evidenceIds = selectedReasoningIds(
    asArray(state.evidenceSelections?.analyst_selections),
    'Choose optional analyst-selected evidence',
  );
  state.reasoningDraft = { kind: 'decision', rationale };
  if (!window.confirm(
    'A recorded decision documents analyst reasoning. It does not perform response actions.',
  )) return;
  const updated = await investigationRequest(
    'POST',
    `${activeReasoningBase()}/reasoning/decisions`,
    {
      decision_id: decisionId,
      decision_type: decisionType,
      rationale,
      author,
      hypothesis_ids: hypothesisIds,
      evidence_reference_ids: evidenceIds,
      expected_revision: state.activeInvestigation.revision,
    },
  );
  state.reasoningDraft = null;
  await refreshReasoning(updated);
  await listWebDecisions();
}

function bindReasoningActions() {
  const actions = [
    ['#viewHypothesesButton', listWebHypotheses],
    ['#createHypothesisButton', createWebHypothesis],
    ['#viewReasoningDecisionsButton', listWebDecisions],
    ['#recordReasoningDecisionButton', recordWebDecision],
  ];
  actions.forEach(([selector, handler]) => {
    const button = $(selector);
    if (button) {
      button.addEventListener('click', () => {
        handler().catch(showReasoningError);
      });
    }
  });
}
