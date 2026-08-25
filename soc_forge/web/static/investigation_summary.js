function summaryNode(tag, text, className) {
  const node = document.createElement(tag);
  if (text !== undefined && text !== null) node.textContent = String(text);
  if (className) node.className = className;
  return node;
}

function showInvestigationSummaryError(error) {
  const mount = document.querySelector('#investigationSummary');
  if (!mount) return;
  mount.replaceChildren(summaryNode('p', error.message || 'Investigation summary is unavailable.', 'error'));
}

async function openSummaryEvidence(evidenceId) {
  setInvestigationTab('evidence');
  await inspectEvidence(evidenceId, false);
  const target = document.querySelector('#evidenceWorkspace');
  if (target) target.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

async function openSummaryTimeline() {
  setInvestigationTab('timeline');
  await openQueryTimeline();
}

function summaryButton(label, handler) {
  const button = summaryNode('button', label);
  button.type = 'button';
  button.addEventListener('click', () => handler().catch(showInvestigationSummaryError));
  return button;
}

function summarySection(title, attribution) {
  const section = summaryNode('section', null, 'summary-group');
  const heading = summaryNode('div', null, 'panel-head');
  heading.appendChild(summaryNode('h3', title));
  if (attribution) heading.appendChild(summaryNode('span', attribution, 'badge'));
  section.appendChild(heading);
  return section;
}

function summaryMetric(label, value, priority = 'secondary') {
  const item = summaryNode('div', null, `summary-metric summary-metric-${priority}`);
  item.appendChild(summaryNode('span', label, 'summary-metric-label'));
  item.appendChild(summaryNode('strong', value));
  return item;
}

function renderInvestigationSummary(summary) {
  const mount = document.querySelector('#investigationSummary');
  if (!mount) return;
  mount.replaceChildren();

  const heading = summaryNode('div', null, 'panel-head');
  heading.appendChild(summaryNode('h2', 'Investigation Summary'));
  heading.appendChild(summaryNode('span', summary.mode === 'full' ? 'Full context' : 'Offline context', 'badge'));
  mount.appendChild(heading);
  mount.appendChild(summaryNode('p', summary.narrative, 'workspace-help'));

  const overview = summaryNode('div', null, 'summary-overview');
  overview.appendChild(summaryMetric('Status', summary.status, 'primary'));
  overview.appendChild(summaryMetric('Owner', summary.owner || 'Unassigned', 'primary'));
  overview.appendChild(summaryMetric('Evidence', summary.state.selected_evidence_count, 'primary'));
  overview.appendChild(summaryMetric('Findings', summary.finding_counts.total, 'primary'));
  overview.appendChild(summaryMetric('Response actions', summary.response_action_counts.total, 'primary'));
  mount.appendChild(overview);

  const lifecycle = summaryNode('div', null, 'summary-lifecycle');
  lifecycle.appendChild(summaryMetric('Revision', summary.revision));
  lifecycle.appendChild(summaryMetric('Selected cases', summary.selected_case_ids.length));
  lifecycle.appendChild(summaryMetric('Decisions', summary.state.decision_count));
  lifecycle.appendChild(summaryMetric('Active findings', summary.finding_counts.active));
  lifecycle.appendChild(summaryMetric('Historical findings', summary.finding_counts.superseded));
  lifecycle.appendChild(summaryMetric('Draft findings', summary.finding_counts.draft));
  lifecycle.appendChild(summaryMetric('Substantiated', summary.finding_counts.substantiated));
  lifecycle.appendChild(summaryMetric('Inconclusive', summary.finding_counts.inconclusive));
  lifecycle.appendChild(summaryMetric('Proposed actions', summary.response_action_counts.proposed));
  lifecycle.appendChild(summaryMetric('Approved actions', summary.response_action_counts.approved));
  lifecycle.appendChild(summaryMetric('Actions in progress', summary.response_action_counts.in_progress));
  lifecycle.appendChild(summaryMetric('Completed actions', summary.response_action_counts.completed));
  lifecycle.appendChild(summaryMetric('Dismissed actions', summary.response_action_counts.dismissed));
  mount.appendChild(lifecycle);

  if (summary.mode === 'full' && summary.findings.length) {
    const findings = summarySection('Machine Context', 'Machine-derived');
    summary.findings.forEach((finding) => {
      const record = summaryNode('article', null, 'workspace-record');
      record.appendChild(summaryNode('strong', `${finding.case_id}: ${finding.title}`));
      record.appendChild(summaryNode('p', `Rules: ${finding.rule_ids.join(', ') || 'None'}`));
      record.appendChild(summaryNode('p', `Severity: ${finding.severities.join(', ') || 'None'}`));
      record.appendChild(summaryNode('p', `ATT&CK tactics: ${finding.attack_tactics.join(', ') || 'None'}`));
      record.appendChild(summaryNode('p', `ATT&CK techniques: ${finding.attack_techniques.join(', ') || 'None'}`));
      findings.appendChild(record);
    });
    mount.appendChild(findings);
  }

  const evidence = summarySection('Selected Evidence', 'Analyst-selected');
  if (!summary.evidence.length) evidence.appendChild(summaryNode('p', 'No evidence selected.'));
  summary.evidence.forEach((item) => {
    const record = summaryNode('article', null, 'workspace-record');
    record.appendChild(summaryNode('strong', item.evidence_id));
    record.appendChild(summaryNode('span', item.classification, 'badge'));
    if (item.sensitive_content) record.appendChild(summaryNode('span', 'Sensitive', 'badge severity-high'));
    record.appendChild(summaryNode('p', item.rationale_summary || 'No rationale recorded.'));
    record.appendChild(summaryButton('Open evidence', () => openSummaryEvidence(item.evidence_id)));
    evidence.appendChild(record);
  });
  mount.appendChild(evidence);

  const reasoning = summarySection('Hypotheses and Decisions', 'Analyst-authored');
  if (!summary.hypotheses.length && !summary.decisions.length) reasoning.appendChild(summaryNode('p', 'No hypotheses or decisions recorded.'));
  summary.hypotheses.forEach((item) => {
    const record = summaryNode('article', null, 'workspace-record');
    record.appendChild(summaryNode('strong', item.hypothesis_id));
    record.appendChild(summaryNode('p', item.statement_summary));
    record.appendChild(summaryNode('p', `Analyst assessment: ${item.state}`));
    record.appendChild(summaryButton('Open hypothesis', () => showWebHypothesis(item.hypothesis_id)));
    reasoning.appendChild(record);
  });
  summary.decisions.forEach((item) => {
    const record = summaryNode('article', null, 'workspace-record');
    record.appendChild(summaryNode('strong', `${item.decision_id}: ${item.outcome}`));
    record.appendChild(summaryNode('p', item.rationale_summary));
    record.appendChild(summaryButton('Open decision', () => showQueryDecision(item.decision_id)));
    reasoning.appendChild(record);
  });
  mount.appendChild(reasoning);

  const analystFindings = summarySection('Analyst Findings', 'Analyst-authored');
  analystFindings.appendChild(summaryNode('p', 'Findings are analyst-authored conclusions. Confidence reflects analyst assessment, not machine certainty.'));
  if (!summary.analyst_findings.length) {
    analystFindings.appendChild(summaryNode('p', 'No analyst-authored findings.'));
  }
  ['active', 'superseded'].forEach((lifecycle) => {
    analystFindings.appendChild(summaryNode(
      'h3',
      lifecycle === 'active' ? 'Active Findings' : 'Historical / Superseded Findings'
    ));
    summary.analyst_findings.filter((item) => item.lifecycle_state === lifecycle).forEach((item) => {
      const record = summaryNode('article', null, 'workspace-record');
      const heading = summaryNode('div', null, 'finding-lifecycle-head');
      heading.appendChild(summaryNode('strong', `${item.finding_id}: ${item.title}`));
      heading.appendChild(summaryNode(
        'span',
        item.lifecycle_state.toUpperCase(),
        `finding-lifecycle-badge finding-lifecycle-${item.lifecycle_state}`
      ));
      record.appendChild(heading);
    record.appendChild(summaryNode('span', item.status, 'badge'));
    record.appendChild(summaryNode('p', `Analyst confidence: ${item.confidence}`));
    record.appendChild(summaryNode('p', item.conclusion));
    record.appendChild(summaryNode('p', `Basis: ${item.evidence_count} evidence, ${item.hypothesis_count} hypotheses, ${item.decision_count} decisions`));
    if (item.attack_tactics.length || item.attack_techniques.length) {
      record.appendChild(summaryNode('p', `ATT&CK: ${item.attack_tactics.concat(item.attack_techniques).join(', ')}`));
    }
    item.limitations.forEach((value) => record.appendChild(summaryNode('p', `Limitation: ${value}`)));
    record.appendChild(summaryButton('Open Finding', () => {
      setInvestigationTab('findings');
      return openFinding(item.finding_id);
    }));
      analystFindings.appendChild(record);
    });
  });
  mount.appendChild(analystFindings);

  const responseActions = summarySection('Response Actions', 'Analyst-controlled');
  responseActions.appendChild(summaryNode('p', 'Response Actions record analyst-controlled work and do not represent executed remediation.'));
  if (!summary.response_actions.length) responseActions.appendChild(summaryNode('p', 'No analyst-controlled Response Actions.'));
  summary.response_actions.forEach((item) => {
    const record = summaryNode('article', null, 'workspace-record');
    record.appendChild(summaryNode('strong', `${item.action_id}: ${item.title}`));
    record.appendChild(summaryNode('span', item.status.toUpperCase(), `badge response-action-${item.status}`));
    record.appendChild(summaryNode('p', `Type: ${item.action_type} | Priority: ${item.priority}`));
    record.appendChild(summaryNode('p', `Owner: ${item.owner}`));
    record.appendChild(summaryNode('p', `Related Findings: ${item.finding_ids.join(', ')}`));
    record.appendChild(summaryNode('p', `Rationale: ${item.rationale}`));
    record.appendChild(summaryNode('p', `Lifecycle transitions: ${item.transition_count}`));
    responseActions.appendChild(record);
  });
  mount.appendChild(responseActions);

  const timeline = summarySection('Timeline', 'Machine and analyst context');
  if (summary.timeline) {
    timeline.appendChild(summaryNode('p', `${summary.timeline.timed_entry_count} timed and ${summary.timeline.untimed_entry_count} untimed entries.`));
    summary.timeline.milestones.forEach((item) => timeline.appendChild(summaryNode('p', `${item.timestamp} | ${item.title}`)));
    timeline.appendChild(summaryButton('Open timeline', openSummaryTimeline));
  } else {
    timeline.appendChild(summaryNode('p', 'Timeline requires the matching source analysis.'));
  }
  mount.appendChild(timeline);

  if (summary.limitations.length) {
    const limitations = summarySection('Limitations');
    const list = summaryNode('ul');
    summary.limitations.forEach((item) => list.appendChild(summaryNode('li', item)));
    limitations.appendChild(list);
    mount.appendChild(limitations);
  }
}

async function loadInvestigationSummary() {
  const investigationId =
    state.activeInvestigation?.investigation?.investigation_id;
  if (!investigationId) return;

  const summary = await investigationRequest(
    'GET',
    `/api/investigations/${encodeURIComponent(investigationId)}/summary`,
  );
  renderInvestigationSummary(summary);
}
