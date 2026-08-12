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
  await inspectEvidence(evidenceId, false);
  const target = document.querySelector('#evidenceWorkspace');
  if (target) target.scrollIntoView({ behavior: 'smooth', block: 'start' });
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

function summaryMetric(label, value) {
  const item = summaryNode('div', null, 'summary-metric');
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

  const identity = summaryNode('div', null, 'summary-metrics');
  identity.appendChild(summaryMetric('Status', summary.status));
  identity.appendChild(summaryMetric('Owner', summary.owner || 'Unassigned'));
  identity.appendChild(summaryMetric('Revision', summary.revision));
  identity.appendChild(summaryMetric('Selected cases', summary.selected_case_ids.length));
  identity.appendChild(summaryMetric('Evidence', summary.state.selected_evidence_count));
  identity.appendChild(summaryMetric('Decisions', summary.state.decision_count));
  mount.appendChild(identity);

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

  const timeline = summarySection('Timeline', 'Machine and analyst context');
  if (summary.timeline) {
    timeline.appendChild(summaryNode('p', `${summary.timeline.timed_entry_count} timed and ${summary.timeline.untimed_entry_count} untimed entries.`));
    summary.timeline.milestones.forEach((item) => timeline.appendChild(summaryNode('p', `${item.timestamp} | ${item.title}`)));
    timeline.appendChild(summaryButton('Open timeline', openQueryTimeline));
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
  if (!state.activeInvestigation) return;
  const summary = await investigationRequest('GET', `/api/investigations/${encodeURIComponent(state.activeInvestigation.investigation_id)}/summary`);
  renderInvestigationSummary(summary);
}
