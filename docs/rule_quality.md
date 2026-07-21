# Rule Quality

SOC-Forge includes a rule quality check for detection content. It is meant to keep rules useful for analysts and clear enough for portfolio review.

## Run The Check

```bash
source .venv/bin/activate
python -m soc_forge.cli --rule-quality
```

A clean result looks like this:

```text
Rule Quality

PASS: no rule quality findings.
```

## What It Checks

The quality gate currently checks that each YAML rule has:

- A stable rule id pattern, such as `SOCF-007`
- Reviewer-facing metadata: `description`, `author`, `created`, `logsource`, and `tags`
- A valid-looking `created` date in `YYYY-MM-DD` format
- At least one MITRE ATT&CK mapping with tactic, technique, and id
- Explicit `emit.details` evidence fields instead of fallback-only alert details
- A source `message` field in emitted evidence when available
- At least one host, identity, IP, group, service, or task context field
- At least one concrete match predicate

## Why This Matters

Working detections are only half the job. Good detection content should also explain what it detects, where it applies, how it maps to ATT&CK, and what evidence the analyst should see when it fires.

This makes SOC-Forge easier to demo and easier to extend: every new rule has to carry enough context to support triage, reports, graphs, and case exports.
