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

## Fixture And Branch Coverage

Every rule needs a matching entry in `tests/fixtures/*.json` (`test_each_yaml_rule_has_a_detection_fixture` enforces this), with a `match` event, a `non_match` event, and optionally `match_overrides` - additional events merged onto `match` to cover other paths through the rule.

A single `match`/`non_match` pair only proves a rule can fire *at all*; it does not prove every alternative inside an `any` block actually works. `SOCF-005` and `SOCF-006` both shipped with a dead alternative (a double-escaped regex that could never match) that stayed unnoticed for weeks because the base fixture happened to satisfy a different alternative in the same block.

`test_rule_branch_coverage.py` closes that gap: for every rule, it walks the full match and score_modifier tree and asserts that every `any` alternative is independently satisfied by at least one fixture event. If you add a new `any` alternative to a rule, add a `match_overrides` entry that isolates it - otherwise this test fails and names exactly which rule and branch is unverified. `test_rule_positive_and_negative_fixtures` enforces the same idea per event: every `match_overrides` entry must independently trigger the rule (aggregate/threshold rules like `SOCF-010` are the one exception, since they only fire across a batch of events by design).
