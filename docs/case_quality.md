# Case Quality Polish

SOC-Forge now attaches a case quality brief to generated cases. The goal is to make each case easier to review, explain, export, and demo.

## What A Case Quality Brief Contains

Each generated case can include:

- Executive summary
- Key findings
- Key evidence with why-it-matters language
- Containment guidance
- Case quality score
- Quality gaps when important context is missing
- Analyst questions for follow-up investigation

## Where It Appears

The case quality profile is attached in several places:

- `out/cases.json` as `case_quality`
- The HTML report as `Case Quality Brief`
- Investigation bundles as `case_brief.txt`
- Normalized case objects as `executive_summary` and `containment_guidance`

## Why This Matters

Raw alerts are useful for detection testing, but a case needs to answer analyst questions:

- What happened?
- Why does it matter?
- Which evidence supports the conclusion?
- What should the analyst do next?
- What is still missing?

The case quality brief gives SOC-Forge a stronger investigation handoff and makes the portfolio demo easier to follow.

## Quick Check

Run the attack-chain demo and inspect `out/cases.json`:

```bash
source .venv/bin/activate
python -m soc_forge.cli --simulate attack_chain --sim-output out/attack_chain_events.jsonl
python -m soc_forge.cli --input out/attack_chain_events.jsonl --out out/alerts.json --html out/report.html
```

Then look for `case_quality` on each generated case.
