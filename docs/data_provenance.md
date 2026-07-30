# Data Provenance

SOC-Forge does not ship the former root-level `security_events.csv` or `security_events.jsonl` exports. They were unnecessary local Windows telemetry, were not used by tests or demos, and had no confirmed public redistribution provenance.

Redistributable test data is kept under `tests/fixtures` with fixture-specific provenance where required. Users provide their own JSONL, Windows Security CSV, or EVTX input for local analysis and are responsible for reviewing generated artifacts before sharing them.
