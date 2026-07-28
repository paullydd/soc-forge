# EVTX Test Fixtures

## issue_38.evtx

- Source: `williballenthin/python-evtx`, `tests/data/issue_38.evtx`
- Upstream repository: https://github.com/williballenthin/python-evtx
- Upstream fixture note: `tests/data/readme.md` says the source for `d75c90e629f38c7b9e612905e02e2255 issue_38.evtx` was `@nbareil`, via GitHub issue #38.
- License: Apache License 2.0 as distributed by the upstream `python-evtx` repository.
- Purpose: Minimal valid EVTX parser proof fixture for SOC-Forge v2.2 Slice 2A.
- Expected record count: 1
- SHA-256: becab64455866f8fae5583fbaa5dab901115e4397ea7abe14f37ad732d5d7eb9
- Privacy note: This is upstream open-source parser test data, not private SOC-Forge telemetry.

## Normalization scope

Slice 2B uses this fixture only to prove that EVTX XML records can be converted into SOC-Forge's existing flat event dictionary shape. The normalizer extracts universal System metadata and compact EventData values, promotes selected aliases such as identities, IP addresses, process names, command lines, services, tasks, and groups, and keeps unknown EventData inside `raw["event_data"]`.

`python-evtx` exposes XML records but does not guarantee Windows-rendered localized messages. SOC-Forge therefore prefers any rendered message already present in XML and otherwise creates a deterministic fallback summary from provider, Event ID, and selected EventData. Normalized events do not retain raw XML by default; raw evidence is compact parsed metadata only.
