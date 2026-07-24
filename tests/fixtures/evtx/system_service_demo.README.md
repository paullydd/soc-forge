# SOC-Forge EVTX Service Telemetry Demo Dataset

## Dataset

- Dataset name: `system_service_demo.evtx`
- Source file: `system.evtx` from `williballenthin/python-evtx`, `tests/data/system.evtx`
- Upstream repository: https://github.com/williballenthin/python-evtx
- Upstream provenance note: `python-evtx/tests/data/readme.md` states this file came from the log2timeline/plaso test data at commit `1e2fa282efa2f839e1f179a3e98dbf922b5dbbc7`.
- Ownership/license statement: Redistributed as open-source test fixture data from the Apache License 2.0 `python-evtx` repository. Plaso is also distributed under Apache License 2.0.
- Created by: Public upstream parser/test-data maintainers; not generated from private SOC-Forge telemetry.
- Creation date: Unknown upstream fixture creation date; integrated into SOC-Forge fixtures for v2.2 Slice 2D on 2026-07-24.
- Source environment: Windows workstation test image, hostname observed as `WKS-WIN764BITB.shieldbase.local`.
- Operating system version: Windows 7 64-bit is inferred from the upstream fixture name/host string and event source; exact OS build is not guaranteed by SOC-Forge.
- File size: 1,118,208 bytes
- SHA-256: `ccb83cfefc9038017224cd97b800b66e248fe14529649ddf47907e5a2021449e`

## Activity and Expected Content

This dataset contains Windows System channel telemetry with Service Control Manager activity. The SOC-Forge demo focuses on service installation events, including PsExec-style service activity represented by `PSEXESVC.EXE`/`PsExec` service evidence.

Expected high-signal Event IDs include:

- `7045` service installed
- `7040` service start type changed
- `7036` service entered a running/stopped state
- `6013`, `6005`, `6009` system uptime/startup context

Expected normalized fields include:

- `event_id`
- `timestamp`
- `host`
- `provider`
- `channel`
- `record_id`
- `service_name`
- `service_account`
- `image_path`
- compact `raw["event_data"]`

Expected SOC-Forge analytical output with the current rules:

- 1,601 normalized events
- no ingest diagnostics
- 12 `SOCF-004` alerts for new service installation
- 4 `SOCF-016` alerts for PsExec-style service execution
- 1 investigation case, titled `PsExec-style service execution`
- 13 hunt findings for suspicious service command evidence
- JSON artifacts and HTML report generated through the normal shared pipeline

## Analyst Narrative

The source activity shows multiple Windows service installation events. Among ordinary-looking service installs, several events reference PsExec-style service execution through `PsExec`/`PSEXESVC.EXE`. SOC-Forge detects this because existing service rules look for Event ID `7045`, service names, image paths, command lines, and message evidence associated with remote service execution.

An analyst should inspect the generated alerts and case evidence to answer:

- Which service names and image paths were installed?
- Were PsExec-style services expected administrative activity?
- What host produced the service-install telemetry?
- Do neighboring service state changes support or contradict the suspected activity?
- Is additional Security channel authentication telemetry needed to identify the initiating user or source host?

SOC-Forge cannot prove intent from this System log alone. This dataset does not include complete authentication context, endpoint process lineage, or network telemetry. Treat the result as an explainable investigation starting point, not a final incident conclusion.

## Sanitization and Privacy

No SOC-Forge private telemetry, real credentials, secrets, or personal user activity were added. The fixture is public upstream test data. Hostnames and service names are retained because they are necessary for parser and analyst-workflow validation.

## Known Limitations

- This is a controlled public fixture, not a full enterprise incident dataset.
- It demonstrates initial local EVTX ingestion and investigation support, not complete Windows Event Log compatibility.
- Windows-rendered localized messages are not guaranteed by `python-evtx`; SOC-Forge uses compact deterministic fallback messages from provider, Event ID, and EventData.
- The dataset is System-channel heavy and does not provide a full authentication-to-execution chain.
