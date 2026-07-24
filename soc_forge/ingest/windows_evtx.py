from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List

from Evtx.Evtx import Evtx

MAX_EVTX_RECORD_XML_CHARS = 16_384


@dataclass(frozen=True)
class EvtxRecordXml:
    record_number: int
    xml: str
    truncated: bool = False


@dataclass
class WindowsEvtxLoadResult:
    records: List[EvtxRecordXml]
    diagnostics: List[Dict[str, Any]] = field(default_factory=list)
    record_count: int = 0
    skipped_record_count: int = 0

    def xml_entries(self) -> List[str]:
        return [record.xml for record in self.records]


def _diagnostic(level: str, message: str, field: str | None = None, row: int | None = None) -> Dict[str, Any]:
    diagnostic: Dict[str, Any] = {"level": level, "message": message}
    if field is not None:
        diagnostic["field"] = field
    if row is not None:
        diagnostic["row"] = row
    return diagnostic


def _bounded_xml(xml: str) -> tuple[str, bool]:
    if len(xml) <= MAX_EVTX_RECORD_XML_CHARS:
        return xml, False
    return xml[:MAX_EVTX_RECORD_XML_CHARS], True


def load_windows_evtx_records(path: str | Path) -> WindowsEvtxLoadResult:
    input_path = Path(path)
    records: List[EvtxRecordXml] = []
    diagnostics: List[Dict[str, Any]] = []
    skipped_record_count = 0

    if not input_path.exists():
        return WindowsEvtxLoadResult(
            records=[],
            diagnostics=[_diagnostic("error", "EVTX file not found", field="input_path")],
            record_count=0,
            skipped_record_count=0,
        )

    try:
        with Evtx(str(input_path)) as log:
            for record_number, record in enumerate(log.records(), start=1):
                try:
                    xml, truncated = _bounded_xml(record.xml())
                    records.append(EvtxRecordXml(record_number=record_number, xml=xml, truncated=truncated))
                except Exception:
                    skipped_record_count += 1
                    diagnostics.append(
                        _diagnostic(
                            "warning",
                            "Unable to extract EVTX record XML",
                            field="record_xml",
                            row=record_number,
                        )
                    )
    except Exception:
        return WindowsEvtxLoadResult(
            records=[],
            diagnostics=[_diagnostic("error", "Unable to parse EVTX file", field="evtx")],
            record_count=0,
            skipped_record_count=0,
        )

    if not records and skipped_record_count == 0:
        diagnostics.append(_diagnostic("warning", "EVTX file contains no records", field="records"))

    return WindowsEvtxLoadResult(
        records=records,
        diagnostics=diagnostics,
        record_count=len(records),
        skipped_record_count=skipped_record_count,
    )