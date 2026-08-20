from __future__ import annotations

from textwrap import wrap
from typing import Iterable

from soc_forge.rule_explainability import RuleExplanation
from soc_forge.ui.terminal import (
    render_application_header,
    render_badge,
    render_breadcrumb,
    render_empty_state,
    render_metadata,
    render_panel,
    resolve_terminal_width,
)


def _wrap_lines(lines: Iterable[object], width: int) -> tuple[str, ...]:
    rendered = []
    for value in lines:
        text = str(value)
        indentation = text[: len(text) - len(text.lstrip())]
        rendered.extend(
            wrap(
                text,
                width=max(1, width),
                subsequent_indent=indentation + "  ",
                break_long_words=True,
                break_on_hyphens=False,
            )
            or ("",)
        )
    return tuple(rendered)


def render_rule_explanation_catalog(
    explanations: Iterable[RuleExplanation],
    *,
    width: int | None = None,
    ansi: bool | None = None,
    unicode: bool = True,
) -> str:
    resolved = resolve_terminal_width(width)
    rows = []
    for index, explanation in enumerate(explanations, start=1):
        rows.extend(
            (
                f"[{index}] {explanation.rule_id} - {explanation.title}",
                (
                    f"{'[ENABLED]' if explanation.enabled else '[DISABLED]'} "
                    f"{render_badge('severity', explanation.severity, ansi=ansi)}"
                ),
                "",
            )
        )
    if not rows:
        rows.append(
            render_empty_state(
                "No rules available.", width=resolved - 4, ansi=ansi
            )
        )
    return "\n".join(
        (
            render_application_header(
                width=resolved, ansi=ansi, unicode=unicode
            ),
            render_breadcrumb(
                ("SOC-FORGE", "DETECTION", "RULE EXPLAINABILITY"),
                width=resolved,
                ansi=ansi,
                unicode=unicode,
            ),
            render_panel(
                rows,
                title="SELECT RULE",
                width=resolved,
                ansi=ansi,
                unicode=unicode,
            ),
        )
    )


def render_rule_explanation(
    explanation: RuleExplanation,
    *,
    width: int | None = None,
    ansi: bool | None = None,
    unicode: bool = True,
) -> str:
    resolved = resolve_terminal_width(width)
    inner = resolved - 4
    sections = [
        render_application_header(width=resolved, ansi=ansi, unicode=unicode),
        render_breadcrumb(
            (
                "SOC-FORGE",
                "DETECTION",
                "RULE EXPLAINABILITY",
                explanation.rule_id,
            ),
            width=resolved,
            ansi=ansi,
            unicode=unicode,
        ),
        render_panel(
            render_metadata(
                (
                    ("Rule ID", explanation.rule_id),
                    ("Title", explanation.title),
                    (
                        "Enabled",
                        "Yes" if explanation.enabled else "No",
                    ),
                    ("Severity", explanation.severity.upper()),
                    (
                        "Description",
                        explanation.description or "Not provided",
                    ),
                ),
                width=inner,
                ansi=ansi,
                wrap_values=True,
            ),
            title="OVERVIEW",
            width=resolved,
            ansi=ansi,
            unicode=unicode,
        ),
        render_panel(
            _wrap_lines(explanation.match_logic, inner - 2),
            title="RULE LOGIC",
            width=resolved,
            ansi=ansi,
            unicode=unicode,
        ),
        render_panel(
            explanation.referenced_fields
            or (
                render_empty_state(
                    "No referenced fields.", width=inner, ansi=ansi
                ),
            ),
            title="REFERENCED FIELDS",
            width=resolved,
            ansi=ansi,
            unicode=unicode,
        ),
    ]
    if explanation.aggregate_behavior:
        sections.append(
            render_panel(
                render_metadata(
                    (
                        ("Behavior", explanation.aggregate_behavior),
                        (
                            "Group by",
                            ", ".join(explanation.grouping_fields),
                        ),
                        ("Distinct field", explanation.aggregate_field),
                        ("Threshold", f">= {explanation.threshold}"),
                        (
                            "Time window",
                            f"{explanation.time_window_minutes} minutes",
                        ),
                    ),
                    width=inner,
                    ansi=ansi,
                    wrap_values=True,
                ),
                title="AGGREGATION",
                width=resolved,
                ansi=ansi,
                unicode=unicode,
            )
        )
    if explanation.score_modifiers:
        modifier_lines = []
        for index, modifier in enumerate(explanation.score_modifiers, start=1):
            modifier_lines.append(f"Modifier {index}:")
            modifier_lines.extend(modifier.logic)
            modifier_lines.append(f"Score addition: +{modifier.score_addition}")
            modifier_lines.append(
                "Bump severity: " + ("Yes" if modifier.bumps_severity else "No")
            )
            if modifier.detail_updates:
                modifier_lines.append(
                    "Detail updates: "
                    + ", ".join(
                        f"{key}={value}"
                        for key, value in modifier.detail_updates
                    )
                )
            if modifier.reason:
                modifier_lines.append(f"Reason: {modifier.reason}")
        sections.append(
            render_panel(
                _wrap_lines(modifier_lines, inner - 2),
                title="SCORE MODIFIERS",
                width=resolved,
                ansi=ansi,
                unicode=unicode,
            )
        )
    attack_lines = tuple(
        mapping.presentation for mapping in explanation.attack_mappings
    )
    sections.append(
        render_panel(
            _wrap_lines(attack_lines, inner - 2)
            or (
                render_empty_state(
                    "No explicit ATT&CK mappings.", width=inner, ansi=ansi
                ),
            ),
            title="MITRE ATT&CK",
            width=resolved,
            ansi=ansi,
            unicode=unicode,
        )
    )
    output_rows = [
        ("Alert title", explanation.title),
        ("Severity", explanation.severity.upper()),
    ]
    if explanation.emit_summary:
        output_rows.append(("Configured summary", explanation.emit_summary))
    output_rows.append(
        (
            "Explicit emitted fields",
            ", ".join(explanation.emit_fields) or "None configured",
        )
    )
    if explanation.emit_source_fields:
        output_rows.append(
            (
                "Emit source fields",
                ", ".join(explanation.emit_source_fields),
            )
        )
    sections.append(
        render_panel(
            render_metadata(
                output_rows,
                width=inner,
                ansi=ansi,
                wrap_values=True,
            ),
            title="OUTPUT",
            width=resolved,
            ansi=ansi,
            unicode=unicode,
        )
    )
    sections.append(
        render_panel(
            render_metadata(
                (
                    (
                        "Log source",
                        explanation.logsource or "Not provided",
                    ),
                    ("Tags", ", ".join(explanation.tags) or "None"),
                    ("Author", explanation.author or "Not provided"),
                    ("Created", explanation.created or "Not provided"),
                ),
                width=inner,
                ansi=ansi,
                wrap_values=True,
            ),
            title="RULE METADATA",
            width=resolved,
            ansi=ansi,
            unicode=unicode,
        )
    )
    limitation_lines = tuple(explanation.limitations) + tuple(
        explanation.assumptions
    )
    if not limitation_lines:
        limitation_lines = (
            "Rule explanation reflects configured rule logic and does not "
            "establish detection completeness.",
        )
    sections.append(
        render_panel(
            render_metadata(
                tuple(
                    ("Guidance", line) for line in limitation_lines
                ),
                width=inner,
                ansi=ansi,
                wrap_values=True,
            ),
            title="LIMITATIONS",
            width=resolved,
            ansi=ansi,
            unicode=unicode,
        )
    )
    return "\n".join(sections)
