# Terminal UI Foundation

SOC-Forge v3.2 Slice 1 establishes shared presentation primitives for the Analyst Console. It improves formatting consistency and portability without changing console control flow, investigation semantics, persistence, analysis, or detection behavior.

## Architecture

`soc_forge.ui.terminal` contains pure renderers. They accept data and presentation options and return strings or immutable tuples of strings. They never read input, pause, clear the screen, dispatch actions, access repositories, or mutate analysis and investigation state. Controllers remain the sole owners of navigation and acknowledgement behavior.

The existing `soc_forge.ui.screen` helper remains responsible for screen clearing. Existing controllers and menus remain authoritative. The older `soc_forge.ui.panels.visible_len` entry point delegates to the shared ANSI-aware visible-length utility for compatibility.

## Primitives

The foundation provides compact application headers, titles, breadcrumbs, sections, dividers, bordered panels, metadata rows, semantic badges, bounded messages, grouped menus, and ANSI-safe width utilities.

Badges always include state text such as `[ACTIVE]`, `[SUPERSEDED]`, or `[HIGH]`. Color is supplementary and never carries meaning by itself. Unknown values receive a bounded neutral presentation rather than changing domain vocabulary.

## Width And Content Policy

The renderer uses an explicit width when supplied. Otherwise it asks the standard library for the current terminal width with an 80-column fallback. Width is clamped between 24 and 100 columns. Titles, breadcrumb segments, metadata values, badge labels, messages, panel content, and menu labels are bounded for presentation only; source values are never mutated.

Panels truncate overlong rows deterministically. Narrow terminals use compact metadata rows. Unicode borders are the default because they match the existing console, while callers can request ASCII borders and separators.

Visible-width calculations remove ANSI control sequences. ANSI-aware truncation appends a reset sequence when truncating styled content. Passing `ansi=False`, setting `NO_COLOR`, or using `TERM=dumb` produces readable text without color codes.

Python's standard string length is used after ANSI removal. Exact display width for uncommon double-width or combining Unicode characters is a documented limitation; adding a new width dependency is intentionally deferred.

## Initial Integration

The Command Center prints the compact application header before its existing dashboard. This passive integration introduces no input, delay, pause, dispatch, menu-number, repository, revision, snapshot, artifact, or `AnalysisResult` change.

Later v3.2 slices can migrate individual console surfaces deliberately. Slice 1 does not redesign the Investigation Workspace, Summary, Evidence, Findings, Handoff, startup experience, or web UI.

v3.2 Slice 1 establishes presentation primitives only. Existing console workflows remain behaviorally unchanged.


## Existing Startup Presentation

The Analyst Console continues to use its original large SOC ASCII logo and cyan/yellow SOC-Forge identity. The existing startup renderer reads the authoritative package version and presents readiness lines for Runtime, Detection Rules, Investigation Workspace, Analysis Snapshots, and Analyst Services beneath that branding. It remains the single startup implementation and does not use the compact Command Center application header as a replacement splash.

## Command Center And Navigation

The startup screen and Command Center have distinct roles. Startup retains the large branded SOC logo and readiness sequence; the Command Center uses the compact application header, SOC-FORGE > COMMAND CENTER breadcrumb, and existing dashboard projections for routine navigation.

The platform overview continues to use the established alert, case, case-status, and severity counts without introducing new calculations. Recent activity preserves the existing source order and three-item display limit. Navigation is grouped as Operations (1 Detection, 2 Investigations, 3 Analysis) and Output & Administration (4 Reporting, 5 System), with 0 retaining its existing exit behavior.

Top-level menus add a minimal SOC-FORGE > MENU breadcrumb while preserving their existing options, dispatch, input handling, and back navigation. Nested workspace redesign remains deferred to later slices. The same bounded-width and no-color behavior used by the terminal foundation applies to the Command Center.

v3.2 Slice 3 changes presentation and navigation hierarchy only; Command Center behavior and menu semantics remain unchanged.
