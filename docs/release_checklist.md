# SOC-Forge v3.6.0 Release Checklist

1. Confirm the working tree is clean.
2. Confirm every authoritative version source reports `3.6.0`.
3. Run the full test suite.
4. Build the wheel and source distribution from a clean build directory.
5. Run `python -m twine check dist/*`.
6. Inspect package contents and checksums.
7. Install the wheel into a clean environment outside the repository.
8. Smoke-test rules, analysis, investigation imports, and handoff validation.
9. Push `main` without tagging.
10. Wait for Python 3.10, 3.11, and 3.12 CI plus the package job.
11. Review and finalize release notes.
12. Tag `v3.6.0` only after green CI.
13. Push the tag and verify it resolves to the release commit.

Do not commit generated `build/`, `dist/`, handoff bundles, reports, workspace records, caches, or package metadata.
