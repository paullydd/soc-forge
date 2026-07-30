from pathlib import Path


DEFAULT_WORKSPACE_DIRECTORY = "workspace"


def resolve_workspace_root(
    output_root: Path | str,
    workspace_root: Path | str | None = None,
) -> Path:
    if workspace_root is not None:
        return Path(workspace_root)
    return Path(output_root) / DEFAULT_WORKSPACE_DIRECTORY
