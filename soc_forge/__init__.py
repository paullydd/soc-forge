from __future__ import annotations

__all__ = ["__version__"]

# Default fallback (never breaks imports)
__version__ = "0.11.0"

try:
    from importlib.metadata import PackageNotFoundError, version

    # Try common distribution names
    for dist in ("soc-forge", "soc_forge"):
        try:
            __version__ = version(dist)
            break
        except PackageNotFoundError:
            pass
except Exception:
    # Keep the fallback string above
    pass