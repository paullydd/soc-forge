from importlib.metadata import version, PackageNotFoundError

try:
    __version__ = version("soc-forge")
except PackageNotFoundError:
    # Fallback for running from source without an installed distribution
    __version__ = "0.0.0"