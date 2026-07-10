"""Diagnose plugin runtime package."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("diagnose-plugin")
except PackageNotFoundError:  # pragma: no cover - editable source without metadata
    __version__ = "0.1.0"

__all__ = ["__version__"]
