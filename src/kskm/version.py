"""Version information."""

from importlib.metadata import version

# https://www.python.org/dev/peps/pep-0440
__version__ = version("kskm")

try:
    from kskm.buildinfo import __commit__, __timestamp__

    __verbose_version__ = f"{__version__} ({__commit__})"
except (ImportError, ModuleNotFoundError):
    __verbose_version__ = __version__
    __commit__ = None
    __timestamp__ = None
