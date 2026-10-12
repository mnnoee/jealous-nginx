"""nginxparse — модульный парсер access-логов nginx."""

from .cli import main
from .constants import VERSION
from .core import NginxLogParser, analyze
from .report import report as build_report

# Версия берётся из constants.VERSION — единственный источник истины.
# pyproject.toml читает её через [tool.setuptools.dynamic].
__version__ = VERSION

__all__ = ["VERSION", "__version__", "NginxLogParser", "analyze", "build_report", "main"]
