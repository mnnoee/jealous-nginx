"""nginxparse - модульный парсер access-логов nginx."""

from .cli import main
from .constants import VERSION
from .core import NginxLogParser, analyze
from .i18n import detect_lang, get_lang, set_lang
from .report import report as build_report

__version__ = VERSION

__all__ = ["VERSION", "__version__", "NginxLogParser", "analyze", "build_report", "main",
           "detect_lang", "get_lang", "set_lang"]
