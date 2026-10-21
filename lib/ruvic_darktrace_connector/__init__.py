"""Detección de amenazas en la red con Darktrace: consultar modelos, obtener alertas (model breaches), consultar incidentes de Cyber AI Analyst y reconocer alertas"""

from .client import DarktraceClient
from .config import ENV_PREFIX, DarktraceConfig
from .exceptions import (
    DarktraceAuthError,
    DarktraceConnectorError,
    DarktraceDataError,
    DarktraceNetworkError,
)
from .logging_utils import setup_logging

__all__ = [
    "DarktraceAuthError",
    "DarktraceClient",
    "DarktraceConfig",
    "DarktraceConnectorError",
    "DarktraceDataError",
    "DarktraceNetworkError",
    "ENV_PREFIX",
    "setup_logging",
]

__version__ = "1.0.0"
