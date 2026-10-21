"""Excepciones propias del conector Darktrace.

Separan los tres tipos de fallo que el usuario debe distinguir:
autenticación, red/servidor y datos. Nunca exponemos excepciones
crípticas del cliente HTTP subyacente.
"""


class DarktraceConnectorError(Exception):
    """Error base del conector."""


class DarktraceAuthError(DarktraceConnectorError):
    """Credenciales inválidas o permisos insuficientes."""


class DarktraceNetworkError(DarktraceConnectorError):
    """No se pudo alcanzar el servicio (red, timeout o error del servidor)."""


class DarktraceDataError(DarktraceConnectorError):
    """La operación es válida pero los datos o parámetros no lo son."""
