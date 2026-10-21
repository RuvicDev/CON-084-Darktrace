"""Prueba de conexión estándar del conector darktrace.

Firma estándar Ruvic: def test_connection() -> tuple[bool, str]
- Lee la configuración EXCLUSIVAMENTE de las env vars RUVIC_DARKTRACE_*.
- Nunca lanza excepciones; retorna (ok, mensaje).

Ejecutable también como script para pruebas locales:
    python test_connection.py
"""

from __future__ import annotations


def test_connection() -> tuple[bool, str]:
    """Lista los modelos de Darktrace con las env vars RUVIC_DARKTRACE_*."""
    try:
        from ruvic_darktrace_connector import (
            DarktraceAuthError,
            DarktraceClient,
            DarktraceDataError,
            DarktraceNetworkError,
        )
    except ImportError:
        return (
            False,
            (
                "La librería ruvic-darktrace-connector no está instalada. "
                "Instala con: pip install git+https://github.com/RuvicDev/"
                "CON-084-Darktrace.git#subdirectory=lib"
            ),
        )

    try:
        client = DarktraceClient()  # valida que existan las env vars
    except ValueError as exc:
        return False, str(exc)

    try:
        client.ping()
    except DarktraceAuthError as exc:
        return False, f"Autenticación fallida: {exc}"
    except DarktraceNetworkError as exc:
        return False, f"Error de red: {exc}"
    except DarktraceDataError as exc:
        return False, f"Error de datos: {exc}"
    except Exception as exc:  # noqa: BLE001 - red de seguridad: jamás propagar
        return False, f"Error inesperado: {exc}"

    return True, f"Conexión exitosa a Darktrace ({client.config.base_url})"


if __name__ == "__main__":
    ok, message = test_connection()
    print(f"{'OK' if ok else 'FALLO'}: {message}")
    raise SystemExit(0 if ok else 1)
