"""Cliente de detección de amenazas para la API de Darktrace.

Capacidades:
- list_models():       consultar los modelos de detección.
- get_alerts():        obtener alertas (model breaches) recientes.
- list_incidents():    consultar incidentes de Cyber AI Analyst.
- acknowledge_alert(): reconocer (acknowledge) una alerta.

Autenticación: cada petición se firma con HMAC-SHA1 usando el token
privado sobre "<ruta>?<query>\\n<token público>\\n<fecha>", enviado en los
headers DTAPI-Token, DTAPI-Date y DTAPI-Signature.

Las credenciales SIEMPRE provienen de variables de entorno RUVIC_DARKTRACE_*
(ver config.DarktraceConfig.from_env). Prohibido hardcodearlas.
"""

from __future__ import annotations

import hashlib
import hmac
import time
from datetime import datetime, timezone
from typing import Any

import requests
import urllib3

from .config import DarktraceConfig
from .exceptions import DarktraceAuthError, DarktraceDataError, DarktraceNetworkError
from .logging_utils import get_logger


def _hours(value: Any, field: str = "hours", maximum: int = 24 * 90) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
        raise DarktraceDataError(f"{field} debe ser un entero entre 1 y {maximum}.")
    return value


def _limit(value: Any, maximum: int = 500) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
        raise DarktraceDataError(f"limit debe ser un entero entre 1 y {maximum}.")
    return value


def _since_ms(hours: int) -> int:
    return int((time.time() - hours * 3600) * 1000)


def _ms_to_iso(value: Any) -> str | None:
    if not isinstance(value, (int, float)):
        return None
    return datetime.fromtimestamp(value / 1000, tz=timezone.utc).isoformat()


class DarktraceClient:
    """Cliente de la API de Darktrace (Threat Visualizer / instancia cloud).

    Args:
        config: configuración de conexión. Si se omite, se lee de las
            variables de entorno RUVIC_DARKTRACE_*.

    Ejemplo:
        >>> client = DarktraceClient()
        >>> client.get_alerts(hours=24, min_score=0.7)
        [{'pbid': 4521, 'model': 'Device / Anomalous Connection', 'score': 0.82, ...}]
    """

    def __init__(self, config: DarktraceConfig | None = None) -> None:
        self.config = config or DarktraceConfig.from_env()
        self._logger = get_logger()
        self._session = requests.Session()
        self._session.verify = self.config.verify_ssl
        if not self.config.verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # ------------------------------------------------------------------ #
    # Conexión y firma
    # ------------------------------------------------------------------ #

    def _headers(self, path_and_query: str) -> dict[str, str]:
        date = datetime.now(timezone.utc).isoformat(timespec="seconds")
        message = f"{path_and_query}\n{self.config.public_token}\n{date}"
        signature = hmac.new(
            self.config.private_token.encode("utf-8"), message.encode("utf-8"), hashlib.sha1
        ).hexdigest()
        return {
            "DTAPI-Token": self.config.public_token,
            "DTAPI-Date": date,
            "DTAPI-Signature": signature,
        }

    def _request(self, method: str, path: str, params: dict[str, Any] | None = None,
                 data: dict[str, str] | None = None) -> Any:
        # La firma cubre la query en el mismo orden y sin codificar, por eso
        # se arma la URL a mano en vez de dejar que requests la reordene.
        query = "&".join(f"{k}={v}" for k, v in (params or data or {}).items())
        signed = f"{path}?{query}" if query else path
        url = f"{self.config.base_url}{path}" + (f"?{query}" if params and query else "")
        try:
            response = self._session.request(
                method, url, data=data, headers=self._headers(signed),
                timeout=self.config.connect_timeout, allow_redirects=False,
            )
        except requests.exceptions.SSLError as exc:
            raise DarktraceNetworkError(
                "Error de certificado SSL. Si el appliance usa un certificado autofirmado, "
                "desactiva 'Verificar certificado SSL' en la configuración del conector."
            ) from exc
        except requests.exceptions.RequestException as exc:
            raise DarktraceNetworkError(f"No se pudo alcanzar Darktrace ({self.config.base_url}): {exc}") from exc

        text = response.text or ""
        if response.status_code in (401, 403) or (response.status_code == 400 and "SIGNATURE" in text.upper()):
            raise DarktraceAuthError("Tokens de API inválidos: revisa el token público y el privado.")
        if response.status_code == 400 and "DATE" in text.upper():
            raise DarktraceAuthError(
                "Darktrace rechazó la fecha de la firma: el reloj del equipo que ejecuta el "
                "conector difiere del appliance en más de 30 minutos."
            )
        if response.status_code == 302:
            location = response.headers.get("Location", "")
            if "403" in location:
                raise DarktraceAuthError("Los tokens de API no tienen permiso para esta operación.")
            raise DarktraceAuthError("Darktrace redirigió al login: la firma o la URL base no son válidas.")
        if response.status_code == 404:
            raise DarktraceDataError("El recurso solicitado no existe en Darktrace.")
        if response.status_code >= 500:
            raise DarktraceNetworkError(f"Darktrace respondió {response.status_code}; reintenta en unos segundos.")
        if response.status_code >= 400:
            raise DarktraceDataError(f"Darktrace respondió {response.status_code}: {text[:300]}")
        try:
            return response.json()
        except ValueError as exc:
            raise DarktraceDataError("Darktrace devolvió una respuesta que no es JSON.") from exc

    def ping(self) -> bool:
        """Verifica la conexión y la firma consultando el estado del sistema.

        Raises:
            DarktraceAuthError / DarktraceNetworkError / DarktraceDataError.
        """
        self._request("GET", "/time")
        self._logger.info("Ping exitoso a Darktrace %s", self.config.base_url)
        return True

    # ------------------------------------------------------------------ #
    # Capacidad 1: modelos
    # ------------------------------------------------------------------ #

    def list_models(self, name_contains: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        """Consulta los modelos de detección configurados.

        Args:
            name_contains: filtra por texto en el nombre (sin distinguir mayúsculas).
            limit: máximo de modelos a devolver (1-500).

        Returns:
            Lista de dicts: uuid, name, active, priority, category, description.

        Ejemplo:
            >>> client.list_models(name_contains="anomalous", limit=5)
            [{'uuid': '...', 'name': 'Device::Anomalous Connection', 'active': True, ...}]
        """
        limit = _limit(limit)
        models = self._request("GET", "/models") or []
        needle = (name_contains or "").lower()
        out = []
        for m in models:
            if needle and needle not in str(m.get("name", "")).lower():
                continue
            out.append({
                "uuid": m.get("uuid"),
                "name": m.get("name"),
                "active": m.get("active"),
                "priority": m.get("priority"),
                "category": m.get("category"),
                "description": (m.get("description") or "")[:500],
            })
            if len(out) >= limit:
                break
        self._logger.info("Modelos listados: %d", len(out))
        return out

    # ------------------------------------------------------------------ #
    # Capacidad 2: alertas (model breaches)
    # ------------------------------------------------------------------ #

    def get_alerts(self, hours: int = 24, min_score: float = 0.0, limit: int = 100,
                   include_acknowledged: bool = False) -> list[dict[str, Any]]:
        """Obtiene alertas (model breaches) recientes.

        Args:
            hours: ventana hacia atrás desde ahora (1-2160).
            min_score: puntaje mínimo entre 0 y 1 (ej. 0.7).
            limit: máximo de alertas a devolver (1-500).
            include_acknowledged: incluir alertas ya reconocidas.

        Returns:
            Lista de dicts: pbid, time, score, model, device, acknowledged.

        Ejemplo:
            >>> client.get_alerts(hours=12, min_score=0.8)
            [{'pbid': 4521, 'time': '2026-10-21T14:02:11+00:00', 'score': 0.83, ...}]
        """
        hours, limit = _hours(hours), _limit(limit)
        if not isinstance(min_score, (int, float)) or isinstance(min_score, bool) or not 0 <= min_score <= 1:
            raise DarktraceDataError("min_score debe ser un número entre 0 y 1 (ej. 0.7).")
        params = {
            "minscore": min_score,
            "starttime": _since_ms(hours),
            "includeacknowledged": str(include_acknowledged).lower(),
            "deviceattop": "true",
        }
        breaches = self._request("GET", "/modelbreaches", params=params) or []
        out = []
        for b in breaches[:limit]:
            model = b.get("model") or {}
            device = b.get("device") or {}
            out.append({
                "pbid": b.get("pbid"),
                "time": _ms_to_iso(b.get("time")),
                "score": b.get("score"),
                "model": (model.get("then") or model).get("name") if isinstance(model, dict) else model,
                "device": device.get("hostname") or device.get("ip") or device.get("did"),
                "device_ip": device.get("ip"),
                "acknowledged": bool(b.get("acknowledged")),
            })
        self._logger.info("Alertas obtenidas: %d (últimas %dh, score>=%s)", len(out), hours, min_score)
        return out

    # ------------------------------------------------------------------ #
    # Capacidad 3: incidentes de Cyber AI Analyst
    # ------------------------------------------------------------------ #

    def list_incidents(self, hours: int = 24, min_score: int = 0, limit: int = 50) -> list[dict[str, Any]]:
        """Consulta incidentes (eventos) de Cyber AI Analyst.

        Args:
            hours: ventana hacia atrás desde ahora (1-2160).
            min_score: puntaje mínimo del grupo de incidentes, 0-100.
            limit: máximo a devolver (1-500).

        Returns:
            Lista de dicts: id, title, summary, score, created, acknowledged, devices.

        Ejemplo:
            >>> client.list_incidents(hours=48, min_score=50)
            [{'id': 'a1b2...', 'title': 'Possible SSL Command and Control', 'score': 74, ...}]
        """
        hours, limit = _hours(hours), _limit(limit)
        if isinstance(min_score, bool) or not isinstance(min_score, int) or not 0 <= min_score <= 100:
            raise DarktraceDataError("min_score debe ser un entero entre 0 y 100.")
        params = {"starttime": _since_ms(hours), "mingroupscore": min_score}
        events = self._request("GET", "/aianalyst/incidentevents", params=params) or []
        out = []
        for e in events[:limit]:
            out.append({
                "id": e.get("id") or e.get("uuid"),
                "title": e.get("title"),
                "summary": (e.get("summary") or "")[:800],
                "score": e.get("groupScore", e.get("aiaScore")),
                "created": _ms_to_iso(e.get("createdAt") or ((e.get("periods") or [{}])[0] or {}).get("start")),
                "acknowledged": bool(e.get("acknowledged")),
                "devices": [d.get("hostname") or d.get("ip") for d in (e.get("breachDevices") or [])],
            })
        self._logger.info("Incidentes AI Analyst obtenidos: %d", len(out))
        return out

    # ------------------------------------------------------------------ #
    # Capacidad 4: reconocer una alerta
    # ------------------------------------------------------------------ #

    def acknowledge_alert(self, pbid: int) -> dict[str, Any]:
        """Reconoce (acknowledge) una alerta: la marca como revisada en Darktrace.

        Args:
            pbid: ID del model breach (campo 'pbid' de get_alerts).

        Returns:
            Dict con pbid y acknowledged=True.

        Ejemplo:
            >>> client.acknowledge_alert(4521)
            {'pbid': 4521, 'acknowledged': True}
        """
        if isinstance(pbid, bool):
            raise DarktraceDataError("pbid debe ser un número entero.")
        try:
            pbid = int(pbid)
        except (TypeError, ValueError):
            raise DarktraceDataError(f"pbid debe ser un número entero, no {pbid!r}.") from None
        self._request("POST", f"/modelbreaches/{pbid}/acknowledge", data={"acknowledge": "true"})
        self._logger.info("Alerta %s reconocida", pbid)
        return {"pbid": pbid, "acknowledged": True}
