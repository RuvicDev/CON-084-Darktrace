---
name: darktrace
description: >
  Usa la librería ruvic_darktrace_connector para consultar detecciones de
  amenazas en la red con Darktrace - listar modelos de detección
  (list_models), obtener alertas o model breaches recientes (get_alerts),
  consultar incidentes de Cyber AI Analyst (list_incidents) y reconocer
  una alerta (acknowledge_alert). Úsala cuando el usuario pregunte por
  alertas, amenazas, anomalías de red o incidentes de Darktrace.
triggers:
- darktrace
- model breach
- alertas de red
- anomalia de red
- ndr
- ai analyst
- amenazas
---

# Conector Darktrace (ruvic_darktrace_connector)

Librería Python para la API de Darktrace (Threat Visualizer o instancia cloud). Está **preinstalada en el runtime** cuando el
conector está configurado (si no, instálala con
`pip install git+https://github.com/RuvicDev/CON-084-Darktrace.git#subdirectory=lib`).

## Regla crítica de credenciales

El código generado **NUNCA hardcodea credenciales**. Siempre se leen de
variables de entorno, disponibles cuando el conector `darktrace` está
configurado:

| Variable | Contenido |
|----------|-----------|
| `RUVIC_DARKTRACE_BASE_URL` | URL del appliance de Darktrace |
| `RUVIC_DARKTRACE_PUBLIC_TOKEN` | Token público |
| `RUVIC_DARKTRACE_PRIVATE_TOKEN` | Token privado |
| `RUVIC_DARKTRACE_VERIFY_SSL` | (opcional) Verificar certificado SSL, default true |
| `RUVIC_DARKTRACE_CONNECT_TIMEOUT` | (opcional) Timeout de conexión (segundos), default 15 |

Si estas variables NO existen, el conector no está configurado: no
generes código que lo use; indica al usuario que lo configure en
**Settings → Conectores**. El código generado **NUNCA** usa nombres con
segmento de alias (`_DEFAULT_INSTANCIA_`, `_PRODUCCION_`, etc.) salvo que
aparezcan en una sección autogenerada `## Variables en tu entorno` al final
de este skill.

## Este conector es casi solo lectura

`list_models`, `get_alerts` y `list_incidents` son de solo lectura.
`acknowledge_alert` **SÍ escribe**: marca la alerta como revisada para todo
el equipo de seguridad y deja de aparecer en las vistas de pendientes.
Reconoce alertas solo cuando el usuario lo pida explícitamente.

## Conexión (siempre igual)

```python
from ruvic_darktrace_connector import DarktraceClient

client = DarktraceClient()  # lee RUVIC_DARKTRACE_* del entorno automáticamente
```

## Capacidad 1 — Listar modelos de detección

```python
modelos = client.list_models(name_contains="anomalous", limit=20)
for m in modelos:
    print(m["name"], "activo" if m["active"] else "inactivo")
```

## Capacidad 2 — Obtener alertas (model breaches)

```python
alertas = client.get_alerts(hours=24, min_score=0.7, limit=50)
for a in alertas:
    print(a["pbid"], a["time"], round(a["score"], 2), a["model"], a["device"])
```

`min_score` va de 0 a 1. `include_acknowledged=True` incluye las ya reconocidas.

## Capacidad 3 — Consultar incidentes de Cyber AI Analyst

```python
incidentes = client.list_incidents(hours=72, min_score=50)
for i in incidentes:
    print(i["score"], i["title"], i["devices"])
```

Aquí `min_score` va de 0 a 100 (puntaje de grupo de AI Analyst).

## Capacidad 4 — Reconocer una alerta

```python
client.acknowledge_alert(4521)  # pbid tomado de get_alerts
```

## Manejo de errores

```python
from ruvic_darktrace_connector import (
    DarktraceAuthError, DarktraceDataError, DarktraceNetworkError,
)

try:
    client.get_alerts(hours=24, min_score=0.8)
except DarktraceAuthError as e:
    print(f"Credenciales o permisos: {e}")
except DarktraceNetworkError as e:
    print(f"No se pudo alcanzar el servicio: {e}")
except DarktraceDataError as e:
    print(f"Error de datos: {e}")
```

Muestra el mensaje de la excepción tal cual al usuario: indica qué corregir.

## Buenas prácticas al generar código

1. Lee credenciales SOLO de las variables `RUVIC_DARKTRACE_*` (el constructor de `DarktraceClient` ya lo hace).
2. Nunca imprimas `RUVIC_DARKTRACE_PRIVATE_TOKEN` en logs ni en la salida.
3. Usa ventanas cortas (`hours`) y `min_score` para no traer miles de alertas de baja relevancia.
4. No reconozcas alertas por iniciativa propia: `acknowledge_alert` cambia lo que ve el equipo de seguridad.
5. Si aparece un error de fecha, el reloj del runtime difiere del appliance; no reintentes en bucle.
