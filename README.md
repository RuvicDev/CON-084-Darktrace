# Conector Darktrace (CON-084)

Conector Ruvic para la API de Darktrace: modelos, alertas (model breaches), incidentes de Cyber AI Analyst y reconocimiento de alertas.

## Instalación

```bash
pip install git+https://github.com/RuvicDev/CON-084-Darktrace.git#subdirectory=lib
```

Python 3.10+. Dependencias: `requests>=2.31,<3.0`.

## Permisos requeridos

Autenticación con un **par de tokens de API** (público + privado). Cada petición se firma con
HMAC-SHA1 sobre `ruta?query\ntoken_público\nfecha` y se envía en los headers `DTAPI-Token`,
`DTAPI-Date` y `DTAPI-Signature`.

1. En el Threat Visualizer ve a **System Config → Settings → API Token → New** (requiere permiso de configuración del sistema).
2. Copia el **token público** y el **privado**: el privado solo se muestra una vez.
3. Limita el par a lectura de model breaches, modelos y Cyber AI Analyst, más reconocer breaches.
4. El runtime de Ruvic debe poder alcanzar el appliance por HTTPS (443).

## Variables de entorno (`RUVIC_DARKTRACE_*`)

| Variable | Obligatoria | Descripción |
|----------|-------------|-------------|
| `RUVIC_DARKTRACE_BASE_URL` | Sí | URL del appliance de Darktrace |
| `RUVIC_DARKTRACE_PUBLIC_TOKEN` | Sí | Token público |
| `RUVIC_DARKTRACE_PRIVATE_TOKEN` | Sí | Token privado |
| `RUVIC_DARKTRACE_VERIFY_SSL` | No (default `true`) | Verificar certificado SSL |
| `RUVIC_DARKTRACE_CONNECT_TIMEOUT` | No (default `15`) | Timeout de conexión (segundos) |

Los campos opcionales vacíos usan su valor por defecto (la plataforma envía
`""` cuando un campo queda en blanco).

## Pruebas locales

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ./lib

export RUVIC_DARKTRACE_BASE_URL=...
export RUVIC_DARKTRACE_PUBLIC_TOKEN=...
export RUVIC_DARKTRACE_PRIVATE_TOKEN=...

python test_connection.py
python validate_local.py
```

`validate_local.py` lista modelos, alertas e incidentes. La parte de reconocer una alerta está comentada: descoméntala con un `pbid` de prueba.

## Notas de integración

- La query se firma en el mismo orden y sin codificar con el que se envía; por eso el conector arma la URL a mano.
- `get_alerts` usa `minscore` de 0 a 1; `list_incidents` usa `mingroupscore` de 0 a 100.
- Un 302 que redirige a /login o /403 se reporta como error de autenticación o de permisos.
- Para appliances con certificado autofirmado, desactiva `verify_ssl` solo en redes de confianza.
- Endpoints y firma verificados contra la integración oficial de Darktrace para Cortex XSOAR.

## Limitaciones conocidas

- No crea ni edita modelos, ni comenta alertas o incidentes.
- No pagina: `limit` recorta en el lado del conector (máximo 500).
- El reloj del equipo que ejecuta el conector debe estar sincronizado con el appliance.
