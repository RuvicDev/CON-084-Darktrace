"""Validación local del conector darktrace (solo lectura por defecto).

Uso:
    python validate_local.py

Requiere RUVIC_DARKTRACE_BASE_URL, RUVIC_DARKTRACE_PUBLIC_TOKEN y
RUVIC_DARKTRACE_PRIVATE_TOKEN exportadas.
"""

from ruvic_darktrace_connector import DarktraceClient, setup_logging

setup_logging("INFO")
client = DarktraceClient()

print("== 0. Ping ==")
client.ping()

print("== 1. Modelos ==")
for m in client.list_models(limit=5):
    print(f"  {m['name']}")

print("== 2. Alertas últimas 24 h ==")
alertas = client.get_alerts(hours=24, min_score=0.5, limit=10)
for a in alertas:
    print(f"  {a['pbid']} {a['score']} {a['model']} {a['device']}")

print("== 3. Incidentes AI Analyst últimas 72 h ==")
for i in client.list_incidents(hours=72, limit=5):
    print(f"  {i['score']} {i['title']}")

# == 4. Reconocer una alerta (ESCRIBE): descomenta con un pbid de prueba ==
# print(client.acknowledge_alert(alertas[0]["pbid"]))

print("\nTodo OK.")
