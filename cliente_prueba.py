import sys

from openai import OpenAI, PermissionDeniedError

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

client = OpenAI(
    base_url="http://127.0.0.1:8000/v1",
    api_key="clave-dummy-local",
)

print("\n--- PRUEBA 1: Datos personales (Anonimización + Rehidratación) ---")
resp1 = client.chat.completions.create(
    model="gpt-4o-mini",
    messages=[
        {
            "role": "user",
            "content": (
                "Redactá un mail para Juan Pérez (CUIT 20-30123456-3, tel 11-4567-8901, "
                "mail jperez@empresa.com) confirmando el acceso al servidor interno 192.168.10.45."
            ),
        }
    ],
)
print("Respuesta recibida por el usuario interno:")
print(resp1.choices[0].message.content)

print("\n--- PRUEBA 2: Credencial crítica (Bloqueo HTTP 403) ---")
token_falso = "sk-proj-" + ("98a7sd" * 5)
try:
    client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {
                "role": "user",
                "content": f"Revisá este código que usa la API key {token_falso}",
            }
        ],
    )
except PermissionDeniedError as e:
    print(f"Bloqueo exitoso atrapado por el cliente (HTTP {e.status_code}):")
    print(e.message)

print("\n--- PRUEBA 3: Conversación multi-turno (el historial se reenvía completo) ---")
historial = [
    {
        "role": "user",
        "content": (
            "Mi nombre es Juan Pérez, CUIT 20-30123456-3, mail jperez@empresa.com. "
            "Guardá estos datos para el siguiente turno."
        ),
    },
]
resp1 = client.chat.completions.create(model="gpt-4o-mini", messages=historial)
print("Turno 1 - respuesta que ve el usuario interno (rehidratada):")
print(resp1.choices[0].message.content)

# El cliente reenvía el historial completo, incluida la respuesta del asistente.
historial.append({"role": "assistant", "content": resp1.choices[0].message.content})
historial.append({"role": "user", "content": "¿Me repetís el CUIT que te pasé?"})
resp2 = client.chat.completions.create(model="gpt-4o-mini", messages=historial)
print("Turno 2 - respuesta que ve el usuario interno (rehidratada):")
print(resp2.choices[0].message.content)
print("\nRevisá el log de la API externa: el historial completo (user y assistant) sale etiquetado.")