from openai import OpenAI, PermissionDeniedError

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
                "Redactá un mail para Juan Pérez (CUIT 20-30123456-7, tel 11-4567-8901, "
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