from openai import OpenAI

# El cliente apunta al proxy (puerto 8000) en lugar de la API externa
client = OpenAI(base_url="http://127.0.0.1:8000/v1", api_key="sk-clave-ficticia")

prompt_sensible = (
    "Hola, soy Juan Pérez (DNI 30.123.456, CUIT 20-30123456-7) de la empresa TechSur S.A. "
    "Mi correo es juan.perez@techsur.com.ar y mi token es " + ("sk-proj-" + "98a7sd" * 5) + "."
    "¿Podés redactar un reclamo de factura?"
)

print("📤 [CLIENTE INTERNO] Enviando prompt con datos reales:")
print(prompt_sensible, "\n")

respuesta = client.chat.completions.create(
    model="gpt-4o-mini",
    messages=[{"role": "user", "content": prompt_sensible}],
)

print("📥 [CLIENTE INTERNO] Respuesta recibida:")
print(respuesta.choices[0].message.content)