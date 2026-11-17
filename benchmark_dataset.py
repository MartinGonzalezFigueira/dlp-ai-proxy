"""Dataset del benchmark del proxy DLP.

En cada turno el cliente reenvía el historial completo,
igual que hace la API de chat real. Todos los datos son inventados.

Cada turno tiene:
  usuario    : prompt que escribe el usuario
  categoria  : positivo | limpio | borde | bloqueo
                 positivo -> tiene datos sensibles que deben eliminarse
                 limpio   -> no tiene datos sensibles (fragmentos técnicos, preguntas generales)
                 borde    -> caso difícil que puede confundir a las reglas
                 bloqueo  -> credenciales o tarjetas: la política exige rechazar con HTTP 403
  sensibles  : [(valor, tipo)] valores que NO deben llegar a la IA externa
  conservar  : [texto] fragmentos NO sensibles que deben llegar intactos (miden falsos positivos)
  neutros    : [texto] entidades ambiguas (ej. ciudades): no cuentan como acierto ni como error
  bloqueo    : True si el turno debe ser bloqueado
  nota       : por qué es un caso difícil (el informe la muestra solo si el caso falla)

Un turno bloqueado se descarta del historial, como haría un cliente que recibe el 403.
"""


def turno(usuario, categoria, sensibles=(), conservar=(), neutros=(), bloqueo=False, nota=""):
    return {
        "usuario": usuario,
        "categoria": categoria,
        "sensibles": list(sensibles),
        "conservar": list(conservar),
        "neutros": list(neutros),
        "bloqueo": bloqueo,
        "nota": nota,
    }


CONVERSACIONES = [
    {
        "id": "C01",
        "titulo": "Alta de proveedor (datos personales + historial)",
        "turnos": [
            turno(
                "Necesito un mail para Juan Pérez, de Logística del Sur S.A. (CUIT 30-71234567-8), "
                "confirmando su alta como proveedor.",
                "positivo",
                sensibles=[
                    ("Juan Pérez", "PERSON"),
                    ("Logística del Sur S.A.", "ORG"),
                    ("30-71234567-8", "CUIT"),
                ],
            ),
            turno(
                "Agregale que su contacto es jperez@logisticadelsur.com.ar y que lo llamamos al "
                "11-4567-8901 para coordinar.",
                "positivo",
                sensibles=[
                    ("jperez@logisticadelsur.com.ar", "EMAIL"),
                    ("11-4567-8901", "PHONE"),
                ],
            ),
            turno(
                "Ahora hacelo más corto y más formal, manteniendo los datos de contacto.",
                "limpio",
                conservar=["más corto", "más formal"],
            ),
            turno(
                "Sumá una línea pidiendo que transfieran al CBU 0170099220000067797370 y que el "
                "servidor de destino es 10.20.30.40.",
                "positivo",
                sensibles=[
                    ("0170099220000067797370", "CBU"),
                    ("10.20.30.40", "IP"),
                ],
            ),
        ],
    },
    {
        "id": "C02",
        "titulo": "Soporte técnico: Docker y FastAPI (todo limpio)",
        "turnos": [
            turno(
                "Me falla el contenedor con este error: ModuleNotFoundError: No module named 'fastapi' "
                "cuando corro docker compose up. ¿Qué reviso?",
                "limpio",
                conservar=["ModuleNotFoundError", "fastapi", "docker compose up"],
            ),
            turno(
                "Mi Dockerfile arranca con FROM python:3.12-slim y después hace pip install -r "
                "requirements.txt. El commit es 9fceb02d0ae598e95dc970b74767f19372d61af7, "
                "¿puede ser un cache viejo?",
                "limpio",
                conservar=[
                    "python:3.12-slim",
                    "requirements.txt",
                    "9fceb02d0ae598e95dc970b74767f19372d61af7",
                ],
            ),
            turno(
                "En los logs veo 2026-11-17T01:12:44Z INFO uvicorn escuchando en 0.0.0.0:8000 con "
                "request_id 3f2b8c1e-5a7d-4e9f-9b1a-2c6d8e0f4a71. ¿Cómo configuro un healthcheck "
                "que consulte http://localhost:8000/health cada 30 segundos?",
                "limpio",
                conservar=[
                    "2026-11-17T01:12:44Z",
                    "0.0.0.0:8000",
                    "3f2b8c1e-5a7d-4e9f-9b1a-2c6d8e0f4a71",
                    "http://localhost:8000/health",
                ],
            ),
        ],
    },
    {
        "id": "C03",
        "titulo": "RRHH: legajo de una empleada",
        "turnos": [
            turno(
                "Cargame el legajo de María Fernanda González, DNI 30.123.456, que vive en "
                "Av. Corrientes 1234, CABA.",
                "positivo",
                sensibles=[
                    ("María Fernanda González", "PERSON"),
                    ("30.123.456", "DNI"),
                    ("Av. Corrientes 1234", "LOCATION"),
                ],
                neutros=["CABA"],
            ),
            turno(
                "Su email es mfgonzalez@correo.com.ar, su CUIL es 27-30123456-4 y su celular es "
                "+54 9 11 5555-1234.",
                "positivo",
                sensibles=[
                    ("mfgonzalez@correo.com.ar", "EMAIL"),
                    ("27-30123456-4", "CUIL"),
                    ("+54 9 11 5555-1234", "PHONE"),
                ],
            ),
            turno(
                "Armame una tabla resumen con esos datos para pasarle a liquidación de sueldos.",
                "limpio",
                conservar=["liquidación de sueldos"],
            ),
        ],
    },
    {
        "id": "C04",
        "titulo": "Finanzas: proyecto, montos y firmantes",
        "turnos": [
            turno(
                "El presupuesto del Proyecto Aurora es de $1.250.000 y lo aprobó Laura Benítez, "
                "gerente de Finanzas de Banco Meridiano.",
                "positivo",
                sensibles=[
                    ("Proyecto Aurora", "PROJECT"),
                    ("1.250.000", "FINANCIAL"),
                    ("Laura Benítez", "PERSON"),
                    ("Banco Meridiano", "ORG"),
                ],
            ),
            turno(
                "Si el monto fuera $850.000 en vez del anterior, ¿cuánto sería el 21% de IVA?",
                "borde",
                sensibles=[("850.000", "FINANCIAL")],
                conservar=["21%", "IVA"],
                nota="Monto con un solo separador de miles: ninguna regex lo cubre, depende del "
                     "analizador contextual (Filtro 2).",
            ),
            turno(
                "Armame una tabla comparativa de ambos escenarios.",
                "limpio",
                conservar=["tabla comparativa"],
            ),
        ],
    },
    {
        "id": "C05",
        "titulo": "Credenciales y tarjetas (bloqueo)",
        "turnos": [
            turno(
                "Revisá este código: client = boto3.client('s3', "
                "aws_access_key_id='AKIAIOSFODNN7EXAMPLE')",
                "bloqueo",
                sensibles=[("AKIAIOSFODNN7EXAMPLE", "SECRET")],
                bloqueo=True,
            ),
            turno(
                "Mi token de GitHub es ghp_16C7e42F292c6912E7710c838347Ae178B4a y me devuelve 401, "
                "¿qué pasa?",
                "bloqueo",
                sensibles=[("ghp_16C7e42F292c6912E7710c838347Ae178B4a", "SECRET")],
                bloqueo=True,
            ),
            turno(
                "Quiero validar el formato de una tarjeta, por ejemplo 4111 1111 1111 1111, con el "
                "algoritmo de Luhn.",
                "bloqueo",
                sensibles=[("4111 1111 1111 1111", "CARD")],
                bloqueo=True,
            ),
            turno(
                "Mejor explicame cómo funciona el algoritmo de Luhn en general, sin ejemplos reales.",
                "limpio",
                conservar=["algoritmo de Luhn"],
            ),
        ],
    },
    {
        "id": "C06",
        "titulo": "Números y teléfonos que parecen datos sensibles",
        "turnos": [
            turno(
                "El pedido 20251117001 salió del depósito, ¿cómo consulto su estado por la API?",
                "borde",
                conservar=["20251117001"],
                nota="Número de 11 dígitos que empieza con 20: la regex de CUIT no valida el dígito "
                     "verificador y puede confundirlo con un CUIT.",
            ),
            turno(
                "Mi número de seguimiento del correo es 1234 5678 9012 3456, ¿qué significa "
                "'en tránsito'?",
                "borde",
                conservar=["1234 5678 9012 3456"],
                nota="Secuencia de 16 dígitos con formato de tarjeta que no es válida según Luhn: "
                     "debería pasar sin alterarse.",
            ),
            turno(
                "Mi WhatsApp es +54 9 11 5555-1233, ¿cómo armo un link wa.me para que me escriban?",
                "borde",
                sensibles=[("+54 9 11 5555-1233", "PHONE")],
                conservar=["wa.me"],
                nota="Los 13 dígitos del formato internacional pasan la verificación de Luhn por "
                     "casualidad y se confunden con una tarjeta (falso bloqueo).",
            ),
            turno(
                "La versión del paquete es 2.31.0, el timeout es de 30000 ms y el puerto es 8080.",
                "limpio",
                conservar=["2.31.0", "30000 ms", "8080"],
            ),
            turno(
                "¿Qué diferencia hay entre una lista y una tupla en Python? Dame un ejemplo corto.",
                "limpio",
                conservar=["lista", "tupla", "Python"],
            ),
        ],
    },
]
