"""Diagnóstico de los backends del Filtro 2.

Comprueba qué analizador contextual está disponible y, opcionalmente, ejecuta
una detección sobre un texto de prueba con datos inventados.

Uso:
  ./venv/bin/python verificar_backends.py                  # usa ANALYZER_BACKEND del .env o auto
  ./venv/bin/python verificar_backends.py --todos          # prueba groq, ollama, presidio y none
  ./venv/bin/python verificar_backends.py --backend ollama
  ./venv/bin/python verificar_backends.py --todos --solo-disponibilidad
"""
import argparse
import os
import sys

from contextual_analyzers import AnalyzerUnavailable, BACKENDS, build_analyzer

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

CARPETA = os.path.dirname(os.path.abspath(__file__))

TEXTO_PRUEBA = (
    "Juan Pérez, de Logística del Sur S.A., vive en Av. Corrientes 1234, CABA. "
    "El Proyecto Aurora tiene un presupuesto de $1.250.000 y lo aprobó Laura Benítez. "
    "Su CUIT es 30-71234567-1 y su mail es jperez@logisticadelsur.com.ar."
)


def cargar_env(ruta):
    """Carga el .env sin depender de librerías externas, igual que benchmark.py."""
    if not os.path.exists(ruta):
        return
    with open(ruta, encoding="utf-8") as f:
        for linea in f:
            linea = linea.strip()
            if not linea or linea.startswith("#") or "=" not in linea:
                continue
            clave, valor = linea.split("=", 1)
            os.environ.setdefault(clave.strip(), valor.strip().strip('"').strip("'"))


def probar(nombre, texto, solo_disponibilidad):
    print(f"\n==> Backend solicitado: {nombre}")
    try:
        analizador = build_analyzer(nombre, strict=True)
    except AnalyzerUnavailable as e:
        print(f"    [FAIL] {e}")
        return False

    print(f"    [OK] {analizador.describe()}")

    if analizador.name == "none":
        print("    Sin análisis contextual: solo se aplicarán las reglas del Filtro 1.")
        return True

    if solo_disponibilidad:
        return True

    entidades = analizador.analyze(texto)
    if not entidades:
        print("    Sin entidades detectadas en el texto de prueba.")
        return True

    print("    Entidades detectadas:")
    for entidad in entidades:
        print(f"      - {entidad['type']:<10} {entidad['text']}")
    return True


def main():
    parser = argparse.ArgumentParser(description="Diagnóstico de backends DLP")
    parser.add_argument(
        "--backend",
        action="append",
        choices=BACKENDS,
        help="backend a probar (se puede repetir)",
    )
    parser.add_argument(
        "--todos",
        action="store_true",
        help="prueba groq, ollama, presidio y none",
    )
    parser.add_argument(
        "--solo-disponibilidad",
        action="store_true",
        help="no ejecuta la detección, solo comprueba que el backend responda",
    )
    parser.add_argument(
        "--texto",
        default=TEXTO_PRUEBA,
        help="texto de prueba (por defecto, datos inventados con PII)",
    )
    args = parser.parse_args()

    cargar_env(os.path.join(CARPETA, ".env"))

    if args.todos:
        backends = ["groq", "ollama", "presidio", "none"]
    elif args.backend:
        backends = args.backend
    else:
        backends = [os.getenv("ANALYZER_BACKEND", "auto")]

    print("Diagnóstico de backends del Filtro 2")
    print(f"ANALYZER_BACKEND actual: {os.getenv('ANALYZER_BACKEND', '(sin definir)')}")

    resultados = [probar(nombre, args.texto, args.solo_disponibilidad) for nombre in backends]

    print()
    if all(resultados):
        print("[OK] Diagnóstico completado.")
        return 0
    print("[WARN] Hay backends no disponibles. Revisá la instalación o el .env.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
