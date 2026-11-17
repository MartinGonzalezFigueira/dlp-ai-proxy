#!/usr/bin/env bash
# Setup inicial del Proxy DLP.
# Uso:
#   ./setup.sh                    -> crea el venv, instala dependencias y prepara el .env
#   ./setup.sh --demo             -> lo anterior + levanta mock y proxy y corre el cliente de prueba
#   ./setup.sh --benchmark [...]  -> lo anterior + corre el benchmark en proceso (sin servidores)
#                                    las opciones extra se pasan a benchmark.py
#                                    (ej: --comparar-original --sin-ia --detalle)
#   ./setup.sh --benchmark --e2e  -> además levanta mock y proxy y mide latencia real
set -euo pipefail
cd "$(dirname "$0")"

MODO="${1:-}"
case "$MODO" in
  ""|--demo|--benchmark) ;;
  *)
    echo "Uso: ./setup.sh [--demo | --benchmark [opciones de benchmark.py]]" >&2
    exit 1
    ;;
esac

if [ "$MODO" = "--benchmark" ] && { [ ! -f benchmark.py ] || [ ! -f benchmark_dataset.py ]; }; then
  echo "ERROR: faltan benchmark.py o benchmark_dataset.py en esta carpeta." >&2
  exit 1
fi

# Python 
echo "==> Verificando Python..."
if ! command -v python3 >/dev/null 2>&1; then
  echo "ERROR: no se encontró python3. Instalalo (se necesita 3.10 o superior)." >&2
  exit 1
fi
if ! python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)'; then
  echo "ERROR: se necesita Python 3.10 o superior (encontrado: $(python3 --version))." >&2
  exit 1
fi

# Entorno virtual y dependencias 
echo "==> Preparando el entorno virtual (venv)..."
if [ ! -d venv ]; then
  python3 -m venv venv || {
    echo "ERROR: no se pudo crear el venv. En Debian/Ubuntu: sudo apt install python3-venv" >&2
    exit 1
  }
fi

echo "==> Instalando dependencias..."
./venv/bin/pip install --quiet --upgrade pip
./venv/bin/pip install --quiet -r requirements.txt

# Variables de entorno 
if [ ! -f .env ] || grep -q "pega_aca" .env; then
  echo "==> Configurando .env..."
  clave=""
  if [ -t 0 ]; then
    read -r -p "Pegá tu GROQ_API_KEY (Enter para omitir; solo se usarán las reglas Regex): " clave
  fi
  {
    printf 'GROQ_API_KEY="%s"\n' "$clave"
    grep -v '^GROQ_API_KEY=' .env.example
  } > .env
  if [ -z "$clave" ]; then
    echo "    Sin GROQ_API_KEY: el Filtro 2 (contextual) queda desactivado."
    echo "    Podés cargarla después editando el archivo .env"
  fi
else
  echo "==> .env ya existe, no se modifica."
fi

chmod +x iniciar_proxy.sh

echo
echo "Setup listo."

# Instrucciones si no se pidió demo ni benchmark 
if [ -z "$MODO" ]; then
  cat <<'EOF'

Para probarlo, abrí 3 terminales en esta carpeta:
  Terminal 1:  ./venv/bin/python mock_external_ai.py
  Terminal 2:  ./iniciar_proxy.sh
  Terminal 3:  ./venv/bin/python cliente_prueba.py && cat audit_log.jsonl

O corré todo junto:
  ./setup.sh --demo              demo rápida con el cliente de prueba
  ./setup.sh --benchmark         benchmark en proceso (40 prompts multi-turno, sin servidores)
  ./setup.sh --benchmark --e2e   benchmark + latencia real (levanta mock y proxy)
EOF
  exit 0
fi

# Servidores (solo para --demo y para --benchmark --e2e)
LOGS=""
PID_MOCK=""
PID_PROXY=""

limpiar() {
  if [ -n "$PID_PROXY" ]; then
    pkill -P "$PID_PROXY" 2>/dev/null || true
    kill "$PID_PROXY" 2>/dev/null || true
  fi
  if [ -n "$PID_MOCK" ]; then
    kill "$PID_MOCK" 2>/dev/null || true
  fi
}
trap limpiar EXIT

esperar_puerto() {
  for _ in $(seq 1 40); do
    if (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; then
      return 0
    fi
    sleep 0.5
  done
  return 1
}

levantar_servidores() {
  LOGS="$(mktemp -d)"

  echo
  echo "==> Levantando la API externa simulada (puerto 9000)..."
  ./venv/bin/python -u mock_external_ai.py >"$LOGS/mock.log" 2>&1 &
  PID_MOCK=$!
  esperar_puerto 9000 || { echo "ERROR: el mock no arrancó." >&2; cat "$LOGS/mock.log" >&2; exit 1; }

  echo "==> Levantando el proxy DLP (puerto 8000)..."
  ./iniciar_proxy.sh >"$LOGS/proxy.log" 2>&1 &
  PID_PROXY=$!
  esperar_puerto 8000 || { echo "ERROR: el proxy no arrancó." >&2; cat "$LOGS/proxy.log" >&2; exit 1; }
}

# Demo en vivo
if [ "$MODO" = "--demo" ]; then
  levantar_servidores

  echo "==> Ejecutando el cliente de prueba..."
  ./venv/bin/python cliente_prueba.py

  echo
  echo "================ Lo que recibió la IA externa (ya sanitizado) ================"
  cat "$LOGS/mock.log"

  echo
  echo "================ Eventos del proxy ================"
  grep '^\[DLP' "$LOGS/proxy.log" || true

  echo
  echo "================ Últimas entradas de audit_log.jsonl ================"
  if [ -f audit_log.jsonl ]; then
    tail -n 2 audit_log.jsonl
  fi
  exit 0
fi

# Benchmark: por defecto corre en proceso, sin servidores.
# Si se pide --e2e, levanta el mock y el proxy para medir latencia real.
shift
NECESITA_SERVIDORES=0
for arg in "$@"; do
  if [ "$arg" = "--e2e" ]; then
    NECESITA_SERVIDORES=1
  fi
done

if [ "$NECESITA_SERVIDORES" -eq 1 ]; then
  levantar_servidores
else
  echo "==> Benchmark en proceso (sin servidores). Agregá --e2e para medir latencia real."
fi

echo "==> Ejecutando el benchmark..."
./venv/bin/python benchmark.py "$@"
