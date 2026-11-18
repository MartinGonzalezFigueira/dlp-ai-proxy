#!/usr/bin/env bash

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

echo "==> Verificando Python..."
PYTHON_CMD=()
PYTHON_DESC=""

probar_python() {
  local desc="$1"
  shift
  if "$@" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' >/dev/null 2>&1; then
    PYTHON_CMD=("$@")
    PYTHON_DESC="$desc"
    return 0
  fi
  return 1
}

buscar_python() {
  for candidato in python3 python py; do
    if command -v "$candidato" >/dev/null 2>&1; then
      probar_python "$candidato" "$candidato" && return 0
    fi
  done
  if command -v py >/dev/null 2>&1; then
    probar_python "py -3" py "-3" && return 0
  fi
  return 1
}

if ! buscar_python; then
  cat >&2 <<'EOF'
ERROR: no se encontró un Python 3.10 o superior ejecutable.
En Windows, `python3` suele ser el alias de Microsoft Store. Instalá Python
desde https://www.python.org/downloads/ y probá con `python`, `py` o `py -3.12`.
En Debian/Ubuntu: sudo apt install python3 python3-venv
EOF
  exit 1
fi
echo "    Usando $PYTHON_DESC ($("${PYTHON_CMD[@]}" --version 2>&1))"

echo "==> Preparando el entorno virtual (venv)..."
if [ ! -d venv ]; then
  "${PYTHON_CMD[@]}" -m venv venv || {
    echo "ERROR: no se pudo crear el venv. En Debian/Ubuntu: sudo apt install python3-venv" >&2
    exit 1
  }
fi

if [ -x venv/bin/python ]; then
  VENV_PY="venv/bin/python"
  VENV_PIP="venv/bin/pip"
elif [ -x venv/Scripts/python.exe ]; then
  VENV_PY="venv/Scripts/python.exe"
  VENV_PIP="venv/Scripts/pip.exe"
else
  echo "ERROR: la carpeta venv existe pero no tiene un intérprete compatible con este entorno." >&2
  echo "       Borrala y volvé a ejecutar el script: rm -rf venv" >&2
  exit 1
fi

echo "==> Instalando dependencias..."
"$VENV_PIP" install --quiet --upgrade pip
"$VENV_PIP" install --quiet -r requirements.txt

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

if [ -f .env ] && grep -q $'\r' .env 2>/dev/null; then
  tr -d '\r' < .env > .env.tmp
  mv .env.tmp .env
fi

chmod +x iniciar_proxy.sh

echo
echo "Setup listo."

if [ -z "$MODO" ]; then
  cat <<EOF

Para probarlo, abrí 3 terminales en esta carpeta:
  Terminal 1:  "$VENV_PY" mock_external_ai.py
  Terminal 2:  ./iniciar_proxy.sh
  Terminal 3:  "$VENV_PY" cliente_prueba.py && cat audit_log.jsonl

O corré todo junto:
  ./setup.sh --demo        demo rápida con el cliente de prueba
  ./setup.sh --benchmark   benchmark detallado multi-turno (sin servidores)

Modo local/offline del Filtro 2 (sin APIs externas de análisis):
  ./setup_local.sh ollama    usa Ollama + qwen2.5:0.5b
  ./setup_local.sh presidio  usa Microsoft Presidio + spaCy
EOF
  exit 0
fi


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
  "$VENV_PY" -u mock_external_ai.py >"$LOGS/mock.log" 2>&1 &
  PID_MOCK=$!
  esperar_puerto 9000 || { echo "ERROR: el mock no arrancó." >&2; cat "$LOGS/mock.log" >&2; exit 1; }

  echo "==> Levantando el proxy DLP (puerto 8000)..."
  ./iniciar_proxy.sh >"$LOGS/proxy.log" 2>&1 &
  PID_PROXY=$!
  esperar_puerto 8000 || { echo "ERROR: el proxy no arrancó." >&2; cat "$LOGS/proxy.log" >&2; exit 1; }
}


if [ "$MODO" = "--demo" ]; then
  levantar_servidores

  echo "==> Ejecutando el cliente de prueba..."
  "$VENV_PY" cliente_prueba.py

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

shift
echo "==> Ejecutando el benchmark..."
"$VENV_PY" benchmark.py "$@"
