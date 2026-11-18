#!/usr/bin/env bash

set -euo pipefail
cd "$(dirname "$0")"

MODO="${1:-ollama}"
case "$MODO" in
  ollama|presidio) ;;
  *)
    echo "Uso: ./setup_local.sh [ollama | presidio]" >&2
    exit 1
    ;;
esac

actualizar_env() {
  local clave="$1" valor="$2" temporal
  temporal="$(mktemp)"
  if grep -q "^${clave}=" .env; then
    awk -v k="$clave" -v v="$valor" '
      BEGIN { FS=OFS="=" }
      $1 == k { print k "=\"" v "\""; next }
      { print }
    ' .env > "$temporal"
  else
    cp .env "$temporal"
    printf '%s="%s"\n' "$clave" "$valor" >> "$temporal"
  fi
  mv "$temporal" .env
}

normalizar_env() {
  if [ -f .env ] && grep -q $'\r' .env 2>/dev/null; then
    tr -d '\r' < .env > .env.tmp
    mv .env.tmp .env
  fi
}

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

  if [ "$MODO" = "presidio" ]; then
    for version in 3.12 3.11 3.10; do
      if command -v "python$version" >/dev/null 2>&1; then
        probar_python "python$version" "python$version" && return 0
      fi
      if command -v py >/dev/null 2>&1; then
        probar_python "py -$version" py "-$version" && return 0
      fi
    done
  fi

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

echo "==> Verificando Python..."
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
elif [ -x venv/Scripts/python.exe ]; then
  VENV_PY="venv/Scripts/python.exe"
else
  echo "ERROR: la carpeta venv existe pero no tiene un intérprete compatible con este entorno (ni bin/ ni Scripts/)." >&2
  echo "       Borrala y volvé a ejecutar el script: rm -rf venv" >&2
  exit 1
fi
echo "    Venv: $VENV_PY"

echo "==> Instalando dependencias base..."
"$VENV_PY" -m pip install --quiet --upgrade pip
"$VENV_PY" -m pip install --quiet -r requirements.txt

if [ ! -f .env ]; then
  echo "==> Creando .env a partir de .env.example..."
  cp .env.example .env
fi
normalizar_env

if [ "$MODO" = "presidio" ]; then
  echo "==> Instalando Presidio + spaCy..."
  "$VENV_PY" -m pip install --quiet -r requirements-local.txt

  MODELO="${PRESIDIO_SPACY_MODEL:-es_core_news_sm}"
  echo "==> Descargando modelo de spaCy: $MODELO..."
  "$VENV_PY" -m spacy download "$MODELO"

  actualizar_env ANALYZER_BACKEND presidio
  actualizar_env PRESIDIO_LANGUAGE "${PRESIDIO_LANGUAGE:-es}"
  actualizar_env PRESIDIO_SPACY_MODEL "$MODELO"
else
  OLLAMA_URL="${OLLAMA_URL:-http://127.0.0.1:11434}"
  OLLAMA_URL="${OLLAMA_URL%/}"
  MODELO="${OLLAMA_MODEL:-qwen2.5:3b}"

  if ! "$VENV_PY" -c "import httpx; httpx.get('$OLLAMA_URL/api/tags', timeout=5, trust_env=False).raise_for_status()" >/dev/null 2>&1; then
    echo "ERROR: Ollama no está respondiendo en $OLLAMA_URL." >&2
    echo "       Abrí la app de Ollama o ejecutá: ollama serve" >&2
    exit 1
  fi

  if ! "$VENV_PY" - "$OLLAMA_URL" "$MODELO" <<'PY'
import sys
import httpx

url, modelo = sys.argv[1], sys.argv[2]
try:
    data = httpx.get(f"{url}/api/tags", timeout=5, trust_env=False).json()
except Exception:
    sys.exit(2)
nombres = {m.get("name") or m.get("model") for m in data.get("models", [])}
sys.exit(0 if modelo in nombres or f"{modelo}:latest" in nombres else 1)
PY
  then
    if ! command -v ollama >/dev/null 2>&1; then
      cat >&2 <<EOF
ERROR: el modelo $MODELO no está descargado y el comando \`ollama\` no está en PATH.
Opciones:
  - Abrí una terminal donde funcione \`ollama\` y ejecutá: ollama pull $MODELO
  - Agregá la carpeta de Ollama al PATH (en Windows suele estar en %LOCALAPPDATA%/Programs/Ollama)
  - O usá un modelo ya descargado: OLLAMA_MODEL=otro-modelo bash setup_local.sh ollama
EOF
      exit 1
    fi
    echo "==> Descargando modelo de Ollama: $MODELO..."
    ollama pull "$MODELO"
  fi

  actualizar_env ANALYZER_BACKEND ollama
  actualizar_env OLLAMA_URL "$OLLAMA_URL"
  actualizar_env OLLAMA_MODEL "$MODELO"
fi

normalizar_env

echo
echo "==> Verificando el backend local..."
"$VENV_PY" verificar_backends.py --backend "$MODO"

echo
echo "Setup local listo. El proxy usará ANALYZER_BACKEND=\"$MODO\"."
echo "Para arrancarlo: ./iniciar_proxy.sh"
echo "Si no tiene permiso de ejecución: bash iniciar_proxy.sh"
