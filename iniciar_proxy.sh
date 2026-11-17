#!/bin/bash
cd "$(dirname "$0")"

# Activar el venv en Linux/macOS (bin/) o Windows/Git Bash (Scripts/).
if [ -f venv/bin/activate ]; then
  # shellcheck disable=SC1091
  source venv/bin/activate
  VENV_PY="venv/bin/python"
elif [ -f venv/Scripts/activate ]; then
  # shellcheck disable=SC1091
  source venv/Scripts/activate
  VENV_PY="venv/Scripts/python.exe"
else
  echo "ERROR: no se encontró venv. Ejecutá primero ./setup.sh o ./setup_local.sh." >&2
  exit 1
fi

# Normalizar .env si viene con CRLF de Windows.
if [ -f .env ] && grep -q $'\r' .env 2>/dev/null; then
  tr -d '\r' < .env > .env.tmp
  mv .env.tmp .env
fi

set -a
# shellcheck disable=SC1091
source .env
set +a

# Destino del proxy. Por defecto, el mock local de la demo.
TARGET_URL="${DLP_TARGET_URL:-http://127.0.0.1:9000}"
echo "[DLP-INIT] Destino externo: $TARGET_URL"

# Aviso temprano si el destino local no está levantado.
case "$TARGET_URL" in
  http://127.0.0.1:*|http://localhost:*)
    TARGET_PORT="${TARGET_URL##*:}"
    if ! "$VENV_PY" -c "import socket; socket.create_connection(('127.0.0.1', $TARGET_PORT), 1).close()" >/dev/null 2>&1; then
      echo "[WARN] No hay nada escuchando en $TARGET_URL." >&2
      echo "       Para la demo, arrancá en otra terminal: $VENV_PY mock_external_ai.py" >&2
      echo "       Para usar Ollama como destino: DLP_TARGET_URL=http://127.0.0.1:11434 ./iniciar_proxy.sh" >&2
    fi
    ;;
esac

if [ -x venv/bin/mitmdump ]; then
  MITMDUMP="venv/bin/mitmdump"
elif [ -x venv/Scripts/mitmdump.exe ]; then
  MITMDUMP="venv/Scripts/mitmdump.exe"
else
  MITMDUMP="mitmdump"
fi

"$MITMDUMP" --mode reverse:"$TARGET_URL" -p 8000 -s proxy_mitm.py
