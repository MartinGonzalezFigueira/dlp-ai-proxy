# Plan B: despliegue 100% local/offline del Filtro 2

Este documento implementa el punto 3 del roadmap: ejecutar el análisis
contextual del proxy DLP sin depender de una API externa. El Filtro 1
(regex, Luhn, módulo 11 y entropía) ya es local; acá se reemplaza o se
complementa el Filtro 2 con alternativas que no sacan datos de la organización.

> Aclaración importante: este Plan B hace local el **analizador**. El destino
> del prompt sigue siendo la API de IA que configure el proxy. Para una demo
> completamente offline, apuntá también el destino a un servidor local
> (por ejemplo, Ollama) en lugar de `mock_external_ai.py` o de un proveedor
> externo. Ver [Demo completamente offline](#demo-completamente-offline).

---

## 1. Backends disponibles

La selección se hace con una sola variable de entorno:

```bash
ANALYZER_BACKEND="groq"      # remoto (default histórico)
ANALYZER_BACKEND="ollama"    # LLM local vía Ollama
ANALYZER_BACKEND="presidio"  # Microsoft Presidio + spaCy
ANALYZER_BACKEND="none"      # sin Filtro 2: solo reglas del Filtro 1
ANALYZER_BACKEND="auto"      # prueba ollama -> presidio -> groq -> solo regex
```

| Backend | Dónde corre | Salida a Internet | Datos que salen | Detección contextual | Costo / latencia | Caso de uso |
| :--- | :--- | :---: | :--- | :--- | :--- | :--- |
| `groq` | API de Groq | Sí | Texto ya pasado por el Filtro 1, pero con las entidades contextuales todavía presentes | LLM remoto; PERSON, ORG, LOCATION, PROJECT, FINANCIAL | Red + límite de uso del proveedor | Default, si la organización acepta enviar texto anonimizado parcialmente a un tercero |
| `ollama` | Proceso local (o servidor interno) | No | Nada fuera de la máquina/servidor local | LLM local pequeño (`qwen2.5:0.5b` por defecto) | CPU/GPU local; primera carga del modelo lenta | Entornos air-gapped o con prohibición de APIs externas |
| `presidio` | Proceso Python local | No | Nada fuera de la máquina | NER de spaCy en español + patrones locales de montos y proyectos | CPU local; carga inicial del modelo | Air-gapped con preferencia por reglas/NER deterministas, sin LLM |
| `none` | — | No | Nada | Solo Filtro 1 | Mínima | Máxima disponibilidad o diagnóstico de solo reglas |

`auto` es útil para imágenes o instalaciones que se mueven entre entornos:
intenta primero Ollama, después Presidio, después Groq y, si ninguno está
disponible, arranca en modo `none` para no tumbar el proxy.

### Qué NO cambia

- El log `audit_log.jsonl` sigue guardando solo categorías, conteos y latencia;
  nunca los valores originales.
- La política de bloqueo HTTP 403 para `SECRET` y `CREDIT_CARD` sigue igual.
- La rehidratación de respuestas (`proxy_mitm.py`) sigue igual.
- El Filtro 1 se ejecuta siempre, antes del Filtro 2.

### Riesgo que elimina el Plan B

Con `groq`, el texto que se manda al analizador remoto ya no tiene DNI, CUIT,
tarjetas, emails ni secretos, pero sí puede tener nombres, empresas,
direcciones o montos que el Filtro 1 no detecta. Ese texto sale de la
organización para que el proveedor lo analice. Con `ollama` o `presidio`, ese
texto nunca sale de la infraestructura local.

---

## 2. Instalación rápida

Los scripts requieren Python 3.10+ y funcionan en Linux/macOS y en Windows con
Git Bash/WSL. En Windows, `setup_local.sh` detecta `python`/`py` (el alias
`python3` de Microsoft Store no ejecuta Python) y usa la carpeta `venv/Scripts/`
en lugar de `venv/bin/`.

### Opción A: Ollama (recomendada para una demo offline)

1. Instalar Ollama desde <https://ollama.com/download>.
2. Arrancar el servicio:

   ```bash
   ollama serve
   ```

3. Descargar el modelo:

   ```bash
   ollama pull qwen2.5:0.5b
   ```

4. Preparar el proxy y el `.env`:

   ```bash
   ./setup_local.sh ollama
   ```

   El script crea/reutiliza el `venv`, instala `requirements.txt`, verifica que
   Ollama responda, descarga el modelo si falta y actualiza `ANALYZER_BACKEND`
   en `.env` sin borrar las demás variables.

5. Verificar y arrancar:

   ```bash
   ./venv/bin/python verificar_backends.py --backend ollama
   ./iniciar_proxy.sh
   ```

Si preferís hacerlo a mano, alcanza con tener Ollama corriendo y estas
variables en `.env`:

```bash
ANALYZER_BACKEND="ollama"
OLLAMA_URL="http://127.0.0.1:11434"
OLLAMA_MODEL="qwen2.5:0.5b"
OLLAMA_TIMEOUT="60"
```

### Opción B: Microsoft Presidio + spaCy

> Nota: Presidio y spaCy suelen publicar wheels para Python 3.10–3.12. Si el
> equipo tiene 3.13/3.14, creá el `venv` con una versión soportada (por
> ejemplo, `py -3.12 -m venv venv` en Windows o `python3.12 -m venv venv` en
> Linux) antes de instalar.

1. Instalar dependencias y el modelo español:

   ```bash
   ./setup_local.sh presidio
   ```

   Equivalente manual:

   ```bash
   ./venv/bin/pip install -r requirements-local.txt
   ./venv/bin/python -m spacy download es_core_news_sm
   ```

2. Configurar `.env`:

   ```bash
   ANALYZER_BACKEND="presidio"
   PRESIDIO_LANGUAGE="es"
   PRESIDIO_SPACY_MODEL="es_core_news_sm"
   PRESIDIO_SCORE_THRESHOLD="0.35"
   ```

3. Verificar y arrancar:

   ```bash
   ./venv/bin/python verificar_backends.py --backend presidio
   ./iniciar_proxy.sh
   ```

Presidio no trae un reconocedor nativo de "Proyecto X", de montos en
pesos/dólares ni de direcciones con "Av./Calle" en español:
`contextual_analyzers.py` agrega regex locales para `PROJECT`, `FINANCIAL`,
`LOCATION` y `ORG` (este último para empresas con sufijos societarios como
`S.A.`, `SRL`, `Banco`, etc., que el NER puede confundir con lugares).

### Opción C: solo reglas

Para un entorno donde ni siquiera se quiere cargar un analizador contextual:

```bash
ANALYZER_BACKEND="none"
```

El proxy sigue detectando DNI, CUIT/CUIL, CBU, tarjetas, emails, teléfonos,
IPs internas, API keys y secretos de alta entropía. No detecta nombres,
organizaciones, ubicaciones, proyectos ni montos que no encajen en una regla.

---

## 3. Diagnóstico

`verificar_backends.py` comprueba instalación, conectividad y, opcionalmente,
una detección sobre datos inventados:

```bash
# Usa ANALYZER_BACKEND del .env (o auto si no está definido)
./venv/bin/python verificar_backends.py

# Prueba todos los backends, uno por uno
./venv/bin/python verificar_backends.py --todos

# Solo comprueba disponibilidad, sin ejecutar el modelo
./venv/bin/python verificar_backends.py --todos --solo-disponibilidad

# Texto propio
./venv/bin/python verificar_backends.py --backend ollama --texto "Juan Pérez trabaja en ACME"
```

Salida esperada, por ejemplo:

```text
==> Backend solicitado: ollama
    [OK] Ollama · qwen2.5:0.5b · http://127.0.0.1:11434
    Entidades detectadas:
      - PERSON     Juan Pérez
      - ORG        Logística del Sur S.A.
      - LOCATION   Av. Corrientes 1234
      - PROJECT    Proyecto Aurora
      - FINANCIAL  $1.250.000
```

Los resultados del modelo chico pueden variar; lo importante es que el
diagnóstico falle con un mensaje claro si falta el binario, el modelo o el
servicio.

---

## 4. Comparación con el benchmark

El benchmark acepta el backend como argumento y mide recall, precisión, falsos
positivos, bloqueos y latencia:

```bash
./venv/bin/python benchmark.py --backend groq
./venv/bin/python benchmark.py --backend ollama
./venv/bin/python benchmark.py --backend presidio
./venv/bin/python benchmark.py --backend none
```

Recomendaciones para comparar:

1. Ejecutar cada backend sobre el mismo dataset y la misma máquina.
2. Anotar los resultados en la tabla de abajo.
3. Para Groq, el benchmark espacia las llamadas por el límite de uso; para
   Ollama y Presidio no aplica ese espaciado.
4. Repetir Ollama/Presidio al menos dos veces: la primera ejecución incluye la
   carga del modelo en memoria.

| Backend | Recall | Precisión | Falsos positivos | Latencia mediana / p95 | Observaciones |
| :--- | ---: | ---: | ---: | :---: | :--- |
| `groq` | | | | | |
| `ollama` (`qwen2.5:0.5b`) | | | | | |
| `presidio` | | | | | |
| `none` | | | | | |

No se incluyen números inventados: completá la tabla con la salida real de
`benchmark.py` en el equipo de la demo.

### Ejemplo de corrida (medición real de referencia)

Estos valores salieron de una corrida sobre el dataset actual (22 prompts) en
el equipo de desarrollo, sin GPU. **No son una garantía**: dependen del
hardware, del modelo y de la versión de spaCy. Sirven como orden de magnitud
para la defensa y para comparar contra la corrida propia.

| Backend | Recall | Precisión | Falsos positivos | Latencia mediana / p95 | Notas |
| :--- | ---: | ---: | ---: | :---: | :--- |
| `groq` | — | — | — | — | No medido en ese equipo por falta de una corrida controlada. |
| `ollama` (`qwen2.5:3b`) | 100.0% | 100.0% | 0.0% | 2056 ms / 5167 ms | CPU; incluye carga del modelo. El default `0.5b` es más rápido pero suele tener menos recall. |
| `presidio` (`es_core_news_sm`) | 100.0% | 100.0% | 0.0% | 31 ms / 63 ms | Determinista; los filtros de falsos positivos descartan verbos y tokens técnicos. |
| `none` | 84.2% | 100.0% | 0.0% | 0 ms / 1 ms | Piso de comparación: solo Filtro 1. No detecta nombres de personas. |

Lectura rápida: con los filtros actuales, Ollama y Presidio detectan todo el dataset
sin falsos positivos; Ollama paga latencia de CPU y Presidio es mucho más rápido
pero depende de las reglas locales para proyectos, montos y direcciones. `none`
es el más rápido, pero deja pasar los nombres de personas.

### Interpretación esperada

- `qwen2.5:0.5b` es un modelo muy chico: puede mejorar bastante usando
  `qwen2.5:1.5b`, `qwen2.5:3b` o `llama3.2:3b` si el hardware lo permite.
  El modelo se cambia solo con `OLLAMA_MODEL`.
- Presidio suele ser más predecible y rápido en CPU, pero su NER depende del
  modelo de spaCy y de los reconocedores cargados; puede no detectar proyectos
  o montos con formatos raros.
- `none` es el piso de comparación: muestra cuánto aporta el Filtro 2 y cuánto
  del recall depende del Filtro 1.

---

## 5. Entornos air-gapped

El script `setup_local.sh` usa PyPI y la descarga de modelos, así que la
primera preparación necesita Internet. Para un despliegue sin salida, prepará
los artefactos en un equipo conectado y copialos:

### Presidio + spaCy

```bash
# En un equipo conectado, con la misma versión de Python y sistema operativo:
mkdir wheelhouse
pip download -r requirements-local.txt -d wheelhouse
python -m spacy download es_core_news_sm
```

Copiá `wheelhouse/` y el modelo de spaCy al equipo destino. Instalá con:

```bash
pip install --no-index --find-links wheelhouse -r requirements-local.txt
# Instalá el wheel/modelo de spaCy copiado, según cómo lo hayas empaquetado.
```

### Ollama

1. Copiá el binario de Ollama para la arquitectura destino.
2. Copiá el modelo desde la carpeta de modelos de Ollama:
   - Linux: `~/.ollama/models`
   - macOS: `~/.ollama/models`
   - Windows: `%USERPROFILE%\.ollama\models`
3. Arrancá `ollama serve` y verificá con `ollama list`.
4. Si el modelo no aparece, importalo con un `Modelfile` y `ollama create`.

### Verificación final

```bash
./venv/bin/python verificar_backends.py --backend ollama --solo-disponibilidad
./venv/bin/python verificar_backends.py --backend presidio --solo-disponibilidad
```

Si el backend falla al arrancar, el proxy **no se cae**: imprime un `[WARN]` y
degrada a solo reglas del Filtro 1. Si falla durante una petición, esa
petición también continúa con el resultado del Filtro 1.

---

## 6. Demo completamente offline

El repo ya trae un destino simulado (`mock_external_ai.py`). Para una demo sin
ninguna salida a Internet, podés usar Ollama también como destino de la IA:

1. Arrancá Ollama y descargá un modelo de chat:

   ```bash
   ollama pull qwen2.5:0.5b
   ```

2. Arrancá el proxy apuntando al puerto compatible con OpenAI de Ollama:

   ```bash
   DLP_TARGET_URL=http://127.0.0.1:11434 ./iniciar_proxy.sh
   ```

   Sin esa variable, el proxy usa el mock local `http://127.0.0.1:9000`.

3. Ejecutá el cliente (usa `http://127.0.0.1:8000/v1`):

   ```bash
   ./venv/bin/python cliente_prueba.py
   ```

El proxy sigue sanitizando el prompt y rehidratando la respuesta; solo cambia
el destino. Si preferís conservar el mock, no hace falta este paso: el mock
también es local y no tiene salida a Internet.

---

## 7. Consideraciones de seguridad y operación

- **Bind local:** dejá Ollama escuchando solo en `127.0.0.1` (por defecto) o en
  una interfaz interna controlada. No lo expongas a Internet.
- **Presidio:** el modelo de spaCy y los reconocedores se cargan en memoria;
  no hay llamadas de red durante el análisis.
- **Integridad de artefactos:** en air-gapped, verificá checksums de wheels,
  binario de Ollama y modelos antes de copiarlos.
- **Datos en el log:** los backends locales no cambian el diseño
  *zero-retention* de `audit_log.jsonl`.
- **Falsos negativos:** un modelo local chico puede no detectar todas las
  entidades. Medí con `benchmark.py` y, si hace falta, subí el tamaño del
  modelo o combiná con Presidio.
- **Falsos positivos:** Presidio puede marcar entidades que no son sensibles
  (por ejemplo, nombres de productos o lugares públicos). Revisá la matriz de
  amenazas y la configuración de `PRESIDIO_SCORE_THRESHOLD`.
- **Disponibilidad:** `ANALYZER_BACKEND=auto` o `none` evitan que una falla del
  analizador bloquee el tráfico.
- **Proxy y destino:** si el destino también es local, el flujo completo no
  sale de la máquina/servidor; si el destino es un proveedor externo, el
  prompt sanitizado sigue saliendo, pero sin las entidades contextuales que
  detectó el analizador local.

---

## 8. Archivos involucrados

| Archivo | Rol |
| :--- | :--- |
| `contextual_analyzers.py` | Clases `GroqAnalyzer`, `OllamaAnalyzer`, `PresidioAnalyzer`, `NullAnalyzer` y fábrica `build_analyzer()`. |
| `sanitizer_engine.py` | Usa el backend elegido en `_apply_llm_ner`; mantiene el Filtro 1 y el etiquetado. |
| `proxy_mitm.py` | Imprime el backend activo al arrancar y sigue con la rehidratación. |
| `verificar_backends.py` | Diagnóstico de disponibilidad y detección de prueba. |
| `requirements-local.txt` | Dependencias extra para Presidio + spaCy. |
| `setup_local.sh` | Instalación/verificación de Ollama o Presidio y actualización del `.env`. |
| `.env.example` | Variables de configuración de los tres backends. |
| `benchmark.py` | Comparación de métricas con `--backend`. |
