# Proxy DLP de Sanitización para APIs de IA Generativa

Prototipo de **Prevención de Pérdida de Datos (DLP)** implementado como proxy HTTP reverso en la frontera de confianza entre la red interna de una organización y los proveedores externos de Inteligencia Artificial. 

A diferencia de un firewall tradicional que bloquea las peticiones sospechosas, este sistema **intercepta, anonimiza en tiempo real y reenvía el tráfico**, permitiendo que los usuarios utilicen LLMs externos sin exponer información confidencial, datos personales (PII) ni credenciales.

---

## Arquitectura y Flujo de Información

```text
[Cliente Interno] ──(1. Prompt con PII)──► [Proxy DLP :8000 (mitmproxy)]
                                                  │
                                    ┌─────────────┴─────────────┐
                                    ▼                           ▼
                          [Filtro 1: Local]           [Filtro 2: Contextual]
                       (Regex, Luhn, CUIT,          (LLM Analizador vía Groq
                        Entropía Shannon)            llama-3.1-8b-instant)
                                    │                           │
                                    └─────────────┬─────────────┘
                                                  ▼
                                    [Reemplazo por Etiquetas]
                                     ([PERSON_1], [ID_1]...)
                                                  │
                                    ┌─────────────┴─────────────┐
                                    ▼                           ▼
                         [audit_log.jsonl]          [API IA Externa :9000]
                        (Métricas sin datos         (Recibe solo el texto
                            sensibles)                   anonimizado)
```

---

## Estructura y Responsabilidad de Archivos

| Archivo | Capa | Responsabilidad |
| :--- | :--- | :--- |
| **`proxy_mitm.py`** | Red / Transporte | Addon de `mitmproxy` que intercepta llamadas `POST` a `/chat/completions`, deserializa el JSON, invoca al motor sanitizador y actualiza el payload recalculando cabeceras HTTP. |
| **`sanitizer_engine.py`** | Motor DLP | Ejecuta el análisis híbrido en dos pasadas exclusivamente sobre los mensajes con `"role": "user"`:<br>• **Filtro 1 (Determinista):** Detecta DNI, CUIT/CUIL (validado con módulo 11), CBU (22 dígitos), tarjetas de crédito (validación de Luhn), emails y secretos con alta entropía de Shannon ($\ge 4.2$).<br>• **Filtro 2 (Contextual):** Consulta a `llama-3.1-8b-instant` (Groq) con salida JSON forzada para detectar personas (`PERSON`), organizaciones (`ORG`) y ubicaciones (`LOCATION`). Incluye *fallback* automático si falla la conexión. |
| **`audit_logger.py`** | Auditoría / Forense | Registra cada evento en formato JSON Lines (`audit_log.jsonl`) guardando timestamp, categorías detectadas, cantidad de reemplazos y latencia en ms, **omitiendo por diseño cualquier valor sensible original**. |
| **`mock_external_ai.py`** | Destino Externo | Servidor HTTP local (puerto `9000`) que emula la API de OpenAI (`chat.completions`) e imprime en consola el JSON limpio recibido para validar que no salen datos reales. |
| **`cliente_prueba.py`** | Cliente Interno | Simula a un empleado enviando un prompt con datos personales, fiscales y tokens utilizando el SDK oficial de `openai` apuntando al proxy (`[http://127.0.0.1:8000/v1](http://127.0.0.1:8000/v1)`). |
| **`iniciar_proxy.sh`** | Infraestructura | Script de arranque que activa el entorno virtual (`venv`), exporta las variables de `.env` y levanta `mitmdump` en modo reverso. |
| **`requirements.txt`** | Dependencias | Lista de paquetes Python requeridos (`mitmproxy`, `httpx`, `openai`). |
| **`.env.example`** | Configuración | Plantilla de variables de entorno (copiar a `.env` antes de ejecutar). |

---

## Instalación y Puesta en Marcha

### 1. Clonar e instalar dependencias
```bash
git clone git@github.com:MartinGonzalezFigueira/dlp-ai-proxy.git
cd dlp-ai-proxy
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Configurar variables de entorno
Crear el archivo `.env` local (ignorado por Git) y pegar una API Key gratuita de [Groq Console](https://console.groq.com/keys):
```bash
cp .env.example .env
# Editar .env y asignar: GROQ_API_KEY="gsk_tu_clave_aqui"
```

### 3. Ejecutar la demo (requiere 3 terminales)

* **Terminal 1 — Simulador de API Externa (puerto 9000):**
  ```bash
  ./venv/bin/python mock_external_ai.py
  ```
* **Terminal 2 — Proxy Reverso DLP (puerto 8000):**
  ```bash
  ./iniciar_proxy.sh
  ```
* **Terminal 3 — Cliente Interno y verificación de auditoría:**
  ```bash
  ./venv/bin/python cliente_prueba.py
  cat audit_log.jsonl
  ```

---

## Estado Actual del Proyecto

* [x] Arquitectura modular definida (separación entre transporte HTTP, motor DLP, auditoría y destino).
* [x] Proxy reverso operativo con `mitmproxy` (`mitmdump`).
* [x] **Filtro 1 (Determinista):** Implementado con expresiones regulares, verificación matemática (Luhn / Módulo 11) y detección de secretos por entropía.
* [x] **Filtro 2 (Contextual):** Implementado vía API de Groq (`llama-3.1-8b-instant`) con manejo de errores (`try/except`) para garantizar disponibilidad ante caídas de red.
* [x] **Coherencia referencial:** Etiquetado numerado (`[PERSON_1]`, `[ID_1]`, `[ORG_1]`) consistente dentro del mismo prompt.
* [x] **Auditoría segura:** Logging estructurado en `audit_log.jsonl` sin almacenamiento de datos crudos.
* [x] Entorno de pruebas local completo (`mock_external_ai.py` + `cliente_prueba.py`).

---

## Roadmap (Tareas Pendientes para el Equipo)

1. **Suite de Evaluación y Métricas (`benchmark.py`):**
   * Crear un dataset de ~40-50 prompts de prueba (casos con PII real, textos técnicos sin PII para medir falsos positivos y casos borde en español).
   * Medir y documentar **Precisión**, **Recall**, **Tasa de Falsos Positivos** y **Latencia agregada (ms)** comparando tráfico directo vs. tráfico a través del proxy.
2. **Rehidratación de Respuestas (De-sanitización):**
   * Implementar el hook `response()` en `proxy_mitm.py` para que, cuando la IA externa responda utilizando las etiquetas (`[PERSON_1]`), el proxy restituya el valor original antes de entregar la respuesta al usuario interno.
3. **Alternativas de Despliegue (Plan B / Comparativa):**
   * Documentar o crear rama alternativa con ejecución 100% local/offline mediante **Ollama** (`qwen2.5:0.5b`) o **Microsoft Presidio + spaCy** para entornos sin salida a APIs externas de análisis.
4. **Documentación Técnica y Defensa del TP:**
   * Elaborar el Diagrama de Flujo de Datos (DFD) formal identificando las fronteras de confianza.
   * Completar la matriz de amenazas **STRIDE** (justificando el diseño *zero-retention* del log y los riesgos residuales de fuga semántica).
   * Preparar presentación y gráficos de resultados del benchmark.
