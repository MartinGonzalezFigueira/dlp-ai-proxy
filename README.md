# Proxy DLP de Sanitización para APIs de IA Generativa (`dlp-ai-proxy`)

**Universidad de Buenos Aires — Facultad de Ingeniería (FIUBA)**  
**Materia:** Taller de Seguridad Informática — Trabajo Práctico: Seguridad en IA (Grupo 9)  
**Repositorio:** [github.com/MartinGonzalezFigueira/dlp-ai-proxy](https://github.com/MartinGonzalezFigueira/dlp-ai-proxy)

| Integrante | Padrón |
| :--- | :---: |
| Luka Thaiel Araujo Grisolia | 111392 |
| Mateo Aguilera | 111605 |
| Enrique Heller | 110701 |
| Martin Gonzalez Figueira | 111245 |
| Brenda Barletta | 112184 |
| Martin Laurito | 109727 |

---

## Resumen Ejecutivo

**`dlp-ai-proxy`** es un prototipo funcional de **Prevención de Pérdida de Datos (DLP) de salida**, implementado como un proxy HTTP reverso sobre `mitmproxy` en la frontera de confianza entre una red corporativa y proveedores externos de Inteligencia Artificial Generativa (compatibles con la API *OpenAI Chat Completions*).

A diferencia de un firewall tradicional que bloquea toda comunicación sospechosa, este sistema aplica una **política diferenciada por nivel de riesgo** en tiempo real:

1. **Bloqueo en frontera (`HTTP 403`):** Rechaza inmediatamente las peticiones del usuario que contengan credenciales (`SECRET`) o tarjetas de crédito válidas (`CREDIT_CARD`), devolviendo un error estructurado compatible con el SDK de OpenAI (`PermissionDeniedError`).
2. **Anonimización con coherencia referencial (`ALLOW`):** Detecta datos personales y corporativos mediante un motor híbrido (reglas deterministas + analizador contextual NLP/LLM intercambiable) y los reemplaza por etiquetas numeradas (`[PERSON_1]`, `[CUIT_1]`, `[EMAIL_1]`, etc.) en **todo el historial de la conversación** y en **todos los roles y formatos** (`user`, `assistant`, `system`, `tool` y listas multimodales).
3. **Rehidratación transparente:** Intercepta la respuesta del modelo externo y restituye los valores originales en memoria antes de entregarla al usuario interno.
4. **Auditoría con retención cero (*Zero-Retention*):** Registra métricas y categorías detectadas en `audit_log.jsonl` sin almacenar nunca los valores sensibles originales ni el texto de los prompts.

---

## Arquitectura y Ciclo de Vida de una Request

```text
[Cliente Interno] ──(1. POST /v1/chat/completions)──► [Proxy DLP :8000 (mitmproxy)]
                                                              │
                                                ┌─────────────┴─────────────┐
                                                ▼                           ▼
                                      [Filtro 1: Reglas]          [Filtro 2: Contextual]
                                    (Entropía, Luhn, CUIT,       (Presidio+spaCy / Ollama
                                     CBU, IP, Tel, Email...)       / Groq según backend)
                                                │                           │
                                                └─────────────┬─────────────┘
                                                              ▼
                                                  ┌───────────────────────┐
                                                  │ Evaluación de Política│
                                                  └─────┬───────────┬─────┘
                                         SECRET / CARD  │           │ PII / Confidencial
                                         (rol: user)    ▼           ▼
                                                [HTTP 403 BLOCK]  [Etiquetado + flow.metadata]
                                                       │            │
                                                       │            ├──► [API IA Externa :9000]
                                                       │            │    (Recibe solo etiquetas)
                                                       │            │              │
                                                       ▼            │              ▼
                                                [audit_log.jsonl] ◄─┘    [Hook response()]
                                                (Métricas sin PII)       (Rehidratación al cliente)
```

### Flujo paso a paso
1. El cliente interno apunta su `base_url` al proxy (`http://127.0.0.1:8000/v1`) y envía el historial completo de la conversación.
2. El hook `request()` de `proxy_mitm.py` deserializa el JSON y genera un identificador único de flujo (`request_id`).
3. `HybridSanitizer` recorre todos los mensajes del historial (cualquier rol y formato string o lista multimodal) ejecutando el **Filtro 1** y luego el **Filtro 2**, compartiendo una única instancia de `SemanticTagManager` para mantener coherencia de etiquetas entre turnos.
4. Si un mensaje con rol `user` contiene `SECRET` o `CREDIT_CARD`, el proxy responde con `403 Forbidden` (`dlp_policy_violation`) sin contactar al proveedor externo.
5. En caso contrario (`ALLOW`), guarda el mapa de etiquetas en `flow.metadata` (aislado por sesión HTTP), registra el evento en `audit_log.jsonl` y reenvía el cuerpo sanitizado al destino (`DLP_TARGET_URL`, por defecto `http://127.0.0.1:9000`).
6. Al recibir la respuesta, el hook `response()` sustituye las etiquetas por los valores reales antes de responder al cliente.

---

## Guía Rápida de Ejecución y Pruebas

### Requisitos Previos
* **Python 3.10 o superior** (en Ubuntu/Debian, si falta el módulo de entornos virtuales: `sudo apt install -y python3-venv`).

```bash
git clone https://github.com/MartinGonzalezFigueira/dlp-ai-proxy.git
cd dlp-ai-proxy
```

### Opción A — Recomendada: 100% Local con NLP Presidio + spaCy (sin API Keys)
Instala el entorno virtual y el motor NLP en español localmente, corre el benchmark cuantitativo completo (22 prompts multi-turno) y ejecuta la demostración integral de extremo a extremo levantando servidor mock, proxy y cliente automáticamente:

```bash
# 1. Instalar entorno virtual y backend NLP local (Microsoft Presidio + spaCy en español)
./setup_local.sh presidio

# 2. Correr benchmark cuantitativo (Recall, Precisión, Falsos Positivos, Fugas y Latencia)
./setup.sh --benchmark-backend presidio

# 3. Correr demostración automática de 3 pruebas de extremo a extremo
./setup.sh --demo
```

### Opción B — Ultra Rápida: Solo Filtro 1 Determinista (< 10 segundos)
Crea el entorno base sin descargar modelos NLP y evalúa todas las reglas deterministas (CUIT Módulo 11, CBU, tarjetas Luhn, secretos por entropía, DNI, teléfonos e IPs internas):

```bash
./setup.sh --benchmark --backend none
```

### Opción C — Con LLM en la nube (Groq API, opcional)
Para probar el Filtro 2 contra `api.groq.com`, ejecutar `./setup.sh` para configurar una `GROQ_API_KEY` en `.env` y luego correr la demo:

```bash
./setup.sh
./setup.sh --demo
```

### Qué Validan Automáticamente `--demo` y `--benchmark`

| Prueba / Suite | Escenario Evaluado | Resultado Esperado |
| :--- | :--- | :--- |
| **Demo Prueba 1** (`ALLOW` + Rehidratación) | Prompt con nombre, CUIT, teléfono, email e IP interna. | El servidor externo recibe solo etiquetas (`[PERSON_1]`, `[CUIT_1]`, etc.) y el cliente recibe los valores reales restituidos. |
| **Demo Prueba 2** (`BLOCK` HTTP 403) | Prompt que incluye una API key simulada (`sk-proj-...`). | El proxy rechaza la petición en frontera con `HTTP 403 Forbidden` (`PermissionDeniedError`); el servidor externo nunca la recibe. |
| **Demo Prueba 3** (Historial Multi-Turno) | Turno 2 que reenvía la respuesta rehidratada previa del `assistant` junto a una nueva pregunta. | El proxy re-sanitiza tanto el historial del `assistant` como el nuevo mensaje del `user`: 0 datos reales salen al exterior. |
| **Benchmark + Auditoría** (`audit_log.jsonl`) | 6 conversaciones multi-turno (22 prompts: datos reales, logs técnicos, casos borde y bloqueos). | Con Presidio: **100% Recall**, **100% Precisión**, **0% Falsos Positivos**, **0 fugas por historial** y **0 valores sensibles** escritos en `audit_log.jsonl`. |

### Ejecución Manual Paso a Paso y Pruebas de Evasión
Si se desea inspeccionar cada componente por separado en 3 terminales:

* **Terminal 1 — Simulador de API Externa (puerto 9000):**
  ```bash
  ./venv/bin/python mock_external_ai.py
  ```
* **Terminal 2 — Proxy Reverso DLP (puerto 8000):**
  ```bash
  ./iniciar_proxy.sh
  ```
* **Terminal 3 — Cliente de prueba, pruebas de evasión y auditoría:**
  ```bash
  ./venv/bin/python cliente_prueba.py
  ./venv/bin/python prueba_evasion.py
  ./venv/bin/python verificar_backends.py --todos
  cat audit_log.jsonl
  ```

---

## Motor de Detección Híbrido

El orden de ejecución de las reglas del **Filtro 1** está diseñado para evitar colisiones entre patrones (por ejemplo, los teléfonos se evalúan antes que las tarjetas para evitar que un número internacional de 13 dígitos dispare Luhn por azar, y los montos monetarios antes que los DNI):

| Orden | Tipo de Entidad | Técnica de Detección | Política (`user`) |
| :---: | :--- | :--- | :---: |
| 1 | `SECRET` | Prefijos conocidos (`sk-`, `ghp_`, `AKIA`, etc.) y tokens de $\ge 24$ caracteres con entropía de Shannon $H(t) = -\sum_{i} p_i \log_2 p_i \ge 4.2$ bits/símbolo. | **BLOCK (403)** |
| 2 | `PHONE` | Formatos telefónicos argentinos con separadores y prefijo `+54 9` opcional. | Anonimización |
| 3 | `CREDIT_CARD` | Secuencias de 13 a 19 dígitos validadas mediante el algoritmo de **Luhn**. | **BLOCK (403)** |
| 4 | `CUIT` | Prefijos `20, 23, 24, 27, 30, 33, 34` + 8 dígitos + dígito verificador validado con **Módulo 11**. | Anonimización |
| 5 | `CBU` | Secuencias de 22 dígitos consecutivos. | Anonimización |
| 6 | `INTERNAL_IP` | Direcciones IPv4 en rangos privados RFC 1918 (`10.x`, `172.16-31.x`, `192.168.x`). | Anonimización |
| 7 | `FINANCIAL` | Montos con signo monetario (`` `$` ``, `` `AR$` ``, `` `US$` ``) y separadores de miles. | Anonimización |
| 8 | `ID` (DNI) | Formato `NN.NNN.NNN` o número precedido por `"DNI"`. | Anonimización |
| 9 | `EMAIL` | Expresión regular estándar de correo electrónico. | Anonimización |
| 10 | `PROJECT`, `ORG`, `LOCATION` | Patrones reconocibles (`"Proyecto X"`, razones sociales `S.A.`/`S.R.L.`/`Banco X`, calles y avenidas). | Anonimización |
| 11 | `PERSON`, `ORG`, `LOCATION`, `PROJECT`, `FINANCIAL` | **Filtro 2:** Analizador contextual intercambiable (`presidio`, `ollama`, `groq`, `none` o `auto`) con filtrado post-detección para descartar palabras genéricas e identificadores técnicos. | Anonimización |

> **Degradación segura (*fail-open*):** Si el backend configurado en `ANALYZER_BACKEND` no está disponible o falla durante una petición, el proxy degrada automáticamente al Filtro 1 determinista sin interrumpir la operación.

---

## Resultados del Benchmark Cuantitativo

El script `benchmark.py` evalúa el motor sobre `benchmark_dataset.py` (**6 conversaciones multi-turno, 22 prompts** divididos en categorías *positivo*, *limpio*, *borde* y *bloqueo*), simulando el reenvío real del historial rehidratado en cada turno y auditando `audit_log.jsonl`:

| Configuración Filtro 2 | Recall | Precisión | Falsos Positivos | Fugas por Historial | Bloqueos 403 | Latencia (Mediana / p95) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Presidio + spaCy (Local)** | **100%** | **100%** | **0%** | **0 de 33** | **3 / 3** | **23 ms / 51 ms** |
| **Groq (`openai/gpt-oss-20b`, Remoto)** | 100% | 100% | 0% | 0 de 33 | 3 / 3 | 5875 ms / 18110 ms |
| **Ninguno (Solo Filtro 1)** | 84.2% | 100% | 0% | 0 de 26 | 3 / 3 | 0 ms / 0 ms |

* **Conclusión técnica:** El backend local **Presidio + spaCy** iguala el 100% de recall y precisión del LLM remoto con una latencia mediana de **23 ms** (~250 veces más rápido que Groq), eliminando además la exposición de texto hacia un proveedor de análisis externo. Sin Filtro 2, el recall cae al 84.2% porque los nombres propios carecen de formato fijo. En las tres configuraciones se registraron **0 valores sensibles** en `audit_log.jsonl`.

---

## Modelado de Amenazas (DFD y STRIDE)

El análisis completo de fronteras de confianza y amenazas se encuentra en el informe técnico (`Informe_IA_grupo9.pdf`). Resumen de hallazgos y controles implementados:

* **Tampering (Evasiones estructurales mitigadas):** En la primera iteración se detectó que los payloads multimodales (`content` como lista de objetos) y los mensajes con roles distintos de `user` (`system`, `tool`, `assistant`) evadían la inspección. En la versión final se inspeccionan todos los roles y formatos, validado mediante `prueba_evasion.py`.
* **Information Disclosure:** Mitigado mediante sanitización previa a la frontera de Internet, uso de analizadores locales (`Presidio` / `Ollama`) y registro de auditoría con retención cero.
* **Repudiation:** Registro estructurado por `request_id` con conteo de entidades únicas anonimizadas y latencia.
* **Spoofing / DoS / Elevation of Privilege:** Documentados como riesgos residuales del prototipo con sus mitigaciones recomendadas para producción (autenticación de clientes, restricción de interfaz de escucha, corte temprano en `BLOCK` antes de invocar al Filtro 2 y permisos restrictivos sobre `.env`).

---

## Estructura del Repositorio

| Archivo | Capa | Descripción |
| :--- | :--- | :--- |
| **`proxy_mitm.py`** | Transporte HTTP | Addon de `mitmproxy` con hooks `request()` y `response()` para interceptación, bloqueo `403`, sanitización y rehidratación aislada por flujo (`flow.metadata`). |
| **`sanitizer_engine.py`** | Motor DLP | Implementa `HybridSanitizer` (pasadas secuenciales de Filtro 1 y Filtro 2 sobre todo el historial) y `SemanticTagManager` (etiquetado numerado coherente). |
| **`contextual_analyzers.py`** | Filtro 2 (NLP/LLM) | Backends intercambiables (`presidio`, `ollama`, `groq`, `none`, `auto`) y fábrica `build_analyzer()` con degradación segura. |
| **`audit_logger.py`** | Auditoría | Escribe eventos en `audit_log.jsonl` sin almacenar valores sensibles ni prompts. |
| **`mock_external_ai.py`** | Destino Simulado | Servidor HTTP local (`:9000`) que emula `/v1/chat/completions` e imprime el payload sanitizado recibido. |
| **`cliente_prueba.py`** | Pruebas E2E | Cliente con SDK oficial de `openai` que ejecuta las 3 pruebas funcionales (anonimización + rehidratación, bloqueo `403` y conversación multi-turno). |
| **`prueba_evasion.py`** | Seguridad / QA | Verifica la detección y bloqueo en payloads multimodales (lista) y mensajes con rol `system`. |
| **`benchmark.py`** & **`benchmark_dataset.py`** | Evaluación | Suite automatizada de 22 prompts multi-turno que calcula Recall, Precisión, Falsos Positivos, fugas por historial, latencia y limpieza del log. |
| **`verificar_backends.py`** | Diagnóstico | Comprueba qué analizadores están operativos y ejecuta una prueba de detección. |
| **`setup.sh`**, **`setup_local.sh`**, **`iniciar_proxy.sh`** | Infraestructura | Scripts de instalación automatizada, configuración de entorno local offline y arranque del proxy. |
| **`docs/PLAN_B_LOCAL.md`** | Documentación | Guía detallada de despliegue offline / air-gapped y comparativa de analizadores locales. |
| **`requirements.txt`** & **`requirements-local.txt`** | Dependencias | Dependencias base (`mitmproxy`, `httpx`, `openai`) y dependencias NLP locales (`presidio-analyzer`, `spacy`). |
| **`.env.example`** | Configuración | Plantilla de variables de entorno (`ANALYZER_BACKEND`, `DLP_TARGET_URL`, `GROQ_API_KEY`). |

---

## Limitaciones Conocidas y Trabajo Futuro

* **Filtrado de ruta con query string:** `mitmproxy` incluye los parámetros de consulta en `flow.request.path`; una petición a `/v1/chat/completions?x=1` debería normalizarse ignorando la query string.
* **Corte temprano (*Early-Exit*):** Evitar invocar el Filtro 2 cuando el Filtro 1 ya detectó una entidad de bloqueo (`SECRET` o `CREDIT_CARD`), reduciendo latencia innecesaria.
* **Soporte de Streaming y `tool_calls`:** El prototipo opera sobre respuestas JSON completas; extender el hook `response()` a Server-Sent Events (`stream=True`) y argumentos de llamadas a funciones queda planteado como evolución.
* **Reemplazo por palabra completa y normalización anti-ofuscación:** Evitar reemplazos parciales dentro de palabras más largas en el Filtro 2 y agregar pre-procesamiento contra ofuscación deliberada (espacios intercalados, Base64 o *prompt injection* dirigido a analizadores LLM).