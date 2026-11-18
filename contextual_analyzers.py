"""Analizadores contextuales (Filtro 2) intercambiables.

El proxy puede ejecutarse con un analizador remoto (Groq) o con alternativas
100% locales para entornos sin salida a Internet:

- ``groq``     : API remota compatible con OpenAI (comportamiento histórico).
- ``ollama``   : LLM local servido por Ollama (por defecto ``qwen2.5:0.5b``).
- ``presidio`` : Microsoft Presidio + spaCy (NER local en español).
- ``none``     : sin Filtro 2; solo reglas deterministas del Filtro 1.
- ``auto``     : elige Ollama, luego Presidio, luego Groq y, si nada está
                 disponible, cae a solo regex.

La selección se controla con la variable de entorno ``ANALYZER_BACKEND``.
Todos los analizadores devuelven una lista de ``{"text": ..., "type": ...}``
con tipos acotados a las entidades contextuales que entiende el motor DLP.
"""
from __future__ import annotations

import importlib.util
import json
import os
import re
from typing import Any, Dict, List, Optional, Tuple

import httpx

BACKENDS = ("groq", "ollama", "presidio", "none", "auto")


CONTEXT_ENTITY_TYPES = {"PERSON", "ORG", "LOCATION", "PROJECT", "FINANCIAL"}

_TYPE_ALIASES = {
    "PERSON": "PERSON",
    "PER": "PERSON",
    "PERSONA": "PERSON",
    "ORG": "ORG",
    "ORGANIZATION": "ORG",
    "ORGANISATION": "ORG",
    "ORGANIZACION": "ORG",
    "ORGANIZACIÓN": "ORG",
    "LOCATION": "LOCATION",
    "LOC": "LOCATION",
    "GPE": "LOCATION",
    "UBICACION": "LOCATION",
    "UBICACIÓN": "LOCATION",
    "ADDRESS": "LOCATION",
    "DIRECCION": "LOCATION",
    "DIRECCIÓN": "LOCATION",
    "PROJECT": "PROJECT",
    "PROYECTO": "PROJECT",
    "FINANCIAL": "FINANCIAL",
    "MONEY": "FINANCIAL",
    "MONTO": "FINANCIAL",
    "AMOUNT": "FINANCIAL",
}


_RE_PROYECTO = re.compile(
    r"\b(?:Proyecto|Programa)\s+"
    r"[A-ZÁÉÍÓÚÑ][\wáéíóúñ]*"
    r"(?:\s+[A-ZÁÉÍÓÚÑ][\wáéíóúñ]*)*"
)
_RE_DINERO = re.compile(r"(?i)(?:\$|USD|ARS|EUR)\s?\d(?:[\d.,]*\d)?")
_RE_DIRECCION = re.compile(
    r"(?i)\b(?:Av\.?|Avenida|Calle|Ruta|Pasaje|Boulevard|Bv\.?)\s+"
    r"[A-ZÁÉÍÓÚÑ][\wáéíóúñ.]*(?:\s+\d{1,6})?"
)
_RE_ETIQUETA = re.compile(r"\[[A-Z_]+_\d+\]")
_RE_EMPRESA = re.compile(
    r"\b[A-ZÁÉÍÓÚÑ][\w&.'-]*"
    r"(?:(?:\s+(?:de|del|la|las|los|el|y|e|da|do|dos|das|van|von|der|di|della))?"
    r"\s+[A-ZÁÉÍÓÚÑ][\w&.'-]*)*"
    r"\s+(?:S\.?A\.?|S\.?R\.?L\.?|SAS|S\.A\.S\.|Sociedad|Inc|Ltd|GmbH|LLC)"
    r"(?![A-Za-z0-9_])"
)
_RE_SUFIJO_ORG = re.compile(
    r"(?i)\b(?:S\.?A\.?|S\.?R\.?L\.?|SAS|S\.A\.S\.|Sociedad|Banco|Compañía|"
    r"Empresa|Corp(?:oration)?|Inc|Ltd|GmbH|LLC)\b"
)

SYSTEM_PROMPT = (
    "Sos un motor DLP de ciberseguridad. Extraé únicamente entidades sensibles "
    "contextuales del texto: nombres de personas (PERSON), empresas/organizaciones (ORG), "
    "ubicaciones/direcciones (LOCATION), proyectos internos (PROJECT) y montos financieros (FINANCIAL). "
    "Los nombres de personas suelen ser dos o más palabras capitalizadas. "
    "No marques palabras genéricas como 'proveedor', 'cliente', 'empresa', 'proyecto' o "
    "'programa' si no forman parte de un nombre propio. "
    "Ignorá etiquetas entre corchetes como [ID_1] o [CUIT_1]. "
    'Respondé ÚNICAMENTE con un JSON válido: {"entities": [{"text": "valor exacto", "type": "PERSON|ORG|LOCATION|PROJECT|FINANCIAL"}]}. '
    'Si no hay entidades, devolvé {"entities": []}. '
    "Ejemplo: texto 'Escribile a Juan Pérez de Acme S.A. sobre el Proyecto Aurora' -> "
    '{"entities": [{"text": "Juan Pérez", "type": "PERSON"}, {"text": "Acme S.A.", "type": "ORG"}, '
    '{"text": "Proyecto Aurora", "type": "PROJECT"}]}.'
)


class AnalyzerUnavailable(RuntimeError):
    """El backend solicitado no está instalado, configurado o accesible."""


class ContextualAnalyzer:
    """Interfaz mínima que implementa cada backend del Filtro 2."""

    name = "base"
    label = "Analizador contextual"

    @property
    def active(self) -> bool:
        """True si el backend puede analizar texto en este momento."""
        return False

    def analyze(self, text: str) -> List[Dict[str, str]]:
        """Devuelve entidades contextuales detectadas en ``text``."""
        return []

    def describe(self) -> str:
        """Descripción corta para logs, benchmark y diagnóstico."""
        return self.label

    def probe(self) -> Tuple[bool, str]:
        """Comprueba disponibilidad sin analizar texto."""
        return self.active, self.describe()


def _normalizar_entidades(entities: Any) -> List[Dict[str, str]]:
    """Valida, normaliza y deduplica la salida cruda de un backend."""
    if not isinstance(entities, list):
        return []

    salida: List[Dict[str, str]] = []
    vistos = set()
    for ent in entities:
        if not isinstance(ent, dict):
            continue
        valor = str(ent.get("text", "")).strip()
        tipo_crudo = str(ent.get("type", "")).strip().upper()
        tipo = _TYPE_ALIASES.get(tipo_crudo, tipo_crudo)
        if (
            not valor
            or valor.startswith("[")
            or "[" in valor
            or "]" in valor
            or tipo not in CONTEXT_ENTITY_TYPES
        ):
            continue
        clave = (valor, tipo)
        if clave in vistos:
            continue
        vistos.add(clave)
        salida.append({"text": valor, "type": tipo})
    return salida


def _extraer_json(content: str) -> Dict[str, Any]:
    """Tolera bloques Markdown y texto alrededor del JSON del modelo."""
    contenido = (content or "").strip()
    if not contenido:
        return {}

    if contenido.startswith("```"):
        contenido = re.sub(r"^```(?:json)?\s*", "", contenido, flags=re.IGNORECASE)
        contenido = re.sub(r"\s*```$", "", contenido)

    try:
        return json.loads(contenido)
    except json.JSONDecodeError:
        coincidencia = re.search(r"\{.*\}", contenido, flags=re.DOTALL)
        if not coincidencia:
            raise
        return json.loads(coincidencia.group(0))


class NullAnalyzer(ContextualAnalyzer):
    """Modo explícito sin Filtro 2: solo reglas del Filtro 1."""

    name = "none"
    label = "Solo reglas del Filtro 1 (sin análisis contextual)"

    @property
    def active(self) -> bool:
        return False

    def probe(self) -> Tuple[bool, str]:
        return True, "desactivado por configuración"


class GroqAnalyzer(ContextualAnalyzer):
    """Backend histórico: API remota de Groq compatible con OpenAI."""

    name = "groq"

    def __init__(
        self,
        url: Optional[str] = None,
        model: Optional[str] = None,
        api_key: Optional[str] = None,
        timeout: Optional[float] = None,
    ):
        self.url = (
            url or os.getenv("ANALYZER_LLM_URL", "https://api.groq.com/openai/v1/chat/completions")
        ).strip()
        self.model = model or os.getenv("ANALYZER_LLM_MODEL", "openai/gpt-oss-20b")
        self.api_key = api_key if api_key is not None else os.getenv("GROQ_API_KEY", "")
        self.timeout = float(timeout or os.getenv("ANALYZER_LLM_TIMEOUT", "15"))
        self._warned = False

    @property
    def active(self) -> bool:
        return self._clave_valida()

    def _clave_valida(self) -> bool:
        return bool(self.api_key) and not self.api_key.startswith("pega_aca")

    def describe(self) -> str:
        return f"Groq · {self.model}"

    def probe(self) -> Tuple[bool, str]:
        if not self._clave_valida():
            return False, "falta GROQ_API_KEY"
        return True, f"API configurada ({self.model})"

    def analyze(self, text: str) -> List[Dict[str, str]]:
        if not self._clave_valida():
            if not self._warned:
                print("[WARN] Falta GROQ_API_KEY. El Filtro 2 contextual queda desactivado.")
                self._warned = True
            return []

        try:
            resp = httpx.post(
                self.url,
                headers={"Authorization": f"Bearer {self.api_key}"},
                json={
                    "model": self.model,
                    "messages": [
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": text},
                    ],
                    "response_format": {"type": "json_object"},
                    "temperature": 0.0,
                },
                timeout=self.timeout,
                trust_env=False,
            )
            resp.raise_for_status()
            content = resp.json()["choices"][0]["message"]["content"]
            return _normalizar_entidades(_extraer_json(content).get("entities", []))
        except Exception as e:
            print(f"[WARN] Error consultando analizador Groq: {e}")
            return []


class OllamaAnalyzer(ContextualAnalyzer):
    """Backend 100% local usando la API nativa de Ollama."""

    name = "ollama"

    def __init__(
        self,
        url: Optional[str] = None,
        model: Optional[str] = None,
        timeout: Optional[float] = None,
    ):
        self.url = (url or os.getenv("OLLAMA_URL", "http://127.0.0.1:11434")).rstrip("/")
        self.model = model or os.getenv("OLLAMA_MODEL", "qwen2.5:0.5b")
        self.timeout = float(timeout or os.getenv("OLLAMA_TIMEOUT", "60"))

    @property
    def active(self) -> bool:
        return True

    def describe(self) -> str:
        return f"Ollama · {self.model} · {self.url}"

    def probe(self) -> Tuple[bool, str]:
        try:
            resp = httpx.get(
                f"{self.url}/api/tags",
                timeout=min(5.0, self.timeout),
                trust_env=False,
            )
            resp.raise_for_status()
            modelos = {
                str(modelo.get("name") or modelo.get("model") or "")
                for modelo in resp.json().get("models", [])
            }
            if self.model not in modelos and f"{self.model}:latest" not in modelos:
                return False, (
                    f"el modelo {self.model} no está descargado "
                    f"(ejecutá: ollama pull {self.model})"
                )
            return True, f"servidor local disponible en {self.url} ({self.model})"
        except Exception as e:
            return False, f"no se pudo conectar a {self.url}: {e}"

    def analyze(self, text: str) -> List[Dict[str, str]]:
        try:
            resp = httpx.post(
                f"{self.url}/api/chat",
                json={
                    "model": self.model,
                    "messages": [
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": text},
                    ],
                    "stream": False,
                    "format": "json",
                    "options": {"temperature": 0.0},
                },
                timeout=self.timeout,
                trust_env=False,
            )
            resp.raise_for_status()
            content = resp.json().get("message", {}).get("content", "")
            return _normalizar_entidades(_extraer_json(content).get("entities", []))
        except Exception as e:
            print(f"[WARN] Error consultando analizador Ollama: {e}")
            return []


class PresidioAnalyzer(ContextualAnalyzer):
    """Backend 100% local con Microsoft Presidio + spaCy en español."""

    name = "presidio"

    def __init__(
        self,
        language: Optional[str] = None,
        model: Optional[str] = None,
        score_threshold: Optional[float] = None,
    ):
        self.language = language or os.getenv("PRESIDIO_LANGUAGE", "es")
        self.model = model or os.getenv("PRESIDIO_SPACY_MODEL", "es_core_news_sm")
        self.score_threshold = float(
            score_threshold or os.getenv("PRESIDIO_SCORE_THRESHOLD", "0.35")
        )
        self._engine = None
        self._error = ""
        self._load()

    @property
    def active(self) -> bool:
        return self._engine is not None

    @property
    def error(self) -> str:
        return self._error

    def describe(self) -> str:
        return f"Presidio + spaCy · {self.model} · lang={self.language}"

    def probe(self) -> Tuple[bool, str]:
        if self._engine is None:
            return False, self._error or "motor no inicializado"
        return True, f"NER local disponible ({self.model})"

    def _load(self) -> None:
        if importlib.util.find_spec("presidio_analyzer") is None:
            self._error = "falta presidio-analyzer (pip install -r requirements-local.txt)"
            return
        if importlib.util.find_spec("spacy") is None:
            self._error = "falta spaCy (pip install -r requirements-local.txt)"
            return

        try:
            from presidio_analyzer import AnalyzerEngine
            from presidio_analyzer.nlp_engine import NlpEngineProvider

            configuracion = {
                "nlp_engine_name": "spacy",
                "models": [{"lang_code": self.language, "model_name": self.model}],
            }
            provider = NlpEngineProvider(nlp_configuration=configuracion)
            nlp_engine = provider.create_engine()
            self._engine = AnalyzerEngine(
                nlp_engine=nlp_engine,
                supported_languages=[self.language],
            )
            self._error = ""
        except Exception as e:
            self._engine = None
            self._error = f"{type(e).__name__}: {e}"

    @staticmethod
    def _reclasificar(valor: str, tipo: str) -> str:
        """Corrige casos típicos del NER: una empresa detectada como lugar."""
        if tipo == "LOCATION" and _RE_SUFIJO_ORG.search(valor):
            return "ORG"
        return tipo

    def analyze(self, text: str) -> List[Dict[str, str]]:
        if self._engine is None:
            return []

        try:
            resultados = self._engine.analyze(
                text=text,
                language=self.language,
                score_threshold=self.score_threshold,
            )
            rangos_etiquetas = [
                (etiqueta.start(), etiqueta.end())
                for etiqueta in _RE_ETIQUETA.finditer(text)
            ]
            entidades: List[Dict[str, str]] = []
            for resultado in resultados:
                tipo = _TYPE_ALIASES.get(str(resultado.entity_type).upper())
                if tipo not in CONTEXT_ENTITY_TYPES:
                    continue
                if any(
                    inicio <= resultado.start and resultado.end <= fin
                    for inicio, fin in rangos_etiquetas
                ):
                    continue
                valor = text[resultado.start : resultado.end].strip()
                if not valor or valor.startswith("["):
                    continue
                entidades.append({"text": valor, "type": self._reclasificar(valor, tipo)})


            for coincidencia in _RE_PROYECTO.finditer(text):
                entidades.append({"text": coincidencia.group(0).strip(), "type": "PROJECT"})
            for coincidencia in _RE_DINERO.finditer(text):
                entidades.append({"text": coincidencia.group(0).strip(), "type": "FINANCIAL"})
            for coincidencia in _RE_DIRECCION.finditer(text):
                entidades.append({"text": coincidencia.group(0).strip(), "type": "LOCATION"})
            for coincidencia in _RE_EMPRESA.finditer(text):
                entidades.append({"text": coincidencia.group(0).strip(), "type": "ORG"})

            return _normalizar_entidades(entidades)
        except Exception as e:
            print(f"[WARN] Error consultando analizador Presidio: {e}")
            return []


def _resolver_backend(backend: Optional[str]) -> str:
    solicitado = (backend or os.getenv("ANALYZER_BACKEND", "groq")).strip().lower()
    if solicitado in ("", "default"):
        return "groq"
    if solicitado in ("regex", "off", "disabled", "solo-regex", "solo_regex"):
        return "none"
    return solicitado


def _no_disponible(mensaje: str, strict: bool) -> ContextualAnalyzer:
    if strict:
        raise AnalyzerUnavailable(mensaje)
    print(f"[WARN] {mensaje} Se usará solo el Filtro 1 (regex).")
    return NullAnalyzer()


def build_analyzer(backend: Optional[str] = None, strict: bool = False) -> ContextualAnalyzer:
    """Construye el backend contextual pedido.

    Con ``strict=True`` lanza ``AnalyzerUnavailable`` si el backend no puede
    usarse. En el proxy se usa ``strict=False`` para degradar a solo regex y
    mantener la disponibilidad del servicio.
    """
    solicitado = _resolver_backend(backend)

    if solicitado == "auto":
        intentos = []
        for candidato in ("ollama", "presidio", "groq"):
            try:
                analizador = build_analyzer(candidato, strict=True)
            except AnalyzerUnavailable as e:
                intentos.append(f"{candidato}: {e}")
                continue
            if analizador.active:
                print(f"[INFO] ANALYZER_BACKEND=auto -> {analizador.describe()}")
                return analizador
            intentos.append(f"{candidato}: no activo")

        mensaje = "Ningún backend contextual está disponible. " + " | ".join(intentos)
        return _no_disponible(mensaje, strict)

    if solicitado == "none":
        return NullAnalyzer()

    if solicitado == "groq":
        analizador = GroqAnalyzer()
        disponible, detalle = analizador.probe()
        if not disponible:
            return _no_disponible(f"Backend groq no disponible: {detalle}.", strict)
        return analizador

    if solicitado == "ollama":
        analizador = OllamaAnalyzer()
        disponible, detalle = analizador.probe()
        if not disponible:
            return _no_disponible(f"Backend ollama no disponible: {detalle}.", strict)
        return analizador

    if solicitado == "presidio":
        analizador = PresidioAnalyzer()
        if not analizador.active:
            return _no_disponible(
                f"Backend presidio no disponible: {analizador.error}.",
                strict,
            )
        return analizador

    return _no_disponible(
        f"Backend desconocido: {solicitado}. Opciones: {', '.join(BACKENDS)}.",
        strict,
    )
