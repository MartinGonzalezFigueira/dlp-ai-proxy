import copy
import math
import os
import re
import time
from typing import Any, Dict, List, Optional, Set

from audit_logger import log_sanitization_event
from contextual_analyzers import ContextualAnalyzer, build_analyzer


class SemanticTagManager:
    """Genera etiquetas numeradas consistentes y guarda el mapa inverso para rehidratar."""

    def __init__(self):
        self.value_to_tag: Dict[str, str] = {}
        self.tag_to_value: Dict[str, str] = {}
        self.counters: Dict[str, int] = {}
        self.type_counts: Dict[str, int] = {}

    def get_tag(self, raw_value: str, entity_type: str) -> str:
        normalized = raw_value.strip()
        if normalized in self.value_to_tag:
            return self.value_to_tag[normalized]

        self.counters[entity_type] = self.counters.get(entity_type, 0) + 1
        tag = f"[{entity_type}_{self.counters[entity_type]}]"
        self.value_to_tag[normalized] = tag
        self.tag_to_value[tag] = normalized
        self.type_counts[entity_type] = self.type_counts.get(entity_type, 0) + 1
        return tag


class HybridSanitizer:
    # Categorías críticas que disparan bloqueo HTTP 403 en lugar de anonimización
    HIGH_RISK_TYPES = {"SECRET", "CREDIT_CARD"}

    # Palabras genéricas que un LLM puede devolver como entidad contextual sin
    # que sean un dato sensible real (ej. "proveedor" como PROJECT).
    CONTEXT_STOPWORDS = {
        "proveedor",
        "cliente",
        "empresa",
        "organizacion",
        "organización",
        "proyecto",
        "programa",
        "finanzas",
        "ventas",
        "compras",
        "marketing",
        "legal",
        "sistemas",
        "operaciones",
        "administracion",
        "administración",
        "recursos humanos",
        "rrhh",
        "tecnologia",
        "tecnología",
        "logistica",
        "logística",
        "necesito",
        "texto",
        "cargame",
        "luhn",
        "hola",
        "gracias",
        "favor",
        "quiero",
    }

    # Detecta en un texto ya sanitizado las etiquetas de categorías críticas, ej. [SECRET_1]
    _PATRON_ETIQUETA_CRITICA = re.compile(
        r"\[(" + "|".join(sorted(HIGH_RISK_TYPES)) + r")_\d+\]"
    )

    def __init__(
        self,
        backend: Optional[str] = None,
        analyzer: Optional[ContextualAnalyzer] = None,
    ):
        # El Filtro 2 es intercambiable: Groq (remoto), Ollama o Presidio (local).
        self.analyzer = analyzer or build_analyzer(backend)

        # Atributos de compatibilidad con benchmark.py y código previo.
        self.llm_url = getattr(
            self.analyzer, "url", os.getenv("ANALYZER_LLM_URL", "")
        )
        self.llm_model = getattr(
            self.analyzer, "model", os.getenv("ANALYZER_LLM_MODEL", "")
        )
        self.llm_api_key = getattr(self.analyzer, "api_key", "")

    @property
    def backend_name(self) -> str:
        return self.analyzer.name

    def backend_label(self) -> str:
        return self.analyzer.describe()

    @staticmethod
    def _luhn_check(card_number: str) -> bool:
        digits = [int(d) for d in re.sub(r"\D", "", card_number)]
        if not (13 <= len(digits) <= 19):
            return False
        checksum = 0
        for i, d in enumerate(digits[::-1]):
            if i % 2 == 1:
                d *= 2
                if d > 9:
                    d -= 9
            checksum += d
        return checksum % 10 == 0

    @staticmethod
    def _cuit_valido(cuit: str) -> bool:
        """Valida CUIT/CUIL con el dígito verificador (módulo 11)."""
        digits = re.sub(r"\D", "", cuit)
        if len(digits) != 11:
            return False
        weights = (5, 4, 3, 2, 7, 6, 5, 4, 3, 2)
        total = sum(int(d) * w for d, w in zip(digits[:10], weights))
        check = 11 - (total % 11)
        if check == 11:
            check = 0
        elif check == 10:
            check = 9
        return check == int(digits[10])

    @staticmethod
    def _shannon_entropy(token: str) -> float:
        if not token:
            return 0.0
        probs = [token.count(c) / len(token) for c in set(token)]
        return -sum(p * math.log2(p) for p in probs)

    def _entidad_contextual_valida(self, valor: str, tipo: str) -> bool:
        """Filtra falsos positivos típicos del analizador contextual."""
        bajo = valor.lower()

        if not re.search(r"[A-Za-z0-9ÁÉÍÓÚÑáéíóúñ]", valor):
            return False

        if tipo in {"PROJECT", "ORG", "PERSON"} and bajo in self.CONTEXT_STOPWORDS:
            return False

        if tipo in {"PERSON", "ORG"}:
            primera = bajo.split()[0] if bajo.split() else ""
            if primera in {"mi", "mis", "este", "esta", "estos", "estas"}:
                return False

        if tipo == "FINANCIAL":
            # Los montos reales suelen traer moneda o separador de miles.
            # Rechaza versiones, tiempos y puertos (2.31.0, 30000 ms, 8080).
            tiene_moneda = re.search(r"(?i)(?:\$|USD|ARS|EUR)", valor) is not None
            tiene_miles = re.search(r"\d{1,3}(?:[.,]\d{3})+", valor) is not None
            if not tiene_moneda and not tiene_miles:
                return False

        if tipo == "LOCATION" and re.fullmatch(r"[\d\s.,-]+", valor):
            return False

        if tipo == "PERSON" and re.search(r"\d", valor):
            return False

        # Identificadores técnicos o palabras sueltas en minúscula: boto3,
        # docker, up, python:3.12-slim.
        if tipo == "ORG" and " " not in valor and (
            valor.islower() or re.search(r"[:._]", valor)
        ):
            return False

        return True

    def _apply_regex_rules(self, text: str, tagger: SemanticTagManager) -> str:
        # 1. API Keys y tokens de alta entropía (CRÍTICO -> dispara bloqueo)
        text = re.sub(
            r"\b(?:sk-[a-zA-Z0-9_-]{20,}|ghp_[a-zA-Z0-9]{30,}|AKIA[0-9A-Z]{16})\b",
            lambda m: tagger.get_tag(m.group(0), "SECRET"),
            text,
        )

        def entropy_replacer(match: re.Match) -> str:
            tok = match.group(0)
            if self._shannon_entropy(tok) >= 4.2 and not tok.startswith("["):
                return tagger.get_tag(tok, "SECRET")
            return tok

        text = re.sub(r"\b[A-Za-z0-9_\-+/=]{24,}\b", entropy_replacer, text)

        # 2. Teléfonos argentinos. Se detectan antes que las tarjetas para que
        # un teléfono que pasa Luhn por casualidad no dispare un bloqueo.
        # Se exige un separador para no confundir números internos como 20251117001.
        text = re.sub(
            r"(?<!\w)(?:\+?54\s?9?\s?)?(?:11|[2368]\d{2,3})[-\s]\d{4}[-\s]\d{4}\b",
            lambda m: tagger.get_tag(m.group(0), "PHONE"),
            text,
        )

        # 3. Tarjetas de crédito (CRÍTICO -> dispara bloqueo)
        text = re.sub(
            r"\b(?:\d[ -]*?){13,19}\b",
            lambda m: tagger.get_tag(m.group(0), "CREDIT_CARD")
            if self._luhn_check(m.group(0))
            else m.group(0),
            text,
        )

        # 4. CUIT / CUIL con validación de dígito verificador
        text = re.sub(
            r"\b(?:20|23|24|27|30|33|34)[-.\s]?\d{8}[-.\s]?\d\b",
            lambda m: tagger.get_tag(m.group(0), "CUIT")
            if self._cuit_valido(m.group(0))
            else m.group(0),
            text,
        )

        # 5. CBU (22 dígitos)
        text = re.sub(r"\b\d{22}\b", lambda m: tagger.get_tag(m.group(0), "CBU"), text)

        # 6. Direcciones IP privadas / internas
        text = re.sub(
            r"\b(?:10\.\d{1,3}|192\.168|172\.(?:1[6-9]|2\d|3[0-1]))\.\d{1,3}\.\d{1,3}\b",
            lambda m: tagger.get_tag(m.group(0), "INTERNAL_IP"),
            text,
        )

        # 7. Montos financieros con símbolo de moneda (ej. $1.250.000).
        # Se ejecuta antes de DNI para que los separadores de miles no se
        # confundan con un documento.
        text = re.sub(
            r"(?<!\w)(?:AR\$|US\$|\$)\s?\d{1,3}(?:[.,]\d{3})*(?:[.,]\d{2})?(?!\w)",
            lambda m: tagger.get_tag(m.group(0), "FINANCIAL"),
            text,
        )

        # 8. DNI: 8 dígitos con puntos o número precedido por la etiqueta DNI.
        def dni_replacer(match: re.Match) -> str:
            numero = match.group(1)
            return match.group(0).replace(numero, tagger.get_tag(numero, "ID"))

        text = re.sub(
            r"(?i)\bDNI\s*:?\s*(\d{1,2}\.?\d{3}\.?\d{3})\b",
            dni_replacer,
            text,
        )
        text = re.sub(
            r"\b\d{2}\.\d{3}\.\d{3}\b",
            lambda m: tagger.get_tag(m.group(0), "ID"),
            text,
        )

        # 9. Emails
        text = re.sub(
            r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b",
            lambda m: tagger.get_tag(m.group(0), "EMAIL"),
            text,
        )

        # 10. Entidades contextuales con formato reconocible, sin depender del LLM.
        text = re.sub(
            r"\b(?:Proyecto|Programa)\s+[A-ZÁÉÍÓÚÑ][\wáéíóúñ]*(?:\s+[A-ZÁÉÍÓÚÑ][\wáéíóúñ]*)*",
            lambda m: tagger.get_tag(m.group(0), "PROJECT"),
            text,
        )
        text = re.sub(
            r"\b[A-ZÁÉÍÓÚÑ][\w&.'-]*(?:(?:\s+(?:de|del|la|las|los|el|y|e|da|do|dos|das|van|von|der|di|della))?"
            r"\s+[A-ZÁÉÍÓÚÑ][\w&.'-]*)*\s+(?:S\.?A\.?|S\.?R\.?L\.?|SAS|S\.A\.S\.|Sociedad|Inc|Ltd|GmbH|LLC)"
            r"(?![A-Za-z0-9_])",
            lambda m: tagger.get_tag(m.group(0), "ORG"),
            text,
        )
        text = re.sub(
            r"\bBanco\s+[A-ZÁÉÍÓÚÑ][\wáéíóúñ]*(?:\s+[A-ZÁÉÍÓÚÑ][\wáéíóúñ]*)*",
            lambda m: tagger.get_tag(m.group(0), "ORG"),
            text,
        )
        text = re.sub(
            r"(?i)\b(?:Av\.?|Avenida|Calle|Ruta|Pasaje|Boulevard|Bv\.?)\s+[\wáéíóúñ.]+(?:\s+\d{1,6})?",
            lambda m: tagger.get_tag(m.group(0), "LOCATION"),
            text,
        )
        return text

    def _apply_llm_ner(self, text: str, tagger: SemanticTagManager) -> str:
        """Envía el texto al backend contextual configurado y aplica sus entidades."""
        if not self.analyzer.active:
            return text

        try:
            entities = self.analyzer.analyze(text)
        except Exception as e:
            print(f"[WARN] Error consultando analizador contextual: {e}")
            return text

        etiquetas_existentes = re.findall(r"\[[A-Z_]+_\d+\]", text)

        for ent in sorted(entities, key=lambda e: len(e.get("text", "")), reverse=True):
            val = str(ent.get("text", "")).strip()
            etype = str(ent.get("type", "ENTITY")).upper()
            if (
                val
                and not val.startswith("[")
                and "[" not in val
                and "]" not in val
                and val in text
                and not re.fullmatch(r"[A-Z]+_\d+", val)
                and not any(val in etiqueta for etiqueta in etiquetas_existentes)
                and self._entidad_contextual_valida(val, etype)
            ):
                text = text.replace(val, tagger.get_tag(val, etype))
        return text

    def _sanitizar_texto(self, texto: str, tagger: SemanticTagManager) -> str:
        """Aplica las dos pasadas (Regex + backend contextual) a un texto plano."""
        paso1 = self._apply_regex_rules(texto, tagger)
        return self._apply_llm_ner(paso1, tagger)

    def _sanitizar_contenido(self, contenido: Any, tagger: SemanticTagManager) -> Any:
        """Sanitiza el contenido de un mensaje: string simple o lista de partes (formato multimodal)."""
        if isinstance(contenido, str):
            return self._sanitizar_texto(contenido, tagger)
        if isinstance(contenido, list):
            for parte in contenido:
                if isinstance(parte, dict) and isinstance(parte.get("text"), str):
                    parte["text"] = self._sanitizar_texto(parte["text"], tagger)
        return contenido

    @staticmethod
    def _textos_del_contenido(contenido: Any) -> List[str]:
        """Devuelve los textos de un contenido, sea string o lista de partes."""
        if isinstance(contenido, str):
            return [contenido]
        if isinstance(contenido, list):
            return [
                parte["text"]
                for parte in contenido
                if isinstance(parte, dict) and isinstance(parte.get("text"), str)
            ]
        return []

    def sanitize_openai_payload(
        self, payload: Dict[str, Any], request_id: str
    ) -> Dict[str, Any]:
        start_time = time.perf_counter()
        sanitized = copy.deepcopy(payload)
        tagger = SemanticTagManager()

        # El cliente reenvía TODO el historial en cada request,
        # incluidas las respuestas previas del asistente, que el proxy ya rehidrató con datos reales.
        # Por eso se sanitizan los mensajes de todos los roles con un único etiquetador por request,
        # así el mismo valor recibe siempre la misma etiqueta en todo el historial.
        tipos_criticos: Set[str] = set()
        for msg in sanitized.get("messages", []):
            if "content" not in msg:
                continue
            msg["content"] = self._sanitizar_contenido(msg["content"], tagger)

            # El bloqueo se decide solo por lo que envía el usuario.
            if msg.get("role") == "user":
                for texto in self._textos_del_contenido(msg["content"]):
                    tipos_criticos.update(self._PATRON_ETIQUETA_CRITICA.findall(texto))

        # Evaluar política de riesgo
        blocked_types: List[str] = sorted(tipos_criticos)
        action = "BLOCK" if blocked_types else "ALLOW"

        elapsed_ms = (time.perf_counter() - start_time) * 1000
        log_sanitization_event(tagger.type_counts, elapsed_ms, request_id, action=action)

        return {
            "action": action,
            "blocked_types": blocked_types,
            "sanitized_payload": sanitized,
            "tag_to_value": tagger.tag_to_value,
        }