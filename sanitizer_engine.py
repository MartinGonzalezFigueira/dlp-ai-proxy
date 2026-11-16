import copy
import json
import math
import os
import re
import time
from typing import Any, Dict, List
import httpx
from audit_logger import log_sanitization_event


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

    def __init__(self):
        self.llm_url = os.getenv(
            "ANALYZER_LLM_URL", "https://api.groq.com/openai/v1/chat/completions"
        )
        self.llm_model = os.getenv("ANALYZER_LLM_MODEL", "openai/gpt-oss-20b")
        self.llm_api_key = os.getenv("GROQ_API_KEY", "")

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
    def _shannon_entropy(token: str) -> float:
        if not token:
            return 0.0
        probs = [token.count(c) / len(token) for c in set(token)]
        return -sum(p * math.log2(p) for p in probs)

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

        # 2. Tarjetas de crédito (CRÍTICO -> dispara bloqueo)
        text = re.sub(
            r"\b(?:\d[ -]*?){13,19}\b",
            lambda m: tagger.get_tag(m.group(0), "CREDIT_CARD")
            if self._luhn_check(m.group(0))
            else m.group(0),
            text,
        )

        # 3. CUIT / CUIL
        text = re.sub(
            r"\b(?:20|23|24|27|30|33|34)[-.\s]?\d{8}[-.\s]?\d\b",
            lambda m: tagger.get_tag(m.group(0), "CUIT"),
            text,
        )

        # 4. CBU (22 dígitos)
        text = re.sub(r"\b\d{22}\b", lambda m: tagger.get_tag(m.group(0), "CBU"), text)

        # 5. Teléfonos argentinos
        text = re.sub(
            r"(?<!\w)(?:\+?54\s?9?\s?)?(?:11|[2368]\d{2,3})[-\s]?\d{4}[-\s]?\d{4}\b",
            lambda m: tagger.get_tag(m.group(0), "PHONE"),
            text,
        )

        # 6. Direcciones IP privadas / internas
        text = re.sub(
            r"\b(?:10\.\d{1,3}|192\.168|172\.(?:1[6-9]|2\d|3[0-1]))\.\d{1,3}\.\d{1,3}\b",
            lambda m: tagger.get_tag(m.group(0), "INTERNAL_IP"),
            text,
        )

        # 7. DNI
        text = re.sub(
            r"\b\d{1,2}\.\d{3}\.\d{3}\b|(?<=\bDNI\s)\d{7,8}\b|(?<=\bDNI:\s)\d{7,8}\b",
            lambda m: tagger.get_tag(m.group(0), "ID"),
            text,
            flags=re.IGNORECASE,
        )

        # 8. Emails
        text = re.sub(
            r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b",
            lambda m: tagger.get_tag(m.group(0), "EMAIL"),
            text,
        )
        return text

    def _apply_llm_ner(self, text: str, tagger: SemanticTagManager) -> str:
        """Envía el texto al LLM analizador (Groq) para extraer entidades en JSON."""
        if not self.llm_api_key:
            print("[WARN] Falta GROQ_API_KEY. Solo se aplicaron reglas Regex.")
            return text

        system_prompt = (
            "Sos un motor DLP de ciberseguridad. Extraé únicamente entidades sensibles "
            "contextuales del texto: nombres de personas (PERSON), empresas/organizaciones (ORG), "
            "ubicaciones/direcciones (LOCATION), proyectos internos (PROJECT) y montos financieros (FINANCIAL). "
            "Ignorá etiquetas entre corchetes como [ID_1] o [CUIT_1]. "
            'Respondé ÚNICAMENTE con un JSON válido: {"entities": [{"text": "valor exacto", "type": "PERSON|ORG|LOCATION|PROJECT|FINANCIAL"}]}. '
            'Si no hay entidades, devolvé {"entities": []}.'
        )
        try:
            resp = httpx.post(
                self.llm_url,
                headers={"Authorization": f"Bearer {self.llm_api_key}"},
                json={
                    "model": self.llm_model,
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": text},
                    ],
                    "response_format": {"type": "json_object"},
                    "temperature": 0.0,
                },
                timeout=15.0,
                trust_env=False,
            )
            resp.raise_for_status()
            content = resp.json()["choices"][0]["message"]["content"]
            entities = json.loads(content).get("entities", [])

            for ent in sorted(entities, key=lambda e: len(e.get("text", "")), reverse=True):
                val = ent.get("text", "").strip()
                etype = ent.get("type", "ENTITY").upper()
                if val and not val.startswith("[") and val in text:
                    text = text.replace(val, tagger.get_tag(val, etype))
        except Exception as e:
            print(f"[WARN] Error consultando LLM analizador: {e}")
        return text

    def sanitize_openai_payload(
        self, payload: Dict[str, Any], request_id: str
    ) -> Dict[str, Any]:
        start_time = time.perf_counter()
        sanitized = copy.deepcopy(payload)
        tagger = SemanticTagManager()

        for msg in sanitized.get("messages", []):
            if msg.get("role") == "user" and isinstance(msg.get("content"), str):
                step1 = self._apply_regex_rules(msg["content"], tagger)
                msg["content"] = self._apply_llm_ner(step1, tagger)

        # Evaluar política de riesgo
        blocked_types: List[str] = [
            t for t in tagger.type_counts if t in self.HIGH_RISK_TYPES
        ]
        action = "BLOCK" if blocked_types else "ALLOW"

        elapsed_ms = (time.perf_counter() - start_time) * 1000
        log_sanitization_event(tagger.type_counts, elapsed_ms, request_id, action=action)

        return {
            "action": action,
            "blocked_types": blocked_types,
            "sanitized_payload": sanitized,
            "tag_to_value": tagger.tag_to_value,
        }