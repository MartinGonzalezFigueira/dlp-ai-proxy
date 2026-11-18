"""Benchmark del proxy DLP.

Mide, sobre un lote de conversaciones con datos inventados:
  - Recall: qué porcentaje de los datos sensibles NO llega a la IA externa.
  - Fugas por historial: datos ya eliminados que reaparecen en turnos posteriores.
  - Precisión y falsos positivos: entidades marcadas de más y texto no sensible alterado.
  - Bloqueos: políticas HTTP 403 correctas e indebidas.
  - Latencia de la sanitización según el largo del historial.

El benchmark corre siempre en modo detallado e imprime todo por terminal:
no genera archivos de resultados.

Uso:
  ./venv/bin/python benchmark.py            corre el benchmark completo
  ./venv/bin/python benchmark.py --backend ollama   usa el analizador local Ollama
  ./venv/bin/python benchmark.py --backend presidio usa Presidio + spaCy (offline)
  ./venv/bin/python benchmark.py --color    fuerza colores aunque la salida no sea una terminal
  ./venv/bin/python benchmark.py --no-color desactiva los colores
"""
import argparse
import contextlib
import io
import os
import re
import statistics
import sys
import tempfile
import time
from datetime import datetime

import audit_logger
from benchmark_dataset import CONVERSACIONES
from sanitizer_engine import HybridSanitizer


if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

CARPETA = os.path.dirname(os.path.abspath(__file__))
RUTA_LOG_AUDITORIA = os.path.join(tempfile.gettempdir(), "dlp_benchmark_audit.jsonl")
PLANTILLA_MOCK = "Procesado con éxito por la IA externa. Texto recibido: {texto}"
CATEGORIAS = ["positivo", "limpio", "borde", "bloqueo"]


class _Color:
    """Activa/desactiva ANSI. Se respeta NO_COLOR y se puede forzar con --color."""

    activo = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
    RESET = "\033[0m"
    NEGRITA = "\033[1m"
    TENUE = "\033[2m"
    ROJO = "\033[31m"
    VERDE = "\033[32m"
    AMARILLO = "\033[33m"
    AZUL = "\033[34m"
    MAGENTA = "\033[35m"
    CIAN = "\033[36m"


def _pintar(texto, codigo):
    return f"{codigo}{texto}{_Color.RESET}" if _Color.activo else str(texto)


def negrita(texto):
    return _pintar(texto, _Color.NEGRITA)


def tenue(texto):
    return _pintar(texto, _Color.TENUE)


def rojo(texto):
    return _pintar(texto, _Color.ROJO)


def verde(texto):
    return _pintar(texto, _Color.VERDE)


def amarillo(texto):
    return _pintar(texto, _Color.AMARILLO)


def azul(texto):
    return _pintar(texto, _Color.AZUL)


def magenta(texto):
    return _pintar(texto, _Color.MAGENTA)


def cian(texto):
    return _pintar(texto, _Color.CIAN)


def seccion(titulo, color=cian):
    print()
    print(color("━" * 72))
    print(color(negrita(f"  {titulo}")))
    print(color("━" * 72))


def barra(pct, ancho=22):
    pct = max(0.0, min(100.0, float(pct)))
    llenos = round(ancho * pct / 100)
    return "█" * llenos + "░" * (ancho - llenos)


def color_por_valor(pct, bueno_si_alto=True):
    if bueno_si_alto:
        return verde if pct >= 90 else (amarillo if pct >= 60 else rojo)
    return verde if pct <= 5 else (amarillo if pct <= 15 else rojo)


def resaltar_etiquetas(texto):
    """Pinta [PERSON_1], [CUIT_1], etc. en la salida detallada."""
    return re.sub(
        r"(\[[A-Z_]+_\d+\])",
        lambda m: cian(negrita(m.group(1))),
        str(texto),
    )


def rol_coloreado(rol):
    pintar = {
        "user": cian,
        "assistant": magenta,
        "system": amarillo,
        "tool": azul,
    }.get(rol, tenue)
    return pintar(f"{rol:<9}")


def truncar(texto, n=160):
    texto = str(texto)
    return texto if len(texto) <= n else texto[: n - 1] + "…"


def color_categoria(categoria):
    return {
        "positivo": magenta,
        "limpio": verde,
        "borde": amarillo,
        "bloqueo": rojo,
    }.get(categoria, tenue)


def banner(config):
    print(cian("╔" + "═" * 70 + "╗"))
    print(cian("║ ") + negrita("BENCHMARK DEL PROXY DLP".ljust(68)) + cian("║"))
    print(cian("╚" + "═" * 70 + "╝"))
    print(f"  {tenue('Dataset'.ljust(14))} {config['conversaciones']} conversaciones · {config['prompts']} prompts")
    print(f"  {tenue('Distribución'.ljust(14))} {config['distribucion']}")
    filtro2 = config["filtro2"]
    print(f"  {tenue('Filtro 2'.ljust(14))} {verde(filtro2) if filtro2.startswith('activo') else amarillo(filtro2)}")
    print(f"  {tenue('Leyenda'.ljust(14))} {verde('[OK] ok')} · {rojo('[ERROR] error')} · "
          f"{amarillo('[AVISO] borde')} · {magenta('[BLOQUEO] bloqueo')}")


def resumen_terminal(a, auditoria):
    """Panel visual con las métricas que importan para la demo."""
    sensibles = a["sensibles"]
    recall = 100 * a["eliminados"] / sensibles if sensibles else 0.0
    tp_fp = a["tp"] + a["fp"]
    precision = 100 * a["tp"] / tp_fp if tp_fp else 0.0
    conservar = a["conservar_total"]
    falsos_positivos = 100 * a["conservar_alterados"] / conservar if conservar else 0.0
    lat = a["latencia"]

    seccion("RESUMEN EJECUTIVO", cian)
    print(f"  {tenue('Recall'.ljust(28))} {barra(recall)} "
          f"{color_por_valor(recall)(f'{recall:5.1f}%')}  {tenue('datos sensibles que no salieron')}")

    fugas_txt = f"{a['hist_fugas']} de {a['hist_exposiciones']} exposiciones"
    print(f"  {tenue('Fugas por historial'.ljust(28))} "
          f"{verde(fugas_txt) if a['hist_fugas'] == 0 else rojo(fugas_txt)}  "
          f"{tenue('datos viejos que reaparecieron')}")

    print(f"  {tenue('Precisión'.ljust(28))} {barra(precision)} "
          f"{color_por_valor(precision)(f'{precision:5.1f}%')}  {tenue('lo marcado que era sensible')}")

    print(f"  {tenue('Falsos positivos'.ljust(28))} {barra(falsos_positivos)} "
          f"{color_por_valor(falsos_positivos, bueno_si_alto=False)(f'{falsos_positivos:5.1f}%')}  "
          f"{tenue('texto técnico alterado')}")

    bloques_ok = (
        a["bloqueos_ok"] == a["bloqueos_esperados"]
        and a["bloqueos_indebidos"] == 0
        and a["bloqueos_omitidos"] == 0
    )
    bloques_txt = (
        f"{a['bloqueos_ok']}/{a['bloqueos_esperados']} correctos · "
        f"{a['bloqueos_indebidos']} indebidos · {a['bloqueos_omitidos']} omitidos"
    )
    print(f"  {tenue('Bloqueos 403'.ljust(28))} {verde(bloques_txt) if bloques_ok else rojo(bloques_txt)}")

    mediana = lat["mediana"]
    p95 = lat["p95"]
    print(f"  {tenue('Latencia (mediana / p95)'.ljust(28))} "
          f"{cian(f'{mediana:.0f} ms / {p95:.0f} ms')}")

    if auditoria:
        if auditoria["filtrados"]:
            cantidad = len(auditoria["filtrados"])
            print(f"  {tenue('Auditoría'.ljust(28))} "
                  f"{rojo(f'{cantidad} valores sensibles encontrados')}")
        else:
            eventos = auditoria["eventos"]
            print(f"  {tenue('Auditoría'.ljust(28))} "
                  f"{verde(f'{eventos} eventos · 0 valores sensibles')}")
    else:
        print(f"  {tenue('Auditoría'.ljust(28))} {amarillo('log no disponible')}")

    print(f"\n  {tenue('Categorías:')}")
    for cat in CATEGORIAS:
        cuenta = a["por_categoria"].get(cat, {"prompts": 0, "sin_errores": 0})
        color = color_categoria(cat)
        print(f"    {color(cat.ljust(10))} {cuenta['prompts']:>2} prompts · "
              f"{cuenta['sin_errores']:>2} sin errores")

def imprimir_fallos(a, limite=12):
    seccion("CASOS A REVISAR", amarillo)
    if not a["fallos"]:
        print(verde("  [OK] Sin fallos: todos los casos del dataset pasaron."))
        return
    for f in a["fallos"][:limite]:
        tipo = f["tipo"]
        color = rojo if ("FILTRADO" in tipo or "FUGA" in tipo or "OMITIDO" in tipo) else amarillo
        print(f"  {rojo('-')} {negrita(f['turno'])} {tenue('(' + f['categoria'] + ')')} "
              f"{color(tipo)} · {f['detalle']}")
    if len(a["fallos"]) > limite:
        print(tenue(f"  … y {len(a['fallos']) - limite} más en el informe completo."))


_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def _visible(texto):
    """Largo real de un texto, sin contar los códigos de color."""
    return len(_ANSI.sub("", texto))


def _celdas(fila):
    return [c.strip() for c in fila.strip().strip("|").split("|")]


def imprimir_tabla(filas):
    """Alinea una tabla Markdown en columnas para que se lea en la terminal."""
    matriz = [_celdas(f) for f in filas]
    columnas = max(len(f) for f in matriz)

    separador = next(
        (f for f in matriz if f and all(set(c) and set(c) <= set(":-") for c in f)),
        None,
    )

    alineaciones = []
    for i in range(columnas):
        marca = separador[i] if separador and i < len(separador) else ":---"
        if marca.startswith(":") and marca.endswith(":"):
            alineaciones.append("centro")
        elif marca.endswith(":"):
            alineaciones.append("derecha")
        else:
            alineaciones.append("izquierda")

    anchos = [0] * columnas
    for f in matriz:
        if f is separador:
            continue
        for i, c in enumerate(f[:columnas]):
            anchos[i] = max(anchos[i], _visible(c))

    def rellenar(celda, ancho, alineacion):
        hueco = max(0, ancho - _visible(celda))
        if alineacion == "derecha":
            return " " * hueco + celda
        if alineacion == "centro":
            izquierda = hueco // 2
            return " " * izquierda + celda + " " * (hueco - izquierda)
        return celda + " " * hueco

    for indice, fila in enumerate(matriz):
        if fila is separador:
            reglas = []
            for i in range(columnas):
                ancho = max(2, anchos[i])
                if alineaciones[i] == "derecha":
                    reglas.append("-" * (ancho - 1) + ":")
                elif alineaciones[i] == "centro":
                    reglas.append(":" + "-" * max(0, ancho - 2) + ":")
                else:
                    reglas.append(":" + "-" * (ancho - 1))
            yield tenue("| " + " | ".join(reglas) + " |")
            continue

        celdas = [rellenar(c, anchos[i], alineaciones[i])
                  for i, c in enumerate(fila[:columnas])]
        if indice == 0:
            celdas = [negrita(c) for c in celdas]
        yield "| " + " | ".join(celdas) + " |"


def imprimir_informe(lineas):
    """Colorea el Markdown y alinea las tablas para que se lea en la terminal."""
    tabla = []

    def volcar():
        if tabla:
            for fila in imprimir_tabla(tabla):
                print(fila)
            tabla.clear()

    for texto in lineas:
        if texto.startswith("|"):
            tabla.append(texto)
            continue
        volcar()
        if texto.startswith("# "):
            print("\n" + cian(negrita(texto)))
        elif texto.startswith("## "):
            print("\n" + magenta(negrita(texto)))
        elif texto.startswith("- **"):
            print(rojo(texto))
        elif texto.startswith(">"):
            print(tenue(texto))
        else:
            print(texto)

    volcar()



def cargar_env(ruta):
    """Carga las variables del .env sin depender de librerías externas."""
    if not os.path.exists(ruta):
        return
    with open(ruta, encoding="utf-8") as f:
        for linea in f:
            linea = linea.strip()
            if not linea or linea.startswith("#") or "=" not in linea:
                continue
            clave, valor = linea.split("=", 1)
            os.environ.setdefault(clave.strip(), valor.strip().strip('"').strip("'"))


def proteger_analizador(sanitizador, intervalo, estado):
    """Instrumenta el Filtro 2 para el benchmark.

    - Groq: silencia avisos, espacia las llamadas para no superar el límite de
      uso y reintenta una vez si falla.
    - Ollama/Presidio: no hay límite remoto, así que no se espacia, pero sí se
      cuentan los errores del analizador.
    - none: no hay nada que instrumentar.

    Las esperas se registran para descontarlas de la latencia."""

    if sanitizador.backend_name == "none":
        return

    original = sanitizador._apply_llm_ner

    def intentar(texto, etiquetador):
        salida = io.StringIO()
        with contextlib.redirect_stdout(salida):
            resultado = original(texto, etiquetador)
        return resultado, salida.getvalue()

    es_groq = sanitizador.backend_name == "groq" and bool(sanitizador.llm_api_key)

    if not es_groq:
        def envuelto_local(texto, etiquetador):
            resultado, log = intentar(texto, etiquetador)
            if "Error consultando" in log:
                estado["fallos_analizador"] += 1
            return resultado

        sanitizador._apply_llm_ner = envuelto_local
        return

    ultima = {"inicio": 0.0}

    def envuelto_groq(texto, etiquetador):
        resultado = texto
        for intento in (1, 2):
            falta = intervalo - (time.perf_counter() - ultima["inicio"])
            if falta > 0:
                time.sleep(falta)
                estado["espera_s"] += falta
            ultima["inicio"] = time.perf_counter()

            resultado, log = intentar(texto, etiquetador)
            if "Error consultando" not in log:
                return resultado

            if intento == 1:
                estado["reintentos"] += 1
                time.sleep(5)
                estado["espera_s"] += 5
        estado["fallos_analizador"] += 1
        return resultado

    sanitizador._apply_llm_ner = envuelto_groq



def rehidratar(texto, mapa):
    """Igual que el hook response() del proxy: etiquetas largas primero."""
    for etiqueta, valor in sorted(mapa.items(), key=lambda par: len(par[0]), reverse=True):
        texto = texto.replace(etiqueta, valor)
    return texto


def coincide(valor, lista):
    valor = valor.lower()
    return any(valor in otro.lower() or otro.lower() in valor for otro in lista if otro)


def enviar(sanitizador, historial, id_peticion):
    """Sanitiza el historial como lo haría el proxy."""
    return sanitizador.sanitize_openai_payload(
        {"model": "gpt-4o-mini", "messages": historial}, id_peticion
    )


def resultado_vacio():
    return {
        "por_tipo": {},        # tipo -> [total, eliminados] en el turno de origen
        "por_categoria": {},   # categoria -> [prompts, sin_errores]
        "hist_exposiciones": 0,
        "hist_fugas": 0,
        "conservar_total": 0,
        "conservar_alterados": 0,
        "tp": 0,
        "fp": 0,
        "neutros": 0,
        "bloqueos_esperados": 0,
        "bloqueos_ok": 0,
        "bloqueos_indebidos": 0,
        "bloqueos_omitidos": 0,
        "latencias": [],       # (mensajes en el historial, ms)
        "fallos": [],
    }


def registrar_fallo(res, id_turno, categoria, tipo, detalle, nota=""):
    res["fallos"].append(
        {"turno": id_turno, "categoria": categoria, "tipo": tipo, "detalle": detalle, "nota": nota}
    )


def simular(sanitizador, estado):
    res = resultado_vacio()

    for conv in CONVERSACIONES:
        print(f"\n{cian('>')} {negrita(conv['id'])} · {negrita(conv['titulo'])}")

        historial = []   # lo que el cliente reenvía en cada turno
        eliminado = {}   # (turno, valor) -> True si no salió en su turno de origen
        predichos = {}   # valor marcado por el proxy -> tipo de etiqueta
        errores_conv = 0

        for k, turno in enumerate(conv["turnos"]):
            id_turno = f"{conv['id']}-t{k + 1}"
            categoria = turno["categoria"]
            historial.append({"role": "user", "content": turno["usuario"]})
            mensajes_enviados = len(historial)
            if turno["bloqueo"]:
                res["bloqueos_esperados"] += 1

            espera_previa = estado["espera_s"]
            inicio = time.perf_counter()
            salida = enviar(sanitizador, historial, id_turno)
            ms = ((time.perf_counter() - inicio) - (estado["espera_s"] - espera_previa)) * 1000
            res["latencias"].append((mensajes_enviados, ms))

            for etiqueta, valor in salida["tag_to_value"].items():
                predichos[valor] = etiqueta.strip("[]").rsplit("_", 1)[0]

            errores = 0
            bloqueado = salida["action"] == "BLOCK"
            filtrados, alterados, fugas = [], [], 0

            if bloqueado:
                historial.pop()  # el cliente recibe el 403 y descarta ese mensaje
                if turno["bloqueo"]:
                    res["bloqueos_ok"] += 1
                else:
                    res["bloqueos_indebidos"] += 1
                    errores += 1
                    registrar_fallo(res, id_turno, categoria, "BLOQUEO INDEBIDO",
                                    "el prompt no debía bloquearse", turno["nota"])
            else:
                saliente = "\n".join(
                    str(m.get("content", "")) for m in salida["sanitized_payload"]["messages"]
                )

                for valor, tipo in turno["sensibles"]:
                    cuenta = res["por_tipo"].setdefault(tipo, [0, 0])
                    cuenta[0] += 1
                    if valor in saliente:
                        filtrados.append(valor)
                        registrar_fallo(res, id_turno, categoria, "DATO FILTRADO",
                                        f'"{valor}" ({tipo})', turno["nota"])
                    else:
                        cuenta[1] += 1
                        eliminado[(k, valor)] = True
                errores += len(filtrados)

                for j in range(k):
                    for valor, tipo in conv["turnos"][j]["sensibles"]:
                        if eliminado.get((j, valor)):
                            res["hist_exposiciones"] += 1
                            if valor in saliente:
                                res["hist_fugas"] += 1
                                fugas += 1
                                registrar_fallo(res, id_turno, categoria, "FUGA POR HISTORIAL",
                                                f'"{valor}" ({tipo}) del turno {j + 1} reapareció')
                errores += fugas

                # 3. Texto no sensible que debía quedar intacto
                alterados = [c for c in turno["conservar"] if c not in saliente]
                res["conservar_total"] += len(turno["conservar"])
                res["conservar_alterados"] += len(alterados)
                for c in alterados:
                    registrar_fallo(res, id_turno, categoria, "TEXTO NO SENSIBLE ALTERADO",
                                    f'"{c}"', turno["nota"])
                errores += len(alterados)

                if turno["bloqueo"]:
                    res["bloqueos_omitidos"] += 1
                    errores += 1
                    registrar_fallo(res, id_turno, categoria, "BLOQUEO OMITIDO",
                                    "el prompt debía bloquearse y se reenvió", turno["nota"])

                ultimo = salida["sanitized_payload"]["messages"][-1]["content"]
                respuesta = rehidratar(PLANTILLA_MOCK.format(texto=ultimo), salida["tag_to_value"])
                historial.append({"role": "assistant", "content": respuesta})

            cuenta_cat = res["por_categoria"].setdefault(categoria, [0, 0])
            cuenta_cat[0] += 1
            if errores == 0:
                cuenta_cat[1] += 1

            if bloqueado:
                if turno["bloqueo"]:
                    texto = amarillo("BLOQUEADO con HTTP 403 (esperado)")
                else:
                    texto = rojo("BLOQUEADO con HTTP 403 (INDEBIDO)")
            else:
                partes = []
                if turno["sensibles"]:
                    eliminados = len(turno["sensibles"]) - len(filtrados)
                    partes.append(f"{eliminados}/{len(turno['sensibles'])} sensibles eliminados")
                if k > 0:
                    partes.append(f"fugas por historial: {fugas}")
                if turno["conservar"]:
                    partes.append(f"texto técnico alterado: {len(alterados)}")
                texto = " · ".join(partes) if partes else tenue("sin datos sensibles")
            marca = verde("[OK]") if errores == 0 else rojo("[ERROR]")
            categoria_color = color_categoria(categoria)
            print(
                f"  {marca} {negrita(f't{k + 1}')} "
                f"{categoria_color(f'[{categoria:<8}]')} {texto} "
                f"{tenue(f'· {mensajes_enviados} msgs · {ms:.0f} ms')}"
            )
            if errores:
                print(f"      {rojo(f'-> {errores} error(es)')}")
            if not bloqueado:
                for m in salida["sanitized_payload"]["messages"]:
                    contenido = m.get("content")
                    if isinstance(contenido, list):
                        contenido = " ".join(
                            p.get("text", "") for p in contenido
                            if isinstance(p, dict)
                        )
                    print(
                        f"        {rol_coloreado(m.get('role', '?'))} → "
                        f"{resaltar_etiquetas(truncar(contenido))}"
                    )
            errores_conv += errores

        if errores_conv == 0:
            resumen_conv = verde(f"{len(conv['turnos'])} turnos · sin errores")
        else:
            resumen_conv = rojo(f"{len(conv['turnos'])} turnos · {errores_conv} error(es)")
        print(f"  {tenue('+--')} {resumen_conv}")

        verdad = [v for t in conv["turnos"] for v, _ in t["sensibles"]]
        neutros = [n for t in conv["turnos"] for n in t["neutros"]]
        for valor, tipo in predichos.items():
            if coincide(valor, verdad):
                res["tp"] += 1
            elif coincide(valor, neutros):
                res["neutros"] += 1
            else:
                res["fp"] += 1
                registrar_fallo(res, conv["id"], "-", "ENTIDAD MARCADA DE MÁS",
                                f'"{valor}" etiquetado como {tipo}')
    return res


# Métricas y auditoría

def resumir(valores):
    if not valores:
        return {"n": 0, "mediana": 0.0, "media": 0.0, "p95": 0.0}
    orden = sorted(valores)
    return {
        "n": len(orden),
        "mediana": statistics.median(orden),
        "media": statistics.mean(orden),
        "p95": orden[int(0.95 * (len(orden) - 1))],
    }


def resumir_resultado(res):
    por_largo = {}
    for largo, ms in res["latencias"]:
        por_largo.setdefault(largo, []).append(ms)
    return {
        "sensibles": sum(t for t, _ in res["por_tipo"].values()),
        "eliminados": sum(e for _, e in res["por_tipo"].values()),
        "hist_exposiciones": res["hist_exposiciones"],
        "hist_fugas": res["hist_fugas"],
        "tp": res["tp"],
        "fp": res["fp"],
        "neutros": res["neutros"],
        "conservar_total": res["conservar_total"],
        "conservar_alterados": res["conservar_alterados"],
        "bloqueos_esperados": res["bloqueos_esperados"],
        "bloqueos_ok": res["bloqueos_ok"],
        "bloqueos_indebidos": res["bloqueos_indebidos"],
        "bloqueos_omitidos": res["bloqueos_omitidos"],
        "latencia": resumir([ms for _, ms in res["latencias"]]),
        "por_tipo": {t: {"total": c[0], "eliminados": c[1]} for t, c in sorted(res["por_tipo"].items())},
        "por_categoria": {c: {"prompts": v[0], "sin_errores": v[1]} for c, v in res["por_categoria"].items()},
        "por_largo_historial": {
            largo: {"muestras": len(v), "mediana": statistics.median(v)}
            for largo, v in sorted(por_largo.items())
        },
        "fallos": res["fallos"],
    }


def auditar_log():
    """Verifica que el log de auditoría del benchmark no contenga ningún dato sensible del dataset."""
    if not os.path.exists(RUTA_LOG_AUDITORIA):
        return None
    with open(RUTA_LOG_AUDITORIA, encoding="utf-8") as f:
        contenido = f.read()
    valores = {v for c in CONVERSACIONES for t in c["turnos"] for v, _ in t["sensibles"]}
    return {
        "eventos": contenido.count("\n"),
        "filtrados": sorted(v for v in valores if v in contenido),
    }


# Informe

def pct(parte, total):
    return f"{100 * parte / total:.1f}% ({parte}/{total})" if total else "n/a"


def armar_informe(config, a, auditoria):
    L = ["# Resultados del benchmark del proxy DLP", ""]
    L.append(f"- Fecha: {config['fecha']}")
    L.append(f"- Dataset: {config['conversaciones']} conversaciones, {config['prompts']} prompts "
             f"({config['distribucion']})")
    L.append(f"- Filtro 2 (analizador contextual): {config['filtro2']}")

    lat = a["latencia"]
    L += ["", "## Resumen", "", "| Métrica | Resultado |", "| :--- | :--- |"]
    L.append(f"| Recall: datos sensibles que no llegan a la IA externa | {pct(a['eliminados'], a['sensibles'])} |")
    L.append(f"| Fugas por historial: datos ya eliminados que reaparecen en turnos siguientes | "
             f"{a['hist_fugas']} de {a['hist_exposiciones']} exposiciones |")
    L.append(f"| Precisión: entidades marcadas que eran realmente sensibles | {pct(a['tp'], a['tp'] + a['fp'])} |")
    L.append(f"| Tasa de falsos positivos: texto no sensible alterado | "
             f"{pct(a['conservar_alterados'], a['conservar_total'])} |")
    L.append(f"| Bloqueos 403 correctos | {a['bloqueos_ok']} de {a['bloqueos_esperados']} |")
    L.append(f"| Bloqueos indebidos (falsos bloqueos) | {a['bloqueos_indebidos']} |")
    L.append(f"| Latencia de sanitización por petición (mediana / p95) | "
             f"{lat['mediana']:.0f} ms / {lat['p95']:.0f} ms |")
    L.append(f"| Fallos del analizador contextual | {config['fallos_analizador']} "
             f"(reintentos: {config['reintentos']}) |")
    if auditoria:
        L.append(f"| Log de auditoría sin datos sensibles | {auditoria['eventos']} eventos revisados, "
                 f"{len(auditoria['filtrados'])} valores sensibles encontrados |")

    L += ["", "## Resultados por categoría de prompt", "",
          "| Categoría | Prompts | Sin errores |", "| :--- | ---: | ---: |"]
    for cat in CATEGORIAS:
        cuenta = a["por_categoria"].get(cat, {"prompts": 0, "sin_errores": 0})
        L.append(f"| {cat} | {cuenta['prompts']} | {cuenta['sin_errores']} |")

    L += ["", "## Recall por tipo de dato", "",
          "| Tipo | Sensibles | Eliminados | Recall |", "| :--- | ---: | ---: | ---: |"]
    for tipo, c in a["por_tipo"].items():
        L.append(f"| {tipo} | {c['total']} | {c['eliminados']} | {pct(c['eliminados'], c['total'])} |")

    L += ["", "## Latencia según el largo del historial", "",
          "| Mensajes en el historial | Peticiones | Mediana (ms) |", "| ---: | ---: | ---: |"]
    for largo, c in a["por_largo_historial"].items():
        L.append(f"| {largo} | {c['muestras']} | {c['mediana']:.0f} |")

    L += ["", "## Casos que fallaron", ""]
    if not a["fallos"]:
        L.append("Ninguno.")
    for f in a["fallos"]:
        causa = f" — posible causa: {f['nota']}" if f["nota"] else ""
        L.append(f"- **{f['turno']}** ({f['categoria']}) · {f['tipo']} · {f['detalle']}{causa}")

    L += ["", "> El dataset es chico y sus datos son inventados. Con un backend LLM "
              "(Groq/Ollama) los resultados pueden variar entre corridas; Presidio y "
              "las reglas del Filtro 1 son deterministas."]
    return L



def main():
    parser = argparse.ArgumentParser(description="Benchmark del proxy DLP")
    parser.add_argument("--intervalo-ia", type=float, default=2.0,
                        help="segundos mínimos entre llamadas al analizador Groq (default: 2.0)")
    parser.add_argument(
        "--backend",
        choices=["groq", "ollama", "presidio", "auto", "none"],
        default=None,
        help="Backend del Filtro 2 (default: ANALYZER_BACKEND del .env o groq)",
    )
    parser.add_argument("--no-color", action="store_true", help="desactiva los colores")
    parser.add_argument("--color", action="store_true",
                        help="fuerza colores aunque la salida no sea una terminal")
    args = parser.parse_args()

    if args.no_color or os.environ.get("NO_COLOR") is not None:
        _Color.activo = False
    elif args.color:
        _Color.activo = True
    else:
        _Color.activo = sys.stdout.isatty()

    inicio_total = time.perf_counter()
    cargar_env(os.path.join(CARPETA, ".env"))

    audit_logger.LOG_FILE = RUTA_LOG_AUDITORIA
    if os.path.exists(RUTA_LOG_AUDITORIA):
        os.remove(RUTA_LOG_AUDITORIA)

    sanitizador = HybridSanitizer(backend=args.backend)
    estado = {"espera_s": 0.0, "reintentos": 0, "fallos_analizador": 0}
    proteger_analizador(sanitizador, args.intervalo_ia, estado)
    ia_activa = sanitizador.analyzer.active

    conteo = {}
    for c in CONVERSACIONES:
        for t in c["turnos"]:
            conteo[t["categoria"]] = conteo.get(t["categoria"], 0) + 1
    config = {
        "fecha": datetime.now().strftime("%Y-%m-%d %H:%M"),
        "conversaciones": len(CONVERSACIONES),
        "prompts": sum(conteo.values()),
        "distribucion": ", ".join(f"{conteo.get(cat, 0)} {cat}" for cat in CATEGORIAS),
        "filtro2": f"activo · {sanitizador.backend_label()}" if ia_activa
        else "inactivo (solo reglas del Filtro 1; los nombres, organizaciones y direcciones no se detectan)",
    }

    banner(config)
    if sanitizador.backend_name == "groq" and ia_activa:
        print(amarillo("  [AVISO] Las llamadas a Groq se espacian para respetar su límite de uso: "
                       "la corrida puede tardar unos minutos."))
    elif sanitizador.backend_name in ("ollama", "presidio") and ia_activa:
        print(verde(f"  [MODO LOCAL] Filtro 2 offline: {sanitizador.backend_label()}"))
    print(tenue("  Cada turno muestra el detalle de lo que recibe la IA externa."))

    seccion("SIMULACIÓN DE CONVERSACIONES", cian)
    actual = simular(sanitizador, estado)

    config["fallos_analizador"] = estado["fallos_analizador"]
    config["reintentos"] = estado["reintentos"]
    resumen_actual = resumir_resultado(actual)
    auditoria = auditar_log()
    informe = armar_informe(config, resumen_actual, auditoria)

    resumen_terminal(resumen_actual, auditoria)
    imprimir_fallos(resumen_actual)

    seccion("INFORME COMPLETO", cian)
    imprimir_informe(informe)

    if os.path.exists(RUTA_LOG_AUDITORIA):
        os.remove(RUTA_LOG_AUDITORIA)

    print()
    print(verde("[OK] Benchmark completado."))
    print(tenue(f"  Tiempo total: {time.perf_counter() - inicio_total:.1f} s"))


if __name__ == "__main__":
    main()
