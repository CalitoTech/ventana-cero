"""Etapas 2-3 · Alcanzabilidad. Sube el Hallazgo por la escalera de confianza.

A) derivar_simbolo: del diff del fix saca el símbolo vulnerable y el parámetro
   peligroso (LLM si hay clave; heurística sobre el diff; ground_truth como último
   recurso).
B) analizar: con AST busca el símbolo en el repo víctima y hace taint
   intra-procedural con punto fijo y detección de sanitizadores.

Honestidad: el taint es intra-procedural y heurístico. "No alcanzable" significa
despriorizar, no "seguro". La certeza la da el PoC (etapa sandbox), no esto.
"""
from __future__ import annotations

import ast
import json
import re
from pathlib import Path

from . import llm
from .hallazgo import Hallazgo

# identificadores que consideramos "fuente de entrada no confiable"
FUENTES = {"params", "query", "args", "form", "body", "request", "payload",
           "parse_qs", "GET", "POST", "tpl", "name", "data", "input", "cmd"}

# si el valor pasa por una de estas llamadas, lo consideramos saneado
SANITIZADORES = {"replace", "escape", "quote", "sanitize", "sanitizar", "clean",
                 "limpiar", "validate", "validar", "int", "float", "sub",
                 "secure_filename", "normpath", "basename", "strip"}


# ---------- A) derivar símbolo del diff del fix -------------------------------
def _heuristica_simbolo(fix_diff: str) -> tuple[str | None, str | None]:
    for linea in fix_diff.splitlines():
        cuerpo = linea[1:] if linea[:1] in "+- " else linea
        m = re.match(r"\s*def\s+([A-Za-z_]\w*)\s*\(([^)]*)\)", cuerpo)
        if m:
            nombre = m.group(1)
            args = [a.strip().split(":")[0].strip() for a in m.group(2).split(",") if a.strip()]
            args = [a for a in args if a not in ("self", "cls") and not a.startswith("*")]
            return nombre, (args[0] if args else None)
    return None, None


def derivar_simbolo(h: Hallazgo, aviso: dict) -> Hallazgo:
    fix_diff = aviso.get("fix_diff", "")
    func = param = None
    fuente = None

    if llm.disponible() and fix_diff:
        prompt = (
            "Dado este diff que corrige una vulnerabilidad, responde SOLO un JSON "
            '{"funcion": "...", "parametro": "..."} con el nombre de la función '
            "vulnerable y el parámetro por el que entra el dato peligroso.\n\n" + fix_diff
        )
        resp = llm.completar(prompt)
        if resp:
            try:
                j = json.loads(re.search(r"\{.*\}", resp, re.S).group(0))
                func, param = j.get("funcion"), j.get("parametro")
                fuente = "propuesto por el LLM" if func else None
            except Exception:
                func = param = None

    if not func and fix_diff:
        func, param = _heuristica_simbolo(fix_diff)
        fuente = "heurística sobre el diff" if func else None

    if not func:
        gt = aviso.get("ground_truth_symbol", "")
        func = gt.split(".")[-1] if gt else None
        param = param or aviso.get("ground_truth_param")
        fuente = "ground truth del aviso"

    if func:
        h.simbolo_vulnerable = f"{h.paquete}.{func}"
        h.parametro_peligroso = param
        h.evidencia.append(f"símbolo vulnerable derivado: {h.simbolo_vulnerable} (param: {param}; {fuente})")
    return h


# ---------- B) análisis estático + taint sobre el repo víctima ----------------
def _nombres(node) -> set[str]:
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}


def _menciona_fuente(node) -> bool:
    for s in ast.walk(node):
        if isinstance(s, ast.Name) and s.id in FUENTES:
            return True
        if isinstance(s, ast.Attribute) and s.attr in FUENTES:
            return True
    return False


def _es_sanitizador(value) -> bool:
    for s in ast.walk(value):
        if isinstance(s, ast.Call):
            f = s.func
            nombre = f.attr if isinstance(f, ast.Attribute) else (f.id if isinstance(f, ast.Name) else "")
            if nombre in SANITIZADORES:
                return True
    return False


def _nombre_llamado(call) -> str | None:
    f = call.func
    if isinstance(f, ast.Attribute):
        return f.attr
    if isinstance(f, ast.Name):
        return f.id
    return None


class _Taint(ast.NodeVisitor):
    """Taint intra-procedural con punto fijo y detección de sanitizadores."""

    def __init__(self, func_vuln: str):
        self.func_vuln = func_vuln
        self.llamado = False
        self.taint = False
        self.caminos: list[list[str]] = []

    def visit_FunctionDef(self, node):
        tainted: dict[str, str] = {}
        asignaciones = [s for s in ast.walk(node) if isinstance(s, ast.Assign)]
        # punto fijo: propaga taint a través de asignaciones encadenadas
        cambio = True
        while cambio:
            cambio = False
            for a in asignaciones:
                if _es_sanitizador(a.value):
                    continue  # el dato se limpia aquí
                if _menciona_fuente(a.value) or (_nombres(a.value) & set(tainted)):
                    for t in a.targets:
                        if isinstance(t, ast.Name) and t.id not in tainted:
                            tainted[t.id] = ast.unparse(a.value)
                            cambio = True
        # llamadas al símbolo vulnerable
        for call in [n for n in ast.walk(node) if isinstance(n, ast.Call)]:
            if _nombre_llamado(call) != self.func_vuln:
                continue
            self.llamado = True
            for arg in call.args:
                nn = _nombres(arg)
                if _menciona_fuente(arg) or (nn & set(tainted)):
                    self.taint = True
                    var = next(iter(nn & set(tainted)), None)
                    origen = tainted.get(var, "entrada no confiable") if var else "entrada no confiable"
                    self.caminos.append([
                        f"fuente: {origen}",
                        f"var: {var}" if var else "arg directo",
                        f"sink: {self.func_vuln}(...) en {node.name}()",
                    ])
        self.generic_visit(node)


def analizar(h: Hallazgo, dir_repo: str) -> Hallazgo:
    if not h.simbolo_vulnerable:
        return h
    func_vuln = h.simbolo_vulnerable.split(".")[-1]
    ref = llamado = taint = False
    caminos: list[list[str]] = []
    for py in Path(dir_repo).rglob("*.py"):
        if "vendor" in py.parts:   # no analizamos la propia librería vulnerable
            continue
        try:
            arbol = ast.parse(py.read_text(encoding="utf-8"))
        except Exception:
            continue
        for nodo in ast.walk(arbol):   # referencia por AST (Name o Attribute)
            if isinstance(nodo, ast.Attribute) and nodo.attr == func_vuln:
                ref = True
            elif isinstance(nodo, ast.Name) and nodo.id == func_vuln:
                ref = True
        v = _Taint(func_vuln)
        v.visit(arbol)
        llamado = llamado or v.llamado
        taint = taint or v.taint
        caminos.extend(v.caminos)

    if taint:
        h.nivel = 3
        h.camino_taint = caminos[0] if caminos else []
        h.evidencia.append("taint: una entrada no confiable alcanza el parámetro peligroso")
    elif llamado:
        h.nivel = 2
        h.evidencia.append("el símbolo se llama, pero con datos constantes (sin taint)")
    elif ref:
        h.nivel = 1
        h.evidencia.append("el símbolo aparece referenciado, sin llamada alcanzable")
    else:
        h.nivel = 0
        h.evidencia.append("el símbolo no aparece en el código propio")
    return h
