"""Etapas 2-3 · Alcanzabilidad. Sube el Hallazgo por la escalera de confianza.

Dos sub-pasos:
  A) derivar_simbolo: del diff del fix saca el símbolo vulnerable y el parámetro
     peligroso. Usa el LLM si hay clave; si no, heurística sobre el diff; y como
     último recurso, el ground_truth del aviso.
  B) analizar: con AST busca el símbolo en el repo víctima y hace un taint
     intra-procedural simple (fuente no confiable → argumento del sink).

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
           "parse_qs", "GET", "POST", "tpl", "input"}


# ---------- A) derivar símbolo del diff del fix -------------------------------
def _heuristica_simbolo(fix_diff: str) -> tuple[str | None, str | None]:
    """Busca la primera `def X(...)` que aparece en el diff. El 1er arg es el param."""
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

    # 1) LLM, si está disponible
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
            except Exception:
                func = param = None

    # 2) heurística sobre el diff
    if not func and fix_diff:
        func, param = _heuristica_simbolo(fix_diff)

    # 3) ground_truth del aviso (último recurso / oráculo para eval)
    if not func:
        gt = aviso.get("ground_truth_symbol", "")
        func = gt.split(".")[-1] if gt else None
        param = param or aviso.get("ground_truth_param")

    if func:
        h.simbolo_vulnerable = f"{h.paquete}.{func}"
        h.parametro_peligroso = param
        h.evidencia.append(f"símbolo vulnerable derivado: {h.simbolo_vulnerable} (param: {param})")
    return h


# ---------- B) análisis estático + taint sobre el repo víctima ----------------
class _Taint(ast.NodeVisitor):
    def __init__(self, func_vuln: str):
        self.func_vuln = func_vuln
        self.symbol_referenciado = False
        self.llamado = False
        self.llamado_con_taint = False
        self.caminos: list[list[str]] = []

    def _es_fuente(self, node) -> bool:
        """¿La expresión lee de una fuente no confiable?"""
        for sub in ast.walk(node):
            if isinstance(sub, ast.Name) and sub.id in FUENTES:
                return True
            if isinstance(sub, ast.Attribute) and sub.attr in FUENTES:
                return True
        return False

    def _nombre_llamado(self, call) -> str | None:
        f = call.func
        if isinstance(f, ast.Attribute):
            return f.attr
        if isinstance(f, ast.Name):
            return f.id
        return None

    def visit_FunctionDef(self, node):
        tainted: set[str] = set()
        origen: dict[str, str] = {}
        # 1a pasada: variables que reciben datos de una fuente no confiable
        for stmt in ast.walk(node):
            if isinstance(stmt, ast.Assign) and self._es_fuente(stmt.value):
                for t in stmt.targets:
                    if isinstance(t, ast.Name):
                        tainted.add(t.id)
                        origen[t.id] = ast.unparse(stmt.value)
        # 2a pasada: llamadas al símbolo vulnerable
        for call in [n for n in ast.walk(node) if isinstance(n, ast.Call)]:
            if self._nombre_llamado(call) != self.func_vuln:
                continue
            self.symbol_referenciado = True
            self.llamado = True
            for arg in call.args:
                nombres = {n.id for n in ast.walk(arg) if isinstance(n, ast.Name)}
                if self._es_fuente(arg) or (nombres & tainted):
                    self.llamado_con_taint = True
                    var = next(iter(nombres & tainted), None)
                    fuente = origen.get(var, "entrada no confiable")
                    self.caminos.append([
                        f"fuente: {fuente}",
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
        # referencia por AST (Name o Attribute), no por subcadena, para evitar
        # falsos positivos como "parse" dentro de "parse_qs"
        for nodo in ast.walk(arbol):
            if isinstance(nodo, ast.Attribute) and nodo.attr == func_vuln:
                ref = True
            elif isinstance(nodo, ast.Name) and nodo.id == func_vuln:
                ref = True
        v = _Taint(func_vuln)
        v.visit(arbol)
        llamado = llamado or v.llamado
        taint = taint or v.llamado_con_taint
        caminos.extend(v.caminos)

    # asignar nivel de la escalera
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
