"""tinytpl 1.0.0 — motor de plantillas mínimo. FICTICIO y DELIBERADAMENTE vulnerable.

Vulnerabilidad sembrada (VC-2026-0001): render() evalúa las expresiones {{ ... }}
de la plantilla con eval(). Si la plantilla viene de una entrada no confiable,
eso es ejecución de código.

Nota de seguridad: restringimos __builtins__ a vacío para que el fixture NO pueda
causar daño real; aun así demuestra la evaluación de código del atacante (el
canario {{7*6}} -> 42). En una librería real el daño sería total; por eso el
sandbox de producción corre en un contenedor aislado, no en subproceso.

NO es una librería real. Existe solo para la demo de Ventana Cero.
"""
import re

__version__ = "1.0.0"

_EXPR = re.compile(r"\{\{(.+?)\}\}")


def render(plantilla: str, **contexto) -> str:
    """Renderiza la plantilla evaluando cada {{ expr }}.  <-- función vulnerable."""
    def _sub(m):
        expr = m.group(1).strip()
        return str(eval(expr, {"__builtins__": {}}, contexto))  # noqa: S307 (sembrado)
    return _EXPR.sub(_sub, plantilla)
