"""logfmt 2.1.0 — formato de líneas de log. FICTICIO y vulnerable (inyección de formato).

Vulnerabilidad sembrada (VC-2026-0006): render_line() pasa la plantilla a
str.format con el contexto completo, así que una plantilla del atacante puede
leer atributos internos. En el repo víctima solo se llama con una constante,
así que la escalera debe quedarse en nivel 2 (preparar). Fixture.
"""
__version__ = "2.1.0"


def render_line(plantilla: str, **contexto) -> str:
    """Formatea una línea de log.  <-- función vulnerable (format sin restringir)."""
    return plantilla.format(**contexto)
