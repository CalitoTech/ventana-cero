"""zipkit 0.4.0 — lectura de documentos empaquetados. FICTICIO y vulnerable (path traversal).

Vulnerabilidad sembrada (VC-2026-0007): open_member() une el nombre al directorio
de documentos sin normalizar. En el repo víctima la entrada pasa antes por
os.path.basename, así que el taint se corta y la escalera queda en nivel 2. Fixture.
"""
import os

__version__ = "0.4.0"
_BASE = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "public", "docs")


def open_member(nombre: str) -> str:
    """Lee un documento.  <-- función vulnerable (sin normalizar)."""
    try:
        with open(os.path.join(_BASE, nombre), encoding="utf-8") as f:
            return f.read()
    except OSError:
        return ""
