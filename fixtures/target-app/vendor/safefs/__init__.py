"""safefs 1.0.0 — lectura de archivos. FICTICIO y vulnerable (path traversal).

Vulnerabilidad sembrada (VC-2026-0003): read() concatena el nombre pedido al
directorio base sin normalizar, así que "../x" escapa del directorio. Fixture.
"""
import os

__version__ = "1.0.0"
_BASE = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "public")


def read(nombre: str) -> str:
    """Lee un archivo del directorio público.  <-- función vulnerable (sin normalizar)."""
    ruta = os.path.join(_BASE, nombre)   # vulnerable: permite "../"
    try:
        with open(ruta, encoding="utf-8") as f:
            return f.read()
    except OSError:
        return ""
