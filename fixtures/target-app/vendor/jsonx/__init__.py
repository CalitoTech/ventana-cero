"""jsonx 1.2.0 — wrapper de JSON. FICTICIO.

El aviso VC-2026-0004 afirma que loads() evalúa claves mágicas (deserialización
insegura). PERO esta versión instalada NO lo hace: delega en json estándar. Sirve
para demostrar que el PoC manda: el taint estático llega al sink, pero como el PoC
no se dispara, NO auto-actuamos; queda para revisión humana.
"""
import json

__version__ = "1.2.0"


def loads(data: str):
    """Deserializa JSON de forma segura (sin eval)."""
    return json.loads(data)
