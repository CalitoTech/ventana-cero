"""Motor de política: mapea la escalera de confianza a una decisión.

Regla central: nada que toque producción se aplica solo por debajo del nivel 4
(hay prueba), salvo que la mitigación sea reversible y de bajo riesgo. El parche
virtual (una regla que se puede quitar) califica como reversible; el parche de
código (un merge) siempre requiere un humano.
"""
from __future__ import annotations

from .hallazgo import Hallazgo

# nivel de la escalera -> decisión
_MAPA = {
    0: "ignorar",
    1: "vigilar",
    2: "preparar",
    3: "mitigar",
    4: "actuar",
}


def decidir(h: Hallazgo) -> str:
    h.decision = _MAPA.get(h.nivel, "ignorar")
    return h.decision


def puede_auto_mitigar(h: Hallazgo) -> bool:
    """¿Se puede aplicar el parche virtual sin humano?

    Sí, solo con PoC confirmado (nivel 4): hay prueba y el parche es reversible.
    """
    return h.nivel >= 4


def requiere_humano(h: Hallazgo) -> bool:
    """El parche de código (merge) siempre pasa por revisión humana."""
    return True
