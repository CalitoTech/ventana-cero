"""Contrato de datos compartido. Ver docs/contrato.md.

Un `Hallazgo` fluye por todo el lazo; cada etapa lee unos campos y escribe otros.
Mantener este contrato estable es lo que permite trabajar en paralelo.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any

# Nombres legibles de cada peldaño de la escalera de confianza.
NIVELES = {
    0: "dependencia presente",
    1: "símbolo referenciado",
    2: "alcanzable en el grafo",
    3: "con taint (fuente → sink)",
    4: "PoC confirmado",
}


@dataclass
class Hallazgo:
    # 1 · detección (OSV / avisos locales)
    advisory_id: str
    paquete: str
    version: str
    commit_fix: str | None = None
    resumen: str = ""

    # 2 · derivar símbolo (LLM sobre el diff del fix, con fallback heurístico)
    simbolo_vulnerable: str | None = None      # p.ej. "tinytpl.render"
    parametro_peligroso: str | None = None     # p.ej. "plantilla"

    # 3 · alcanzabilidad
    nivel: int = 0                             # 0..4
    camino_taint: list[str] = field(default_factory=list)  # fuente → ... → sink
    evidencia: list[str] = field(default_factory=list)     # notas legibles

    # 4 · prueba
    poc: dict | None = None
    resultado_poc: str | None = None           # "disparo" | "no_disparo" | None

    # 5 · mitigación
    parche_virtual: dict | None = None
    parche_virtual_verificado: bool = False
    pr_parche_codigo: str | None = None        # ruta/url del parche

    # priorización (de la detección: EPSS + CISA KEV)
    epss: float | None = None                  # probabilidad de explotación (0..1)
    kev: bool = False                          # ¿explotada activamente (CISA KEV)?
    prioridad: str = "baja"                    # baja|media|alta|crítica

    # 6 · decisión (motor de política)
    decision: str = "ignorar"                  # ignorar|vigilar|revisar|preparar|mitigar|actuar

    def nivel_texto(self) -> str:
        return NIVELES.get(self.nivel, str(self.nivel))

    def dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["nivel_texto"] = self.nivel_texto()
        return d
