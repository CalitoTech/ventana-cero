"""Contrato de datos compartido. Ver docs/contrato.md."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Hallazgo:
    # 1 · detección (OSV)
    advisory_id: str
    paquete: str
    version: str
    commit_fix: str | None = None

    # 2 · derivar símbolo (LLM sobre el diff del fix)
    simbolo_vulnerable: str | None = None
    parametro_peligroso: str | None = None

    # 3 · alcanzabilidad
    nivel: int = 0  # 0..4, la escalera de confianza
    camino_taint: list[str] = field(default_factory=list)

    # 4 · prueba
    poc: str | None = None
    resultado_poc: str | None = None  # "disparo" | "no_disparo" | None

    # 5 · mitigación
    parche_virtual: dict | None = None
    pr_parche_codigo: str | None = None

    # 6 · decisión (motor de política)
    decision: str = "ignorar"
