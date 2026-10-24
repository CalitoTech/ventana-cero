"""Etapas 4-5 · Mitigación. Parche virtual instantáneo + parche de código.

Parche virtual: una regla reversible que la app víctima aplica en el borde
(bloquea el parámetro peligroso con un patrón). Es lo que gana la carrera: se
aplica en segundos y se puede quitar.

Parche de código: el diff que arregla la raíz, como artefacto para un PR. Siempre
requiere revisión humana (no se mergea solo).
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from .hallazgo import Hallazgo

# patrón de bloqueo por clase de vulnerabilidad
PATRON_POR_CLASE = {
    "SSTI": r"\{\{.*\}\}",
    "path-traversal": r"\.\.[\/]",
    "deserializacion": r"__(eval|reduce|class|import)__",
}


def generar_parche_virtual(h: Hallazgo, clase: str | None, ruta: str, param: str) -> dict:
    patron = PATRON_POR_CLASE.get(clase or "", r"\{\{.*\}\}")
    return {
        "id": f"vp-{h.advisory_id.lower()}",
        "tipo": "regla_borde",
        "ruta": ruta,
        "param": param,
        "patron": patron,
        "descr": f"bloquea {param} que coincide con {patron} en {ruta}",
        "reversible": True,
    }


def escribir_reglas(parches: list[dict], destino: str) -> str:
    Path(destino).parent.mkdir(parents=True, exist_ok=True)
    Path(destino).write_text(
        json.dumps({"reglas": parches}, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    return destino


def generar_parche_codigo(h: Hallazgo, aviso: dict, destino: str) -> str | None:
    """Guarda el diff del fix como artefacto para un PR (no se aplica solo)."""
    diff = aviso.get("fix_diff")
    if not diff:
        return None
    Path(destino).parent.mkdir(parents=True, exist_ok=True)
    Path(destino).write_text(diff, encoding="utf-8")
    return destino
