"""Etapa 1 · Detección. Cruza las dependencias con los avisos.

Reusa lo que ya existe: en producción esto consulta OSV.dev (y GHSA/KEV/EPSS). En
el esqueleto trabaja offline contra avisos locales estilo OSV (fixtures/advisories),
para que la demo sea reproducible. La ruta online queda documentada abajo.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path

from .hallazgo import Hallazgo


def _parse_version(v: str) -> tuple:
    return tuple(int(x) for x in re.findall(r"\d+", v)[:3]) or (0,)


def _afectado(version: str, afectado: dict) -> bool:
    """¿La versión instalada cae en el rango afectado (introduced..fixed)?"""
    v = _parse_version(version)
    for rango in afectado.get("ranges", []):
        introduced = (0,)
        fixed = None
        for ev in rango.get("events", []):
            if "introduced" in ev:
                introduced = _parse_version(ev["introduced"])
            if "fixed" in ev:
                fixed = _parse_version(ev["fixed"])
        if v >= introduced and (fixed is None or v < fixed):
            return True
    return False


def leer_manifiesto(ruta: str) -> dict[str, str]:
    """requirements.txt -> {paquete: version}. Ignora comentarios y vacíos."""
    deps = {}
    for linea in Path(ruta).read_text(encoding="utf-8").splitlines():
        linea = linea.split("#", 1)[0].strip()
        if not linea:
            continue
        m = re.match(r"([A-Za-z0-9_.\-]+)\s*==\s*([0-9A-Za-z.\-]+)", linea)
        if m:
            deps[m.group(1).lower()] = m.group(2)
    return deps


def cargar_avisos(dir_avisos: str) -> list[dict]:
    avisos = []
    for f in sorted(Path(dir_avisos).glob("*.json")):
        avisos.append(json.loads(f.read_text(encoding="utf-8")))
    return avisos


def detectar(manifiesto: str, dir_avisos: str) -> list[Hallazgo]:
    """Devuelve un Hallazgo por cada dependencia afectada por un aviso."""
    deps = leer_manifiesto(manifiesto)
    avisos = cargar_avisos(dir_avisos)
    hallazgos: list[Hallazgo] = []
    for aviso in avisos:
        for afectado in aviso.get("affected", []):
            nombre = afectado.get("package", {}).get("name", "").lower()
            if nombre in deps and _afectado(deps[nombre], afectado):
                hallazgos.append(Hallazgo(
                    advisory_id=aviso["id"],
                    paquete=nombre,
                    version=deps[nombre],
                    commit_fix=aviso.get("commit_fix"),
                    resumen=aviso.get("summary", ""),
                    nivel=0,  # peldaño 0: dependencia presente
                    evidencia=[f"{nombre}=={deps[nombre]} cae en el rango afectado de {aviso['id']}"],
                    epss=aviso.get("epss"),
                    kev=bool(aviso.get("kev", False)),
                ))
    return hallazgos


# --- Ruta online (documentada, desactivada por defecto) -----------------------
def detectar_osv_online(manifiesto: str) -> list[dict]:
    """Esqueleto de la consulta real a OSV.dev (querybatch). Requiere red.

    POST https://api.osv.dev/v1/querybatch con {"queries":[{"package":{"name","ecosystem"},
    "version"}...]}. Se deja como referencia; el detector offline es el que usa la demo.
    """
    raise NotImplementedError("Ruta online: implementar contra api.osv.dev cuando haya red.")
