"""Backend de la demo interactiva del panel.

Mantiene una app víctima REAL corriendo y deja que el panel, con botones:
  1. lance un ataque real y vea la brecha (roba un archivo secreto del servidor),
  2. active Ventana Cero (corre el lazo real y aplica el parche virtual),
  3. repita el mismo ataque y lo vea bloqueado, con el tráfico legítimo intacto.

Todo contra un servidor real en 127.0.0.1. No es un mock: cada botón es una
petición HTTP de verdad a una app que de verdad lee (o deja de leer) el archivo.

Caso estrella: path traversal (CWE-22) en safefs.read — el más fácil de entender
para cualquiera ("el atacante se robó un archivo que no debía ver").
"""
from __future__ import annotations

import threading
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import quote

from . import orchestrator
from .demo import _levantar, _bajar, _resolver_puerto

DIR_REPO = "fixtures/target-app"
AVISO = "VC-2026-0003"                        # safefs path traversal (CWE-22)
ATAQUE = ("/file", "name", "../secret.txt")   # roba un archivo fuera del dir público
LEGITIMO = ("/file", "name", "index.txt")     # un usuario normal pide la página pública
PUERTO_PREFERIDO = 8010

_lock = threading.Lock()
_S = {"proc": None, "puerto": None, "protegido": False}


def _pedir(puerto: int, peticion: tuple[str, str, str]) -> dict:
    ruta, param, valor = peticion
    url = f"http://127.0.0.1:{puerto}{ruta}?{param}={quote(valor)}"
    try:
        with urllib.request.urlopen(url, timeout=3) as r:
            codigo, cuerpo = r.status, r.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        codigo, cuerpo = e.code, e.read().decode(errors="replace")
    except Exception as e:  # noqa: BLE001
        codigo, cuerpo = 0, f"(sin respuesta: {e})"
    return {"codigo": codigo, "cuerpo": cuerpo[:300],
            "curl": f'curl "http://127.0.0.1:{puerto}{ruta}?{param}={valor}"',
            "ruta": ruta, "param": param, "valor": valor}


def _bajar_app() -> None:
    if _S["proc"]:
        _bajar(_S["proc"])
        _S["proc"] = None


def _asegurar(protegido: bool) -> int:
    """(Re)levanta la app víctima en el estado pedido (con o sin parche virtual)."""
    if _S["proc"] and _S["protegido"] == protegido:
        return _S["puerto"]
    _bajar_app()
    puerto = _resolver_puerto(_S["puerto"] or PUERTO_PREFERIDO, lambda m: None)
    guard = str(Path("out") / f"guard-{AVISO}.json") if protegido else None
    _S["proc"] = _levantar(puerto, guard=guard)
    _S["puerto"] = puerto
    _S["protegido"] = protegido
    return puerto


def estado() -> dict:
    return {
        "protegido": _S["protegido"],
        "activa": _S["proc"] is not None,
        "aviso": AVISO,
        "ataque": {"ruta": ATAQUE[0], "param": ATAQUE[1], "valor": ATAQUE[2]},
        "legitimo": {"ruta": LEGITIMO[0], "param": LEGITIMO[1], "valor": LEGITIMO[2]},
    }


def atacar() -> dict:
    """Dispara el ataque real y una petición legítima; devuelve ambas respuestas."""
    with _lock:
        puerto = _asegurar(_S["protegido"])
        ataque = _pedir(puerto, ATAQUE)
        legitimo = _pedir(puerto, LEGITIMO)
        robado = "VC_SECRETO" in ataque["cuerpo"]
        return {"protegido": _S["protegido"], "ataque": ataque,
                "legitimo": legitimo, "robado": robado}


def proteger() -> dict:
    """Corre el lazo real sobre el caso estrella y relevanta la app con el parche."""
    with _lock:
        rep = orchestrator.correr(f"{DIR_REPO}/requirements.txt", "fixtures/advisories",
                                  DIR_REPO, "out", dir_ui="ui/public", solo=AVISO)
        h = next((i for i in rep["hallazgos"] if i["advisory_id"] == AVISO), None)
        _asegurar(True)
        return {"protegido": True, "hallazgo": h}


def reset() -> dict:
    with _lock:
        _asegurar(False)
        return estado()


def apagar() -> None:
    with _lock:
        _bajar_app()
