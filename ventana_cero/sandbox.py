"""Etapa de prueba · Sandbox. La certeza la da el PoC que se dispara, no el LLM.

Levanta la app víctima en un subproceso local y dispara un PoC HTTP. Si el PoC
confirma ejecución de código, el Hallazgo sube a nivel 4.

Aislamiento: en el esqueleto usamos un subproceso escuchando solo en 127.0.0.1.
En producción esto va en un CONTENEDOR AISLADO SIN SALIDA A RED (documentado en
docs/producto.md). El PoC corre solo contra el código propio.
"""
from __future__ import annotations

import os
import socket
import subprocess
import sys
import time
import urllib.request
import urllib.error
from contextlib import closing

from . import llm
from .hallazgo import Hallazgo

# PoC canónico por clase de vulnerabilidad. Para SSTI, el canario aritmético
# {{7*6}} -> "42" demuestra evaluación de la plantilla del atacante (benigno).
POCS_POR_CLASE = {
    "SSTI": {"metodo": "GET", "ruta": "/preview", "param": "tpl",
             "valor": "{{7*6}}", "espera_contiene": "42",
             "descr": "canario aritmético: si la plantilla se evalúa, responde 42"},
}


def _puerto_libre() -> int:
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _esperar(puerto: int, timeout: float = 5.0) -> bool:
    fin = time.time() + timeout
    while time.time() < fin:
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{puerto}/health", timeout=0.5)
            return True
        except Exception:
            time.sleep(0.1)
    return False


def proponer_poc(h: Hallazgo, clase: str | None) -> dict | None:
    """PoC canónico por clase; el LLM podría proponer uno a medida (ruta futura)."""
    if clase and clase in POCS_POR_CLASE:
        return dict(POCS_POR_CLASE[clase])
    # ruta LLM documentada; en el esqueleto, sin clase conocida no hay PoC
    return None


def ejecutar(h: Hallazgo, dir_repo: str, clase: str | None = "SSTI",
             guard: str | None = None) -> tuple[str, dict | None]:
    """Levanta la app (opcionalmente con parche virtual) y dispara el PoC.

    Devuelve ("disparo"|"no_disparo", poc). "disparo" = el PoC confirmó el fallo.
    """
    poc = proponer_poc(h, clase)
    if not poc:
        return "no_disparo", None

    puerto = _puerto_libre()
    env = dict(os.environ, VC_PORT=str(puerto))
    if guard:
        env["VC_GUARD"] = guard
    proc = subprocess.Popen(
        [sys.executable, os.path.join(dir_repo, "app.py")],
        env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        if not _esperar(puerto):
            return "no_disparo", poc
        from urllib.parse import quote
        url = f"http://127.0.0.1:{puerto}{poc['ruta']}?{poc['param']}={quote(poc['valor'])}"
        try:
            with urllib.request.urlopen(url, timeout=3) as r:
                cuerpo = r.read().decode(errors="replace")
                codigo = r.status
        except urllib.error.HTTPError as e:
            cuerpo, codigo = e.read().decode(errors="replace"), e.code
        except Exception:
            return "no_disparo", poc
        disparo = (codigo == 200) and (poc["espera_contiene"] in cuerpo)
        poc["respuesta_codigo"] = codigo
        poc["respuesta_muestra"] = cuerpo[:80]
        return ("disparo" if disparo else "no_disparo"), poc
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except Exception:
            proc.kill()
