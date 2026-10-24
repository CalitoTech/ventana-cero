"""Etapa de prueba · Sandbox. La certeza la da el PoC que se dispara, no el LLM.

Levanta la app víctima en un subproceso local y dispara un PoC HTTP. Si el PoC
confirma ejecución de código, el Hallazgo sube a nivel 4.

Aislamiento: la app corre dentro de la jaula (ventana_cero/jaula.py): audit hooks
que bloquean red saliente, procesos hijos y archivos fuera del repo, más un
timeout duro (y límite de memoria en POSIX). Es aislamiento por política, no de
kernel; en producción va un CONTENEDOR SIN RED (docs/producto.md). Los intentos
bloqueados se devuelven en poc["bloqueos"] como evidencia.
"""
from __future__ import annotations

import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
import urllib.error
from contextlib import closing

from . import jaula, llm
from .hallazgo import Hallazgo

RAIZ_PAQUETE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TIMEOUT_S = float(os.environ.get("VC_SANDBOX_TIMEOUT", "15"))

# PoC canónico por clase de vulnerabilidad. Para SSTI, el canario aritmético
# {{7*6}} -> "42" demuestra evaluación de la plantilla del atacante (benigno).
POCS_POR_CLASE = {
    "SSTI": {"metodo": "GET", "ruta": "/preview", "param": "tpl",
             "valor": "{{7*6}}", "espera_contiene": "42",
             "descr": "canario aritmético: si la plantilla se evalúa, responde 42"},
    "path-traversal": {"metodo": "GET", "ruta": "/file", "param": "name",
                       "valor": "../secret.txt", "espera_contiene": "VC_SECRETO_1337",
                       "descr": "lee un archivo fuera del directorio público con ../"},
    "deserializacion": {"metodo": "GET", "ruta": "/parse", "param": "data",
                        "valor": '{"__eval__": "6*7"}', "espera_contiene": "42",
                        "descr": "clave mágica __eval__: solo se dispara si hay eval inseguro"},
    "deserializacion-yaml": {"metodo": "GET", "ruta": "/config", "param": "doc",
                             "valor": "!!python/object/apply:builtins.eval ['6*7']",
                             "espera_contiene": "42",
                             "descr": "etiqueta !!python/object/apply: si el loader la honra, responde 42"},
    "inyeccion-comando": {"metodo": "GET", "ruta": "/gpg", "param": "data",
                          "valor": ";echo 42", "espera_contiene": "42",
                          "descr": "comando encadenado ';echo 42': si la entrada llega al shell, responde 42"},
    "inyeccion-sql": {"metodo": "GET", "ruta": "/buscar", "param": "nombre",
                      "valor": "' UNION SELECT '42' -- ", "espera_contiene": "42",
                      "descr": "UNION SELECT '42': si la entrada llega cruda al SQL, responde 42"},
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
    env["PYTHONPATH"] = RAIZ_PAQUETE + os.pathsep + env.get("PYTHONPATH", "")
    errlog = tempfile.TemporaryFile(mode="w+", encoding="utf-8", errors="replace")
    proc = subprocess.Popen(
        [sys.executable, "-m", "ventana_cero.jaula", os.path.join(dir_repo, "app.py")],
        env=env, stdout=subprocess.DEVNULL, stderr=errlog,
    )
    # timeout duro: pase lo que pase, el proceso muere al vencer el plazo
    reloj = threading.Timer(TIMEOUT_S, proc.kill)
    reloj.start()
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
        reloj.cancel()
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except Exception:
            proc.kill()
        errlog.seek(0)
        bloqueos = [ln.strip() for ln in errlog if ln.startswith(jaula.PREFIJO)]
        errlog.close()
        if bloqueos:
            poc["bloqueos"] = bloqueos
