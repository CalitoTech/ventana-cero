"""Jaula sin Docker: aislamiento por política con audit hooks (PEP 578).

Uso:  python -m ventana_cero.jaula <script.py> [args...]

Antes de ejecutar el script instala un audit hook que:
  - solo permite sockets contra 127.0.0.1 / ::1 / localhost (sin salida a red),
  - prohíbe lanzar procesos (subprocess, os.system, exec*, spawn*, fork),
  - solo permite leer dentro del repo, la instalación de Python y el guard,
    y escribir solo en un directorio temporal propio.
Cada bloqueo se anota en stderr con el prefijo VC_BLOQUEO para que el host lo
recoja como evidencia.

OJO: esto NO es una frontera de seguridad de kernel. Código nativo (ctypes) o un
script hostil puede evadirla. Sirve para correr nuestros PoC canario contra
nuestro propio código; en producción va un contenedor sin red.
"""
from __future__ import annotations

import os
import runpy
import sys
import sysconfig
import tempfile

PREFIJO = "VC_BLOQUEO"
_LOCALES = {"127.0.0.1", "::1", "localhost", "0.0.0.0", ""}
_EVENTOS_PROCESO = {"subprocess.Popen", "os.system", "os.exec", "os.posix_spawn",
                    "os.spawn", "os.fork", "os.forkpty", "os.startfile", "ctypes.dlopen"}


class Bloqueado(PermissionError):
    pass


def _norm(p) -> str | None:
    if isinstance(p, int):  # descriptor ya abierto
        return None
    try:
        return os.path.normcase(os.path.realpath(os.fsdecode(p)))
    except Exception:
        return None


def instalar(dir_repo: str, extra_lectura: list[str] | None = None) -> str:
    """Instala el hook (irreversible en este proceso). Devuelve el tmp escribible."""
    tmp = tempfile.mkdtemp(prefix="vc-jaula-")
    escritura = [_norm(tmp)]
    lectura = [_norm(dir_repo), *escritura]
    for p in (sys.prefix, sys.base_prefix, sys.exec_prefix,
              *(sysconfig.get_paths().values()), *(extra_lectura or [])):
        if p:
            lectura.append(_norm(p))
    lectura = [p for p in lectura if p]

    def _dentro(ruta: str, bases: list[str]) -> bool:
        return any(ruta == b or ruta.startswith(b + os.sep) for b in bases)

    def _bloquear(evento: str, detalle) -> None:
        print(f"{PREFIJO} {evento} {detalle!r}", file=sys.stderr, flush=True)
        raise Bloqueado(f"jaula: {evento} bloqueado")

    def hook(evento: str, args: tuple) -> None:
        if evento in ("socket.connect", "socket.bind", "socket.sendto"):
            direccion = args[1]
            host = direccion[0] if isinstance(direccion, tuple) and direccion else direccion
            if not (isinstance(host, str) and host in _LOCALES):
                _bloquear(evento, direccion)
        elif evento == "socket.getaddrinfo":
            if args[0] not in _LOCALES and args[0] is not None:
                _bloquear(evento, args[0])
        elif evento in _EVENTOS_PROCESO:
            _bloquear(evento, args[0] if args else None)
        elif evento == "open":
            ruta = _norm(args[0])
            if ruta is None:
                return
            modo = args[1] or "r"
            escribe = isinstance(modo, str) and any(c in modo for c in "wax+")
            if isinstance(modo, int):  # os.open con flags
                escribe = bool(modo & (os.O_WRONLY | os.O_RDWR | os.O_CREAT))
            if escribe and not _dentro(ruta, escritura):
                _bloquear("open-escritura", args[0])
            if not escribe and not _dentro(ruta, lectura):
                _bloquear("open-lectura", args[0])

    sys.addaudithook(hook)
    return tmp


def _limitar_memoria() -> None:
    """Límite de memoria donde el SO lo permite (POSIX). En Windows: solo timeout."""
    mb = int(os.environ.get("VC_MEM_MB", "256"))
    try:
        import resource
        resource.setrlimit(resource.RLIMIT_AS, (mb * 2**20, mb * 2**20))
    except (ImportError, ValueError, OSError):
        pass


def main(argv: list[str]) -> None:
    if not argv:
        sys.exit("uso: python -m ventana_cero.jaula <script.py> [args...]")
    script = os.path.abspath(argv[0])
    dir_repo = os.path.dirname(script)
    guard = os.environ.get("VC_GUARD")
    _limitar_memoria()
    instalar(dir_repo, extra_lectura=[guard] if guard else None)
    sys.argv = [script, *argv[1:]]
    runpy.run_path(script, run_name="__main__")


if __name__ == "__main__":
    main(sys.argv[1:])
