"""Servidor del panel: sirve ui/public y expone el lazo real por HTTP.

    python -m ventana_cero.server          # http://localhost:8000

- GET  /             el panel
- GET  /api/status   {"en_vivo": true}: el panel sabe que puede correr el lazo
- POST /api/run      corre detector → alcanzabilidad → sandbox → mitigador ahora
                     mismo y devuelve el run.json recién generado

Solo stdlib, igual que el resto. Escucha en 127.0.0.1: el sandbox ejecuta PoCs,
no se expone a la red.
"""
from __future__ import annotations

import argparse
import functools
import json
import threading
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

from . import orchestrator

_lock = threading.Lock()  # una corrida a la vez: el sandbox usa puertos fijos


class _Handler(SimpleHTTPRequestHandler):
    def __init__(self, *a, opciones: dict, **kw):
        self.opciones = opciones
        super().__init__(*a, **kw)

    def _json(self, codigo: int, cuerpo: dict):
        data = json.dumps(cuerpo, ensure_ascii=False).encode("utf-8")
        self.send_response(codigo)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path == "/api/status":
            return self._json(200, {"en_vivo": True})
        return super().do_GET()

    def do_POST(self):
        if self.path != "/api/run":
            return self._json(404, {"error": "no existe"})
        if not _lock.acquire(blocking=False):
            return self._json(409, {"error": "ya hay una corrida en curso"})
        try:
            o = self.opciones
            rep = orchestrator.correr(o["manifiesto"], o["avisos"], o["repo"], o["dir_salida"],
                                      dir_ui=o["dir_ui"] if o["publicar_ui"] else None)
            return self._json(200, rep)
        except Exception as e:  # el panel muestra el error en vez de colgarse
            return self._json(500, {"error": f"{type(e).__name__}: {e}"})
        finally:
            _lock.release()

    def log_message(self, fmt, *args):
        if self.path.startswith("/api/"):
            super().log_message(fmt, *args)


def crear_servidor(puerto: int = 8000, *, dir_ui: str = "ui/public", dir_salida: str = "out",
                   manifiesto: str = "fixtures/target-app/requirements.txt",
                   avisos: str = "fixtures/advisories", repo: str = "fixtures/target-app",
                   publicar_ui: bool = True) -> ThreadingHTTPServer:
    opciones = dict(dir_ui=dir_ui, dir_salida=dir_salida, manifiesto=manifiesto,
                    avisos=avisos, repo=repo, publicar_ui=publicar_ui)
    handler = functools.partial(_Handler, opciones=opciones, directory=dir_ui)
    return ThreadingHTTPServer(("127.0.0.1", puerto), handler)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Panel de Ventana Cero conectado al lazo real")
    ap.add_argument("--puerto", type=int, default=8000)
    args = ap.parse_args(argv)
    srv = crear_servidor(args.puerto)
    print(f"panel en vivo: http://localhost:{args.puerto}  (Ctrl+C para salir)")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()


if __name__ == "__main__":
    main()
