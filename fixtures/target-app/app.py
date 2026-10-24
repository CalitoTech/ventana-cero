"""App víctima para la demo de Ventana Cero. Solo stdlib, corre en cualquier lado.

Rutas:
  GET /preview?tpl=...   -> tinytpl.render(tpl)       VULNERABLE: entrada no confiable → sink
  GET /banner            -> tinytpl.render(CONSTANTE) usa el sink, pero SIN taint (negativo)
  GET /welcome?name=...  -> saludo literal             no usa el sink (negativo)
  GET /health            -> ok

Parche virtual: si la variable de entorno VC_GUARD apunta a un JSON de reglas, se
bloquean (403) las peticiones cuyo parámetro coincide con el patrón de la regla.
Así el mitigador puede "aplicar" una mitigación sin tocar el código vulnerable.
"""
import json
import os
import re
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "vendor"))
import tinytpl  # noqa: E402  (librería vendored, ficticia y vulnerable)


def _cargar_guard():
    ruta = os.environ.get("VC_GUARD")
    if not ruta or not os.path.exists(ruta):
        return []
    try:
        with open(ruta, encoding="utf-8") as f:
            return json.load(f).get("reglas", [])
    except Exception:
        return []


GUARD = _cargar_guard()


def _bloqueado(ruta: str, params: dict) -> dict | None:
    for regla in GUARD:
        if regla.get("ruta") and regla["ruta"] != ruta:
            continue
        param = regla.get("param")
        patron = regla.get("patron")
        valores = params.get(param, []) if param else []
        for v in valores:
            if patron and re.search(patron, v):
                return regla
    return None


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # silencio
        pass

    def _responder(self, codigo: int, cuerpo: str):
        self.send_response(codigo)
        self.send_header("content-type", "text/plain; charset=utf-8")
        self.end_headers()
        self.wfile.write(cuerpo.encode())

    def do_GET(self):
        u = urlparse(self.path)
        params = parse_qs(u.query)

        regla = _bloqueado(u.path, params)
        if regla:
            self._responder(403, f"bloqueado por Ventana Cero (regla {regla.get('id','?')})")
            return

        if u.path == "/health":
            self._responder(200, "ok")
        elif u.path == "/preview":
            tpl = params.get("tpl", [""])[0]      # fuente: entrada no confiable
            self._responder(200, tinytpl.render(tpl))  # sink: símbolo vulnerable
        elif u.path == "/banner":
            self._responder(200, tinytpl.render("Banner {{1}}"))  # sink con constante (sin taint)
        elif u.path == "/welcome":
            name = params.get("name", ["amigo"])[0]
            self._responder(200, f"Hola {name}")  # tainted, pero NO llega al sink
        else:
            self._responder(404, "no encontrado")


def main():
    puerto = int(os.environ.get("VC_PORT", sys.argv[1] if len(sys.argv) > 1 else "8000"))
    srv = ThreadingHTTPServer(("127.0.0.1", puerto), Handler)
    print(f"target-app escuchando en 127.0.0.1:{puerto} (guard: {len(GUARD)} reglas)", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
