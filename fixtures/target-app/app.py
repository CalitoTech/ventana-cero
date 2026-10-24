"""App víctima para la demo de Ventana Cero. Solo stdlib, corre en cualquier lado.

Rutas (cada una ejercita un caso distinto de la escalera de confianza):
  GET /preview?tpl=...   -> tinytpl.render(tpl)   SSTI: entrada no confiable → sink (nivel 4)
  GET /file?name=...     -> safefs.read(name)      path traversal: tainted → sink (nivel 4)
  GET /parse?data=...    -> jsonx.loads(data)      tainted → sink, pero impl segura (PoC falla → revisar)
  GET /banner            -> tinytpl.render(const)  sink con constante (sin taint)
  GET /status            -> logfmt.render_line(const)  sink con constante (nivel 2)
  GET /doc?name=...      -> zipkit.open_member(basename(name))  saneado antes del sink (nivel 2)
  GET /config?doc=...   -> yaml.load(doc)       CVE-2017-18342 real (PyYAML 3.13): nivel 4
  GET /gpg?data=...     -> gnupg.encrypt(data)   CVE-2019-6690 real (python-gnupg 0.4.3): nivel 4
  GET /buscar?nombre=.. -> sqlalchemy.buscar(n)   CVE-2019-7164 real (SQLAlchemy 1.2.17): nivel 4
  GET /welcome?name=...  -> saludo literal          no usa ningún sink
  GET /health            -> ok

Además referencia (sin llamar) oldhash.md5 -> demuestra "símbolo referenciado" (nivel 1).

Parche virtual: si VC_GUARD apunta a un JSON de reglas, se bloquean (403) las
peticiones cuyo parámetro coincide con el patrón de la regla.
"""
import json
import os
import re
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "vendor"))
import tinytpl   # noqa: E402  (vendored, vulnerable: SSTI)
import safefs    # noqa: E402  (vendored, vulnerable: path traversal)
import jsonx     # noqa: E402  (vendored, impl segura)
import oldhash   # noqa: E402  (vendored, md5 débil)
import logfmt    # noqa: E402  (vendored, vulnerable: inyección de formato)
import zipkit    # noqa: E402  (vendored, vulnerable: path traversal)
import yaml      # noqa: E402  (reproducción de PyYAML 3.13: CVE-2017-18342)
import gnupg     # noqa: E402  (reproducción de python-gnupg 0.4.3: CVE-2019-6690)
import sqlalchemy  # noqa: E402  (reproducción de SQLAlchemy 1.2.17: CVE-2019-7164)

# Referencia al símbolo débil SIN llamarlo: la escalera debe quedarse en nivel 1.
HASHER = oldhash.md5  # referenciado, nunca invocado


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


def _bloqueado(ruta: str, params: dict):
    for regla in GUARD:
        if regla.get("ruta") and regla["ruta"] != ruta:
            continue
        valores = params.get(regla.get("param"), []) if regla.get("param") else []
        for v in valores:
            if regla.get("patron") and re.search(regla["patron"], v):
                return regla
    return None


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _responder(self, codigo, cuerpo):
        self.send_response(codigo)
        self.send_header("content-type", "text/plain; charset=utf-8")
        self.end_headers()
        self.wfile.write(cuerpo.encode())

    def do_GET(self):
        u = urlparse(self.path)
        params = parse_qs(u.query)

        regla = _bloqueado(u.path, params)
        if regla:
            self._responder(403, f"bloqueado por Ventana Cero (regla {regla.get('id', '?')})")
            return

        if u.path == "/health":
            self._responder(200, "ok")
        elif u.path == "/preview":
            tpl = params.get("tpl", [""])[0]          # fuente no confiable
            self._responder(200, tinytpl.render(tpl))  # sink SSTI
        elif u.path == "/file":
            name = params.get("name", ["index.txt"])[0]  # fuente no confiable
            self._responder(200, safefs.read(name))       # sink path traversal
        elif u.path == "/parse":
            data = params.get("data", ["{}"])[0]       # fuente no confiable
            self._responder(200, str(jsonx.loads(data)))  # sink deserialización (impl segura)
        elif u.path == "/banner":
            self._responder(200, tinytpl.render("Banner {{1}}"))  # sink con constante
        elif u.path == "/status":
            self._responder(200, logfmt.render_line("estado: ok"))  # sink con constante
        elif u.path == "/doc":
            name = params.get("name", ["manual.txt"])[0]   # fuente no confiable
            limpio = os.path.basename(name)                 # sanitizador: corta el taint
            self._responder(200, zipkit.open_member(limpio))
        elif u.path == "/config":
            doc = params.get("doc", ["modo: demo"])[0]  # fuente no confiable
            self._responder(200, str(yaml.load(doc)))     # sink CVE-2017-18342
        elif u.path == "/gpg":
            data = params.get("data", ["hola"])[0]        # fuente no confiable
            self._responder(200, gnupg.encrypt(data))       # sink CVE-2019-6690
        elif u.path == "/buscar":
            nombre = params.get("nombre", ["alpha"])[0]   # fuente no confiable
            self._responder(200, str(sqlalchemy.buscar(nombre)))  # sink CVE-2019-7164
        elif u.path == "/welcome":
            name = params.get("name", ["amigo"])[0]
            self._responder(200, f"Hola {name}")       # tainted, no llega a un sink
        else:
            self._responder(404, "no encontrado")


def main():
    puerto = int(os.environ.get("VC_PORT", sys.argv[1] if len(sys.argv) > 1 else "8000"))
    srv = ThreadingHTTPServer(("127.0.0.1", puerto), Handler)
    print(f"target-app en 127.0.0.1:{puerto} (guard: {len(GUARD)} reglas)", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
