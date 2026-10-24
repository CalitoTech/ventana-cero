"""Demo en vivo del pitch: el mismo ataque, dos finales.

1. Levanta la app víctima SIN Ventana Cero y dispara el ataque: 200, el atacante entra.
2. Corre el lazo: alcanzabilidad -> PoC -> parche virtual verificado.
3. Reinicia la app CON el parche virtual y repite el ataque: 403. El tráfico
   legítimo sigue pasando (200).

Ejecutar:  python -m ventana_cero.demo            (pausa entre pasos, puerto 8001)
           python -m ventana_cero.demo --sin-pausa
La app queda en el puerto fijo para que quien maneja la demo repita el curl a mano;
la UI se sirve aparte en el 8000 (make ui), así no chocan.
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import quote

from . import orchestrator
from .sandbox import _esperar, _puerto_libre

DIR_REPO = "fixtures/target-app"
AVISO = "VC-2026-0001"
ATAQUE = ("/preview", "tpl", "{{7*6}}")      # SSTI: el canario aritmético responde 42
LEGITIMO = ("/preview", "tpl", "hola")


def _levantar(puerto: int, guard: str | None = None) -> subprocess.Popen:
    env = dict(os.environ, VC_PORT=str(puerto))
    env.pop("VC_GUARD", None)
    if guard:
        env["VC_GUARD"] = guard
    proc = subprocess.Popen([sys.executable, os.path.join(DIR_REPO, "app.py")],
                            env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if not _esperar(puerto):
        _bajar(proc)
        raise RuntimeError(f"la app víctima no levantó en el puerto {puerto}")
    return proc


def _bajar(proc: subprocess.Popen) -> None:
    proc.terminate()
    try:
        proc.wait(timeout=3)
    except Exception:
        proc.kill()


def _pedir(puerto: int, peticion: tuple[str, str, str], salida) -> dict:
    ruta, param, valor = peticion
    # -g: sin él, curl toma {{...}} como patrón de URLs y falla al copiarlo
    salida(f'$ curl -g "http://127.0.0.1:{puerto}{ruta}?{param}={valor}"')
    url = f"http://127.0.0.1:{puerto}{ruta}?{param}={quote(valor)}"
    try:
        with urllib.request.urlopen(url, timeout=3) as r:
            codigo, cuerpo = r.status, r.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        codigo, cuerpo = e.code, e.read().decode(errors="replace")
    salida(f"  -> {codigo} {cuerpo[:80]}")
    return {"codigo": codigo, "cuerpo": cuerpo}


def ejecutar(puerto: int | None = None, dir_salida: str = "out",
             dir_ui: str | None = "ui/public", pausa: bool = True,
             salida=print) -> dict:
    """Corre los tres pasos y devuelve el resultado de cada petición."""
    puerto = puerto or _puerto_libre()
    esperar = (lambda m: input(f"\n[Enter] {m}")) if pausa else (lambda m: None)
    pasos = {}

    salida("== 1 · SIN Ventana Cero")
    proc = _levantar(puerto)
    try:
        pasos["sin_ventana_cero"] = _pedir(puerto, ATAQUE, salida)
    finally:
        _bajar(proc)

    esperar("activar Ventana Cero")
    salida("== 2 · Ventana Cero: alcanzabilidad -> PoC -> parche virtual")
    rep = orchestrator.correr(f"{DIR_REPO}/requirements.txt", "fixtures/advisories",
                              DIR_REPO, dir_salida, dir_ui=dir_ui)
    h = next(i for i in rep["hallazgos"] if i["advisory_id"] == AVISO)
    salida(f"  {AVISO}: nivel {h['nivel']} -> {h['decision'].upper()}, "
           f"parche virtual verificado={h['parche_virtual_verificado']} "
           f"en {h['segundos_hasta_mitigar']}s")

    salida("== 3 · CON Ventana Cero: el mismo ataque")
    proc = _levantar(puerto, guard=str(Path(dir_salida) / f"guard-{AVISO}.json"))
    try:
        pasos["con_ventana_cero"] = _pedir(puerto, ATAQUE, salida)
        pasos["legitimo"] = _pedir(puerto, LEGITIMO, salida)
        esperar(f"terminar (la app protegida sigue en el puerto {puerto} para el curl a mano)")
    finally:
        _bajar(proc)
    return pasos


def main(argv=None):
    ap = argparse.ArgumentParser(prog="ventana_cero.demo",
                                 description="Demo en vivo: 200 sin Ventana Cero, 403 con ella.")
    ap.add_argument("--puerto", type=int, default=8001)
    ap.add_argument("--sin-pausa", action="store_true", help="corre los pasos de corrido")
    args = ap.parse_args(argv)
    orchestrator._utf8_stdout()
    pasos = ejecutar(puerto=args.puerto, pausa=not args.sin_pausa)
    ok = (pasos["sin_ventana_cero"]["codigo"], pasos["con_ventana_cero"]["codigo"],
          pasos["legitimo"]["codigo"]) == (200, 403, 200)
    print("\nVentana cerrada." if ok else "\nATENCIÓN: la demo no dio 200 -> 403 -> 200.")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
