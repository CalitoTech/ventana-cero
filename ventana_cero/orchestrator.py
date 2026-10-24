"""El lazo. Une detector → alcanzabilidad → sandbox → mitigador y emite el reporte.

Ejecuta todo sobre el caso de la demo y escribe out/run.json (lo lee la UI) con el
estado final de cada Hallazgo y las métricas de la "carrera" (tiempo del defensor
vs. tiempo supuesto del atacante).
"""
from __future__ import annotations

import json
import time
from pathlib import Path

from . import detector, reachability, sandbox, mitigator, policy
from .detector import cargar_avisos

# Supuesto para la demo: al atacante con IA le toma ~4 horas armar el exploit tras
# el aviso. Es una cota ilustrativa para el contraste; ajústenla con lo que midan.
ATACANTE_SEG_SUPUESTO = 4 * 3600


def _indexar_avisos(dir_avisos: str) -> dict[str, dict]:
    return {a["id"]: a for a in cargar_avisos(dir_avisos)}


def correr(manifiesto: str, dir_avisos: str, dir_repo: str,
           dir_salida: str = "out") -> dict:
    t0 = time.time()
    avisos = _indexar_avisos(dir_avisos)
    hallazgos = detector.detectar(manifiesto, dir_repo_avisos := dir_avisos)

    salida = Path(dir_salida)
    salida.mkdir(parents=True, exist_ok=True)

    reporte_items = []
    for h in hallazgos:
        aviso = avisos.get(h.advisory_id, {})
        clase = aviso.get("clase")
        t_hallazgo = time.time()

        # 2-3 · alcanzabilidad
        reachability.derivar_simbolo(h, aviso)
        reachability.analizar(h, dir_repo)

        # prueba · solo vale la pena si hay taint (nivel 3)
        if h.nivel >= 3:
            resultado, poc = sandbox.ejecutar(h, dir_repo, clase=clase)
            h.resultado_poc = resultado
            h.poc = poc
            if resultado == "disparo":
                h.nivel = 4
                h.evidencia.append("PoC confirmado en el sandbox: ejecución reproducida")

        # decisión según la escalera
        policy.decidir(h)
        seg_mitigacion = None

        # 4-5 · mitigación (solo si hay prueba: nivel 4)
        if policy.puede_auto_mitigar(h):
            ruta = h.poc.get("ruta", "/") if h.poc else "/"
            param = h.poc.get("param", "") if h.poc else ""
            pv = mitigator.generar_parche_virtual(h, clase, ruta, param)
            reglas = mitigator.escribir_reglas([pv], str(salida / "guard.json"))
            h.parche_virtual = pv

            # verificar: re-disparar el PoC con el parche virtual puesto
            resultado2, _ = sandbox.ejecutar(h, dir_repo, clase=clase, guard=reglas)
            h.parche_virtual_verificado = (resultado2 == "no_disparo")
            h.evidencia.append(
                "parche virtual verificado: el PoC ya no se dispara"
                if h.parche_virtual_verificado else
                "ATENCIÓN: el parche virtual no bloqueó el PoC"
            )
            seg_mitigacion = round(time.time() - t_hallazgo, 2)

            # parche de código como artefacto para PR (requiere humano)
            pr = mitigator.generar_parche_codigo(
                h, aviso, str(salida / f"{h.advisory_id}.patch"))
            h.pr_parche_codigo = pr

        item = h.dict()
        item["segundos_hasta_mitigar"] = seg_mitigacion
        reporte_items.append(item)

    reporte = {
        "proyecto": "Ventana Cero",
        "generado": time.strftime("%Y-%m-%d %H:%M:%S"),
        "segundos_totales": round(time.time() - t0, 2),
        "atacante_seg_supuesto": ATACANTE_SEG_SUPUESTO,
        "hallazgos": reporte_items,
    }
    (salida / "run.json").write_text(
        json.dumps(reporte, ensure_ascii=False, indent=2), encoding="utf-8")
    # copia para la UI
    ui_pub = Path("ui/public")
    if ui_pub.exists():
        (ui_pub / "run.json").write_text(
            json.dumps(reporte, ensure_ascii=False, indent=2), encoding="utf-8")
    return reporte


def _imprimir(reporte: dict):
    print(f"\n=== Ventana Cero · corrida {reporte['generado']} ===")
    print(f"hallazgos: {len(reporte['hallazgos'])} · "
          f"tiempo total: {reporte['segundos_totales']}s\n")
    for h in reporte["hallazgos"]:
        print(f"[{h['advisory_id']}] {h['paquete']}=={h['version']} — {h['resumen']}")
        print(f"  escalera: nivel {h['nivel']} ({h['nivel_texto']}) → decisión: {h['decision'].upper()}")
        if h.get("simbolo_vulnerable"):
            print(f"  símbolo: {h['simbolo_vulnerable']}  param: {h['parametro_peligroso']}")
        if h.get("camino_taint"):
            print("  taint: " + " → ".join(h["camino_taint"]))
        if h.get("resultado_poc"):
            print(f"  PoC: {h['resultado_poc']}")
        if h.get("parche_virtual"):
            ok = "verificado" if h["parche_virtual_verificado"] else "SIN verificar"
            print(f"  parche virtual: {h['parche_virtual']['descr']} [{ok}]")
        if h.get("segundos_hasta_mitigar") is not None:
            print(f"  tiempo hasta mitigar: {h['segundos_hasta_mitigar']}s "
                  f"(atacante supuesto: {reporte['atacante_seg_supuesto']}s)")
        print()


def _utf8_stdout():
    """Evita UnicodeEncodeError en consolas Windows (cp1252)."""
    try:
        import sys
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass


def main():
    _utf8_stdout()
    rep = correr(
        manifiesto="fixtures/target-app/requirements.txt",
        dir_avisos="fixtures/advisories",
        dir_repo="fixtures/target-app",
    )
    _imprimir(rep)
    print("reporte escrito en out/run.json")


if __name__ == "__main__":
    main()
