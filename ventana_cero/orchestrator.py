"""El lazo. Une detector → alcanzabilidad → sandbox → mitigador y emite el reporte.

Corre sobre el caso de la demo y escribe out/run.json (lo lee la UI) con el estado
final de cada Hallazgo, la línea de tiempo por etapa (para animar la UI) y las
métricas de la carrera. También genera out/report.md: el "informe de modo sombra"
que es la herramienta de venta.
"""
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

from . import detector, reachability, sandbox, mitigator, policy
from .detector import cargar_avisos

# Supuesto ilustrativo: al atacante con IA le toma ~4 horas armar el exploit tras
# el aviso. Ajústenlo con lo que midan.
ATACANTE_SEG_SUPUESTO = 4 * 3600


def _utf8_stdout():
    try:
        import sys
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass


def _indexar_avisos(dir_avisos: str) -> dict[str, dict]:
    return {a["id"]: a for a in cargar_avisos(dir_avisos)}


def correr(manifiesto: str, dir_avisos: str, dir_repo: str,
           dir_salida: str = "out", dir_ui: str | None = None,
           solo: str | None = None) -> dict:
    t0 = time.time()
    avisos = _indexar_avisos(dir_avisos)
    hallazgos = detector.detectar(manifiesto, dir_avisos)
    if solo:  # demo interactiva: correr un solo aviso para que sea instantáneo
        hallazgos = [h for h in hallazgos if h.advisory_id == solo]

    salida = Path(dir_salida)
    salida.mkdir(parents=True, exist_ok=True)

    items = []
    for h in hallazgos:
        aviso = avisos.get(h.advisory_id, {})
        clase = aviso.get("clase")
        t_h = time.time()
        etapas = [("detectado", 0.0)]

        policy.prioridad(h)

        # 2-3 · alcanzabilidad
        reachability.derivar_simbolo(h, aviso)
        etapas.append(("símbolo derivado", round(time.time() - t_h, 3)))
        reachability.analizar(h, dir_repo)
        etapas.append((f"alcanzabilidad: nivel {h.nivel}", round(time.time() - t_h, 3)))

        # prueba · solo si hay taint (nivel 3)
        if h.nivel >= 3:
            resultado, poc = sandbox.ejecutar(h, dir_repo, clase=clase)
            h.resultado_poc = resultado
            h.poc = poc
            etapas.append((f"PoC: {resultado}", round(time.time() - t_h, 3)))
            if resultado == "disparo":
                h.nivel = 4
                h.evidencia.append("PoC confirmado en el sandbox: ejecución reproducida")

        policy.decidir(h)
        seg_mitigacion = None

        # 4-5 · mitigación (solo con prueba: nivel 4)
        if policy.puede_auto_mitigar(h):
            ruta = h.poc.get("ruta", "/") if h.poc else "/"
            param = h.poc.get("param", "") if h.poc else ""
            pv = mitigator.generar_parche_virtual(h, clase, ruta, param)
            reglas = mitigator.escribir_reglas([pv], str(salida / f"guard-{h.advisory_id}.json"))
            h.parche_virtual = pv
            resultado2, _ = sandbox.ejecutar(h, dir_repo, clase=clase, guard=reglas)
            h.parche_virtual_verificado = (resultado2 == "no_disparo")
            h.evidencia.append(
                "parche virtual verificado: el PoC ya no se dispara"
                if h.parche_virtual_verificado else
                "ATENCIÓN: el parche virtual no bloqueó el PoC")
            etapas.append(("parche virtual verificado", round(time.time() - t_h, 3)))
            # relativo a la salida (junto a run.json): no filtra rutas de la máquina
            if mitigator.generar_parche_codigo(
                    h, aviso, str(salida / f"{h.advisory_id}.patch")):
                h.pr_parche_codigo = f"{h.advisory_id}.patch"
            seg_mitigacion = round(time.time() - t_h, 3)

        item = h.dict()
        item["clase"] = clase
        item["segundos_hasta_mitigar"] = seg_mitigacion
        item["etapas"] = [{"etapa": e, "t": t} for e, t in etapas]
        items.append(item)

    # ordenar por prioridad y nivel para el reporte
    orden_pri = {"crítica": 0, "alta": 1, "media": 2, "baja": 3}
    items.sort(key=lambda i: (orden_pri.get(i["prioridad"], 9), -i["nivel"]))

    reporte = {
        "proyecto": "Ventana Cero",
        "generado": time.strftime("%Y-%m-%d %H:%M:%S"),
        "segundos_totales": round(time.time() - t0, 2),
        "atacante_seg_supuesto": ATACANTE_SEG_SUPUESTO,
        "resumen": _resumen(items),
        "hallazgos": items,
    }
    (salida / "run.json").write_text(
        json.dumps(reporte, ensure_ascii=False, indent=2), encoding="utf-8")
    # solo el CLI publica en la UI; tests y eval no deben ensuciar el repo
    if dir_ui and Path(dir_ui).exists():
        (Path(dir_ui) / "run.json").write_text(
            json.dumps(reporte, ensure_ascii=False, indent=2), encoding="utf-8")
    _escribir_informe(reporte, salida / "report.md")
    return reporte


def _resumen(items: list[dict]) -> dict:
    por_decision: dict[str, int] = {}
    for i in items:
        por_decision[i["decision"]] = por_decision.get(i["decision"], 0) + 1
    accionables = sum(1 for i in items if i["decision"] in ("mitigar", "actuar"))
    return {
        "total": len(items),
        "accionables": accionables,
        "ruido_descartado": len(items) - accionables,
        "por_decision": por_decision,
    }


def _escribir_informe(rep: dict, destino: Path):
    """Informe de 'modo sombra': qué se habría hecho y por qué. La venta."""
    r = rep["resumen"]
    L = [
        "# Ventana Cero — informe de exposición",
        "",
        f"_Generado {rep['generado']} · {r['total']} hallazgos · "
        f"{r['accionables']} accionables · {r['ruido_descartado']} descartados como ruido_",
        "",
        "| Prioridad | Aviso | Paquete | Nivel | Decisión | Mitigado |",
        "|---|---|---|---|---|---|",
    ]
    for i in rep["hallazgos"]:
        mit = "✓" if i.get("parche_virtual_verificado") else "—"
        kev = " · KEV" if i.get("kev") else ""
        L.append(f"| {i['prioridad']}{kev} | {i['advisory_id']} | "
                 f"{i['paquete']}=={i['version']} | {i['nivel']} ({i['nivel_texto']}) | "
                 f"{i['decision'].upper()} | {mit} |")
    L += ["", "## Detalle", ""]
    for i in rep["hallazgos"]:
        L.append(f"### {i['advisory_id']} — {i['resumen']}")
        if i.get("simbolo_vulnerable"):
            L.append(f"- símbolo: `{i['simbolo_vulnerable']}` (param `{i['parametro_peligroso']}`)")
        if i.get("camino_taint"):
            L.append("- taint: " + " → ".join(i["camino_taint"]))
        if i.get("resultado_poc"):
            L.append(f"- PoC: **{i['resultado_poc']}**")
        if i.get("parche_virtual"):
            ok = "verificado" if i["parche_virtual_verificado"] else "SIN verificar"
            L.append(f"- parche virtual: {i['parche_virtual']['descr']} [{ok}]")
        L.append(f"- decisión: **{i['decision'].upper()}** · prioridad {i['prioridad']}")
        L.append("")
    destino.write_text("\n".join(L), encoding="utf-8")


def imprimir(rep: dict):
    _utf8_stdout()
    r = rep["resumen"]
    print(f"\n=== Ventana Cero · {rep['generado']} ===")
    print(f"{r['total']} hallazgos · {r['accionables']} accionables · "
          f"{r['ruido_descartado']} ruido · {rep['segundos_totales']}s\n")
    for h in rep["hallazgos"]:
        kev = " [KEV]" if h.get("kev") else ""
        print(f"[{h['advisory_id']}] {h['paquete']}=={h['version']} · "
              f"prioridad {h['prioridad']}{kev}")
        print(f"  {h['resumen']}")
        print(f"  escalera: nivel {h['nivel']} ({h['nivel_texto']}) -> {h['decision'].upper()}")
        if h.get("camino_taint"):
            print("  taint: " + " -> ".join(h["camino_taint"]))
        if h.get("resultado_poc"):
            print(f"  PoC: {h['resultado_poc']}")
        if h.get("parche_virtual"):
            ok = "verificado" if h["parche_virtual_verificado"] else "SIN verificar"
            print(f"  parche virtual: {h['parche_virtual']['descr']} [{ok}]")
        if h.get("segundos_hasta_mitigar") is not None:
            print(f"  tiempo hasta mitigar: {h['segundos_hasta_mitigar']}s "
                  f"(atacante supuesto: {rep['atacante_seg_supuesto']}s)")
        print()


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="ventana_cero", description="Defensa autónoma del n-day, con prueba.")
    ap.add_argument("--manifiesto", default="fixtures/target-app/requirements.txt")
    ap.add_argument("--avisos", default="fixtures/advisories")
    ap.add_argument("--repo", default="fixtures/target-app")
    ap.add_argument("--salida", default="out")
    ap.add_argument("--json", action="store_true", help="imprime el run.json en crudo")
    args = ap.parse_args(argv)
    rep = correr(args.manifiesto, args.avisos, args.repo, args.salida, dir_ui="ui/public")
    if args.json:
        _utf8_stdout()
        print(json.dumps(rep, ensure_ascii=False, indent=2))
    else:
        imprimir(rep)
        print(f"reporte: {args.salida}/run.json - informe: {args.salida}/report.md")


if __name__ == "__main__":
    main()
