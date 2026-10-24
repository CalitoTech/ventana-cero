"""Banco de pruebas de Ventana Cero.

Corre el lazo sobre los fixtures y compara la decisión con la etiqueta esperada
(ground truth) de cada caso, reportando precisión, recall, tiempo hasta mitigar y
confirmaciones por PoC. Es la base de la métrica del aspecto técnico; agreguen más
casos a casos.json a medida que amplíen.

Ejecutar:  python eval/run_eval.py
"""
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from ventana_cero import orchestrator  # noqa: E402

# etiqueta esperada por aviso: ¿debería terminar mitigado (alcanzable+explotable)?
GROUND_TRUTH = {
    "VC-2026-0001": {"debe_mitigar": True},   # SSTI realmente alcanzable
    "VC-2026-0002": {"debe_mitigar": False},  # presente pero no alcanzable (ruido)
}


def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    with tempfile.TemporaryDirectory() as d:
        rep = orchestrator.correr(
            manifiesto="fixtures/target-app/requirements.txt",
            dir_avisos="fixtures/advisories",
            dir_repo="fixtures/target-app",
            dir_salida=d,
        )
    vp = fp = fn = vn = 0
    tiempos = []
    for h in rep["hallazgos"]:
        gt = GROUND_TRUTH.get(h["advisory_id"], {}).get("debe_mitigar")
        if gt is None:
            continue
        mitigado = h["decision"] in ("mitigar", "actuar")
        if gt and mitigado:
            vp += 1
        elif gt and not mitigado:
            fn += 1
        elif not gt and mitigado:
            fp += 1
        else:
            vn += 1
        if h.get("segundos_hasta_mitigar") is not None:
            tiempos.append(h["segundos_hasta_mitigar"])

    total = vp + fp + fn + vn
    precision = vp / (vp + fp) if (vp + fp) else 1.0
    recall = vp / (vp + fn) if (vp + fn) else 1.0
    ruido_reducido = (vn + fn) / total if total else 0.0

    print("\n=== Evaluación Ventana Cero ===")
    print(f"casos: {total}  (VP={vp} FP={fp} FN={fn} VN={vn})")
    print(f"precisión de la decisión de mitigar: {precision:.0%}")
    print(f"recall (alcanzables mitigados):      {recall:.0%}")
    print(f"ruido descartado (no se mitiga):     {ruido_reducido:.0%}")
    if tiempos:
        print(f"tiempo medio hasta mitigar:          {sum(tiempos)/len(tiempos):.2f}s")
        print(f"atacante supuesto:                   {rep['atacante_seg_supuesto']}s")
    print("\nnota: cifras sobre los fixtures actuales. Agreguen casos a GROUND_TRUTH.")


if __name__ == "__main__":
    main()
