# Contribuir

## Setup
Requiere Python 3.11+. No hay dependencias (el esqueleto usa solo stdlib).

```bash
git clone https://github.com/CalitoTech/ventana-cero.git
cd ventana-cero
python -m ventana_cero        # corre el lazo sobre la demo
python -m unittest discover -s tests
python eval/run_eval.py
```

## Convenciones
- Un módulo por etapa del lazo en `ventana_cero/`. Mantener el contrato
  `Hallazgo` (ver `docs/contrato.md`) estable; es lo que conecta a todos.
- El LLM **propone**; la verificación determinista y el sandbox **deciden**.
  No declarar "alcanzable/explotable" sin que el PoC lo confirme.
- Código y PoCs **solo defensivos**: sandbox aislado, contra código propio.
- Agregar un caso nuevo = una lib vendored + una ruta en la app víctima + un
  aviso en `fixtures/advisories/` + (si aplica) un PoC por clase en `sandbox.py`
  y un patrón en `mitigator.py`. Sumarlo a `GROUND_TRUTH` en el eval.
- Antes de pushear: `python -m unittest discover -s tests` en verde.

## Ramas
`main` siempre corre. Trabajar en ramas y abrir PR; la CI corre tests + eval.
