# UI — panel de la demo

Panel estático (sin framework) que lee `public/run.json` y muestra:
- Los **dos relojes** de la carrera: atacante supuesto vs. tiempo medido de Ventana Cero.
- Por cada hallazgo, la **escalera de confianza** (0-4) iluminada hasta su nivel.
- Para el caso mitigado: el **camino de taint**, la **terminal del atacante**
  (antes 200 / después 403) y el **parche virtual** verificado.

## Correr

```bash
python -m ventana_cero.server          # panel en vivo en http://localhost:8000
```

"Correr análisis" hace `POST /api/run`: el servidor ejecuta el lazo real
(detector → alcanzabilidad → sandbox → mitigador), devuelve el `run.json` recién
generado y el panel lo reproduce. Si se sirve como estático
(`python -m http.server -d ui/public`), el panel cae a modo "foto de la última
corrida" y solo anima el `run.json` versionado:

```bash
python -m ventana_cero                 # regenera ui/public/run.json
```

`run.json` se regenera en cada corrida del orquestador. Se versiona una copia de
muestra para poder ver el panel sin correr nada.
