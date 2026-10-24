# UI — panel de la demo

Panel estático (sin framework) que lee `public/run.json` y muestra:
- Los **dos relojes** de la carrera: atacante supuesto vs. tiempo medido de Ventana Cero.
- Por cada hallazgo, la **escalera de confianza** (0-4) iluminada hasta su nivel.
- Para el caso mitigado: el **camino de taint**, la **terminal del atacante**
  (antes 200 / después 403) y el **parche virtual** verificado.

## Correr

```bash
python -m ventana_cero                 # genera out/run.json y ui/public/run.json
python -m http.server -d ui/public     # sirve el panel
# abrir http://localhost:8000
```

`run.json` se regenera en cada corrida del orquestador. Se versiona una copia de
muestra para poder ver el panel sin correr nada.
