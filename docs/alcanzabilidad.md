# Alcanzabilidad — el núcleo técnico

La pregunta que separa el proyecto de un escáner: no "¿tengo la librería
vulnerable?", sino "¿el código vulnerable es realmente alcanzable desde una
entrada no confiable en mi app?".

## La escalera de confianza

"Alcanzable" no es sí/no: es una escalera. Cada peldaño es más caro de calcular
pero más confiable, y define qué hace el sistema.

| Nivel | Significa | Acción |
|---|---|---|
| 0 | Dependencia presente (lo que hace `npm audit`) | Ruido |
| 1 | Símbolo vulnerable referenciado en tu código | Vigilar |
| 2 | Alcanzable en el grafo de llamadas | Preparar |
| 3 | Con taint: una entrada no confiable llega al parámetro peligroso | Mitigar |
| 4 | PoC confirmado en el sandbox | Actuar solo |

## El detalle que casi nadie resuelve

La mayoría de los avisos no dicen qué función es vulnerable. Pero casi siempre
enlazan el **commit que arregla el bug**. El diff del fix dice qué función cambió
y qué parámetro es peligroso → de ahí sale el "símbolo vulnerable" y el "sink".

## Cómo lo calculamos (híbrido)

Un motor general de grafo de llamadas por lenguaje es trabajo de meses. No lo
intentamos. Tres pasos de costo creciente, y la prueba dinámica manda:

- **Barato y determinista:** buscar el símbolo (AST), recortar archivos y rutas, ejecutar el PoC y comparar.
- **Donde entra el LLM:** derivar el símbolo del diff, razonar el camino de taint, proponer el PoC.

**Regla de oro:** el LLM propone; el análisis estático recorta; el sandbox
confirma. Nunca se declara "alcanzable" por la opinión del modelo: lo declara el
PoC que se dispara.

## Ejemplo

```python
@app.get("/preview")
def preview(request):
    plantilla = request.args["tpl"]   # fuente: entrada no confiable
    return lib.render(plantilla)      # sink: símbolo vulnerable
```

El dato del atacante viaja sin filtro desde la URL hasta el parámetro peligroso.
Eso es nivel 3. El PoC lo confirma → nivel 4 → se aplica el parche virtual.

## Lo que esto NO garantiza

"No alcanzable" significa **despriorizar, no "seguro"**. El análisis estático
pierde caminos por reflexión, `eval`, inyección de dependencias o dispatch
dinámico (sobre todo en JS). Es priorización y prueba, no una garantía de
solidez matemática. Decirlo claro en el pitch.

## Recorte para la hackathon

- **Ecosistema:** Python (rutas claras, taint fácil de mostrar).
- **Clase de vuln:** una con fuente→sink clara (inyección de plantilla, comandos, deserialización).
- **Construir:** derivar símbolo del diff → AST → recortar rutas → razonar taint → PoC en sandbox.
- **Métrica:** sobre N casos sembrados, precisión/recall de la escalera y cuántos confirma el PoC.
