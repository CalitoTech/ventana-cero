# Contrato de datos: `Hallazgo`

Objeto que fluye por todo el lazo. Cada servicio lee unos campos y escribe otros.
Acordarlo temprano es lo que deja trabajar en paralelo sin bloquearse.

```python
from dataclasses import dataclass, field

@dataclass
class Hallazgo:
    # 1 · detección (OSV)
    advisory_id: str
    paquete: str
    version: str
    commit_fix: str | None = None

    # 2 · derivar símbolo (LLM sobre el diff del fix)
    simbolo_vulnerable: str | None = None      # p.ej. "lib.render"
    parametro_peligroso: str | None = None     # p.ej. "arg 0"

    # 3 · alcanzabilidad
    nivel: int = 0                              # 0..4, la escalera de confianza
    camino_taint: list[str] = field(default_factory=list)  # fuente → ... → sink

    # 4 · prueba
    poc: str | None = None
    resultado_poc: str | None = None           # "disparo" | "no_disparo" | None

    # 5 · mitigación
    parche_virtual: dict | None = None
    pr_parche_codigo: str | None = None        # url del PR

    # 6 · decisión (motor de política)
    decision: str = "ignorar"                  # ignorar|vigilar|preparar|mitigar|actuar
```

## La escalera (`nivel`)

| nivel | significa | decisión sugerida |
|---|---|---|
| 0 | dependencia presente | ignorar |
| 1 | símbolo referenciado en el código | vigilar |
| 2 | alcanzable en el grafo de llamadas | preparar |
| 3 | con taint (fuente no confiable → parámetro peligroso) | mitigar |
| 4 | PoC confirmado en sandbox | actuar |

Regla: nada que toque producción se aplica solo por debajo del nivel 4 (prueba),
salvo mitigaciones reversibles de bajo riesgo según la política.
