# 👋 Empieza aquí (team-21)

Este documento es el punto de partida. Léelo completo (5 min), corre el proyecto
(2 min) y recién después métete al código. Así llegas con el contexto puesto.

> **Orden sugerido:** este archivo → correr el lazo → `README.md` → `docs/` → los
> issues de GitHub.

---

## 1. Qué estamos construyendo, en una frase

**Ventana Cero: defensa autónoma del n-day, con prueba.** Cuando se publica una
vulnerabilidad, confirmamos si te afecta y es *alcanzable*, lo probamos con un PoC
en un sandbox, aplicamos una mitigación instantánea y preparamos el parche de
código — **sin un humano en el camino crítico**.

Track: **AI Security → Defensa (def/acc)** de Platanus Hack 26.

## 2. Por qué ESTE proyecto (y no otro)

Comparamos cuatro ideas. Esta ganó por dos razones (detalle en `docs/decision.md`):

- **"AI Security" tiene dos carriles.** Uno es *proteger a la IA* (guardrails,
  firewalls): está **saturado** — casi los 16 finalistas pasados son de ahí. El
  otro es *usar IA para defender* (def/acc): está **vacío**. Nosotros vamos por el
  vacío, así nos diferenciamos por categoría, no por detalle.
- **La originalidad pesa solo 15%.** Lo técnico + ambición + ejecución + impacto
  suman 85%. Elegimos algo que podemos construir, demostrar y medir.

## 3. La idea clave que tienes que entender

El peligro no es el día cero: es la **ventana del n-day**, entre que se publica el
aviso y que estás protegido. Los atacantes con IA arman el exploit en horas; los
defensores parchean en días. **Nosotros cerramos esa ventana en minutos.**

Y nuestro diferenciador, que hay que poder decir de memoria:

> **La detección de vulnerabilidades ya está resuelta (Dependabot, Snyk, Socket).
> Nosotros no la reconstruimos: la consumimos. Construimos lo que ACTÚA después.**

No somos "una IA que parchea" (eso ya existe: AIxCC, Copilot Autofix). Somos un
sistema con tres propiedades que ellos no tienen: **con prueba**, **autónomo** y
**a tiempo**.

## 4. Cómo funciona (el lazo)

```
aviso → ¿me afecta y es ALCANZABLE? → PoC en sandbox → mitigación instantánea → PR con parche
```

El corazón técnico es la **alcanzabilidad**, que no es sí/no sino una escalera:

| Nivel | Significa | Qué hace el sistema |
|---|---|---|
| 0 | la dependencia está instalada | ignorar (ruido) |
| 1 | el símbolo vulnerable se referencia | vigilar |
| 2 | se llama, pero con datos constantes | preparar |
| 3 | una entrada no confiable llega al parámetro peligroso (taint) | mitigar |
| 4 | el PoC lo confirmó en el sandbox | **actuar solo** |

**Regla de oro del proyecto:** el LLM *propone* (qué símbolo, qué camino, qué PoC);
el análisis estático *recorta* y el **sandbox *confirma***. Nunca decimos
"explotable" por la opinión del modelo: lo dice el PoC que se dispara.

## 5. Qué ya está hecho (el esqueleto camina)

El lazo corre de punta a punta sobre 5 casos de demo. No inventamos nada en el
pitch: esto ya funciona y está medido.

- 2 clases llegan a **nivel 4 → ACTUAR** con parche virtual verificado (SSTI y path traversal).
- 1 caso demuestra el **proof-gating**: hay taint pero el PoC no confirma → **REVISAR** (no auto-actuamos).
- 2 casos son **ruido filtrado** (presente-no-alcanzable, y solo-referenciado).
- Eval: 100% precisión/recall, 60% de ruido descartado, sobre los fixtures actuales.

## 6. Córrelo ahora (2 minutos)

Solo necesitas **Python 3.11+**. No hay que instalar nada.

```bash
git clone https://github.com/CalitoTech/ventana-cero.git
cd ventana-cero

python -m ventana_cero                 # corre el lazo; imprime el resultado
python -m http.server -d ui/public     # abre http://localhost:8000 y dale "Reproducir"
python -m ventana_cero.demo            # demo en vivo: curl 200 → Ventana Cero → curl 403
python -m unittest discover -s tests   # tests en verde
python eval/run_eval.py                # las métricas
```

El LLM es **opcional**: sin `ANTHROPIC_API_KEY` todo corre con heurísticas, offline
y determinista. Las respuestas del LLM se guardan en `fixtures/llm-cache.json`, así
que la demo reproduce lo que propuso el modelo sin red ni clave (y sin gastar
créditos). Con la clave, los avisos nuevos se consultan una vez y quedan en caché.

## 7. Dónde está cada cosa

**Documentos (`docs/`)** — léelos en este orden:
- `producto.md` — el producto completo (problema, lazo, negocio, ética).
- `alcanzabilidad.md` — el núcleo técnico, a fondo.
- `decision.md` — por qué elegimos esto.
- `roadmap.md` — el plan de 36h y el reparto por persona.
- `contrato.md` — el objeto `Hallazgo` que conecta todo el código.
- `TASKS.md` — los tickets del siguiente tramo.
- `guion-pitch.md` — el guion cronometrado del pitch de 3 minutos.
- `artifacts/` — las páginas interactivas (respaldo).

**Código (`ventana_cero/`)** — un módulo por etapa del lazo:
`detector` → `reachability` → `sandbox` → `mitigator`, con `policy` y `orchestrator`.

**Lo demás:** `fixtures/` (el caso de demo), `ui/` (el panel), `eval/`, `tests/`.

## 8. Tu primer aporte

1. Corre el proyecto y abre el panel; entiende los 5 casos.
2. Lee tu bloque en `docs/roadmap.md` (reparto) y `docs/TASKS.md`.
3. Toma un [issue](https://github.com/CalitoTech/ventana-cero/issues), haz una rama, abre un PR. La CI corre tests + eval.

Regla para no romper la demo: **`main` siempre tiene que correr.** Antes de pushear,
`python -m unittest discover -s tests` en verde.

## 9. Lo no negociable (ética)

Esto genera PoCs. Solo defensivo:
- PoCs **solo contra código propio**, en sandbox aislado.
- La salida son **parches y mitigaciones, nunca exploits**.
- Nada irreversible sin prueba o sin aprobación humana.

---

¿Dudas? Todo el "porqué" está en `docs/`. Todo el "cómo" está en el código y corre
con un comando. Bienvenido. 🛡️
