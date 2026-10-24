# Ventana Cero

**Defensa autónoma del n-day, con prueba.** Cuando se publica una vulnerabilidad,
Ventana Cero confirma si te afecta y es *alcanzable*, lo prueba con un PoC en un
sandbox aislado, aplica una mitigación instantánea y prepara el parche de código
verificado — sin un humano en el camino crítico.

> Proyecto para Platanus Hack 26 · Track **AI Security** (def/acc). Equipo: team-21.
> Nombre provisional.

---

## El problema

El peligro no es el día cero: es la **ventana del n-day**, entre que se publica el
aviso y que estás protegido. Los atacantes con IA arman un exploit en horas; los
defensores parchean en días. Ahí ocurre casi todo el daño.

## Nuestro diferenciador

La detección de vulnerabilidades conocidas ya está resuelta (Dependabot, Snyk,
Socket, CodeQL). **No la reconstruimos: la consumimos.** Nuestro valor empieza
donde esas herramientas terminan:

| Capacidad | ¿Ya existe? | ¿Es nuestro? |
|---|---|---|
| Detectar vulns conocidas | Sí, maduro | No — lo consumimos |
| Priorizar por alcanzabilidad | Emergente | En parte |
| Descubrir 0-days con IA | Frontera | No — es la amenaza |
| **Mitigar y parchar solo, con prueba** | **Casi nadie** | **Sí — el foso** |

## El lazo

1. **Vigilar** — feeds de avisos (OSV, GHSA, CISA KEV, EPSS) + tus dependencias.
2. **Triar por alcanzabilidad** — ¿el código vulnerable es llamable desde una entrada no confiable?
3. **Probar** — PoC en sandbox aislado que lo confirma en tu contexto.
4. **Mitigar al instante** — parche virtual que tapa el hueco en segundos.
5. **Parchear de verdad** — PR con el parche de código y su prueba.
6. **Verificar y vigilar** — el PoC ahora falla; se retira el parche virtual.

## La escalera de confianza (alcanzabilidad)

| Nivel | Significa | Acción |
|---|---|---|
| 0 | Dependencia presente | Ruido |
| 1 | Símbolo referenciado | Vigilar |
| 2 | Alcanzable en el grafo de llamadas | Preparar |
| 3 | Con taint: entrada no confiable → parámetro peligroso | Mitigar |
| 4 | PoC confirmado en sandbox | Actuar solo |

El LLM **propone** (símbolo, camino de taint, PoC); el análisis estático recorta
y el **sandbox confirma**. Nunca declaramos "alcanzable" por la opinión del modelo.

## Cómo arrancar

Requisito: **Python 3.11+**. No hace falta instalar nada (el esqueleto usa solo la
librería estándar). El LLM es opcional: sin `ANTHROPIC_API_KEY`, cada etapa cae a
una heurística determinista y el lazo corre completo offline.

```bash
# 1. correr el lazo de punta a punta sobre el caso de la demo
python -m ventana_cero

# 2. ver el panel de la demo
python -m http.server -d ui/public      # abrir http://localhost:8000

# 3. pruebas
python -m unittest discover -s tests

# 4. evaluación (métricas)
python eval/run_eval.py
```

Con el LLM activo (opcional, mejora derivar el símbolo y el PoC):
```bash
export ANTHROPIC_API_KEY=sk-...
```

## Estructura del repo

```
ventana_cero/        # el paquete: un módulo por etapa del lazo
  hallazgo.py        #   contrato de datos (el objeto que fluye por el lazo)
  llm.py             #   puente OPCIONAL con el LLM (+ fallback heurístico)
  detector.py        # 1 · matching de avisos contra dependencias (OSV)
  reachability.py    # 2-3 · símbolo del fix, AST, taint, la escalera
  sandbox.py         #   prueba: subproceso aislado + runner de PoC
  mitigator.py       # 4-5 · parche virtual + parche de código
  policy.py          #   mapea la escalera a una decisión
  orchestrator.py    #   el lazo que une todo + emite out/run.json
fixtures/
  target-app/        # repo víctima sembrado (app + librería vulnerable ficticia)
  advisories/        # avisos enlatados estilo OSV, con su commit de fix
ui/public/           # panel de la demo (estático, lee run.json)
eval/                # banco de pruebas y métricas
tests/               # prueba de humo del lazo (unittest)
docs/                # product brief, alcanzabilidad, roadmap, decisión
```

## Contrato de datos

Objeto `Hallazgo` que fluye por todo el lazo. Ver [`docs/contrato.md`](docs/contrato.md).

## Estado actual

Esqueleto que camina: el lazo corre de punta a punta sobre el caso de la demo.
- `VC-2026-0001` (tinytpl, SSTI) → nivel 4 → **ACTUAR** + parche virtual verificado.
- `VC-2026-0002` (fastjson, presente pero no alcanzable) → nivel 0 → **IGNORAR** (ruido descartado).

Siguiente: endurecer el taint, más casos, el PR del parche de código y pulir la UI.
Ver la [hoja de ruta](docs/roadmap.md).

## ⚠️ Ética y alcance

Esto genera PoCs. Úsalo solo de forma defensiva:

- Los PoC corren **solo contra código propio, en un sandbox aislado sin red**.
- La salida son **parches y mitigaciones, nunca exploits** listos para usar.
- Nada irreversible se aplica sin prueba o sin aprobación humana.

## Equipo (team-21)

Maikol Aguilar · Christian Mendoza · José Gómez · Carlos Navas · Juan Alvarado
