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

## Estructura del repo

```
services/
  detector/      # 1 · matching de avisos contra dependencias (OSV)
  reachability/  # 2-3 · símbolo del fix, AST, taint, la escalera
  sandbox/       # prueba: contenedor aislado + runner de PoC
  mitigator/     # 4-5 · parche virtual + PR del parche de código
  orchestrator/  # el lazo que une todo + motor de política
  ui/            # dashboard: grafo, los dos relojes, terminal del atacante
fixtures/
  target-app/    # repo víctima sembrado para la demo
  advisories/    # avisos enlatados con su commit de fix
eval/            # banco de pruebas y métricas
docs/            # product brief, alcanzabilidad, roadmap
```

## Contrato de datos

Objeto `Hallazgo` que fluye por todo el lazo. Ver [`docs/contrato.md`](docs/contrato.md).

## Cómo arrancar

Ver la [hoja de ruta](docs/roadmap.md). Regla de oro: primero el **esqueleto que
camina** (el lazo entero sobre un caso, aunque sea feo), después la calidad.

## ⚠️ Ética y alcance

Esto genera PoCs. Úsalo solo de forma defensiva:

- Los PoC corren **solo contra código propio, en un sandbox aislado sin red**.
- La salida son **parches y mitigaciones, nunca exploits** listos para usar.
- Nada irreversible se aplica sin prueba o sin aprobación humana.

## Equipo (team-21)

Maikol Aguilar · Christian Mendoza · José Gómez · Carlos Navas · Juan Alvarado
