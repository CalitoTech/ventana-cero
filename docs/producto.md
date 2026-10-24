# Ventana Cero — brief de producto

**Defensa autónoma del n-day, con prueba.** Cuando sale una vulnerabilidad,
cierra tu ventana de exposición antes de que el atacante llegue. Con prueba, sin
humano en el camino crítico. ("Ventana Cero" es nombre provisional.)

## El problema: la ventana del n-day

El peligro no es el día cero, es lo que pasa después del anuncio. Al publicarse
una vuln crítica (el caso reciente de PHP), los atacantes con IA arman un exploit
en horas; los defensores tardan días o semanas. Esa franja es la ventana, y ahí
ocurre casi todo el daño.

Por qué el defensor es lento:
1. **Ruido** — los escáneres marcan cientos de CVEs; el ~95% no es alcanzable.
2. **Fricción del parche** — el parche de código tarda días (review, regresión, deploy).
3. **Desconfianza** — nadie deja que una IA parchee producción sola.

La ventaja def/acc: el defensor llega primero porque tiene el código fuente, el
CI y el derecho de actuar antes del ataque.

## La idea

No es "una IA que parchea". Es un sistema que **solo actúa sobre lo que puede
probar**, tapa el hueco **ya** y prepara el parche bueno **con calma**, sin un
humano en el camino crítico.

## Nuestro diferenciador

La detección de vulns conocidas está resuelta y saturada (Dependabot, Snyk,
Socket, CodeQL, Semgrep). **No la reconstruimos: la consumimos como entrada.**
Nuestro valor empieza donde esas herramientas terminan.

| Capacidad | ¿Ya existe? | ¿Es nuestro diferenciador? |
|---|---|---|
| Detectar vulns conocidas (deps y código) | Sí, muy maduro | No — lo consumimos |
| Priorizar por alcanzabilidad | Emergente (Endor, Socket, Semgrep) | En parte — es un paso del lazo |
| Descubrir 0-days con IA | Frontera / research | No — es la amenaza, no el producto |
| **Mitigar y parchar solo, con prueba, tras el aviso** | **Casi nadie** | **Sí — aquí está el foso** |

Marco para el pitch: que la IA ya descubra y explote 0-days sola (Google "Big
Sleep" en SQLite, XBOW en HackerOne) no nos compite; **es justo lo que nos
justifica**. A esa velocidad de ataque, la única respuesta es una defensa igual
de automática. (Verificar esos ejemplos antes de citarlos.)

## El lazo, de aviso a protección

1. **Vigilar** — feeds de avisos (OSV, GHSA, CISA KEV, EPSS) + tu SBOM.
2. **Triar por alcanzabilidad** — ¿el código vulnerable es llamable desde una entrada no confiable?
3. **Probar en sandbox** — PoC aislado que lo confirma en tu contexto.
4. **Mitigar al instante** — parche virtual (regla WAF/RASP, flag) que tapa el hueco en segundos.
5. **Parchear de verdad** — PR con el parche de código y su PoC adjunto.
6. **Verificar y vigilar** — el PoC ahora falla; se retira el parche virtual.

## Por qué no es un auto-patcher

Un auto-patcher es una **capacidad** ("dame un bug, te doy un parche"); Ventana
Cero es una **propiedad del sistema**: confiable, autónomo y a tiempo. Cuatro
cosas lo separan: (1) con prueba, (2) a dos velocidades, (3) alcanzabilidad
primero, (4) en tu contexto.

## Arquitectura (resumen)

El LLM **propone** (símbolo vulnerable, camino de taint, PoC, parches); la
verificación determinista y la política **deciden**. Nada irreversible se aplica
sin prueba o sin humano.

## Negocio

- **A quién:** equipos que envían rápido y tienen superficie (SaaS, fintech, infra), y MSSPs.
- **Cómo entrar:** primero observar (triage de alcanzabilidad, solo lectura), luego parche virtual, luego PRs.
- **Precio:** núcleo abierto + nube (panel de flota, políticas, auditoría).
- **Foso que compone:** biblioteca de firmas de alcanzabilidad, PoCs verificados y recetas de parche por CWE/ecosistema.

## Ética y doble uso (no negociable)

- Los PoC corren **solo contra código propio, en un sandbox aislado sin red**.
- La salida son **parches y mitigaciones, nunca exploits** listos para usar.
- Nada irreversible se aplica sin prueba o sin aprobación humana.
