# Guion del pitch (3:00)

Guion cronometrado para el pitch de Ventana Cero. Dos roles: **quien habla** (H) y
**quien maneja la demo** (D). Ensáyenlo 10 veces con cronómetro. Deck:
"Ventana Cero: pitch". Todo lo que se dice está también en las notas de cada slide.

> Regla: la demo va en vivo con modo guion (temperatura 0, datos cacheados) y un
> **video de respaldo** listo por si algo falla.

---

## 0:00 – 0:25 · Gancho (slide: cover → ventana)
**H:** "Cuando sale una vulnerabilidad crítica, los atacantes con IA arman el
exploit en **horas**. Los defensores tardan **días** en parchear su código. Con
PHP2Shell, Cloudflare puso una regla antes del parche porque le avisaron antes.
¿Quién hace eso por la librería de *tu* app? Nadie. En esa ventana ocurre casi todo
el daño."
*(pasa a `ventana`, señala la franja)*
"Esto es la ventana del n-day. Ventana Cero la cierra en **minutos**, y lo prueba."

## 0:25 – 0:50 · Por qué se pierde (slide: pierde)
**H:** "El defensor llega tarde por tres cosas: **ruido** —cientos de alertas, casi
ninguna explotable—; **fricción** —el parche tarda días—; y **desconfianza**:
nadie deja que una IA parchee producción sola. Pero el defensor tiene una ventaja:
tiene el código y el derecho de actuar primero."

## 0:50 – 1:10 · La idea + diferenciador (slide: idea → diferenciador)
**H:** "Ventana Cero **no es una IA que parchea** —eso ya existe. Es un sistema que
solo actúa sobre lo que puede **probar**."
*(pasa a `diferenciador`)*
"La detección ya está resuelta: Dependabot, Snyk, Socket. No la reconstruimos, la
**consumimos**. Nuestro foso es la última fila: mitigar y parchar solo, con prueba."

## 1:10 – 1:30 · El lazo + la escalera (slide: lazo → escalera)
**H:** "El lazo: del aviso, triamos por **alcanzabilidad**, probamos con un PoC,
mitigamos al instante y preparamos el parche."
*(pasa a `escalera`)*
"La alcanzabilidad no es sí o no: es una escalera. Y el salto a 'actuar' solo pasa
cuando el **PoC se dispara**. El modelo propone; el sandbox confirma."

## 1:30 – 2:15 · DEMO EN VIVO (slide: demo → el panel)
**D** maneja; **H** narra.
**H:** "Mismo aviso, dos finales."
- **D** muestra el ataque sin Ventana Cero: `curl → 200 OK`. "El atacante entra."
- **D** activa Ventana Cero y le da a **Reproducir**: la escalera se ilumina, el PoC
  confirma, el parche virtual se aplica. El reloj del defensor marca segundos.
- **D** repite el ataque: `curl → 403`.
**H:** "Mismo ataque. Ventana cerrada. En segundos, con el PoC como prueba."

## 2:15 – 2:30 · Proof-gating (slide: proofgating)
**H:** "¿Y si se equivoca? Este caso tiene taint, parece explotable, pero el PoC
**no** lo confirma. El sistema **no actúa**: lo manda a revisión. La prueba manda
sobre la sospecha. Cero falsos positivos accionados."

## 2:30 – 2:45 · Resultados + carril (slide: resultados → carril)
**H:** "No lo contamos, lo medimos: 8 escenarios controlados, uno por cada peldaño
de la escalera, incluido el sanitizador y la versión ya parcheada. Las 2 explotables
se mitigan, cero acciones sin PoC confirmado. Repo público con CI."
*(pasa a `carril`)*
"Y elegimos el carril que nadie toca: **IA para defender**, no otro firewall."

## 2:45 – 3:00 · Cierre (slide: negocio → cierre)
**H (rápido):** "Entra en modo sombra —un informe de exposición es la venta—, núcleo
abierto más nube."
*(pasa a `cierre`, mira al jurado, sin leer)*
"**La detección ya está resuelta. Nosotros construimos lo que actúa.** Ventana Cero."

---

## Preguntas probables (y respuestas)

- **"Cloudflare ya bloqueó PHP2Shell antes del parche de PHP: los WAF ya cierran
  la ventana."** → Es cierto, y nos da la razón: un parche virtual antes del parche
  funciona. Pero fue la excepción: un CVE del runtime, con divulgación coordinada,
  donde Cloudflare tuvo aviso previo y escribió una regla genérica. Solo protege el
  tráfico que pasa por Cloudflare, los atacantes mutaron payloads para esquivarla y
  el propio Cloudflare pide parchear igual. Las librerías de *tu* app no reciben
  regla de nadie, y un WAF conoce el CVE pero no tu código. Ventana Cero hace la
  regla para tu app: acotada a la ruta y el parámetro alcanzables, confirmada por un
  PoC y verificando que el tráfico legítimo pasa. Esa regla se puede cargar en un WAF:
  no competimos con el WAF, le damos reglas. *(Hoy la regla la aplica la app de la
  demo; exportarla a un WAF es roadmap.)*
  **En una línea:** "Cloudflare cerró PHP2Shell porque le avisaron. Nosotros
  cerramos la ventana de lo que nadie avisa."
- **"¿Esto no es AIxCC / un auto-patcher?"** → "AIxCC descubre y parchea en un
  repo dado. Nosotros hacemos el lazo autónomo de respuesta al n-day: alcanzabilidad
  + PoC + mitigación instantánea, gated por prueba. Ese lazo pegado casi no existe."
- **"¿Cómo sé que no rompe producción?"** → "Solo auto-actuamos con PoC confirmado,
  y el parche virtual es reversible. El parche de código siempre pasa por un humano."
- **"¿Funciona en mi stack?"** → "El esqueleto es Python; el enfoque (símbolo del
  fix + taint + PoC) es general. Hoy cubrimos dos clases; agregar una es una lib,
  una ruta, un aviso y un PoC."
- **"¿Y los falsos negativos?"** → "El taint estático pierde casos; por eso 'no
  alcanzable' significa despriorizar, no 'seguro'. Somos honestos: es priorización
  y prueba, no una garantía formal."
- **"¿El LLM es confiable?"** → "No dependemos de él para decidir: propone; el
  sandbox decide. En el panel se ve: 'símbolo propuesto por el LLM', y después el
  taint y el PoC lo confirman o lo descartan. Corre incluso sin LLM, con heurísticas."
- **"¿Dónde corre el PoC?"** → "En la demo, en un subproceso local contra nuestra
  propia app. En producción, en un contenedor aislado sin red y con límites. Y los
  PoC son canarios benignos (7*6=42), nunca un exploit con daño."

## Checklist antes de subir al escenario
- [ ] `python -m ventana_cero.demo --sin-pausa` termina en "Ventana cerrada."
  (ensayo general: 200 → 403 → 200).
- [ ] `python -m ventana_cero` corrido; `ui/public` servido y abierto (puerto 8000).
- [ ] En el escenario, `python -m ventana_cero.demo` (app en el 8001, pausa en cada
  paso para narrar).
- [ ] Video de respaldo de la demo, cargado y listo.
- [ ] Modo guion / temperatura 0; sin dependencia de red.
- [ ] Repo abierto en otra pestaña (la prueba de que funciona).
- [ ] Cronometrado a 3:00 con margen de 10s.
