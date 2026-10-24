# Hoja de ruta (36h · 5 personas)

**Regla de oro:** primero el *esqueleto que camina* (el lazo entero sobre UN caso,
aunque sea feo), después la calidad. La demo debe correr de punta a punta al final
del día 1.

## Primeros 60 minutos — decidir
- **Ecosistema:** Python (FastAPI/Flask). Rutas claras, taint fácil de mostrar.
- **Clase de vuln:** una con fuente→sink clara (inyección de plantilla, de comandos o deserialización). Elegir UNA.
- **Caso de la demo:** repo víctima sembrado + aviso enlatado con su commit de fix + 2-3 rutas.
- **Modelos:** Claude Haiku 4.5 para pasos baratos; uno más fuerte para taint y PoC.
- **Repo + contrato de datos** acordado (ver `contrato.md`).

## Fases
| Horas | Fase | Resultado |
|---|---|---|
| H0–H2 | Arranque | decisiones, contrato, caso sembrado, keys |
| H2–H10 | Esqueleto que camina | el lazo entero sobre 1 caso, crudo |
| H10–H20 | Endurecer | taint mejor, PoC robusto, política, PR de parche |
| H20–H28 | Demo pulida | grafo, dos relojes, terminal del atacante, WebSocket |
| H28–H32 | Evaluación | N casos, métricas (precisión, tiempo, bloqueo) |
| H32–H36 | Pitch | video de respaldo, slides, 10 ensayos |

## Reparto
- **A** — orquestación + detección (OSV). Dueño del contrato.
- **B** — alcanzabilidad (símbolo del diff, AST, taint, la escalera).
- **C** — sandbox + PoC. *Riesgo alto: empieza en H2.*
- **D** — mitigación + política + eventos.
- **E** — UI + evaluación + pitch. Arranca con datos falsos.

## Ruta crítica
Sandbox/PoC y taint son lo riesgoso: empiezan en H2. La UI arranca con datos
falsos. Detección (OSV) es reusar una API: rápido.

## Líneas de corte (si van atrasados)
1. Cae el PR del parche de código (se queda el parche virtual).
2. Evaluación a 3 casos en vez de N.
3. Animación fina del grafo.

**Nunca se recorta:** un caso completo de punta a punta, la demo de la carrera y el video de respaldo.
