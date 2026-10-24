# Tareas (siguiente tramo)

El esqueleto ya camina de punta a punta. Esto es lo que sigue, mapeado al reparto
de la [hoja de ruta](roadmap.md). Marca con [x] al cerrar.

## A — Orquestación + detección
- [ ] Ruta OSV online real (`api.osv.dev/v1/querybatch`) detrás de un flag.
- [ ] Ingerir CISA KEV y EPSS reales (hoy vienen del aviso enlatado).
- [ ] Config de política en archivo (umbrales de prioridad, qué auto-mitiga).

## B — Alcanzabilidad
- [ ] Taint inter-procedural (seguir a través de funciones propias, no solo intra).
- [ ] Más fuentes/sinks por framework (Flask, FastAPI, Django).
- [ ] Activar la ruta LLM para derivar símbolo y camino (hoy cae a heurística).

## C — Sandbox + PoC
- [ ] Ejecutar el PoC en un contenedor aislado sin red (hoy es subproceso local).
- [ ] Límites de CPU/memoria/tiempo al PoC.
- [ ] Generación de PoC por LLM para clases nuevas (hoy canarios fijos).

## D — Mitigación + política
- [ ] Abrir el PR del parche de código de verdad (hoy guarda el .patch).
- [ ] Retirar el parche virtual cuando el de código está en producción.
- [ ] Más tipos de parche virtual (middleware real, no solo regla de patrón).

## E — UI, evaluación y pitch
- [ ] Eventos en vivo por WebSocket (hoy el panel lee run.json).
- [ ] Más casos en el banco de pruebas (apuntar a 20+).
- [ ] Guion de 3 min + video de respaldo + slides.

## Transversal
- [x] Un caso con un CVE real de PyPI (CVE-2017-18342, PyYAML `yaml.load`).
- [x] Segundo CVE real de PyPI, clase nueva (CVE-2019-6690, python-gnupg: inyección de comando).
- [x] Tercer CVE real de PyPI, clase nueva (CVE-2019-7164, SQLAlchemy: inyección SQL, SQLite en memoria).
- [ ] Medir y publicar la latencia que agrega la atribución.
