# Sandbox sin Docker (jaula por audit hooks)

Objective: run the PoC target app isolated without Docker: no outbound network, no
subprocesses, restricted file access, hard time limit, memory limit where the OS allows.

Scope: `ventana_cero/jaula.py` (new), `ventana_cero/sandbox.py`, `tests/test_jaula.py`.
Constraint: stdlib only. Policy-level isolation, not a kernel boundary.

- [x] T1 audit-hook jail + sandbox integration + tests (route: inline)
  Evidence: python -m unittest discover -s tests -> 13 tests OK
