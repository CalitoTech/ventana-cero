"""Ventana Cero — defensa autónoma del n-day, con prueba.

Paquete con un módulo por etapa del lazo:
  detector      → 1 · matching de avisos contra dependencias
  reachability  → 2-3 · símbolo del fix, AST, taint, la escalera
  sandbox       → prueba: subproceso aislado + runner de PoC
  mitigator     → 4-5 · parche virtual + parche de código
  policy        → mapea la escalera a una decisión
  orchestrator  → el lazo que une todo y emite el reporte
"""
from .hallazgo import Hallazgo

__all__ = ["Hallazgo"]
__version__ = "0.1.0"
