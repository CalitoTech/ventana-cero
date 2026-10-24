# Referencia: cómo queda render() en tinytpl 1.1.0 (ya NO evalúa la plantilla).
def render(plantilla: str, **contexto) -> str:
    """Renderiza la plantilla sustituyendo {{ nombre }} SOLO por valores del contexto."""
    def _sub(m):
        nombre = m.group(1).strip()
        return str(contexto.get(nombre, ""))  # sin eval: solo lookup seguro
    return _EXPR.sub(_sub, plantilla)
