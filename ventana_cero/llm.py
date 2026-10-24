"""Puente opcional con el LLM.

Diseño clave: el LLM es OPCIONAL. Si hay ANTHROPIC_API_KEY, se usa para los pasos
difusos (derivar el símbolo del diff, razonar taint, proponer PoC). Si no, cada
etapa cae a una heurística determinista, de modo que el esqueleto corre completo
offline y la demo es reproducible.

Sin dependencias externas: usa urllib. El LLM *propone*; la verificación
determinista y el sandbox *deciden*.
"""
from __future__ import annotations

import json
import os
import urllib.request

API_URL = "https://api.anthropic.com/v1/messages"
MODELO_BARATO = os.environ.get("VC_MODELO_BARATO", "claude-haiku-4-5-20251001")
MODELO_FUERTE = os.environ.get("VC_MODELO_FUERTE", "claude-sonnet-5-5")


def disponible() -> bool:
    return bool(os.environ.get("ANTHROPIC_API_KEY"))


def completar(prompt: str, *, system: str | None = None, fuerte: bool = False,
              max_tokens: int = 1024) -> str | None:
    """Devuelve el texto del modelo, o None si no hay clave o falla la llamada.

    Nunca lanza: el que llama debe tener siempre una ruta heurística de respaldo.
    """
    key = os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        return None
    cuerpo = {
        "model": MODELO_FUERTE if fuerte else MODELO_BARATO,
        "max_tokens": max_tokens,
        "messages": [{"role": "user", "content": prompt}],
    }
    if system:
        cuerpo["system"] = system
    req = urllib.request.Request(
        API_URL,
        data=json.dumps(cuerpo).encode(),
        headers={
            "content-type": "application/json",
            "x-api-key": key,
            "anthropic-version": "2023-06-01",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            data = json.loads(r.read())
        partes = [b.get("text", "") for b in data.get("content", []) if b.get("type") == "text"]
        return "".join(partes).strip() or None
    except Exception:
        return None
