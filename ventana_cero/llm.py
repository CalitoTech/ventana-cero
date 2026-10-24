"""Puente opcional con el LLM.

Diseño clave: el LLM es OPCIONAL. Si hay ANTHROPIC_API_KEY, se usa para los pasos
difusos (derivar el símbolo del diff, razonar taint, proponer PoC). Si no, cada
etapa cae a una heurística determinista, de modo que el esqueleto corre completo
offline y la demo es reproducible.

Sin dependencias externas: usa urllib. El LLM *propone*; la verificación
determinista y el sandbox *deciden*.

Caché: cada respuesta se guarda en fixtures/llm-cache.json (o VC_LLM_CACHE), con
clave = hash de modelo + system + prompt. La demo reproduce esas respuestas sin
red ni clave, así que es determinista y no gasta créditos en el escenario.
"""
from __future__ import annotations

import hashlib
import json
import os
import urllib.request
from pathlib import Path

API_URL = "https://api.anthropic.com/v1/messages"
MODELO_BARATO = os.environ.get("VC_MODELO_BARATO", "claude-haiku-4-5-20251001")
MODELO_FUERTE = os.environ.get("VC_MODELO_FUERTE", "claude-sonnet-5-5")


def _ruta_cache() -> Path:
    defecto = Path(__file__).resolve().parent.parent / "fixtures" / "llm-cache.json"
    return Path(os.environ.get("VC_LLM_CACHE", defecto))


def _leer_cache() -> dict:
    try:
        return json.loads(_ruta_cache().read_text(encoding="utf-8"))
    except Exception:
        return {}


def _guardar_cache(clave: str, texto: str) -> None:
    cache = _leer_cache()
    cache[clave] = texto
    try:
        _ruta_cache().write_text(
            json.dumps(cache, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8")
    except Exception:
        pass  # el caché es una optimización: nunca rompe el lazo


def clave_cache(prompt: str, *, system: str | None = None, fuerte: bool = False) -> str:
    modelo = MODELO_FUERTE if fuerte else MODELO_BARATO
    return hashlib.sha256(f"{modelo}\n{system or ''}\n{prompt}".encode()).hexdigest()[:16]


def disponible() -> bool:
    """Hay LLM si hay clave o respuestas en caché para reproducir sin red."""
    return bool(os.environ.get("ANTHROPIC_API_KEY")) or bool(_leer_cache())


def completar(prompt: str, *, system: str | None = None, fuerte: bool = False,
              max_tokens: int = 1024) -> str | None:
    """Devuelve el texto del modelo (del caché si ya se pidió), o None.

    Nunca lanza: el que llama debe tener siempre una ruta heurística de respaldo.
    """
    clave = clave_cache(prompt, system=system, fuerte=fuerte)
    cache = _leer_cache()
    if clave in cache:
        return cache[clave]
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
    texto = _llamar_api(cuerpo, key)
    if texto:
        _guardar_cache(clave, texto)
    return texto


def _llamar_api(cuerpo: dict, key: str) -> str | None:
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
