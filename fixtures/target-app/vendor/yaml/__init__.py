"""Minimal reproduction of PyYAML 3.13 `yaml.load` (CVE-2017-18342). Fixture.

Real bug: before 5.1, yaml.load() without an explicit Loader used the full
Loader, which honours `!!python/object/apply:<module>.<func> [args]` and calls
that function with attacker data. Only that tag and flat `key: value` scalars
are reproduced here; the real package is not vendored to keep the demo offline.
"""
import importlib
import re

__version__ = "3.13"
_APPLY = re.compile(r"!!python/object/apply:([\w.]+)\s*\[(.*)\]\s*$")


def _escalar(v: str):
    v = v.strip()
    m = _APPLY.match(v)
    if m:  # vulnerable: imports and calls whatever the document names
        modulo, _, func = m.group(1).rpartition(".")
        args = [a.strip().strip("'\"") for a in m.group(2).split(",") if a.strip()]
        return getattr(importlib.import_module(modulo or "builtins"), func)(*args)
    return v.strip("'\"")


def load(stream, Loader=None):
    """Parse a YAML document.  <-- vulnerable: no safe Loader by default."""
    texto = stream if isinstance(stream, str) else stream.read()
    if ":" not in texto.split("!!")[0] or texto.lstrip().startswith("!!"):
        return _escalar(texto)
    out = {}
    for linea in texto.splitlines():
        k, sep, v = linea.partition(":")
        if sep and k.strip():
            out[k.strip()] = _escalar(v)
    return out
