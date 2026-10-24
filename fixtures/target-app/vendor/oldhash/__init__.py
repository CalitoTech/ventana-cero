"""oldhash 0.9.0 — hashes legacy. FICTICIO. md5() es débil (VC-2026-0005)."""
import hashlib

__version__ = "0.9.0"


def md5(x: bytes) -> str:
    return hashlib.md5(x).hexdigest()  # noqa: S324 (débil, sembrado)
