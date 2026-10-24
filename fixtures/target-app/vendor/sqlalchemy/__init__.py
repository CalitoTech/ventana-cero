"""Minimal reproduction of a SQLAlchemy < 1.3.0 SQL injection (CVE-2019-7164). Fixture.

Real bug: before 1.3.0 some clauses were built from caller strings without
binding, so attacker data reached the SQL text and could inject arbitrary SQL.
Here a tiny in-memory SQLite table and a `buscar()` that concatenates the input
into the WHERE clause reproduce that class offline (no file, no network, so the
jail is happy); the real package is not vendored.
"""
import sqlite3

__version__ = "1.2.17"

_db = sqlite3.connect(":memory:", check_same_thread=False)
_db.execute("CREATE TABLE items (name TEXT)")
_db.executemany("INSERT INTO items (name) VALUES (?)", [("alpha",), ("beta",)])
_db.commit()


def buscar(nombre):
    """Buscar items por nombre.  <-- vulnerable: la entrada va cruda al SQL."""
    # SQLAlchemy < 1.3.0 armaba parte del SQL por concatenación, sin bind params.
    sql = "SELECT name FROM items WHERE name = '%s'" % nombre
    return [fila[0] for fila in _db.execute(sql).fetchall()]
