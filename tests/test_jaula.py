"""La jaula sin Docker: bloquea red saliente, procesos y archivos fuera del repo."""
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _correr_en_jaula(codigo: str) -> subprocess.CompletedProcess:
    with tempfile.TemporaryDirectory() as d:
        script = os.path.join(d, "intento.py")
        with open(script, "w", encoding="utf-8") as f:
            f.write(textwrap.dedent(codigo))
        env = dict(os.environ, PYTHONPATH=RAIZ)
        return subprocess.run([sys.executable, "-m", "ventana_cero.jaula", script],
                              env=env, capture_output=True, text=True, timeout=20)


class TestJaula(unittest.TestCase):
    def test_bloquea_red_saliente(self):
        r = _correr_en_jaula("""
            import socket
            s = socket.socket()
            try:
                s.connect(("1.1.1.1", 80))
                print("SALIO")
            except PermissionError:
                print("BLOQUEADO")
        """)
        self.assertIn("BLOQUEADO", r.stdout)
        self.assertIn("VC_BLOQUEO socket.connect", r.stderr)

    def test_bloquea_red_saliente_por_nombre(self):
        # create_connection resuelve el nombre primero: la jaula corta en getaddrinfo
        r = _correr_en_jaula("""
            import socket
            try:
                socket.create_connection(("example.com", 80), timeout=3)
                print("CONECTO A INTERNET")
            except PermissionError:
                print("BLOQUEADO")
        """)
        self.assertNotIn("CONECTO A INTERNET", r.stdout)
        self.assertIn("BLOQUEADO", r.stdout)
        self.assertIn("VC_BLOQUEO socket.getaddrinfo", r.stderr)

    def test_permite_localhost(self):
        r = _correr_en_jaula("""
            import socket
            s = socket.socket()
            s.bind(("127.0.0.1", 0))
            print("OK")
        """)
        self.assertIn("OK", r.stdout, r.stderr)

    def test_bloquea_procesos(self):
        r = _correr_en_jaula("""
            import subprocess, sys
            try:
                subprocess.run([sys.executable, "-c", "print(1)"])
                print("LANZO")
            except PermissionError:
                print("BLOQUEADO")
        """)
        self.assertIn("BLOQUEADO", r.stdout)

    def test_bloquea_lectura_fuera_del_repo(self):
        r = _correr_en_jaula(f"""
            try:
                open({os.path.join(RAIZ, "README.md")!r}).read()
                print("LEYO")
            except PermissionError:
                print("BLOQUEADO")
        """)
        self.assertIn("BLOQUEADO", r.stdout)


if __name__ == "__main__":
    unittest.main()
