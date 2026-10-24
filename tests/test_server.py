"""El panel conectado: POST /api/run corre el lazo real y devuelve su run.json.

Ejecutar:  python -m unittest discover -s tests
"""
import json
import tempfile
import threading
import unittest
import urllib.request

from ventana_cero import server


class TestServer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.srv = server.crear_servidor(0, dir_ui="ui/public", dir_salida=cls.tmp.name, publicar_ui=False)
        cls.base = f"http://127.0.0.1:{cls.srv.server_address[1]}"
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()
        cls.tmp.cleanup()

    def test_sirve_el_panel(self):
        with urllib.request.urlopen(self.base + "/") as r:
            self.assertEqual(r.status, 200)
            self.assertIn("VENTANA", r.read().decode("utf-8"))

    def test_api_run_corre_el_lazo_real(self):
        req = urllib.request.Request(self.base + "/api/run", method="POST")
        with urllib.request.urlopen(req, timeout=120) as r:
            self.assertEqual(r.status, 200)
            rep = json.loads(r.read().decode("utf-8"))
        self.assertTrue(rep["hallazgos"])
        mitigados = [h for h in rep["hallazgos"] if h.get("parche_virtual_verificado")]
        self.assertTrue(mitigados, "el lazo debe mitigar al menos un hallazgo con PoC")

    def test_api_status_indica_modo_en_vivo(self):
        with urllib.request.urlopen(self.base + "/api/status") as r:
            self.assertEqual(json.loads(r.read())["en_vivo"], True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
