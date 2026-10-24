"""Prueba de humo del lazo completo sobre los fixtures. Solo stdlib (unittest).

Ejecutar:  python -m unittest discover -s tests
"""
import tempfile
import unittest
from pathlib import Path

from ventana_cero import orchestrator


class TestLazo(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with tempfile.TemporaryDirectory() as d:
            cls.rep = orchestrator.correr(
                manifiesto="fixtures/target-app/requirements.txt",
                dir_avisos="fixtures/advisories",
                dir_repo="fixtures/target-app",
                dir_salida=d,
            )
        cls.por_id = {h["advisory_id"]: h for h in cls.rep["hallazgos"]}

    def test_detecta_dos(self):
        self.assertEqual(len(self.rep["hallazgos"]), 2)

    def test_verdadero_positivo_llega_a_nivel_4(self):
        h = self.por_id["VC-2026-0001"]
        self.assertEqual(h["nivel"], 4)
        self.assertEqual(h["decision"], "actuar")
        self.assertEqual(h["resultado_poc"], "disparo")

    def test_simbolo_derivado_del_diff(self):
        h = self.por_id["VC-2026-0001"]
        self.assertEqual(h["simbolo_vulnerable"], "tinytpl.render")

    def test_taint_encontrado(self):
        h = self.por_id["VC-2026-0001"]
        self.assertTrue(h["camino_taint"], "debe haber un camino de taint")

    def test_parche_virtual_verificado(self):
        h = self.por_id["VC-2026-0001"]
        self.assertTrue(h["parche_virtual_verificado"])

    def test_ruido_se_ignora(self):
        h = self.por_id["VC-2026-0002"]
        self.assertEqual(h["nivel"], 0)
        self.assertEqual(h["decision"], "ignorar")


if __name__ == "__main__":
    unittest.main(verbosity=2)
