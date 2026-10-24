"""Prueba de humo del lazo completo sobre los fixtures. Solo stdlib (unittest).

Ejecutar:  python -m unittest discover -s tests
"""
import tempfile
import unittest

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

    def test_detecta_cinco(self):
        self.assertEqual(len(self.rep["hallazgos"]), 5)

    def test_ssti_llega_a_nivel_4_y_mitiga(self):
        h = self.por_id["VC-2026-0001"]
        self.assertEqual(h["nivel"], 4)
        self.assertEqual(h["decision"], "actuar")
        self.assertEqual(h["resultado_poc"], "disparo")
        self.assertTrue(h["parche_virtual_verificado"])

    def test_path_traversal_segunda_clase_mitiga(self):
        h = self.por_id["VC-2026-0003"]
        self.assertEqual(h["nivel"], 4)
        self.assertTrue(h["parche_virtual_verificado"])

    def test_proof_gating_degrada_a_revisar(self):
        # taint estático presente, pero el PoC no confirma -> no auto-mitigar
        h = self.por_id["VC-2026-0004"]
        self.assertEqual(h["nivel"], 3)
        self.assertEqual(h["resultado_poc"], "no_disparo")
        self.assertEqual(h["decision"], "revisar")
        self.assertFalse(h["parche_virtual_verificado"])

    def test_simbolo_derivado_del_diff(self):
        self.assertEqual(self.por_id["VC-2026-0001"]["simbolo_vulnerable"], "tinytpl.render")
        self.assertEqual(self.por_id["VC-2026-0003"]["simbolo_vulnerable"], "safefs.read")

    def test_ruido_dependencia_no_alcanzable(self):
        h = self.por_id["VC-2026-0002"]
        self.assertEqual(h["nivel"], 0)
        self.assertEqual(h["decision"], "ignorar")

    def test_ruido_solo_referenciado(self):
        h = self.por_id["VC-2026-0005"]
        self.assertEqual(h["nivel"], 1)
        self.assertEqual(h["decision"], "vigilar")

    def test_prioridad_kev_es_critica(self):
        self.assertEqual(self.por_id["VC-2026-0001"]["prioridad"], "crítica")
        self.assertTrue(self.por_id["VC-2026-0001"]["kev"])

    def test_no_hay_falsos_positivos(self):
        accionables = [h for h in self.rep["hallazgos"] if h["decision"] in ("mitigar", "actuar")]
        self.assertEqual(len(accionables), 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
