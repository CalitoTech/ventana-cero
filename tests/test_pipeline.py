"""Prueba de humo del lazo completo sobre los fixtures. Solo stdlib (unittest).

Ejecutar:  python -m unittest discover -s tests
"""
import json
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

    def test_detecta_nueve(self):
        # 10 avisos; minicache ya está en una versión con el fix y no se reporta
        self.assertEqual(len(self.rep["hallazgos"]), 9)

    def test_version_ya_parcheada_no_es_hallazgo(self):
        self.assertNotIn("VC-2026-0008", self.por_id)

    def test_llamado_con_constante_queda_en_nivel_2(self):
        h = self.por_id["VC-2026-0006"]
        self.assertEqual(h["nivel"], 2)
        self.assertEqual(h["decision"], "preparar")
        self.assertIsNone(h["resultado_poc"])

    def test_sanitizador_corta_el_taint(self):
        # la entrada no confiable pasa por os.path.basename antes del sink
        h = self.por_id["VC-2026-0007"]
        self.assertEqual(h["nivel"], 2)
        self.assertEqual(h["decision"], "preparar")
        self.assertFalse(h["camino_taint"])

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
        self.assertEqual(len(accionables), 4)

    def test_cve_real_de_pypi_se_confirma_y_mitiga(self):
        # CVE-2017-18342: yaml.load() de PyYAML < 5.1 construye objetos Python arbitrarios
        h = self.por_id["CVE-2017-18342"]
        self.assertEqual(h["paquete"], "pyyaml")
        self.assertEqual(h["nivel"], 4)
        self.assertEqual(h["resultado_poc"], "disparo")
        self.assertTrue(h["parche_virtual_verificado"])

    def test_cve_inyeccion_comando_se_confirma_y_mitiga(self):
        # CVE-2019-6690: python-gnupg < 0.4.4 arma la línea de gpg sin escapar
        h = self.por_id["CVE-2019-6690"]
        self.assertEqual(h["paquete"], "python-gnupg")
        self.assertEqual(h["simbolo_vulnerable"], "python-gnupg.encrypt")
        self.assertEqual(h["nivel"], 4)
        self.assertEqual(h["resultado_poc"], "disparo")
        self.assertTrue(h["parche_virtual_verificado"])

    def test_parche_codigo_sin_ruta_absoluta(self):
        # el reporte se publica en la UI: no debe filtrar rutas de la máquina
        for aid in ("VC-2026-0001", "VC-2026-0003"):
            self.assertEqual(self.por_id[aid]["pr_parche_codigo"], f"{aid}.patch")


class TestPublicacionUI(unittest.TestCase):
    def _correr(self, salida, **kw):
        return orchestrator.correr(
            manifiesto="fixtures/target-app/requirements.txt",
            dir_avisos="fixtures/advisories",
            dir_repo="fixtures/target-app",
            dir_salida=salida, **kw)

    def test_correr_no_toca_la_ui_por_defecto(self):
        ui = Path("ui/public/run.json")
        antes = ui.read_bytes()
        with tempfile.TemporaryDirectory() as d:
            self._correr(d)
        self.assertEqual(ui.read_bytes(), antes)

    def test_correr_publica_en_la_ui_pedida(self):
        with tempfile.TemporaryDirectory() as d, tempfile.TemporaryDirectory() as ui:
            rep = self._correr(d, dir_ui=ui)
            publicado = json.loads((Path(ui) / "run.json").read_text(encoding="utf-8"))
        self.assertEqual(publicado["resumen"], rep["resumen"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
