"""La demo en vivo del pitch: mismo ataque, 200 sin Ventana Cero y 403 con ella.

Ejecutar:  python -m unittest discover -s tests
"""
import tempfile
import unittest
from pathlib import Path

from ventana_cero import demo


class TestDemo(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with tempfile.TemporaryDirectory() as d:
            cls.pasos = demo.ejecutar(dir_salida=d, dir_ui=None, pausa=False, salida=lambda *_: None)
            cls.archivos = sorted(p.name for p in Path(d).iterdir())

    def test_ataque_sin_ventana_cero_entra(self):
        p = self.pasos["sin_ventana_cero"]
        self.assertEqual(p["codigo"], 200)
        self.assertIn("42", p["cuerpo"])

    def test_mismo_ataque_con_ventana_cero_bloqueado(self):
        p = self.pasos["con_ventana_cero"]
        self.assertEqual(p["codigo"], 403)
        self.assertIn("bloqueado por Ventana Cero", p["cuerpo"])

    def test_trafico_legitimo_sigue_pasando(self):
        self.assertEqual(self.pasos["legitimo"]["codigo"], 200)

    def test_usa_el_parche_virtual_generado_por_el_lazo(self):
        self.assertIn("guard-VC-2026-0001.json", self.archivos)


if __name__ == "__main__":
    unittest.main(verbosity=2)
