"""El puente LLM: caché de respuestas para que la demo corra offline y determinista.

Ejecutar:  python -m unittest discover -s tests
"""
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from ventana_cero import llm, reachability
from ventana_cero.hallazgo import Hallazgo

AVISO = {"fix_diff": "--- a/x.py\n+++ b/x.py\n@@\n def render(plantilla: str) -> str:\n-    a\n+    b\n"}


class TestCacheLLM(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.cache = Path(self.dir.name) / "cache.json"
        self.env = mock.patch.dict(os.environ, {"VC_LLM_CACHE": str(self.cache)})
        self.env.start()
        os.environ.pop("ANTHROPIC_API_KEY", None)

    def tearDown(self):
        self.env.stop()
        self.dir.cleanup()

    def test_sin_clave_ni_cache_devuelve_none(self):
        self.assertIsNone(llm.completar("hola"))
        self.assertFalse(llm.disponible())

    def test_respuesta_en_cache_se_usa_sin_clave(self):
        self.cache.write_text(json.dumps({llm.clave_cache("hola"): "respuesta guardada"}))
        self.assertTrue(llm.disponible())
        self.assertEqual(llm.completar("hola"), "respuesta guardada")

    def test_respuesta_nueva_se_guarda_en_cache(self):
        with mock.patch.dict(os.environ, {"ANTHROPIC_API_KEY": "k"}), \
             mock.patch.object(llm, "_llamar_api", return_value="del modelo") as api:
            self.assertEqual(llm.completar("hola"), "del modelo")
            self.assertEqual(llm.completar("hola"), "del modelo")
        api.assert_called_once()
        self.assertEqual(json.loads(self.cache.read_text())[llm.clave_cache("hola")], "del modelo")

    def test_fallo_de_api_no_se_guarda(self):
        with mock.patch.dict(os.environ, {"ANTHROPIC_API_KEY": "k"}), \
             mock.patch.object(llm, "_llamar_api", return_value=None):
            self.assertIsNone(llm.completar("hola"))
        self.assertFalse(self.cache.exists())

    def test_evidencia_dice_que_el_simbolo_lo_propuso_el_llm(self):
        with mock.patch.object(llm, "completar", return_value='{"funcion": "render", "parametro": "plantilla"}'), \
             mock.patch.object(llm, "disponible", return_value=True):
            h = reachability.derivar_simbolo(Hallazgo(advisory_id="A", paquete="tinytpl", version="1"), AVISO)
        self.assertEqual(h.simbolo_vulnerable, "tinytpl.render")
        self.assertIn("propuesto por el LLM", h.evidencia[-1])

    def test_evidencia_dice_heuristica_sin_llm(self):
        h = reachability.derivar_simbolo(Hallazgo(advisory_id="A", paquete="tinytpl", version="1"), AVISO)
        self.assertEqual(h.simbolo_vulnerable, "tinytpl.render")
        self.assertIn("heurística sobre el diff", h.evidencia[-1])


if __name__ == "__main__":
    unittest.main(verbosity=2)
