import json
import tempfile
import unittest
from pathlib import Path

from nuiwallfix import core
from nuiwallfix.cli import _load_runtime


RUNTIME = _load_runtime()


def create_resource(root, body, extra=None):
    root.mkdir(parents=True)
    (root / "html").mkdir()
    (root / "fxmanifest.lua").write_text(
        "fx_version 'cerulean'\n"
        "game 'gta5'\n"
        "ui_page 'html/index.html'\n"
        "files { 'html/index.html' }\n",
        encoding="utf-8",
    )
    (root / "html" / "index.html").write_text(body, encoding="utf-8")
    for relative, text in (extra or {}).items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")


class RegressionTests(unittest.TestCase):
    def test_files_outside_manifest_are_not_rewritten(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "demo"
            create_resource(
                target,
                "<script src='https://cdn.example/loaded.js'></script>",
                {"html/unused.js": "import 'https://cdn.example/unused.js';"},
            )
            result = core.scan_target(target)
            self.assertEqual([item.url for item in result.references], ["https://cdn.example/loaded.js"])
            self.assertTrue(any("not covered" in item["message"] for item in result.diagnostics))

    def test_existing_provider_target_is_idempotent_without_network(self):
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            target = workspace / "demo"
            domestic = "https://cn.example/assets/lib.js"
            create_resource(target, "<script src='{}'></script>".format(domestic))
            providers = workspace / "providers.json"
            providers.write_text(json.dumps({
                "schema_version": 1,
                "rules": [{
                    "name": "fixture",
                    "type": "prefix",
                    "source": "https://foreign.example/assets/",
                    "target": "https://cn.example/assets/",
                }],
            }), encoding="utf-8")
            result = RUNTIME.api_apply(target, mode="cn-cdn", providers=providers)
            self.assertEqual(result["summary"]["remote"], 1)
            self.assertEqual(result["summary"]["unresolved"], 0)
            self.assertEqual(result["references"][0]["replacement"], domestic)
            self.assertEqual(result["references"][0]["verification"], "already-provider-target")


if __name__ == "__main__":
    unittest.main()
