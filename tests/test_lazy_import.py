import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class LazyImportTests(unittest.TestCase):
    def test_direct_top_level_scan_loads_active_guards(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "demo"
            (target / "html").mkdir(parents=True)
            (target / "fxmanifest.lua").write_text(
                "fx_version 'cerulean'\ngame 'gta5'\nui_page 'html/index.html'\nfiles {'html/**/*'}\n",
                encoding="utf-8",
            )
            (target / "html" / "index.html").write_text(
                "<script>loader.import('https://cdn.example/app.js')</script>",
                encoding="utf-8",
            )
            project = Path(__file__).resolve().parents[1]
            code = (
                "import nuiwallfix; "
                "result=nuiwallfix.scan_target(r'{}'); "
                "print(result.references[0].context, result.references[0].auto_allowed)"
            ).format(str(target).replace("'", "\\'"))
            process = subprocess.run(
                [sys.executable, "-c", code],
                cwd=str(project),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
            )
            self.assertEqual(process.returncode, 0, process.stderr)
            self.assertEqual(process.stdout.strip(), "js-member-import False")


if __name__ == "__main__":
    unittest.main()
