import base64
import hashlib
import json
import subprocess
import sys
import tempfile
import threading
import unittest
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from nuiwallfix import core
from nuiwallfix.cli import _load_runtime


RUNTIME = _load_runtime()


class _RouteHandler(BaseHTTPRequestHandler):
    routes = {}

    def do_GET(self):
        route = self.routes.get(self.path.split("?", 1)[0])
        if route is None:
            self.send_response(404)
            self.end_headers()
            return
        content_type, data = route
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, _format, *_args):
        return


@contextmanager
def route_server(routes):
    handler = type("FixtureRouteHandler", (_RouteHandler,), {"routes": routes})
    server = HTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever)
    thread.daemon = True
    thread.start()
    try:
        yield "http://127.0.0.1:{}".format(server.server_port)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def write_resource(root, html_text, extra=None, broad_files=False):
    root.mkdir(parents=True)
    html_dir = root / "html"
    html_dir.mkdir()
    manifest_files = "'html/**/*'" if broad_files else "'html/index.html'"
    (root / "fxmanifest.lua").write_text(
        "fx_version 'cerulean'\n"
        "game 'gta5'\n"
        "ui_page 'html/index.html'\n"
        "files { " + manifest_files + " }\n",
        encoding="utf-8",
    )
    (html_dir / "index.html").write_text(html_text, encoding="utf-8")
    for relative, content in (extra or {}).items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")


def file_snapshot(root):
    return {
        str(path.relative_to(root)).replace("\\", "/"): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


class ScannerTests(unittest.TestCase):
    def test_manifest_aware_scan_and_false_positive_boundaries(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "resources"
            resource = target / "[local]" / "demo"
            write_resource(
                resource,
                """<!doctype html>
<!-- <script src="https://comment.example/ignored.js"></script> -->
<link rel="stylesheet" href="//cdn.example.com/main.css?x=1&amp;y=2">
<script src='https://cdn.example.com/app.js'></script>
<style>.hero { background: url(https://img.example.com/a.png); }</style>
<script type="module">
  import "https://esm.example.com/module.js";
  fetch("https://api.example.com/player");
  const note = "https://text.example.com/not-an-import.js";
</script>
""",
                extra={
                    "html/app.css": "/* url(https://ignored.example/a.png) */\n@import 'https://cdn.example.com/theme.css';",
                    "html/app.js": "export { x } from 'https://esm.example.com/x.js';\n// import 'https://ignored.example/y.js';",
                },
            )
            before = file_snapshot(target)
            result = core.scan_target(target)
            after = file_snapshot(target)
            self.assertEqual(before, after)
            urls = [item.url for item in result.references]
            self.assertNotIn("https://comment.example/ignored.js", urls)
            self.assertNotIn("https://text.example.com/not-an-import.js", urls)
            self.assertNotIn("https://ignored.example/y.js", urls)
            self.assertIn("https://cdn.example.com/app.js", urls)
            self.assertIn("https://cdn.example.com/main.css?x=1&y=2", urls)
            self.assertIn("https://api.example.com/player", urls)
            network = next(item for item in result.references if item.url == "https://api.example.com/player")
            self.assertFalse(network.auto_allowed)
            self.assertEqual(network.context, "js-network")
            self.assertEqual(len(result.resources), 1)

    def test_old_manifest_and_missing_ui_page_diagnostic(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary)
            old = target / "old"
            old.mkdir()
            (old / "__resource.lua").write_text("ui_page 'web/index.html'\nfiles {'web/index.html'}\n", encoding="utf-8")
            (old / "web").mkdir()
            (old / "web" / "index.html").write_text("<script src='https://cdn.example/a.js'></script>", encoding="utf-8")
            broken = target / "broken"
            broken.mkdir()
            (broken / "fxmanifest.lua").write_text("ui_page 'missing.html'\n", encoding="utf-8")
            result = core.scan_target(target)
            self.assertEqual(len(result.resources), 1)
            self.assertTrue(any("does not exist" in item["message"] for item in result.diagnostics))


class RewriteTests(unittest.TestCase):
    def test_local_preview_apply_recursive_dependencies_and_restore(self):
        routes = {
            "/style.css": ("text/css", b"@font-face{src:url('./font.woff2')} body{background:url(data:image/png;base64,AA==)}"),
            "/font.woff2": ("font/woff2", b"font-data"),
            "/app.js": ("application/javascript", b"import './chunk.js';\nwindow.wallfixLoaded = true;"),
            "/chunk.js": ("application/javascript", b"export const value = 42;"),
        }
        with route_server(routes) as base:
            with tempfile.TemporaryDirectory() as temporary:
                workspace = Path(temporary)
                target = workspace / "demo"
                html_text = (
                    "<link rel='stylesheet' href='{0}/style.css'>\n"
                    "<script type='module' src='{0}/app.js'></script>\n"
                ).format(base)
                write_resource(target, html_text)
                original = file_snapshot(target)
                providers = workspace / "providers.json"
                providers.write_text('{"schema_version":1,"rules":[]}', encoding="utf-8")
                state_dir = workspace / "backups"

                preview = RUNTIME.api_apply(
                    target,
                    mode="local",
                    write=False,
                    providers=providers,
                    state_dir=state_dir,
                    allow_private_network=True,
                )
                self.assertEqual(preview["status"], "preview")
                self.assertEqual(file_snapshot(target), original)
                self.assertFalse(state_dir.exists())
                self.assertEqual(preview["summary"]["local"], 2)
                self.assertEqual(preview["summary"]["vendor_files"], 4)

                applied = RUNTIME.api_apply(
                    target,
                    mode="local",
                    write=True,
                    providers=providers,
                    state_dir=state_dir,
                    allow_private_network=True,
                )
                self.assertEqual(applied["status"], "applied")
                self.assertGreaterEqual(applied["summary"]["written_files"], 7)
                changed_html = (target / "html" / "index.html").read_text(encoding="utf-8")
                self.assertNotIn(base, changed_html)
                vendor_files = [path for path in (target / "html" / "_vendor").rglob("*") if path.is_file()]
                self.assertEqual(len(vendor_files), 4)
                css_text = next(path for path in vendor_files if path.suffix == ".css").read_text(encoding="utf-8")
                js_text = next(path for path in vendor_files if path.suffix == ".js" and "app" in path.name).read_text(encoding="utf-8")
                self.assertNotIn(base, css_text)
                self.assertIn("font", css_text)
                self.assertNotIn(base, js_text)
                self.assertIn("chunk", js_text)
                manifest = (target / "fxmanifest.lua").read_text(encoding="utf-8")
                self.assertIn("nui-wallfix managed local assets", manifest)
                self.assertIn("html/_vendor/**/*", manifest)

                restored = RUNTIME.api_restore(target, applied["run_id"], state_dir=state_dir)
                self.assertEqual(restored["status"], "restored")
                self.assertEqual(file_snapshot(target), original)

    def test_cn_cdn_requires_identical_bytes(self):
        data = b"window.lib = true;"
        routes = {
            "/origin/lib.js": ("application/javascript", data),
            "/mirror/lib.js": ("application/javascript", data),
            "/bad/lib.js": ("application/javascript", b"window.lib = false;"),
        }
        with route_server(routes) as base:
            with tempfile.TemporaryDirectory() as temporary:
                workspace = Path(temporary)
                target = workspace / "demo"
                write_resource(target, "<script src='{}/origin/lib.js'></script>".format(base), broad_files=True)
                providers = workspace / "providers.json"
                providers.write_text(json.dumps({
                    "schema_version": 1,
                    "rules": [{
                        "name": "fixture",
                        "type": "prefix",
                        "source": base + "/origin/",
                        "target": base + "/mirror/",
                    }],
                }), encoding="utf-8")
                result = RUNTIME.api_apply(
                    target,
                    mode="cn-cdn",
                    providers=providers,
                    allow_private_network=True,
                )
                self.assertEqual(result["summary"]["remote"], 1)
                self.assertIn("/mirror/lib.js", result["references"][0]["replacement"])
                self.assertIn("sha256", result["references"][0]["verification"])

                providers.write_text(json.dumps({
                    "schema_version": 1,
                    "rules": [{
                        "name": "bad-fixture",
                        "type": "prefix",
                        "source": base + "/origin/",
                        "target": base + "/bad/",
                    }],
                }), encoding="utf-8")
                rejected = RUNTIME.api_apply(
                    target,
                    mode="cn-cdn",
                    providers=providers,
                    allow_private_network=True,
                )
                self.assertEqual(rejected["summary"]["unresolved"], 1)
                self.assertIn("differ", rejected["references"][0]["resolution_reason"])

    def test_sri_is_updated_after_recursive_local_rewrite(self):
        stylesheet = b"body{background:url('./image.png')}"
        integrity = "sha384-" + base64.b64encode(hashlib.sha384(stylesheet).digest()).decode("ascii")
        routes = {
            "/style.css": ("text/css", stylesheet),
            "/image.png": ("image/png", b"not-really-a-png-but-not-html"),
        }
        with route_server(routes) as base:
            with tempfile.TemporaryDirectory() as temporary:
                workspace = Path(temporary)
                target = workspace / "demo"
                write_resource(
                    target,
                    "<link rel='stylesheet' href='{0}/style.css' integrity='{1}'>".format(base, integrity),
                )
                providers = workspace / "providers.json"
                providers.write_text('{"schema_version":1,"rules":[]}', encoding="utf-8")
                applied = RUNTIME.api_apply(
                    target,
                    mode="local",
                    write=True,
                    providers=providers,
                    state_dir=workspace / "state",
                    allow_private_network=True,
                )
                updated = (target / "html" / "index.html").read_text(encoding="utf-8")
                self.assertNotIn(integrity, updated)
                local_css = next((target / "html" / "_vendor").rglob("*.css")).read_bytes()
                expected = "sha384-" + base64.b64encode(hashlib.sha384(local_css).digest()).decode("ascii")
                self.assertIn(expected, updated)

    def test_restore_detects_post_apply_changes(self):
        routes = {"/app.js": ("application/javascript", b"window.ok = true;")}
        with route_server(routes) as base:
            with tempfile.TemporaryDirectory() as temporary:
                workspace = Path(temporary)
                target = workspace / "demo"
                write_resource(target, "<script src='{}/app.js'></script>".format(base))
                providers = workspace / "providers.json"
                providers.write_text('{"schema_version":1,"rules":[]}', encoding="utf-8")
                state = workspace / "state"
                applied = RUNTIME.api_apply(
                    target,
                    mode="local",
                    write=True,
                    providers=providers,
                    state_dir=state,
                    allow_private_network=True,
                )
                index = target / "html" / "index.html"
                index.write_text(index.read_text(encoding="utf-8") + "\n<!-- user edit -->", encoding="utf-8")
                with self.assertRaises(core.RestoreConflict):
                    RUNTIME.api_restore(target, applied["run_id"], state_dir=state)


class CliContractTests(unittest.TestCase):
    def test_json_scan_stdout_is_valid_json(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "demo"
            write_resource(target, "<script src='https://cdn.example/app.js'></script>")
            launcher = Path(__file__).resolve().parents[1] / "nui-wallfix.py"
            process = subprocess.run(
                [sys.executable, str(launcher), "scan", str(target), "--json"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
            )
            self.assertEqual(process.returncode, 0, process.stderr)
            payload = json.loads(process.stdout)
            self.assertEqual(payload["command"], "scan")
            self.assertEqual(payload["summary"]["references"], 1)


if __name__ == "__main__":
    unittest.main()
