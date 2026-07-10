import json
import tempfile
import threading
import unittest
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from nuiwallfix import core
from nuiwallfix.cli import _load_runtime


RUNTIME = _load_runtime()


class _Handler(BaseHTTPRequestHandler):
    routes = {}

    def do_GET(self):
        item = self.routes.get(self.path)
        if item is None:
            self.send_response(404)
            self.end_headers()
            return
        content_type, data = item
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, _format, *_args):
        return


@contextmanager
def server(routes):
    handler = type("BrowserGuardHandler", (_Handler,), {"routes": routes})
    instance = HTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=instance.serve_forever)
    thread.daemon = True
    thread.start()
    try:
        yield "http://127.0.0.1:{}".format(instance.server_port)
    finally:
        instance.shutdown()
        instance.server_close()
        thread.join(timeout=2)


def resource(root, html):
    root.mkdir(parents=True)
    (root / "html").mkdir()
    (root / "fxmanifest.lua").write_text(
        "fx_version 'cerulean'\ngame 'gta5'\nui_page 'html/index.html'\nfiles {'html/**/*'}\n",
        encoding="utf-8",
    )
    (root / "html" / "index.html").write_text(html, encoding="utf-8")


def provider(path, source=None, target=None):
    rules = [] if not source else [{"name": "fixture", "type": "prefix", "source": source, "target": target}]
    path.write_text(json.dumps({"schema_version": 1, "rules": rules}), encoding="utf-8")


class BrowserGuardTests(unittest.TestCase):
    def test_bare_crossorigin_requires_cors_and_falls_back_local(self):
        data = b"image"
        routes = {"/origin/a.png": ("image/png", data), "/mirror/a.png": ("image/png", data)}
        with server(routes) as base:
            with tempfile.TemporaryDirectory() as temporary:
                workspace = Path(temporary)
                target = workspace / "demo"
                resource(target, "<img crossorigin src='{}/origin/a.png'>".format(base))
                config = workspace / "providers.json"
                provider(config, base + "/origin/", base + "/mirror/")
                result = RUNTIME.api_apply(target, mode="auto", providers=config, allow_private_network=True)
                self.assertEqual(result["references"][0]["context"], "html-crossorigin-asset")
                self.assertEqual(result["summary"]["local"], 1)

    def test_csp_blocks_local_asset_when_self_is_not_allowed(self):
        routes = {"/app.js": ("application/javascript", b"window.ok=true;")}
        with server(routes) as base:
            with tempfile.TemporaryDirectory() as temporary:
                workspace = Path(temporary)
                target = workspace / "demo"
                resource(
                    target,
                    "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; script-src https://allowed.example\">"
                    "<script src='{}/app.js'></script>".format(base),
                )
                config = workspace / "providers.json"
                provider(config)
                result = RUNTIME.api_apply(target, mode="local", providers=config, allow_private_network=True)
                self.assertEqual(result["summary"]["unresolved"], 1)
                self.assertEqual(result["summary"]["vendor_files"], 0)
                self.assertIn("Content-Security-Policy", result["references"][0]["resolution_reason"])

    def test_csp_self_allows_local_asset(self):
        routes = {"/app.js": ("application/javascript", b"window.ok=true;")}
        with server(routes) as base:
            with tempfile.TemporaryDirectory() as temporary:
                workspace = Path(temporary)
                target = workspace / "demo"
                resource(
                    target,
                    "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; script-src 'self'\">"
                    "<script src='{}/app.js'></script>".format(base),
                )
                config = workspace / "providers.json"
                provider(config)
                result = RUNTIME.api_apply(target, mode="local", providers=config, allow_private_network=True)
                self.assertEqual(result["summary"]["local"], 1)
                self.assertEqual(result["summary"]["unresolved"], 0)


if __name__ == "__main__":
    unittest.main()
