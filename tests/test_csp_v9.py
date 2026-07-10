import json
import tempfile
import threading
import unittest
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from nuiwallfix.cli import _load_runtime
from nuiwallfix import runtime_v9


RUNTIME = _load_runtime()


class _Handler(BaseHTTPRequestHandler):
    routes = {}

    def do_GET(self):
        item = self.routes.get(self.path)
        if item is None:
            self.send_response(404)
            self.end_headers()
            return
        content_type, body = item
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format, *_args):
        return


@contextmanager
def server(routes):
    handler = type("CspV9Handler", (_Handler,), {"routes": routes})
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


def resource(root, html, css=""):
    root.mkdir(parents=True)
    (root / "html").mkdir()
    (root / "fxmanifest.lua").write_text(
        "fx_version 'cerulean'\ngame 'gta5'\nui_page 'html/index.html'\nfiles {'html/**/*'}\n",
        encoding="utf-8",
    )
    (root / "html" / "index.html").write_text(html, encoding="utf-8")
    if css:
        (root / "html" / "app.css").write_text(css, encoding="utf-8")


def providers(path):
    path.write_text(json.dumps({"schema_version": 1, "rules": []}), encoding="utf-8")


class CspV9Tests(unittest.TestCase):
    def test_script_src_falls_back_to_default_src(self):
        routes = {"/app.js": ("application/javascript", b"window.ok=true;")}
        with server(routes) as base:
            with tempfile.TemporaryDirectory() as temporary:
                workspace = Path(temporary)
                target = workspace / "demo"
                resource(
                    target,
                    "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'\">"
                    "<script src='{}/app.js'></script>".format(base),
                )
                config = workspace / "providers.json"
                providers(config)
                result = RUNTIME.api_apply(target, mode="local", providers=config, allow_private_network=True)
                self.assertEqual(result["summary"]["unresolved"], 1)
                self.assertIn("script-src-elem", result["references"][0]["resolution_reason"])

    def test_css_font_uses_loaded_html_font_policy(self):
        routes = {"/font.woff2": ("font/woff2", b"font")}
        with server(routes) as base:
            with tempfile.TemporaryDirectory() as temporary:
                workspace = Path(temporary)
                target = workspace / "demo"
                resource(
                    target,
                    "<meta http-equiv='Content-Security-Policy' content=\"default-src 'self'; font-src 'none'\">"
                    "<link rel='stylesheet' href='app.css'>",
                    "@font-face{src:url('%s/font.woff2')}" % base,
                )
                config = workspace / "providers.json"
                providers(config)
                result = RUNTIME.api_apply(target, mode="local", providers=config, allow_private_network=True)
                self.assertEqual(result["summary"]["unresolved"], 1)
                self.assertEqual(result["summary"]["vendor_files"], 0)
                self.assertIn("font-src", result["references"][0]["resolution_reason"])

    def test_csp_wildcard_does_not_match_bare_host(self):
        self.assertFalse(runtime_v9._source_matches_remote_v9("*.example.com", "https://example.com/a.js"))
        self.assertTrue(runtime_v9._source_matches_remote_v9("*.example.com", "https://cdn.example.com/a.js"))

    def test_csp_non_slash_path_is_exact_not_prefix(self):
        self.assertTrue(runtime_v9._source_matches_remote_v9("https://cdn.example.com/lib.js", "https://cdn.example.com/lib.js"))
        self.assertFalse(runtime_v9._source_matches_remote_v9("https://cdn.example.com/lib.js", "https://cdn.example.com/lib.js.map"))
        self.assertTrue(runtime_v9._source_matches_remote_v9("https://cdn.example.com/assets/", "https://cdn.example.com/assets/app.js"))


if __name__ == "__main__":
    unittest.main()
