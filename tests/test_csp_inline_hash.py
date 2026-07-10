import json
import tempfile
import threading
import unittest
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from nuiwallfix.cli import _load_runtime


RUNTIME = _load_runtime()


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.endswith(".css"):
            content_type, body = "text/css", b"body{color:red}"
        else:
            content_type, body = "application/javascript", b"export const ok=true;"
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format, *_args):
        return


@contextmanager
def server():
    instance = HTTPServer(("127.0.0.1", 0), _Handler)
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


class InlineHashTests(unittest.TestCase):
    def test_inline_script_with_csp_hash_is_unresolved(self):
        with server() as base:
            with tempfile.TemporaryDirectory() as temporary:
                workspace = Path(temporary)
                target = workspace / "demo"
                resource(
                    target,
                    "<meta http-equiv='Content-Security-Policy' content=\"script-src 'self' 'sha256-ZmFrZQ=='\">"
                    "<script type='module'>import '{}/module.js';</script>".format(base),
                )
                config = workspace / "providers.json"
                config.write_text(json.dumps({"schema_version": 1, "rules": []}), encoding="utf-8")
                result = RUNTIME.api_apply(target, mode="local", providers=config, allow_private_network=True)
                self.assertEqual(result["summary"]["unresolved"], 1)
                self.assertEqual(result["summary"]["vendor_files"], 0)
                self.assertIn("invalidate", result["references"][0]["resolution_reason"])

    def test_inline_style_with_csp_hash_is_unresolved(self):
        with server() as base:
            with tempfile.TemporaryDirectory() as temporary:
                workspace = Path(temporary)
                target = workspace / "demo"
                resource(
                    target,
                    "<meta http-equiv='Content-Security-Policy' content=\"style-src 'self' 'sha384-ZmFrZQ=='\">"
                    "<style>@import '{}/theme.css';</style>".format(base),
                )
                config = workspace / "providers.json"
                config.write_text(json.dumps({"schema_version": 1, "rules": []}), encoding="utf-8")
                result = RUNTIME.api_apply(target, mode="local", providers=config, allow_private_network=True)
                self.assertEqual(result["summary"]["unresolved"], 1)
                self.assertIn("invalidate", result["references"][0]["resolution_reason"])

    def test_inline_script_without_hash_can_localize(self):
        with server() as base:
            with tempfile.TemporaryDirectory() as temporary:
                workspace = Path(temporary)
                target = workspace / "demo"
                resource(
                    target,
                    "<meta http-equiv='Content-Security-Policy' content=\"script-src 'self' 'nonce-test'\">"
                    "<script nonce='test' type='module'>import '{}/module.js';</script>".format(base),
                )
                config = workspace / "providers.json"
                config.write_text(json.dumps({"schema_version": 1, "rules": []}), encoding="utf-8")
                result = RUNTIME.api_apply(target, mode="local", providers=config, allow_private_network=True)
                self.assertEqual(result["summary"]["local"], 1)
                self.assertEqual(result["summary"]["unresolved"], 0)


if __name__ == "__main__":
    unittest.main()
