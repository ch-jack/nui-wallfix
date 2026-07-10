import json
import subprocess
import sys
import tempfile
import threading
import unittest
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from nuiwallfix import runtime_v10
from nuiwallfix.cli import _load_runtime


RUNTIME = _load_runtime()


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"window.ok=true;"
        self.send_response(200)
        self.send_header("Content-Type", "application/javascript")
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


class CspV10Tests(unittest.TestCase):
    def test_first_duplicate_csp_directive_wins(self):
        with server() as base:
            with tempfile.TemporaryDirectory() as temporary:
                workspace = Path(temporary)
                target = workspace / "demo"
                resource(
                    target,
                    "<meta http-equiv='Content-Security-Policy' content=\"script-src 'none'; script-src 'self'\">"
                    "<script src='{}/app.js'></script>".format(base),
                )
                config = workspace / "providers.json"
                config.write_text('{"schema_version":1,"rules":[]}', encoding="utf-8")
                result = RUNTIME.api_apply(target, mode="local", providers=config, allow_private_network=True)
                self.assertEqual(result["summary"]["unresolved"], 1)

    def test_wildcard_source_enforces_port_path_and_case(self):
        source = "https://*.example.com:8443/Assets/"
        self.assertTrue(runtime_v10._source_matches_remote_v10(source, "https://cdn.example.com:8443/Assets/app.js"))
        self.assertFalse(runtime_v10._source_matches_remote_v10(source, "https://cdn.example.com/Assets/app.js"))
        self.assertFalse(runtime_v10._source_matches_remote_v10(source, "https://cdn.example.com:8443/other/app.js"))
        self.assertFalse(runtime_v10._source_matches_remote_v10(source, "https://cdn.example.com:8443/assets/app.js"))

    def test_json_parse_error_has_no_stderr_noise(self):
        launcher = Path(__file__).resolve().parents[1] / "nui-wallfix.py"
        process = subprocess.run(
            [sys.executable, str(launcher), "apply", "--json"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
        )
        self.assertEqual(process.returncode, 20)
        self.assertEqual(json.loads(process.stdout)["status"], "error")
        self.assertEqual(process.stderr, "")


if __name__ == "__main__":
    unittest.main()
