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
from nuiwallfix import runtime_v1
from nuiwallfix.cli import _load_runtime


RUNTIME = _load_runtime()


class _Handler(BaseHTTPRequestHandler):
    routes = {}

    def do_GET(self):
        route = self.routes.get(self.path.split("?", 1)[0])
        if route is None:
            self.send_response(404)
            self.end_headers()
            return
        content_type, content, headers = route
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        for key, value in headers.items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(content)

    def log_message(self, _format, *_args):
        return


@contextmanager
def server(routes):
    handler = type("HardeningHandler", (_Handler,), {"routes": routes})
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


def resource(root, html, files=None, extras=None):
    root.mkdir(parents=True)
    (root / "html").mkdir()
    file_items = files or ["html/index.html"]
    quoted = ", ".join("'{}'".format(item) for item in file_items)
    (root / "fxmanifest.lua").write_text(
        "fx_version 'cerulean'\ngame 'gta5'\nui_page 'html/index.html'\nfiles { " + quoted + " }\n",
        encoding="utf-8",
    )
    (root / "html" / "index.html").write_text(html, encoding="utf-8")
    for relative, value in (extras or {}).items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value, encoding="utf-8")


def snapshot(root):
    return {
        str(path.relative_to(root)).replace("\\", "/"): path.read_bytes()
        for path in root.rglob("*")
        if path.is_file()
    }


def empty_providers(path):
    path.write_text('{"schema_version":1,"rules":[]}', encoding="utf-8")


class HardeningTests(unittest.TestCase):
    def test_manifest_covered_file_outside_ui_root_is_scanned(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "demo"
            resource(
                target,
                "<div>ok</div>",
                files=["html/index.html", "shared/module.js"],
                extras={"shared/module.js": "import 'https://cdn.example/outside.js';"},
            )
            result = core.scan_target(target)
            self.assertEqual([item.url for item in result.references], ["https://cdn.example/outside.js"])
            self.assertEqual(result.references[0].file_path, (target / "shared" / "module.js").resolve())

    def test_html_base_blocks_local_relative_rewrite(self):
        routes = {"/app.js": ("application/javascript", b"window.ok=true;", {})}
        with server(routes) as base:
            with tempfile.TemporaryDirectory() as temporary:
                workspace = Path(temporary)
                target = workspace / "demo"
                resource(target, "<base href='https://example.invalid/sub/'><script src='{}/app.js'></script>".format(base))
                providers = workspace / "providers.json"
                empty_providers(providers)
                original = snapshot(target)
                result = RUNTIME.api_apply(
                    target,
                    mode="local",
                    providers=providers,
                    allow_private_network=True,
                )
                self.assertEqual(result["summary"]["unresolved"], 1)
                self.assertEqual(result["summary"]["vendor_files"], 0)
                self.assertIn("<base href>", result["references"][0]["resolution_reason"])
                self.assertEqual(snapshot(target), original)

    def test_module_mirror_without_cors_falls_back_to_local(self):
        module = b"export const ok = true;"
        routes = {
            "/origin/module.js": ("application/javascript", module, {}),
            "/mirror/module.js": ("application/javascript", module, {}),
        }
        with server(routes) as base:
            with tempfile.TemporaryDirectory() as temporary:
                workspace = Path(temporary)
                target = workspace / "demo"
                resource(target, "<script type='module'>import '{}/origin/module.js';</script>".format(base))
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
                    mode="auto",
                    providers=providers,
                    allow_private_network=True,
                )
                self.assertEqual(result["summary"]["remote"], 0)
                self.assertEqual(result["summary"]["local"], 1)

    def test_failed_final_journal_write_rolls_target_back(self):
        routes = {"/app.js": ("application/javascript", b"window.ok=true;", {})}
        with server(routes) as base:
            with tempfile.TemporaryDirectory() as temporary:
                workspace = Path(temporary)
                target = workspace / "demo"
                resource(target, "<script src='{}/app.js'></script>".format(base))
                providers = workspace / "providers.json"
                empty_providers(providers)
                original = snapshot(target)
                original_writer = runtime_v1._write_json
                calls = {"count": 0}

                def failing_writer(path, payload):
                    calls["count"] += 1
                    if calls["count"] == 2:
                        raise OSError("simulated final journal failure")
                    return original_writer(path, payload)

                runtime_v1._write_json = failing_writer
                try:
                    with self.assertRaises(OSError):
                        RUNTIME.api_apply(
                            target,
                            mode="local",
                            write=True,
                            providers=providers,
                            state_dir=workspace / "state",
                            allow_private_network=True,
                        )
                finally:
                    runtime_v1._write_json = original_writer
                self.assertEqual(snapshot(target), original)

    def test_preparing_journal_can_be_recovered(self):
        routes = {"/app.js": ("application/javascript", b"window.ok=true;", {})}
        with server(routes) as base:
            with tempfile.TemporaryDirectory() as temporary:
                workspace = Path(temporary)
                target = workspace / "demo"
                resource(target, "<script src='{}/app.js'></script>".format(base))
                providers = workspace / "providers.json"
                empty_providers(providers)
                original = snapshot(target)
                state = workspace / "state"
                applied = RUNTIME.api_apply(
                    target,
                    mode="local",
                    write=True,
                    providers=providers,
                    state_dir=state,
                    allow_private_network=True,
                )
                journal_path = state / "runs" / applied["run_id"] / "run.json"
                journal = json.loads(journal_path.read_text(encoding="utf-8"))
                journal["status"] = "preparing"
                journal_path.write_text(json.dumps(journal), encoding="utf-8")
                restored = RUNTIME.api_restore(target, applied["run_id"], state_dir=state)
                self.assertEqual(restored["status"], "recovered")
                self.assertEqual(snapshot(target), original)

    def test_invalid_cli_usage_returns_documented_exit(self):
        launcher = Path(__file__).resolve().parents[1] / "nui-wallfix.py"
        process = subprocess.run(
            [sys.executable, str(launcher)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
        )
        self.assertEqual(process.returncode, 20)

    def test_json_output_failure_keeps_applied_run_visible(self):
        routes = {"/app.js": ("application/javascript", b"window.ok=true;", {})}
        with server(routes) as base:
            with tempfile.TemporaryDirectory() as temporary:
                workspace = Path(temporary)
                target = workspace / "demo"
                resource(target, "<script src='{}/app.js'></script>".format(base))
                providers = workspace / "providers.json"
                empty_providers(providers)
                state = workspace / "state"
                launcher = Path(__file__).resolve().parents[1] / "nui-wallfix.py"
                process = subprocess.run(
                    [
                        sys.executable,
                        str(launcher),
                        "apply",
                        str(target),
                        "--mode",
                        "local",
                        "--write",
                        "--providers",
                        str(providers),
                        "--state-dir",
                        str(state),
                        "--allow-private-network",
                        "--json",
                        "--json-output",
                        str(workspace),
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    universal_newlines=True,
                )
                self.assertEqual(process.returncode, 40)
                payload = json.loads(process.stdout)
                self.assertEqual(payload["status"], "applied")
                self.assertTrue(payload.get("run_id"))
                self.assertTrue(payload.get("json_output_error"))
                self.assertTrue((state / "runs" / payload["run_id"] / "run.json").is_file())


if __name__ == "__main__":
    unittest.main()
