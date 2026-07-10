"""Runtime v2: transaction setup fix for backup creation."""

from pathlib import Path

from . import core
from . import runtime_v1 as _v1
from .runtime_v1 import *  # noqa: F401,F403


def _apply_outputs_v2(target, state_dir, mode, outputs, expected, result_payload):
    state_dir = Path(state_dir).expanduser().resolve()
    if core._is_within(state_dir, target):
        raise core.WallfixError("state directory must be outside the target resource tree")
    run_id = _v1._datetime_run_id()
    run_dir = state_dir / "runs" / run_id
    backup_root = run_dir / "files"
    records = []
    changed = {}
    with _v1._TargetLock(state_dir, target):
        for path, data in sorted(outputs.items(), key=lambda item: str(item[0]).lower()):
            path = Path(path).resolve()
            _v1._assert_safe_output(path, target)
            before = path.read_bytes() if path.exists() else None
            if path in expected and before != expected[path]:
                raise core.WallfixError("file changed after scan; refusing to overwrite: {}".format(path))
            if before == data:
                continue
            relative = path.relative_to(target)
            records.append({
                "path": core._posix(relative),
                "existed_before": before is not None,
                "before_sha256": _v1.hashlib.sha256(before).hexdigest() if before is not None else "",
                "after_sha256": _v1.hashlib.sha256(data).hexdigest(),
                "backup": core._posix(Path("files") / relative) if before is not None else "",
            })
            changed[path] = (before, data)

        run_dir.mkdir(parents=True, exist_ok=False)
        for item in records:
            if not item["existed_before"]:
                continue
            path = (target / item["path"]).resolve()
            backup_path = run_dir / item["backup"]
            backup_path.parent.mkdir(parents=True, exist_ok=True)
            backup_path.write_bytes(changed[path][0])

        run_payload = {
            "schema_version": 1,
            "run_id": run_id,
            "target": str(target),
            "mode": mode,
            "status": "preparing",
            "created_at": core._utc_now(),
            "files": records,
            "result_summary": result_payload.get("summary", {}),
        }
        _v1._write_json(run_dir / "run.json", run_payload)
        written = []
        try:
            for path, (before, after) in changed.items():
                mode_bits = path.stat().st_mode if before is not None else None
                _v1._atomic_write(path, after, mode_bits)
                written.append(path)
        except Exception:
            for path in reversed(written):
                before = changed[path][0]
                try:
                    if before is None:
                        path.unlink()
                    else:
                        _v1._atomic_write(path, before)
                except OSError:
                    pass
            run_payload["status"] = "failed-and-rolled-back"
            run_payload["finished_at"] = core._utc_now()
            _v1._write_json(run_dir / "run.json", run_payload)
            raise
        run_payload["status"] = "applied"
        run_payload["finished_at"] = core._utc_now()
        _v1._write_json(run_dir / "run.json", run_payload)
    return run_id, records


_v1._apply_outputs = _apply_outputs_v2
