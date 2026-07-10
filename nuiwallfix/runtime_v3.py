"""Runtime v3: strict SRI selection and explicit write accounting."""

import base64
import hashlib

from . import runtime_v1 as _v1
from .runtime_v2 import *  # noqa: F401,F403


def _strict_sri_matches(data, integrity):
    rank = {"sha256": 1, "sha384": 2, "sha512": 3}
    tokens = []
    for token in integrity.split():
        token = token.split("?", 1)[0]
        if "-" not in token:
            continue
        algorithm, expected = token.split("-", 1)
        algorithm = algorithm.lower()
        if algorithm in rank:
            tokens.append((algorithm, expected))
    if not tokens:
        return False
    strongest = max(rank[item[0]] for item in tokens)
    for algorithm, expected in tokens:
        if rank[algorithm] != strongest:
            continue
        actual = base64.b64encode(hashlib.new(algorithm, data).digest()).decode("ascii")
        if actual.rstrip("=") == expected.rstrip("="):
            return True
    return False


_v1._sri_matches = _strict_sri_matches

_api_apply_previous = _v1.api_apply


def api_apply(*args, **kwargs):
    result = _api_apply_previous(*args, **kwargs)
    if result.get("status") == "applied":
        target_files = result["summary"].get("written_files", 0)
        state_files = 1
        try:
            state_files += sum(1 for item in result.get("assets", []) if False)
            run_record = _v1.Path(result["state_dir"]) / "runs" / result["run_id"] / "run.json"
            payload = _v1.json.loads(run_record.read_text(encoding="utf-8"))
            state_files += sum(1 for item in payload.get("files", []) if item.get("existed_before"))
        except (OSError, ValueError):
            pass
        result["summary"]["target_files_written"] = target_files
        result["summary"]["state_files_written"] = state_files
        result["summary"]["written_files"] = target_files + state_files
    return result


_v1.api_apply = api_apply
