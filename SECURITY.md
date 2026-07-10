# Security and recovery notes

## Trust model

`nui-wallfix` treats scanned resource text and external URLs as untrusted input. It never executes JavaScript, Lua, CSS, or downloaded files.

The normal network client resolves a hostname once, validates every returned address, and connects to one of those exact validated IP addresses. Redirect targets are resolved and checked again. Loopback, private, link-local, multicast, reserved, and unspecified addresses are rejected unless the caller explicitly supplies `--allow-private-network`.

The client does not disable TLS certificate verification and refuses HTTPS-to-HTTP redirects. Per-file timeout and byte limits must be finite positive values.

## Mirror acceptance

A configured domestic mirror is accepted only when one of these conditions is true:

1. Its bytes exactly equal the original response.
2. Its bytes match an existing supported SRI value.
3. The operator explicitly passes `--allow-unverified-mirror`.

When Chromium requires CORS, including module scripts, modulepreload, fonts, SRI resources, and explicit `crossorigin` assets, a remote mirror must return `Access-Control-Allow-Origin: *`. Otherwise `auto` falls back to local mode and `cn-cdn` leaves the reference unresolved.

Existing domestic provider targets are treated as no-op results so repeated runs remain idempotent.

## Browser policy guards

- An HTML document containing `<base href>` is not given new relative local URLs automatically.
- A meta Content-Security-Policy is parsed conservatively. If the planned local or remote source is not allowed by the applicable directive, that reference remains unresolved.
- Business network calls, remote pages, dynamic URLs, and member methods merely named `import` are report-only.

## Transaction journal

Every write run stores backups and a journal outside the target tree before the first target mutation. Journal states include:

- `preparing`: apply may have been interrupted; restore accepts a before/after mixture.
- `applied`: apply completed.
- `restoring`: restore may have been interrupted; restore accepts a before/after mixture and continues safely.
- `restored` or `recovered`: target returned to its pre-apply state.
- `rollback-incomplete`: automatic rollback encountered at least one error and requires manual inspection.

Atomic same-directory replacement is used for file writes. Both apply and restore roll back on normal exceptions and `KeyboardInterrupt`. A stale PID lock is removed only after its owning process is confirmed absent.

If a process or machine is terminated during apply/restore, rerun `restore` with the same target, state directory, and run ID. Do not delete the run directory before recovery.

## Supported integration API

Toolbox integrations should use the stable lazy-loading module:

```python
from nuiwallfix.api import scan, apply, restore
```

For subprocess integration, prefer `--json` and inspect both the fixed exit code and result status. If `--json-output` fails after a successful apply, stdout still reports `status: applied` and includes the run ID; the process exits with code `40` to indicate only the report-file failure.

## Provider configuration

Provider JSON is configuration code and should be writable only by trusted operators. The loader validates its schema, types, credential-free HTTP(S) URLs, and supported rule kinds before any network operation.
