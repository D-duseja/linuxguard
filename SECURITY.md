# Security Policy

## Reporting a vulnerability
Please **do not open a public issue** for security problems. Use GitHub's private
"Report a vulnerability" button on the Security tab of this repository. Include steps to
reproduce and the version (`linuxguard.py` prints it on start). You will get a response within a few days.

## Scope
The local server (`linuxguard.py`), the API (`/api/scan`, `/api/plan`, `/api/apply`, `/api/undo`)
and the interface (`ui/index.html`).

## Design and known trade-offs
- Binds to `127.0.0.1` only; checks `Host` and `Origin`; every API call needs a per-run secret token.
- Strict CSP with a nonce for scripts. The interface uses inline event handlers, so the policy
  allows `script-src-attr 'unsafe-inline'`. All dynamic text is HTML-escaped. Moving to
  `addEventListener` would remove this exception (open to contributions).
- Apply refuses SUID, SGID, sticky and world-writable modes, never follows symlinks, and keeps restore points.
- Apply walks from the scanned folder with `O_NOFOLLOW` descriptors and changes the opened object (`fchmod`), so
  a file or parent folder swapped for a symlink after validation cannot redirect the change. Files the user cannot
  open fall back to chmod by name, which keeps a very small window for someone who can already write to that folder.
  Run LinuxGuard as a normal user, never as root, unless you must.

## Responsible use
Only scan systems you own or have written permission to assess.
