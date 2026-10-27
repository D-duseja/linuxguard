#!/usr/bin/env python3
"""LinuxGuard Desktop - local, read-only file permission risk scanner.

Security design: listens on 127.0.0.1 only (random port), Host/Origin checks
(blocks DNS rebinding and cross-site requests), per-run secret token on the API,
strict CSP + security headers, changes only after preview + confirm, with undo (never follows symlinks, refuses SUID/world-write, never follows symlinks,
never reads file contents), size/depth/entry limits, no external network use.
"""
import hmac, json, os, re, secrets, shutil, stat, subprocess, sys, threading, time, webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
try:
    import pwd, grp
except ImportError:  # Windows
    pwd = grp = None

BASE = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))  # works when frozen by PyInstaller
PAGE = open(os.path.join(BASE, "ui", "index.html"), encoding="utf-8").read()
VERSION = "1.1.0"
TOKEN = secrets.token_urlsafe(32)
MAX_ENTRIES, MAX_BODY = 5000, 262144
ROOT, PENDING, LASTLOG = [None], {}, [None]
LOGDIR = os.path.join(os.path.expanduser("~"), ".linuxguard")
ALLOWED = set()
LOCK, LAST = threading.Lock(), [0.0]
CTRL = re.compile(r"[\x00-\x1f\x7f]")
HEADERS = {"X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer",
           "Cache-Control": "no-store", "Cross-Origin-Resource-Policy": "same-origin",
           "Cross-Origin-Opener-Policy": "same-origin",
           "Permissions-Policy": "camera=(), microphone=(), geolocation=()"}

def name_of(table, key, fn):
    try:
        return re.sub(r"\s+", "_", fn(key)) if table else str(key)
    except Exception:
        return str(key)

def sniff(full):
    """Local-only content hints from the first 512 bytes. Nothing is stored or sent anywhere."""
    try:
        fd = os.open(full, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        try: b = os.read(fd, 512)
        finally: os.close(fd)
    except OSError:
        return ""
    if b[:4] == b"\x7fELF": return "elf"
    if b"PRIVATE KEY-----" in b: return "private key"
    t = b.decode("utf-8", "ignore")
    if re.search(r"(?i)(password|passwd|secret|api[_-]?key|token)\s*[=:]", t): return "credential"
    return "script" if t.startswith("#!") else ""

def scan(path, depth, inspect=True):
    root = os.path.realpath(os.path.expanduser(path))
    if not os.path.isdir(root):
        raise ValueError("That path is not a folder.")
    ROOT[0] = root
    items, truncated = [], False
    base = root.rstrip(os.sep).count(os.sep)
    for dp, dns, fns in os.walk(root, followlinks=False):
        level = dp.rstrip(os.sep).count(os.sep) - base
        if level + 1 >= depth:
            names, dns[:] = dns + fns, []
        else:
            names = dns + fns
        for n in names:
            if len(items) >= MAX_ENTRIES:
                return items, True
            full = os.path.join(dp, n)
            try:
                st = os.lstat(full)
            except OSError:
                continue
            rel = os.path.relpath(full, root)
            if CTRL.search(rel) or len(rel) > 300:
                continue
            fm = stat.filemode(st.st_mode)
            items.append({"t": fm[0], "p": fm[1:], "o": name_of(pwd, st.st_uid, lambda u: pwd.getpwuid(u).pw_name),
                          "g": name_of(grp, st.st_gid, lambda g: grp.getgrgid(g).gr_name), "s": st.st_size,
                          "m": time.strftime("%b %d %H:%M", time.localtime(st.st_mtime)), "n": rel, "x": sniff(full) if (inspect and fm[0] == "-") else ""})
    items.sort(key=lambda i: i["n"])
    return items, truncated

class H(BaseHTTPRequestHandler):
    server_version, sys_version = "LinuxGuard", ""
    def log_message(self, *a): pass
    def send(self, code, body, ctype="application/json", extra=None):
        b = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype + "; charset=utf-8")
        self.send_header("Content-Length", str(len(b)))
        for k, v in {**HEADERS, **(extra or {})}.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(b)
    def err(self, code, msg): self.send(code, json.dumps({"error": msg}))
    def do_GET(self):
        if self.headers.get("Host") not in ALLOWED: return self.err(403, "Forbidden host")
        if self.path.split("?")[0] not in ("/", "/index.html"): return self.err(404, "Not found")
        nonce = secrets.token_urlsafe(16)
        html = PAGE.replace("__LG_TOKEN__", TOKEN).replace("<script>", '<script nonce="%s">' % nonce)
        csp = ("default-src 'none'; script-src 'nonce-%s'; script-src-attr 'unsafe-inline'; style-src 'unsafe-inline'; "
               "img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'" % nonce)
        self.send(200, html, "text/html", {"Content-Security-Policy": csp})
    def do_POST(self):
        host = self.headers.get("Host")
        if host not in ALLOWED: return self.err(403, "Forbidden host")
        origin = self.headers.get("Origin")
        if origin and origin != "http://" + host: return self.err(403, "Forbidden origin")
        route = ROUTES.get(self.path)
        if not route: return self.err(404, "Not found")
        if not hmac.compare_digest(self.headers.get("X-LG-Token", ""), TOKEN): return self.err(403, "Bad token")
        if not self.headers.get("Content-Type", "").startswith("application/json"): return self.err(415, "JSON only")
        try:
            n = int(self.headers.get("Content-Length", "0"))
            if not 0 < n <= MAX_BODY: return self.err(413, "Bad request size")
            data = json.loads(self.rfile.read(n))
            if not isinstance(data, dict): raise ValueError
        except (ValueError, TypeError): return self.err(400, "Malformed request")
        if route is api_scan:  # only the expensive route is rate-limited
            with LOCK:
                if time.time() - LAST[0] < 0.3: return self.err(429, "Slow down")
                LAST[0] = time.time()
        try: self.send(200, json.dumps(route(data)))
        except ValueError as e: self.err(400, str(e))
        except PermissionError: self.err(403, "Permission denied.")
        except Exception: self.err(500, "Request failed.")

def api_scan(d):
    path = d.get("path")
    if not isinstance(path, str) or not path.strip() or len(path) > 1024 or "\x00" in path:
        raise ValueError("Enter a valid folder path.")
    items, trunc = scan(path.strip(), max(1, min(int(d.get("depth", 1)), 8)), bool(d.get("inspect", True)))
    warn = ("Windows does not store Linux permissions, so these values are approximations and Apply is disabled. "
            "Use scripts/run-wsl.bat (WSL) or run on Linux for real results.") if os.name == "nt" else ""
    return {"items": items, "truncated": trunc, "warning": warn}

def safe_path(rel):
    """Resolve a path inside the last scanned folder. Refuses symlinks anywhere on the path."""
    root = ROOT[0]
    if not root: raise ValueError("Scan a folder first.")
    if not isinstance(rel, str) or CTRL.search(rel) or os.path.isabs(rel): raise ValueError("Bad path.")
    full = os.path.normpath(os.path.join(root, rel))
    if full == root or os.path.commonpath([root, full]) != root: raise ValueError("Path is outside the scanned folder.")
    if os.path.realpath(full) != full: raise ValueError("Symlinks are never modified.")
    st = os.lstat(full)
    if not (stat.S_ISREG(st.st_mode) or stat.S_ISDIR(st.st_mode)): raise ValueError("Unsupported file type.")
    return full, st

def secure_chmod(rel, mode):
    """Race-free chmod. Walks from the scanned root using O_NOFOLLOW descriptors and changes the
    opened object itself, so a path component swapped for a symlink after validation cannot redirect it."""
    parts = [p for p in rel.split(os.sep) if p]
    if not parts: raise ValueError("Bad path.")
    fd = os.open(ROOT[0], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for p in parts[:-1]:
            nfd = os.open(p, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd); os.close(fd); fd = nfd
        name = parts[-1]
        st = os.stat(name, dir_fd=fd, follow_symlinks=False)
        if not (stat.S_ISREG(st.st_mode) or stat.S_ISDIR(st.st_mode)): raise ValueError("Unsupported file type.")
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | (os.O_DIRECTORY if stat.S_ISDIR(st.st_mode) else 0)
        try: ffd = os.open(name, flags, dir_fd=fd)
        except PermissionError: ffd = None  # unreadable file: fall back to chmod by name below
        if ffd is None:
            prev = stat.S_IMODE(st.st_mode); os.chmod(name, mode, dir_fd=fd); return prev
        try:
            st2 = os.fstat(ffd)
            if (st2.st_dev, st2.st_ino) != (st.st_dev, st.st_ino): raise ValueError("Changed during apply; skipped.")
            prev = stat.S_IMODE(st2.st_mode); os.fchmod(ffd, mode); return prev
        finally: os.close(ffd)
    finally: os.close(fd)

def api_plan(d):
    if os.name == "nt": raise ValueError("Applying changes works on Linux, macOS and WSL only.")
    ch = d.get("changes")
    if not isinstance(ch, list) or not 0 < len(ch) <= 500: raise ValueError("Choose between 1 and 500 files.")
    plan = []
    for c in ch:
        mode = str(c.get("mode", ""))
        if not re.fullmatch(r"[0-7]{3,4}", mode): raise ValueError("Bad permission value.")
        m = int(mode, 8)
        if m & 0o7002: raise ValueError("SUID, SGID, sticky and world-writable modes are refused.")
        full, st = safe_path(c.get("n"))
        cur = stat.S_IMODE(st.st_mode)
        if cur != m: plan.append({"n": os.path.relpath(full, ROOT[0]), "from": "%03o" % cur, "to": "%03o" % m})
    code = secrets.token_urlsafe(12)
    PENDING.clear(); PENDING[code] = (ROOT[0], plan, time.time())
    return {"code": code, "plan": plan}

def api_apply(d):
    code = d.get("code")
    p = PENDING.pop(code, None) if isinstance(code, str) else None
    if not p or p[0] != ROOT[0] or time.time() - p[2] > 180: raise ValueError("Preview expired. Preview the changes again.")
    done, errors, undo = 0, [], []
    for c in p[1]:
        try:
            safe_path(c["n"])
            cur = secure_chmod(c["n"], int(c["to"], 8))
            undo.append({"n": c["n"], "from": "%03o" % cur}); done += 1
        except (OSError, ValueError) as e:
            errors.append("%s: %s" % (c["n"], str(e)[:80]))
    if undo:
        os.makedirs(LOGDIR, mode=0o700, exist_ok=True)
        fn = os.path.join(LOGDIR, "undo-%d.json" % int(time.time()))
        with open(fn, "w", encoding="utf-8") as fh: json.dump({"root": ROOT[0], "items": undo}, fh)
        LASTLOG[0] = fn
    return {"applied": done, "errors": errors}

def api_undo(d):
    fn = LASTLOG[0]
    if not fn or not os.path.exists(fn): raise ValueError("Nothing to undo in this session.")
    with open(fn, encoding="utf-8") as fh: log = json.load(fh)
    if log["root"] != ROOT[0]: raise ValueError("The last change was in a different folder. Scan that folder first.")
    n, errors = 0, []
    for c in log["items"]:
        try:
            safe_path(c["n"]); secure_chmod(c["n"], int(c["from"], 8)); n += 1
        except (OSError, ValueError) as e:
            errors.append("%s: %s" % (c["n"], str(e)[:80]))
    os.replace(fn, fn + ".done"); LASTLOG[0] = None
    return {"restored": n, "errors": errors}

ROUTES = {"/api/scan": api_scan, "/api/plan": api_plan, "/api/apply": api_apply, "/api/undo": api_undo}

def open_window(url):
    c = []
    if os.name == "nt":
        for b in filter(None, [os.environ.get("PROGRAMFILES"), os.environ.get("PROGRAMFILES(X86)"), os.environ.get("LOCALAPPDATA")]):
            c += [os.path.join(b, r"Microsoft\Edge\Application\msedge.exe"), os.path.join(b, r"Google\Chrome\Application\chrome.exe")]
    else:
        c = [shutil.which(x) for x in ("google-chrome", "chromium", "chromium-browser", "microsoft-edge")]
    for p in c:
        if p and os.path.exists(p):
            try:
                subprocess.Popen([p, "--app=" + url, "--window-size=1240,820"]); return
            except OSError: pass
    webbrowser.open(url)

def main():
    try: srv = ThreadingHTTPServer(("127.0.0.1", 47651), H)  # fixed port keeps saved history/baselines
    except OSError: srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    port = srv.server_address[1]
    ALLOWED.update({"127.0.0.1:%d" % port, "localhost:%d" % port})
    url = "http://127.0.0.1:%d/" % port
    print("LinuxGuard v%s running at" % VERSION, url, "(press Ctrl+C to quit)")
    if "--no-window" not in sys.argv:
        threading.Timer(0.6, open_window, [url]).start()
    try: srv.serve_forever()
    except KeyboardInterrupt: print("\nBye")

if __name__ == "__main__":
    main()
