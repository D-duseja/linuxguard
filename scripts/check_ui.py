"""Syntax-check the JavaScript inside the HTML files (needs Node.js)."""
import os, re, subprocess, sys, tempfile
bad = 0
for f in ("ui/index.html", "docs/app.html"):
    m = re.search(r"<script>(.*)</script>", open(f, encoding="utf-8").read(), re.S)
    with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False, encoding="utf-8") as t: t.write(m.group(1))
    r = subprocess.run(["node", "--check", t.name], capture_output=True, text=True); os.unlink(t.name)
    print(("OK   " if r.returncode == 0 else "FAIL ") + f); bad |= r.returncode
sys.exit(bad)
