"""Replace the placeholder with your GitHub username:  python scripts/personalize.py your-name"""
import pathlib, sys
ph = "YOUR-" + "USERNAME"
if len(sys.argv) != 2: sys.exit("usage: python scripts/personalize.py <github-username>")
for p in pathlib.Path(".").rglob("*"):
    if p.is_file() and ".git" not in p.parts and p.suffix in {".md", ".html", ".yml", ".py", ".txt"}:
        t = p.read_text(encoding="utf-8")
        if ph in t: p.write_text(t.replace(ph, sys.argv[1]), encoding="utf-8"); print("updated", p)
