# Publishing this repo on GitHub

1. Create an empty repo named `linuxguard` on github.com (no README, no license).
2. In this folder: `python scripts/personalize.py YOUR_GITHUB_NAME`
3. `git init -b main && git add . && git commit -m "Initial commit"`
4. `git remote add origin https://github.com/YOUR_GITHUB_NAME/linuxguard.git && git push -u origin main`
5. Repo **Settings > Pages > Source: GitHub Actions**. The site appears at `https://YOUR_GITHUB_NAME.github.io/linuxguard/`.
6. Add a description and topics (`linux`, `security`, `permissions`, `chmod`, `cybersecurity`, `python`).
7. Release: `git tag v1.0.0 && git push origin v1.0.0`. The Release workflow attaches `LinuxGuard.exe` and a source zip.
