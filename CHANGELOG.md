# Changelog

## 1.1.0
- Race-free apply and undo using file descriptors
- Misconfiguration checks: exposed .git, backup leftovers, Docker socket, risky SSH and sudo settings
- Scanner accepts `find -printf` listings from any machine; WSL launcher for Windows
- Assistant tolerates typos and suggests related questions
- Refined website with screenshots and FAQ

## 1.0.0
- Live Scan of real folders with local content hints
- Scanner for any file type (magic bytes, secrets, disguised executables, SHA-256, duplicates)
- Quick Fix importance ranking with shortest chmod commands and safe script with undo
- Apply with preview, confirmation, single-use codes and undo
- Drift watch with baselines
- Permission calculator and offline assistant
