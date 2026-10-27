#!/usr/bin/env bash
# Creates a demo folder with deliberately risky permissions (Linux / macOS / WSL).
# Usage: bash demo-setup.sh [folder]     Default folder: ~/linuxguard-demo
D="${1:-$HOME/linuxguard-demo}"; rm -rf "$D"; mkdir -p "$D/uploads" "$D/secure" "$D/tmp"
printf -- '-----BEGIN OPENSSH PRIVATE KEY-----\nFAKE-DEMO-KEY-NOT-REAL\n-----END OPENSSH PRIVATE KEY-----\n' > "$D/id_rsa"; chmod 644 "$D/id_rsa"
printf 'DB_PASSWORD=demo-not-real\nAPI_KEY=demo\n' > "$D/.env"; chmod 664 "$D/.env"
printf '#!/bin/bash\necho deploying\n' > "$D/deploy.sh"; chmod 777 "$D/deploy.sh"
printf '#!/bin/sh\necho backup\n' > "$D/backup"; chmod 4755 "$D/backup"
printf 'server { listen 80; }\n' > "$D/app.conf"; chmod 664 "$D/app.conf"
printf 'DEMO PLACEHOLDER\n' > "$D/customers.sqlite"; chmod 666 "$D/customers.sqlite"
printf 'Meeting notes\n' > "$D/notes.txt"; chmod 644 "$D/notes.txt"
printf '2026-10-12 INFO started\n' > "$D/access.log"; chmod 644 "$D/access.log"
printf 'notes.txt placeholder with private key marker\n-----BEGIN RSA PRIVATE KEY-----\n' > "$D/readme.txt"; chmod 644 "$D/readme.txt"
chmod 777 "$D/uploads"; chmod 755 "$D/secure"; chmod 1777 "$D/tmp"; ln -s deploy.sh "$D/latest"
echo "Demo folder ready: $D"; echo "In LinuxGuard > Live Scan, scan this path (all fake data)."
