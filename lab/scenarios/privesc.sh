#!/bin/sh
# sudo-auth-failure, sudo-credential-file-access, sudo-root-shell: intern
# (a sudoer, intentionally) gets a sudo password wrong, then reads
# /etc/shadow via sudo, then opens a root shell via sudo.
set -eu
VICTIM="${VICTIM_HOST:-victim}"
INTERN_PASS="${INTERN_PASSWORD:-password123}"
SSH="sshpass -p $INTERN_PASS ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null intern@$VICTIM"
echo "SCENARIO_START privesc $(date -u +%Y-%m-%dT%H:%M:%SZ)"

# 1. wrong sudo password
$SSH 'echo wrongpassword | sudo -S -k true' || true

# 2. sudo reads a credential file
$SSH "printf '%s\n' '$INTERN_PASS' | sudo -S -k cat /etc/shadow > /dev/null" || true

# 3. interactive root shell via sudo
$SSH "printf '%s\nid\nexit\n' '$INTERN_PASS' | sudo -S -k /bin/bash" || true

echo "SCENARIO_END privesc"
