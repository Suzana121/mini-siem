#!/bin/sh
# ssh-root-login: a direct SSH login as root (the weak root password is
# known to the attacker here, simulating post-guess exploitation).
set -eu
VICTIM="${VICTIM_HOST:-victim}"
ROOT_PASS="${ROOT_PASSWORD:-toor}"
echo "SCENARIO_START root-login $(date -u +%Y-%m-%dT%H:%M:%SZ)"
sshpass -p "$ROOT_PASS" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    root@"$VICTIM" 'id; exit' || true
echo "SCENARIO_END root-login"
