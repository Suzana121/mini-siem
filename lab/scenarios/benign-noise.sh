#!/bin/sh
# False-positive check: ordinary successful logins and commands, no attack
# signature. Expected to produce zero alerts.
set -eu
VICTIM="${VICTIM_HOST:-victim}"
INTERN_PASS="${INTERN_PASSWORD:-password123}"
echo "SCENARIO_START benign-noise $(date -u +%Y-%m-%dT%H:%M:%SZ)"

i=0
while [ "$i" -lt 3 ]; do
    sshpass -p "$INTERN_PASS" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        intern@"$VICTIM" 'date; whoami; exit' || true
    i=$((i + 1))
    sleep 1
done

echo "SCENARIO_END benign-noise"
