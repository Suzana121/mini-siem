#!/bin/sh
# ssh-brute-force: many failed SSH logins for one account from this IP.
# `deploy`'s real password is a strong random string set at image build
# time and never appears in the wordlist, so every attempt fails.
set -eu
VICTIM="${VICTIM_HOST:-victim}"
echo "SCENARIO_START brute-force $(date -u +%Y-%m-%dT%H:%M:%SZ)"
hydra -l deploy -P /lab/wordlist-passwords.txt -t 4 -I ssh://"$VICTIM" || true
echo "SCENARIO_END brute-force"
