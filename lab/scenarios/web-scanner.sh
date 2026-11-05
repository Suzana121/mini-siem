#!/bin/sh
# web-scanner: a burst of requests for non-existent paths (404s), as a
# directory brute-forcer would produce. Rule threshold: 20 in 60s.
set -eu
. /lab/scenarios/web-common.sh
echo "SCENARIO_START web-scanner $(date -u +%Y-%m-%dT%H:%M:%SZ)"
for p in $(seq 1 40); do
    curl -s -o /dev/null "http://$WEB/$(head -c 6 /dev/urandom | od -An -tx1 | tr -d ' \n').php"
done
echo "SCENARIO_END web-scanner"
