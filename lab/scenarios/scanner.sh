#!/bin/sh
# ssh-scanner: connections to port 22 that never send the SSH identification
# string, as a scanner or banner-grabber would produce.
set -eu
VICTIM="${VICTIM_HOST:-victim}"
echo "SCENARIO_START scanner $(date -u +%Y-%m-%dT%H:%M:%SZ)"
i=0
while [ "$i" -lt 5 ]; do
    timeout 2 nc -w1 "$VICTIM" 22 < /dev/null || true
    i=$((i + 1))
done
echo "SCENARIO_END scanner"
