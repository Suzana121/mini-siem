#!/bin/sh
# web-attack-tool-agent: requests announcing a known attack tool in the User-Agent.
set -eu
. /lab/scenarios/web-common.sh
echo "SCENARIO_START web-attack-tool-agent $(date -u +%Y-%m-%dT%H:%M:%SZ)"
curl -s -o /dev/null -A "sqlmap/1.7.11#stable (https://sqlmap.org)" "http://$WEB/"
curl -s -o /dev/null -A "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:001)" "http://$WEB/"
echo "SCENARIO_END web-attack-tool-agent"
