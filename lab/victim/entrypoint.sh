#!/bin/sh
set -e

mkdir -p /var/log
touch /var/log/auth.log
chmod 644 /var/log/auth.log  # read by the shipper container (different uid) via a shared volume

# /run is a tmpfs, recreated empty on every container start.
mkdir -p /run/sshd

# Host keys aren't baked into the image (would be shared across every build);
# generate them once per container instance.
ssh-keygen -A

rsyslogd
exec /usr/sbin/sshd -D
