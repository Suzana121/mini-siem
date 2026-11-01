# Attack tooling for the lab. Runs only on the internal lab-net network
# (no internet, no route to anything but `victim`) -- see docker-compose.lab.yml.
# Build context is the `lab/` directory (see docker-compose.lab.yml).
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        hydra nmap openssh-client netcat-openbsd sshpass python3 ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY attacker/wordlist-users.txt attacker/wordlist-passwords.txt /lab/
COPY scenarios /lab/scenarios
RUN chmod +x /lab/scenarios/*.sh
RUN mkdir -p /root/.ssh && echo "StrictHostKeyChecking no" > /root/.ssh/config \
    && echo "UserKnownHostsFile /dev/null" >> /root/.ssh/config

WORKDIR /lab
CMD ["sleep", "infinity"]
