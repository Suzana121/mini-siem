# Intentionally insecure target for the attack lab: password auth, root SSH
# login, and a weak account are all enabled on purpose. Never expose this
# image outside the isolated lab-net network.
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        openssh-server rsyslog sudo passwd adduser \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd /var/log

COPY sshd_config.d.conf /etc/ssh/sshd_config.d/lab.conf
COPY rsyslog.conf /etc/rsyslog.conf
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Build-time secrets: a strong random password for `deploy` so it cannot be
# brute-forced within the lab's timeouts, and a deliberately weak one for
# `intern` (also listed in lab/attacker/wordlist.txt).
ARG DEPLOY_PASSWORD
ARG INTERN_PASSWORD=password123
ARG ROOT_PASSWORD=toor

RUN useradd -m -s /bin/bash deploy \
    && useradd -m -s /bin/bash intern \
    && usermod -aG sudo intern \
    && echo "deploy:${DEPLOY_PASSWORD}" | chpasswd \
    && echo "intern:${INTERN_PASSWORD}" | chpasswd \
    && echo "root:${ROOT_PASSWORD}" | chpasswd

EXPOSE 22
ENTRYPOINT ["/entrypoint.sh"]
