"""Deterministic generator of realistic auth.log traffic with injected attacks.

    lines, truth = generate(100_000, seed=1)

`lines` are BSD-syslog auth.log lines the parser in app/parsers/auth_log.py
understands (plus a few percent of lines it deliberately ignores, as in a real
file), timestamps never decrease. `truth` lists every injected attack as
`{"rule_id", "source_ip", "line_index"}` where `line_index` is the line whose
arrival should make the rule fire. Attacks are bursts shaped to satisfy the
real rules in rules/, with spacing chosen so one burst does not accidentally
trigger a sibling rule (e.g. spraying is paced slower than the brute-force
threshold) -- except where the overlap is genuine (a brute-force that ends in
a login legitimately triggers both ssh-brute-force and ssh-brute-force-success).

Same (n_lines, seed, attack_ratio, start) gives byte-identical output.
BSD timestamps have no year: parse with a reference time after the last line
(`parse_line(line, reference)`) and keep the span inside one calendar year.
"""

import random
from datetime import datetime, timedelta, timezone
from typing import TypedDict

MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
DEFAULT_START = datetime(2026, 10, 26, 8, 0, 0, tzinfo=timezone.utc)
BACKGROUND_RATE = 4.0  # average background lines per second of log time

HOSTS = ["web01", "web02", "web03", "db01", "app01", "bastion01"]
USERS = ["alice", "bob", "carol", "dave", "erin", "frank", "grace", "heidi", "ivan", "judy",
         "deploy", "ubuntu", "ops", "jenkins", "backup", "intern"]
# Usernames attackers like to guess.
GUESS_USERS = ["admin", "test", "oracle", "postgres", "ubuntu", "git", "user", "guest", "pi", "ftpuser",
               "www-data", "mysql", "tomcat", "nagios", "vagrant", "support", "root", "deploy"]
SUDO_COMMANDS = [
    "/usr/bin/apt update", "/usr/bin/apt upgrade -y", "/usr/bin/systemctl restart nginx",
    "/usr/bin/systemctl status sshd", "/usr/bin/journalctl -u ssh --since today",
    "/usr/bin/tail -n 200 /var/log/syslog", "/usr/bin/docker ps", "/bin/ls -la /root",
    "/usr/bin/systemctl reload postgresql", "/usr/sbin/ufw status", "/usr/bin/du -sh /var/lib",
]
# Documentation-style and private ranges for ordinary users; attackers come from
# "public-looking" ranges so enrichment marks them external.
ATTACKER_OCTETS = [45, 91, 103, 118, 141, 159, 185, 193, 194, 218]
FEED_OCTETS = list(range(11, 45))  # synthetic threat-intel feeds stay clear of every address used above

ATTACK_TYPES = [
    "brute-force", "spraying", "brute-force-success", "scanner",
    "root-login", "privesc", "persistence",
]


class GroundTruth(TypedDict):
    rule_id: str
    source_ip: str
    line_index: int


_Item = tuple[datetime, str, "tuple[tuple[str, str], ...]"]  # (time, line, ((rule_id, ip), ...) it should trigger)


class _Gen:
    def __init__(self, seed: int, start: datetime):
        self.rng = random.Random(seed)
        self.start = start
        self.pid = {h: self.rng.randint(800, 4000) for h in HOSTS}
        self.used_ips: set[str] = set()
        self.uid = {u: 1001 + i for i, u in enumerate(USERS)}
        self.next_uid = 1100
        self.accounts = 0

    # --- primitives -------------------------------------------------------

    def fmt(self, t: datetime, host: str, proc: str, msg: str, pid: int | None = None) -> str:
        tag = f"{proc}[{pid}]" if pid is not None else proc
        return f"{MONTHS[t.month - 1]} {t.day:>2} {t:%H:%M:%S} {host} {tag}: {msg}"

    def new_pid(self, host: str) -> int:
        self.pid[host] += self.rng.randint(1, 40)
        if self.pid[host] > 65000:
            self.pid[host] = 1000
        return self.pid[host]

    def user_ip(self) -> str:
        r = self.rng
        pick = r.random()
        if pick < 0.5:
            return f"10.{r.randint(0, 7)}.{r.randint(0, 255)}.{r.randint(2, 254)}"
        if pick < 0.8:
            return f"192.168.{r.randint(0, 20)}.{r.randint(2, 254)}"
        return f"198.51.100.{r.randint(2, 254)}"

    def attacker_ip(self) -> str:
        while True:
            ip = f"{self.rng.choice(ATTACKER_OCTETS)}.{self.rng.randint(0, 255)}.{self.rng.randint(0, 255)}.{self.rng.randint(1, 254)}"
            if ip not in self.used_ips:
                self.used_ips.add(ip)
                return ip

    def port(self) -> int:
        return self.rng.randint(32768, 61000)

    def key_fingerprint(self) -> str:
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        return "SHA256:" + "".join(self.rng.choice(alphabet) for _ in range(43))

    # --- background traffic ---------------------------------------------------

    def background_item(self, t: datetime) -> list[_Item]:
        r = self.rng
        host = r.choice(HOSTS)
        kind = r.random()
        if kind < 0.40:
            return self._login(t, host, publickey=True)
        if kind < 0.55:
            return self._login(t, host, publickey=False)
        if kind < 0.75:
            return self._sudo(t, host)
        if kind < 0.85:
            return self._cron(t, host)
        if kind < 0.90:
            return self._probe(t, host)
        return self._noise(t, host)

    def _login(self, t: datetime, host: str, publickey: bool) -> list[_Item]:
        r = self.rng
        user, ip, port, pid = r.choice(USERS), self.user_ip(), self.port(), self.new_pid(host)
        out: list[_Item] = []
        if not publickey and r.random() < 0.3:  # a mistyped password, then success
            out.append((t, self.fmt(t, host, "sshd", f"Failed password for {user} from {ip} port {port} ssh2", pid), ()))
            t += timedelta(seconds=r.randint(2, 8))
            port = self.port()
        if publickey:
            msg = f"Accepted publickey for {user} from {ip} port {port} ssh2: RSA {self.key_fingerprint()}"
        else:
            msg = f"Accepted password for {user} from {ip} port {port} ssh2"
        out.append((t, self.fmt(t, host, "sshd", msg, pid), ()))
        out.append((t, self.fmt(t, host, "sshd", f"pam_unix(sshd:session): session opened for user {user}(uid={self.uid[user]}) by (uid=0)", pid), ()))
        out.append((t, self.fmt(t, host, "systemd-logind", f"New session {r.randint(1, 900)} of user {user}.", 612), ()))
        end = t + timedelta(seconds=r.randint(20, 3600))
        out.append((end, self.fmt(end, host, "sshd", f"Disconnected from user {user} {ip} port {port}", pid), ()))
        out.append((end, self.fmt(end, host, "sshd", f"pam_unix(sshd:session): session closed for user {user}", pid), ()))
        return out

    def _sudo(self, t: datetime, host: str) -> list[_Item]:
        r = self.rng
        user = r.choice(USERS)
        uid = self.uid[user]
        cmd = r.choice(SUDO_COMMANDS)
        tty = f"pts/{r.randint(0, 4)}"
        out: list[_Item] = [
            (t, self.fmt(t, host, "sudo", f"  {user} : TTY={tty} ; PWD=/home/{user} ; USER=root ; COMMAND={cmd}"), ()),
            (t, self.fmt(t, host, "sudo", f"pam_unix(sudo:session): session opened for user root(uid=0) by {user}(uid={uid})"), ()),
        ]
        end = t + timedelta(seconds=r.randint(1, 120))
        out.append((end, self.fmt(end, host, "sudo", f"pam_unix(sudo:session): session closed for user root"), ()))
        return out

    def _cron(self, t: datetime, host: str) -> list[_Item]:
        pid = self.new_pid(host)
        end = t + timedelta(seconds=self.rng.randint(0, 3))
        return [
            (t, self.fmt(t, host, "CRON", "pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)", pid), ()),
            (end, self.fmt(end, host, "CRON", "pam_unix(cron:session): session closed for user root", pid), ()),
        ]

    def _probe(self, t: datetime, host: str) -> list[_Item]:
        # A lone health-check style connection: parsed, never enough to alert.
        ip, port, pid = self.user_ip(), self.port(), self.new_pid(host)
        return [(t, self.fmt(t, host, "sshd", f"Connection closed by {ip} port {port} [preauth]", pid), ())]

    def _noise(self, t: datetime, host: str) -> list[_Item]:
        r = self.rng
        choices = [
            ("systemd", f"Started Session {r.randint(1, 900)} of user {r.choice(USERS)}.", 1),
            ("systemd-logind", f"Removed session {r.randint(1, 900)}.", 612),
            ("sshd", f"Received disconnect from {self.user_ip()} port {self.port()}:11: disconnected by user", self.new_pid(host)),
            ("polkitd", f"Registered Authentication Agent for unix-session:{r.randint(1, 900)}", 745),
        ]
        proc, msg, pid = r.choice(choices)
        return [(t, self.fmt(t, host, proc, msg, pid), ())]

    # --- attacks ---------------------------------------------------------------

    def attack(self, kind: str, t: datetime) -> list[_Item]:
        return getattr(self, "_attack_" + kind.replace("-", "_"))(t)

    def _failed(self, t: datetime, host: str, user: str, ip: str, invalid: bool = False) -> list[_Item]:
        pid, port = self.new_pid(host), self.port()
        out: list[_Item] = []
        if invalid:
            out.append((t, self.fmt(t, host, "sshd", f"Invalid user {user} from {ip} port {port}", pid), ()))
            out.append((t, self.fmt(t, host, "sshd", f"Failed password for invalid user {user} from {ip} port {port} ssh2", pid), ()))
        else:
            out.append((t, self.fmt(t, host, "sshd", f"Failed password for {user} from {ip} port {port} ssh2", pid), ()))
        return out

    def _attack_brute_force(self, t: datetime) -> list[_Item]:
        host, ip = self.rng.choice(HOSTS), self.attacker_ip()
        users = self.rng.sample(["root", "admin", "deploy"], 2)  # <5 distinct: not spraying
        out: list[_Item] = []
        n = self.rng.randint(6, 9)  # <10: the threshold re-arms after firing and needs 5 more
        for i in range(n):
            t += timedelta(seconds=self.rng.randint(1, 4))
            items = self._failed(t, host, users[i % 2], ip)
            if i == 4:  # the fifth failure inside 60s trips the threshold
                items[-1] = (items[-1][0], items[-1][1], (("ssh-brute-force", ip),))
            out += items
        pid = self.new_pid(host)
        out.append((t, self.fmt(t, host, "sshd", f"Connection closed by authenticating user {users[0]} {ip} port {self.port()} [preauth]", pid), ()))
        return out

    def _attack_spraying(self, t: datetime) -> list[_Item]:
        host, ip = self.rng.choice(HOSTS), self.attacker_ip()
        users = self.rng.sample(GUESS_USERS, self.rng.randint(6, 8))  # the 5th user re-enters the reset window
        out: list[_Item] = []
        for i, user in enumerate(users):
            t += timedelta(seconds=self.rng.randint(20, 35))  # slower than 5 failures / 60s
            items = self._failed(t, host, user, ip, invalid=user not in USERS and user != "root")
            if i == 4:
                items[0] = (items[0][0], items[0][1], (("ssh-password-spraying", ip),))
            out += items
        return out

    def _attack_brute_force_success(self, t: datetime) -> list[_Item]:
        host, ip = self.rng.choice(HOSTS), self.attacker_ip()
        user = self.rng.choice(["deploy", "ops", "backup", "jenkins"])
        out: list[_Item] = []
        for i in range(self.rng.randint(6, 9)):
            t += timedelta(seconds=self.rng.randint(1, 4))
            items = self._failed(t, host, user, ip)
            if i == 4:
                items[-1] = (items[-1][0], items[-1][1], (("ssh-brute-force", ip),))
            out += items
        t += timedelta(seconds=self.rng.randint(2, 6))
        pid, port = self.new_pid(host), self.port()
        accepted = self.fmt(t, host, "sshd", f"Accepted password for {user} from {ip} port {port} ssh2", pid)
        out.append((t, accepted, (("ssh-brute-force-success", ip),)))
        out.append((t, self.fmt(t, host, "sshd", f"pam_unix(sshd:session): session opened for user {user}(uid={self.uid[user]}) by (uid=0)", pid), ()))
        return out

    def _attack_scanner(self, t: datetime) -> list[_Item]:
        host, ip = self.rng.choice(HOSTS), self.attacker_ip()
        out: list[_Item] = []
        for i in range(self.rng.randint(3, 5)):
            t += timedelta(seconds=self.rng.randint(1, 8))
            line = self.fmt(t, host, "sshd", f"Did not receive identification string from {ip} port {self.port()}", self.new_pid(host))
            out.append((t, line, (("ssh-scanner", ip),) if i == 2 else ()))
        return out

    def _attack_root_login(self, t: datetime) -> list[_Item]:
        host, ip = self.rng.choice(HOSTS), self.attacker_ip()
        pid, port = self.new_pid(host), self.port()
        accepted = self.fmt(t, host, "sshd", f"Accepted password for root from {ip} port {port} ssh2", pid)
        return [
            (t, accepted, (("ssh-root-login", ip),)),
            (t, self.fmt(t, host, "sshd", "pam_unix(sshd:session): session opened for user root(uid=0) by (uid=0)", pid), ()),
        ]

    def _attack_privesc(self, t: datetime) -> list[_Item]:
        # A hijacked low-privilege account: login, wrong sudo password, credential read, root shell.
        host, ip = self.rng.choice(HOSTS), self.attacker_ip()
        user = "intern"
        pid, port = self.new_pid(host), self.port()
        out: list[_Item] = [
            (t, self.fmt(t, host, "sshd", f"Accepted password for {user} from {ip} port {port} ssh2", pid), ()),
            (t, self.fmt(t, host, "sshd", f"pam_unix(sshd:session): session opened for user {user}(uid={self.uid[user]}) by (uid=0)", pid), ()),
        ]
        t += timedelta(seconds=self.rng.randint(5, 30))
        out.append((t, self.fmt(t, host, "sudo", f"  {user} : 3 incorrect password attempts ; TTY=pts/1 ; PWD=/home/{user} ; USER=root ; COMMAND=/usr/bin/apt install netcat"),
                    (("sudo-auth-failure", ip),)))
        t += timedelta(seconds=self.rng.randint(5, 30))
        out.append((t, self.fmt(t, host, "sudo", f"  {user} : TTY=pts/1 ; PWD=/home/{user} ; USER=root ; COMMAND=/bin/cat /etc/shadow"),
                    (("sudo-credential-file-access", ip),)))
        t += timedelta(seconds=self.rng.randint(5, 30))
        out.append((t, self.fmt(t, host, "sudo", f"  {user} : TTY=pts/1 ; PWD=/home/{user} ; USER=root ; COMMAND=/bin/bash"),
                    (("sudo-root-shell", ip),)))
        out.append((t, self.fmt(t, host, "sudo", f"pam_unix(sudo:session): session opened for user root(uid=0) by {user}(uid={self.uid[user]})"), ()))
        return out

    def _attack_persistence(self, t: datetime) -> list[_Item]:
        # Compromised admin creates a backdoor account and grants it sudo.
        host, ip = self.rng.choice(HOSTS), self.attacker_ip()
        admin = self.rng.choice(["deploy", "ops"])
        name = f"svc{self.accounts:03d}"
        self.accounts += 1
        uid = self.next_uid
        self.next_uid += 1
        pid, port = self.new_pid(host), self.port()
        out: list[_Item] = [
            (t, self.fmt(t, host, "sshd", f"Accepted publickey for {admin} from {ip} port {port} ssh2: RSA {self.key_fingerprint()}", pid), ()),
            (t, self.fmt(t, host, "sshd", f"pam_unix(sshd:session): session opened for user {admin}(uid={self.uid[admin]}) by (uid=0)", pid), ()),
        ]
        t += timedelta(seconds=self.rng.randint(5, 40))
        out.append((t, self.fmt(t, host, "sudo", f"  {admin} : TTY=pts/0 ; PWD=/home/{admin} ; USER=root ; COMMAND=/usr/sbin/useradd -m -s /bin/bash {name}"), ()))
        upid = self.new_pid(host)
        out.append((t, self.fmt(t, host, "useradd", f"new group: name={name}, GID={uid}", upid), ()))
        out.append((t, self.fmt(t, host, "useradd", f"new user: name={name}, UID={uid}, GID={uid}, home=/home/{name}, shell=/bin/bash, from=/dev/pts/0", upid),
                    (("local-account-created", ip),)))
        t += timedelta(seconds=self.rng.randint(3, 30))
        out.append((t, self.fmt(t, host, "sudo", f"  {admin} : TTY=pts/0 ; PWD=/home/{admin} ; USER=root ; COMMAND=/usr/sbin/usermod -aG sudo {name}"), ()))
        mpid = self.new_pid(host)
        # One usermod line completes both the single-event rule and the created -> privileged sequence.
        out.append((t, self.fmt(t, host, "usermod", f"add '{name}' to group 'sudo'", mpid),
                    (("privileged-group-change", ip), ("backdoor-account", ip))))
        out.append((t, self.fmt(t, host, "usermod", f"add '{name}' to shadow group 'sudo'", mpid),
                    (("privileged-group-change", ip),)))
        return out


def generate(
    n_lines: int,
    seed: int = 1,
    attack_ratio: float = 0.02,
    start: datetime | None = None,
) -> tuple[list[str], list[GroundTruth]]:
    """Return `n_lines` auth.log lines and the ground truth of the injected attacks."""
    start = start or DEFAULT_START
    if start.tzinfo is None:
        start = start.replace(tzinfo=timezone.utc)
    gen = _Gen(seed, start)
    rng = gen.rng

    # 1. Attacks first, round-robin over the types until the budget is spent.
    budget = int(n_lines * attack_ratio)
    span = max(60.0, n_lines / BACKGROUND_RATE)
    attacks: list[_Item] = []
    order = ATTACK_TYPES[:]
    rng.shuffle(order)
    i = 0
    while len(attacks) < budget or (attack_ratio > 0 and n_lines >= 1000 and i < len(order)):  # >= one of every type
        kind = order[i % len(order)]
        i += 1
        burst = gen.attack(kind, start + timedelta(seconds=rng.uniform(0, span)))
        if len(attacks) + len(burst) > n_lines:
            break
        attacks += sorted(burst, key=lambda item: item[0])  # stable: keeps emitted order on ties
    attack_lines = len(attacks)

    # 2. Background composites until there are enough lines, then trim to size.
    target = max(0, n_lines - attack_lines)
    background: list[_Item] = []
    while len(background) < target + 8:
        t = start + timedelta(seconds=rng.uniform(0, span))
        background += gen.background_item(t)
    background.sort(key=lambda item: item[0])
    del background[target:]

    # 3. Merge; ties keep background before attacks, then generation order.
    merged = sorted(
        [(item[0], 0, k, item) for k, item in enumerate(background)]
        + [(item[0], 1, k, item) for k, item in enumerate(attacks)],
        key=lambda x: x[:3],
    )
    lines: list[str] = []
    truth: list[GroundTruth] = []
    for _, _, _, (_, line, triggers) in merged:
        for rule_id, ip in triggers:
            truth.append({"rule_id": rule_id, "source_ip": ip, "line_index": len(lines)})
        lines.append(line)
    return lines, truth


def synthetic_feed(n: int, seed: int = 7) -> list[str]:
    """`n` threat-intel entries (mostly /32 hosts, then /24 and /16 networks).

    Drawn from address space the log generator never uses, so a large feed
    changes lookup cost but not detection results.
    """
    rng = random.Random(seed)
    entries = []
    for _ in range(n):
        a, b, c, d = rng.choice(FEED_OCTETS), rng.randint(0, 255), rng.randint(0, 255), rng.randint(0, 255)
        roll = rng.random()
        if roll < 0.6:
            entries.append(f"{a}.{b}.{c}.{d}")
        elif roll < 0.95:
            entries.append(f"{a}.{b}.{c}.0/24")
        else:
            entries.append(f"{a}.{b}.0.0/16")
    return entries
