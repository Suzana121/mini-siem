"""Download public IP blocklists into intel/.

    python scripts/update_intel.py

Feeds (all free, no API key):
  firehol_level1    -- FireHOL Level 1: attacks, malware C2, bogons
  spamhaus_drop     -- Spamhaus DROP: hijacked netblocks run by criminals
  blocklist_de_ssh  -- blocklist.de: IPs reported attacking SSH in the last 48h
"""

import urllib.request
from pathlib import Path

FEEDS = {
    "firehol_level1": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
    "spamhaus_drop": "https://www.spamhaus.org/drop/drop.txt",
    "blocklist_de_ssh": "https://lists.blocklist.de/lists/ssh.txt",
}
INTEL_DIR = Path(__file__).resolve().parent.parent / "intel"


def main() -> None:
    for name, url in FEEDS.items():
        request = urllib.request.Request(url, headers={"User-Agent": "mini-siem/0.3"})
        with urllib.request.urlopen(request, timeout=30) as response:
            body = response.read().decode("utf-8", errors="replace")
        target = INTEL_DIR / f"{name}.txt"
        target.write_text(body)
        entries = sum(1 for line in body.splitlines() if line.strip() and line.lstrip()[0] not in "#;")
        print(f"{name}: {entries} entries -> {target.relative_to(INTEL_DIR.parent)}")


if __name__ == "__main__":
    main()
