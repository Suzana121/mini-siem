"""Send a log file to the Mini-SIEM ingest API in batches.

Usage: python scripts/ship_logs.py samples/auth.log [--source auth.log] [--url http://localhost:8000]
"""

import argparse
import json
import urllib.request

BATCH_SIZE = 1000


def ship(path: str, source: str, url: str) -> None:
    with open(path, encoding="utf-8", errors="replace") as f:
        lines = [line.rstrip("\n") for line in f if line.strip()]

    totals = {"received": 0, "parsed": 0, "unparsed": 0}
    for start in range(0, len(lines), BATCH_SIZE):
        payload = json.dumps({"source": source, "lines": lines[start : start + BATCH_SIZE]})
        request = urllib.request.Request(
            f"{url}/ingest",
            data=payload.encode(),
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(request) as response:
            for key, value in json.load(response).items():
                totals[key] += value
    print(totals)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("path")
    parser.add_argument("--source", default="auth.log")
    parser.add_argument("--url", default="http://localhost:8000")
    args = parser.parse_args()
    ship(args.path, args.source, args.url)
