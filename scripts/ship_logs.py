"""Send a log file to the Mini-SIEM ingest API in batches.

Usage: python scripts/ship_logs.py samples/auth.log [--source auth.log] [--url http://localhost:8000]
       [--api-key msk_...]   (or SIEM_API_KEY; create one in the dashboard under Admin)

With --follow, tails the file like `tail -f` instead of sending it once and
exiting: new lines are batched (up to --batch-size lines or --batch-seconds
seconds, whichever comes first) and POSTed to /ingest. Handles log rotation
(the file being replaced or truncated) and a partial last line that hasn't
been flushed by the writer yet. A failed POST is retried with backoff and
the batch is never dropped, so lines are never lost on retry -- only
re-sent, which the API tolerates (re-ingesting the same line is harmless).
"""

import argparse
import json
import os
import time
import urllib.error
import urllib.request

BATCH_SIZE = 1000
FOLLOW_BATCH_SIZE = 500
FOLLOW_BATCH_SECONDS = 1.0
POLL_INTERVAL = 0.2
MAX_BACKOFF = 30.0


def _headers(api_key: str | None) -> dict:
    return {"Content-Type": "application/json", **({"Authorization": f"Bearer {api_key}"} if api_key else {})}


def send_batch(lines: list[str], source: str, url: str, api_key: str | None) -> dict:
    """POST one batch. Raises on failure; caller decides whether to retry."""
    payload = json.dumps({"source": source, "lines": lines}).encode()
    request = urllib.request.Request(f"{url}/ingest", data=payload, headers=_headers(api_key))
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)


def send_with_retry(lines: list[str], source: str, url: str, api_key: str | None, sleep=time.sleep) -> dict:
    """Send a batch, retrying with exponential backoff on any HTTP/network error.

    Retries forever (capped delay) so a transient outage never loses lines --
    it just delays them. Returns the server's response once it succeeds.
    """
    delay = 1.0
    while True:
        try:
            return send_batch(lines, source, url, api_key)
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, ConnectionError) as e:
            print(f"ship_logs: ingest failed ({e}), retrying in {delay:.0f}s", flush=True)
            sleep(delay)
            delay = min(delay * 2, MAX_BACKOFF)


def ship(path: str, source: str, url: str, api_key: str | None = None) -> None:
    with open(path, encoding="utf-8", errors="replace") as f:
        lines = [line.rstrip("\n") for line in f if line.strip()]

    totals = {"received": 0, "parsed": 0, "unparsed": 0}
    for start in range(0, len(lines), BATCH_SIZE):
        batch = lines[start : start + BATCH_SIZE]
        for key, value in send_with_retry(batch, source, url, api_key).items():
            totals[key] += value
    print(totals)


# --- follow mode -------------------------------------------------------------


class LogFollower:
    """Poll-based tail -f with rotation/truncation handling.

    Tracks the file's inode and read offset. If the file shrinks or is
    replaced (new inode) it is treated as a rotation: any unterminated
    partial line buffered from before the rotation is discarded (it belongs
    to the log that is gone) and reading resumes from the start of the new
    file.
    """

    def __init__(self, path: str, from_start: bool = False):
        self.path = path
        self._inode: int | None = None
        self._offset = 0
        self._buffer = ""
        self._from_start = from_start
        self._initialized = False

    def _open_initial(self) -> None:
        try:
            st = os.stat(self.path)
        except FileNotFoundError:
            return
        self._inode = st.st_ino
        self._offset = 0 if self._from_start else st.st_size
        self._initialized = True

    def poll(self) -> list[str]:
        """Return any new complete lines since the last call (possibly empty)."""
        if not self._initialized:
            self._open_initial()
            if not self._initialized:
                return []

        try:
            st = os.stat(self.path)
        except FileNotFoundError:
            return []

        if st.st_ino != self._inode or st.st_size < self._offset:
            # Rotated (new inode) or truncated (e.g. copytruncate): start over.
            self._inode = st.st_ino
            self._offset = 0
            self._buffer = ""

        if st.st_size <= self._offset:
            return []

        with open(self.path, encoding="utf-8", errors="replace") as f:
            f.seek(self._offset)
            chunk = f.read()
            self._offset = f.tell()

        self._buffer += chunk
        lines = self._buffer.split("\n")
        self._buffer = lines.pop()  # last element: partial line (or "" if chunk ended in \n)
        return [line for line in lines if line.strip()]


def run_follow(
    path: str,
    source: str,
    url: str,
    api_key: str | None,
    from_start: bool = False,
    batch_size: int = FOLLOW_BATCH_SIZE,
    batch_seconds: float = FOLLOW_BATCH_SECONDS,
    poll_interval: float = POLL_INTERVAL,
    sleep=time.sleep,
    now=time.monotonic,
    max_iterations: int | None = None,
) -> None:
    """Tail `path` forever (or `max_iterations` polls, for tests), shipping batches."""
    follower = LogFollower(path, from_start=from_start)
    buffer: list[str] = []
    last_flush = now()
    iterations = 0

    while max_iterations is None or iterations < max_iterations:
        iterations += 1
        buffer.extend(follower.poll())

        due = buffer and (len(buffer) >= batch_size or now() - last_flush >= batch_seconds)
        if due:
            while buffer:
                batch, buffer = buffer[:batch_size], buffer[batch_size:]
                send_with_retry(batch, source, url, api_key, sleep=sleep)
            last_flush = now()
        elif not buffer:
            last_flush = now()

        sleep(poll_interval)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("path")
    parser.add_argument("--source", default="auth.log")
    parser.add_argument("--url", default="http://localhost:8000")
    parser.add_argument("--api-key", default=os.getenv("SIEM_API_KEY"))
    parser.add_argument("--follow", action="store_true", help="tail the file instead of sending it once")
    parser.add_argument("--from-start", action="store_true", help="with --follow, start at the beginning of the file instead of the end")
    parser.add_argument("--batch-size", type=int, default=FOLLOW_BATCH_SIZE)
    parser.add_argument("--batch-seconds", type=float, default=FOLLOW_BATCH_SECONDS)
    args = parser.parse_args()

    if args.follow:
        run_follow(
            args.path,
            args.source,
            args.url,
            args.api_key,
            from_start=args.from_start,
            batch_size=args.batch_size,
            batch_seconds=args.batch_seconds,
        )
    else:
        ship(args.path, args.source, args.url, args.api_key)
