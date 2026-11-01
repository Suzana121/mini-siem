"""Unit tests for the --follow tail logic in scripts/ship_logs.py (no network, no Docker)."""

import os

import pytest

from scripts.ship_logs import LogFollower, run_follow, send_with_retry


def test_follow_from_end_ignores_existing_content(tmp_path):
    path = tmp_path / "auth.log"
    path.write_text("old line 1\nold line 2\n")
    follower = LogFollower(str(path), from_start=False)
    assert follower.poll() == []  # starts at end; nothing new yet

    with open(path, "a") as f:
        f.write("new line\n")
    assert follower.poll() == ["new line"]


def test_follow_from_start_reads_existing_content(tmp_path):
    path = tmp_path / "auth.log"
    path.write_text("line 1\nline 2\n")
    follower = LogFollower(str(path), from_start=True)
    assert follower.poll() == ["line 1", "line 2"]


def test_partial_last_line_is_buffered_until_newline(tmp_path):
    path = tmp_path / "auth.log"
    path.write_text("")
    follower = LogFollower(str(path), from_start=True)

    with open(path, "a") as f:
        f.write("full line 1\npartial line")
    assert follower.poll() == ["full line 1"]

    with open(path, "a") as f:
        f.write(" continues\n")
    assert follower.poll() == ["partial line continues"]


def test_missing_file_returns_nothing_until_created(tmp_path):
    path = tmp_path / "auth.log"
    follower = LogFollower(str(path), from_start=True)
    assert follower.poll() == []

    path.write_text("first line\n")
    assert follower.poll() == ["first line"]


def test_truncation_resets_offset_and_drops_stale_partial(tmp_path):
    path = tmp_path / "auth.log"
    path.write_text("line 1\npartial")
    follower = LogFollower(str(path), from_start=True)
    assert follower.poll() == ["line 1"]

    # Truncate in place (e.g. logrotate copytruncate) and write fresh content.
    with open(path, "w") as f:
        f.write("new content\n")
    assert follower.poll() == ["new content"]


def test_rotation_new_inode_starts_from_beginning_of_new_file(tmp_path):
    path = tmp_path / "auth.log"
    path.write_text("old file line\n")
    follower = LogFollower(str(path), from_start=True)
    assert follower.poll() == ["old file line"]

    rotated = tmp_path / "auth.log.1"
    os.rename(path, rotated)
    path.write_text("fresh file line\n")
    assert follower.poll() == ["fresh file line"]


def test_send_with_retry_retries_until_success():
    attempts = []
    sleeps = []

    def fake_send(lines, source, url, api_key):
        attempts.append(lines)
        if len(attempts) < 3:
            raise ConnectionError("boom")
        return {"received": len(lines), "parsed": len(lines), "unparsed": 0}

    import scripts.ship_logs as ship_logs

    original = ship_logs.send_batch
    ship_logs.send_batch = fake_send
    try:
        result = send_with_retry(["a", "b"], "auth.log", "http://api", None, sleep=sleeps.append)
    finally:
        ship_logs.send_batch = original

    assert len(attempts) == 3
    assert result == {"received": 2, "parsed": 2, "unparsed": 0}
    assert sleeps == [1.0, 2.0]


def test_run_follow_batches_by_size(tmp_path, monkeypatch):
    path = tmp_path / "auth.log"
    path.write_text("")
    for i in range(5):
        with open(path, "a") as f:
            f.write(f"line {i}\n")

    sent = []
    monkeypatch.setattr("scripts.ship_logs.send_with_retry", lambda lines, *a, **kw: sent.append(list(lines)) or {})

    run_follow(
        str(path),
        "auth.log",
        "http://api",
        None,
        from_start=True,
        batch_size=2,
        batch_seconds=1000,  # never trips on time for this test
        poll_interval=0,
        sleep=lambda s: None,
        now=lambda: 0.0,
        max_iterations=1,
    )

    assert sent == [["line 0", "line 1"], ["line 2", "line 3"], ["line 4"]]


def test_run_follow_flushes_small_batch_after_timeout(tmp_path, monkeypatch):
    path = tmp_path / "auth.log"
    path.write_text("only line\n")

    sent = []
    monkeypatch.setattr("scripts.ship_logs.send_with_retry", lambda lines, *a, **kw: sent.append(list(lines)) or {})

    clock = {"t": 0.0}
    run_follow(
        str(path),
        "auth.log",
        "http://api",
        None,
        from_start=True,
        batch_size=500,
        batch_seconds=1.0,
        poll_interval=0,
        sleep=lambda s: clock.__setitem__("t", clock["t"] + s + 1.0),
        now=lambda: clock["t"],
        max_iterations=2,
    )

    assert sent == [["only line"]]
