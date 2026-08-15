"""
Stress test for sign_event()'s file-locking guarantee: many processes
appending to the same log concurrently must not fork the chain or
lose entries, because the flock serializes the read-prev-hash+sign+
append sequence.

This spawns real OS processes (not threads) so it actually exercises
the flock across process boundaries, matching how agentproof would be
used by multiple independent agent runs writing to a shared log.
"""

import base64
import json
import multiprocessing
import tempfile
from pathlib import Path

import pytest

from agentproof import generate_key, sign_event, verify_log


def _worker(log_path_str, key_b64, worker_id, n_events):
    """Runs in a separate process. Signs n_events, returns nothing —
    correctness is checked by the parent after all workers finish."""
    for i in range(n_events):
        sign_event(
            log_path_str,
            "concurrent_write",
            {"worker": worker_id, "seq": i},
            signing_key=key_b64,
        )


@pytest.fixture
def key_b64():
    _, b64 = generate_key()
    return b64


def test_concurrent_appends_do_not_fork_chain(key_b64):
    """
    N processes each append M events to the same log simultaneously.
    After they all finish: verify_log must report exactly N*M entries,
    the chain must be intact (no forked prev_hash), and every worker's
    events must all be present with no duplicates or drops.
    """
    n_workers = 8
    n_events_per_worker = 20
    total_expected = n_workers * n_events_per_worker

    with tempfile.TemporaryDirectory() as d:
        log_path = Path(d) / "concurrent.log"

        procs = [
            multiprocessing.Process(
                target=_worker,
                args=(str(log_path), key_b64, worker_id, n_events_per_worker),
            )
            for worker_id in range(n_workers)
        ]
        for p in procs:
            p.start()
        for p in procs:
            p.join(timeout=60)
            assert p.exitcode == 0, f"worker process crashed, exitcode={p.exitcode}"

        # 1. Chain must verify cleanly end to end — this is the real
        #    proof the lock held: if two writers had ever read the same
        #    prev_hash, the chain would branch and verify_log would
        #    report a broken link well before reaching entry N.
        ok, msg = verify_log(log_path, signing_key=key_b64)
        assert ok is True, f"chain verification failed after concurrent writes: {msg}"
        assert f"{total_expected} entries verified" in msg

        # 2. Every entry every worker wrote must actually be present,
        #    exactly once — rules out silent drops or duplication that
        #    a merely-intact-looking chain could still have if entries
        #    were skipped in a way that didn't break linkage.
        lines = log_path.read_text().strip().splitlines()
        assert len(lines) == total_expected

        seen = set()
        for line in lines:
            entry = json.loads(line)
            key = (entry["data"]["worker"], entry["data"]["seq"])
            assert key not in seen, f"duplicate entry: {key}"
            seen.add(key)

        expected = {(w, i) for w in range(n_workers) for i in range(n_events_per_worker)}
        assert seen == expected, f"missing entries: {expected - seen}"


def test_concurrent_appends_no_lock_file_leftover_corruption(key_b64):
    """
    Sanity check that the .lock sibling file mechanism itself doesn't
    leak into or corrupt the actual log content — the lock file is a
    separate empty/control file, never mixed into the JSONL log.
    """
    with tempfile.TemporaryDirectory() as d:
        log_path = Path(d) / "concurrent2.log"
        procs = [
            multiprocessing.Process(target=_worker, args=(str(log_path), key_b64, w, 5))
            for w in range(4)
        ]
        for p in procs:
            p.start()
        for p in procs:
            p.join(timeout=30)
            assert p.exitcode == 0

        for line in log_path.read_text().strip().splitlines():
            entry = json.loads(line)  # raises if lock-file noise leaked in
            assert entry["type"] == "concurrent_write"
