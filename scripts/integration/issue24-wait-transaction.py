#!/usr/bin/env python3
"""Wait for a durable transaction state and print its transaction ID."""

import glob
import json
import os
import sys
import time

if len(sys.argv) not in (3, 4):
    raise SystemExit("usage: issue24-wait-transaction.py STATE TIMEOUT_SECONDS [TRANSACTION_ID]")

expected, timeout = sys.argv[1], float(sys.argv[2])
transaction_id = sys.argv[3] if len(sys.argv) == 4 else None
deadline = time.monotonic() + timeout
while time.monotonic() < deadline:
    paths = sorted(
        glob.glob("/var/lib/manyfw/transactions/*.json"),
        key=lambda path: os.stat(path).st_mtime_ns,
        reverse=True,
    )
    for path in paths:
        try:
            with open(path, encoding="utf-8") as source:
                record = json.load(source)
        except (OSError, ValueError):
            continue
        if record.get("state", "").lower() == expected.lower() and (
            transaction_id is None or record["plan"]["transaction_id"] == transaction_id
        ):
            print(record["plan"]["transaction_id"])
            raise SystemExit(0)
    time.sleep(0.1)
raise SystemExit(f"timed out waiting for transaction state {expected}")
