#!/usr/bin/env python3
"""Assert a ManyFW transaction preserved an unrelated nftables table."""

import json
import pathlib
import sys


def normalized(path: str) -> object:
    document = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))

    def strip_runtime_handles(value: object) -> object:
        if isinstance(value, dict):
            return {
                key: strip_runtime_handles(item)
                for key, item in value.items()
                if key not in {"handle", "packets", "bytes"}
            }
        if isinstance(value, list):
            return [strip_runtime_handles(item) for item in value]
        return value

    return strip_runtime_handles(document)


before, after = map(normalized, sys.argv[1:3])
if before != after:
    raise SystemExit("foreign nftables table changed across ManyFW recovery")
print("foreign nftables table preserved")
