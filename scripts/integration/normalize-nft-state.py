#!/usr/bin/env python3
"""Normalize nft JSON for foreign-state preservation comparisons."""

import json
import sys

state = json.load(sys.stdin)
objects = state.get("nftables", [])
filtered = []
for entry in objects:
    kind, value = next(iter(entry.items()))
    if kind in {"table", "chain", "rule", "set", "map", "counter", "flowtable"}:
        if value.get("family") == "inet" and value.get("table") == "manyfw":
            continue
        if kind == "table" and value.get("family") == "inet" and value.get("name") == "manyfw":
            continue
    filtered.append(entry)

def strip_volatile(value):
    if isinstance(value, dict):
        return {
            key: strip_volatile(child)
            for key, child in value.items()
            if key not in {"handle", "packets", "bytes"}
        }
    if isinstance(value, list):
        return [strip_volatile(child) for child in value]
    return value

state["nftables"] = strip_volatile(filtered)
json.dump(state, sys.stdout, sort_keys=True, separators=(",", ":"))
sys.stdout.write("\n")
