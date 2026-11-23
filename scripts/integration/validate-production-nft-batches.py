#!/usr/bin/env python3
"""Fail-closed validation of archived production nftables JSON batches."""

import json
import pathlib
import sys


ENTITY_OPERATIONS = {
    "add": {"table", "chain", "rule"},
    "create": {"table"},
    "delete": {"table"},
}
ENTITY_FIELDS = {
    "table": {"family", "name", "comment", "flags", "handle"},
    "chain": {
        "family", "table", "name", "handle", "type", "hook", "prio",
        "policy", "dev", "flags", "comment",
    },
    "rule": {
        "family", "table", "chain", "handle", "index", "expr",
        "position", "position_id", "comment",
    },
}


def _decode_operation(command):
    if not isinstance(command, dict) or len(command) != 1:
        return None
    operation, body = next(iter(command.items()))
    if operation not in ENTITY_OPERATIONS or not isinstance(body, dict) or len(body) != 1:
        return None
    entity, details = next(iter(body.items()))
    if entity not in ENTITY_OPERATIONS[operation] or not isinstance(details, dict):
        return None
    if not set(details).issubset(ENTITY_FIELDS[entity]):
        return None
    if not isinstance(details.get("family"), str) or details["family"] != "inet":
        return None
    if entity == "table":
        if not isinstance(details.get("name"), str) or not details["name"]:
            return None
    else:
        if details.get("table") != "manyfw":
            return None
        if not isinstance(details.get("name" if entity == "chain" else "chain"), str):
            return None
        if not details.get("name" if entity == "chain" else "chain"):
            return None
    if entity == "chain" and (
        "hook" in details
        and (
            details.get("type") != "filter"
            or details.get("hook") not in {"input", "forward"}
            or details.get("policy") != "accept"
            or type(details.get("prio")) is not int
        )
    ):
        return None
    if entity == "rule" and (
        not isinstance(details.get("expr"), list) or not details["expr"]
    ):
        return None
    return operation, entity, details


def _is_manyfw_operation(operation, entity, details):
    if entity == "table":
        return details.get("name") == "manyfw"
    return details.get("table") == "manyfw"


def validate(text):
    lines = [line for line in text.splitlines() if line.strip()]
    if not lines:
        raise ValueError("production batch archive contains no JSON transactions")

    has_manyfw_transaction = False
    for number, line in enumerate(lines, 1):
        try:
            transaction = json.loads(line)
        except json.JSONDecodeError as error:
            raise ValueError(
                f"production batch archive line {number} is not JSON: {error}"
            ) from error
        if (
            not isinstance(transaction, dict)
            or set(transaction) != {"nftables"}
            or not isinstance(transaction["nftables"], list)
            or not transaction["nftables"]
        ):
            raise ValueError(
                f"production batch archive line {number} has an invalid nftables batch envelope"
            )
        for command in transaction["nftables"]:
            if isinstance(command, dict) and "flush" in command:
                raise ValueError("production batch archive contains an nftables flush operation")
            decoded = _decode_operation(command)
            if decoded is None:
                raise ValueError(
                    f"production batch archive line {number} has an invalid nftables operation"
                )
            if not _is_manyfw_operation(*decoded):
                raise ValueError(
                    f"production batch archive line {number} mutates outside inet manyfw"
                )
            has_manyfw_transaction = True
    if not has_manyfw_transaction:
        raise ValueError("production batch archive contains no ManyFW table operation")


def main():
    if len(sys.argv) != 2:
        raise SystemExit("usage: validate-production-nft-batches.py ARCHIVE")
    try:
        validate(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise SystemExit(str(error)) from error


if __name__ == "__main__":
    main()
