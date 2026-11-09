#!/usr/bin/env python3
"""Run apply locally and persist only its token-redacted result."""

import json
import subprocess
import sys
from pathlib import Path

if len(sys.argv) != 4:
    raise SystemExit("usage: issue24-redacted-apply.py PLAN TIMEOUT OUTPUT")

plan, timeout, output = sys.argv[1:]
result = subprocess.run(
    ["/usr/bin/manyfw", "apply", "--experimental", "--timeout", timeout, "--file", plan],
    check=False,
    capture_output=True,
    text=True,
)
if result.returncode:
    print(result.stderr, file=sys.stderr, end="")
    raise SystemExit(result.returncode)
try:
    # OpenRC's `rc-service start` may write status lines to stdout while the
    # service is armed. The production CLI still emits one JSON object; select
    # that object without treating supervisor chatter as CLI output.
    json_start = result.stdout.find("{")
    if json_start < 0:
        raise json.JSONDecodeError("no JSON object in apply output", result.stdout, 0)
    response, end = json.JSONDecoder().raw_decode(result.stdout, json_start)
    if result.stdout[end:].strip():
        raise json.JSONDecodeError("unexpected text after apply JSON", result.stdout, end)
except json.JSONDecodeError as error:
    print(f"ManyFW apply did not return JSON: {error}; stdout={result.stdout!r}", file=sys.stderr)
    raise SystemExit(1) from error
response.pop("confirmation_token", None)
Path(output).write_text(json.dumps(response, indent=2) + "\n", encoding="utf-8")
