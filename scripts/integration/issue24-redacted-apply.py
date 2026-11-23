#!/usr/bin/env python3
"""Run apply locally and persist only its token-redacted result."""

import json
import os
import subprocess
import sys
import tempfile
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
    print(
        f"ManyFW apply did not return JSON (parse error at position {error.pos})",
        file=sys.stderr,
    )
    raise SystemExit(1) from error
response.pop("confirmation_token", None)
output_path = Path(output)
file_descriptor, temporary_name = tempfile.mkstemp(
    prefix=f".{output_path.name}.", suffix=".tmp", dir=output_path.parent
)
temporary_path = Path(temporary_name)
try:
    with os.fdopen(file_descriptor, "w", encoding="utf-8") as temporary_file:
        temporary_file.write(json.dumps(response, indent=2) + "\n")
        temporary_file.flush()
        os.fsync(temporary_file.fileno())
    os.replace(temporary_path, output_path)
finally:
    temporary_path.unlink(missing_ok=True)
