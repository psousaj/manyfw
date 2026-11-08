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
response = json.loads(result.stdout)
response.pop("confirmation_token", None)
Path(output).write_text(json.dumps(response, indent=2) + "\n", encoding="utf-8")
