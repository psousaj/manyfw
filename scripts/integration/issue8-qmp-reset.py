#!/usr/bin/env python3
"""Issue a QMP system_reset to the explicitly owned disposable guest."""

import json
import pathlib
import socket
import sys

path = pathlib.Path(sys.argv[1])
with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as qmp:
    qmp.connect(str(path))
    greeting = json.loads(qmp.makefile("rb").readline())
    if "QMP" not in greeting:
        raise SystemExit("QEMU endpoint did not return a QMP greeting")
    stream = qmp.makefile("rwb", buffering=0)
    stream.write(b'{"execute":"qmp_capabilities"}\r\n')
    capabilities = json.loads(stream.readline())
    if "return" not in capabilities:
        raise SystemExit(f"QMP capability negotiation failed: {capabilities}")
    stream.write(b'{"execute":"system_reset"}\r\n')
    while True:
        result = json.loads(stream.readline())
        if "event" not in result:
            break
    if "return" not in result:
        raise SystemExit(f"QMP system_reset failed: {result}")
    print(json.dumps({"greeting": greeting, "system_reset": result}, sort_keys=True))
