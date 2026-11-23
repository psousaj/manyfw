#!/usr/bin/env python3
"""Exercise a real published Docker FORWARD drop in a disposable KVM guest."""

import json
import pathlib
import select
import subprocess
import sys


CLIENT = r"""
import socket, sys, time
address, source = sys.argv[1:]
deadline = time.monotonic() + 30
while True:
    if time.monotonic() >= deadline:
        raise TimeoutError("published-port connection readiness deadline expired")
    try:
        connection = socket.create_connection(
            (address, 18080), timeout=2, source_address=(source, 0)
        )
        break
    except OSError:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise
        time.sleep(min(0.25, remaining))
if time.monotonic() >= deadline:
    connection.close()
    raise TimeoutError("published-port connection established after readiness deadline")
stream = connection.makefile("rwb", buffering=0)
stream.write(b"before\n")
if stream.readline() != b"reply\n":
    raise SystemExit("initial published-port response failed")
print("ESTABLISHED", flush=True)
for command in sys.stdin:
    if command.strip() == "after":
        stream.write(b"after\n")
        if stream.readline() != b"reply\n":
            raise SystemExit("existing flow did not receive its reply")
        print("REPLY", flush=True)
    elif command.strip() == "close":
        break
connection.close()
"""

NEW_FLOW = r"""
import socket
import sys
connection = socket.create_connection(
    (sys.argv[1], 18080), timeout=2, source_address=(sys.argv[2], 0)
)
connection.close()
raise SystemExit("a new published-port flow was not dropped")
"""

OUTSIDE_SOURCE_FLOW = r"""
import socket
import sys
import time
import select
address, source = sys.argv[1:]
deadline = time.monotonic() + 30
while True:
    if time.monotonic() >= deadline:
        raise TimeoutError("outside-source connection retry deadline expired")
    try:
        connection = socket.create_connection(
            (address, 18080), timeout=3, source_address=(source, 0)
        )
        break
    except OSError:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise
        time.sleep(min(0.25, remaining))
if time.monotonic() >= deadline:
    connection.close()
    raise TimeoutError("outside-source connection established after retry deadline")
with connection:
    connection.sendall(b"outside-source\n")
    connection.shutdown(socket.SHUT_WR)
    reply_deadline = time.monotonic() + 5
    response = bytearray()
    while True:
        remaining = reply_deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("outside-source reply deadline expired")
        connection.settimeout(remaining)
        chunk = connection.recv(1024)
        if not chunk:
            break
        response.extend(chunk)
        if len(response) > 1024:
            raise RuntimeError("outside-source response exceeded the line limit")
    if bytes(response) != b"reply\n":
        raise SystemExit(f"unexpected outside-source response: {response!r}")
"""


def checked(command, **kwargs):
    result = subprocess.run(command, text=True, **kwargs)
    if result.returncode:
        raise RuntimeError(
            f"command failed ({result.returncode}): {command!r}\n"
            f"stdout: {result.stdout or ''}\nstderr: {result.stderr or ''}"
        )
    return result


def read_line(process, timeout):
    ready, _, _ = select.select([process.stdout], [], [], timeout)
    if not ready:
        if process.poll() is not None:
            raise RuntimeError(
                f"packet client exited with status {process.returncode}: "
                f"{process.stderr.read().strip()}"
            )
        raise TimeoutError("timed out waiting for the persistent published-port client")
    line = process.stdout.readline()
    if not line and process.poll() is not None:
        raise RuntimeError(
            f"packet client exited with status {process.returncode}: "
            f"{process.stderr.read().strip()}"
        )
    return line.strip()


def main():
    if len(sys.argv) != 5:
        raise SystemExit(
            "usage: issue51-forward-packet.py <planner-bundle> "
            "<published-host-address> <planned-source-address> <outside-source-address>"
        )
    plan = pathlib.Path(sys.argv[1])
    client = subprocess.Popen(
        [
            "ip",
            "netns",
            "exec",
            "issue51-client",
            "python3",
            "-u",
            "-c",
            CLIENT,
            sys.argv[2],
            sys.argv[3],
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )
    try:
        if read_line(client, 40) != "ESTABLISHED":
            raise RuntimeError("persistent client failed before establishing the published flow")

        applied = checked(
            ["manyfw", "apply", "--experimental", "--timeout", "60", "--file", str(plan)],
            capture_output=True,
            timeout=90,
        )
        result = json.loads(applied.stdout)
        transaction_id = result["transaction_id"]
        token = result["confirmation_token"]
        checked(
            ["manyfw", "confirm", transaction_id],
            input=token + "\n",
            capture_output=True,
            timeout=20,
        )

        client.stdin.write("after\n")
        client.stdin.flush()
        if read_line(client, 10) != "REPLY":
            raise RuntimeError("the existing conntrack flow did not receive its post-apply reply")

        blocked = subprocess.run(
            [
                "ip",
                "netns",
                "exec",
                "issue51-client",
                "python3",
                "-c",
                NEW_FLOW,
                sys.argv[2],
                sys.argv[3],
            ],
            text=True,
            capture_output=True,
        )
        if blocked.returncode == 0 or "timed out" not in blocked.stderr.lower():
            raise RuntimeError(
                "new published-port flow was not silently dropped: "
                f"status={blocked.returncode}, stderr={blocked.stderr.strip()}"
            )
        client.stdin.write("close\n")
        client.stdin.flush()
        client.wait(timeout=5)
        if client.returncode != 0:
            raise RuntimeError(f"persistent client failed: {client.stderr.read()}")

        outside_source = checked(
            [
                "ip",
                "netns",
                "exec",
                "issue51-client",
                "python3",
                "-c",
                OUTSIDE_SOURCE_FLOW,
                sys.argv[2],
                sys.argv[4],
            ],
            capture_output=True,
            timeout=45,
        )
        print(
            json.dumps(
                {
                    "new_flow": "dropped",
                    "existing_flow_reply": "passed",
                    "outside_source_flow": "passed",
                    "outside_source_stdout": outside_source.stdout.strip(),
                }
            )
        )
    finally:
        if client.poll() is None:
            client.kill()
            client.wait()


if __name__ == "__main__":
    main()
