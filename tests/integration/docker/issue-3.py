#!/usr/bin/env python3
"""Real Docker Engine issue #3 tests; refuses to run outside the KVM guest."""

import json
import os
import pathlib
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request


def fail(message):
    raise RuntimeError(message)


def command(args, *, check=True, capture=True):
    result = subprocess.run(args, text=True, capture_output=capture)
    if check and result.returncode:
        fail(f"command failed ({result.returncode}): {args!r}\n{result.stderr}")
    return result


def docker(*args, check=True):
    return command(["docker", *args], check=check)


def expect(condition, message):
    if not condition:
        fail(message)
    print(f"PASS: {message}", flush=True)


def container_by_id(snapshot, instance_id):
    matches = [c for c in snapshot["docker"]["containers"] if c["instance"]["id"] == instance_id]
    return matches[0] if len(matches) == 1 else None


def endpoint(container, *, address, protocol, host_port, container_port, family):
    return any(
        e["host"]["address"] == address
        and e["protocol"] == protocol
        and e["host"]["port"] == host_port
        and e["container_port"] == container_port
        and e["family"] == family
        for e in container["observed_endpoints"]
    )


def main():
    if len(sys.argv) != 4:
        fail("usage: issue-3.py <run-id> <manyfw-binary> <evidence-directory>")
    run_id, manyfw_path, evidence_arg = sys.argv[1:]
    marker = pathlib.Path("/etc/manyfw-disposable-vm")
    if not marker.is_file() or marker.read_text().strip() != run_id:
        fail("disposable VM marker is missing or does not match this run")
    if command(["systemd-detect-virt"]).stdout.strip() != "kvm":
        fail("this test must execute inside a KVM guest")
    if not pathlib.Path("/var/run/docker.sock").is_socket():
        fail("guest-local Docker Unix socket is absent")
    if os.environ.get("DOCKER_HOST") != "unix:///var/run/docker.sock":
        fail("Docker endpoint is not explicitly the guest-local Unix socket")
    if os.environ.get("DOCKER_CONTEXT"):
        fail("Docker context override must not be inherited")
    if not pathlib.Path(manyfw_path).is_file() or not os.access(manyfw_path, os.X_OK):
        fail("ManyFW executable is missing")

    evidence = pathlib.Path(evidence_arg)
    evidence.mkdir(parents=True, exist_ok=True)
    prefix = f"mfw-{run_id}"
    project = f"{run_id}-compose"
    other_project = f"{run_id}-other"
    state_project = f"{run_id}-state"
    names = {
        "web": f"{prefix}-web",
        "replica": f"{prefix}-replica",
        "other": f"{prefix}-other-web",
        "override": f"{prefix}-override",
        "private": f"{prefix}-private",
        "unlabeled": f"{prefix}-unlabeled",
        "incomplete": f"{prefix}-incomplete",
        "stateful": f"{prefix}-stateful",
        "host": f"{prefix}-host-network",
        "ipv6": f"{prefix}-ipv6",
    }
    image = "busybox:1.36.1"

    def run_container(key, *args):
        docker("run", "--detach", "--name", names[key], *args)
        return docker("inspect", "--format", "{{.Id}}", names[key]).stdout.strip()

    def snapshot(label):
        path = evidence / f"{label}.json"
        env = {
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "HOME": "/root",
            "DOCKER_HOST": "unix:///var/run/docker.sock",
        }
        result = subprocess.run(
            [manyfw_path, "--color", "never", "discover", "--format", "json", "--output", "-"],
            env=env,
            text=True,
            capture_output=True,
        )
        if result.returncode:
            fail(f"ManyFW discovery failed: {result.stderr}")
        path.write_text(result.stdout)
        data = json.loads(result.stdout)
        expect(data["version"] == 1, f"{label} snapshot is versioned JSON")
        return data

    def host_port(name, target):
        value = docker("port", name, target).stdout.strip().splitlines()[0].rsplit(":", 1)[1]
        return int(value)

    def http(url, expected):
        last_error = None
        for _ in range(30):
            try:
                with urllib.request.urlopen(url, timeout=2) as response:
                    body = response.read().decode().strip()
                if body == expected:
                    return body
                last_error = f"unexpected body {body!r}"
            except (OSError, urllib.error.URLError) as error:
                last_error = str(error)
            time.sleep(1)
        fail(f"published endpoint {url} did not answer with {expected!r}: {last_error}")

    created = []
    try:
        engine_id = docker("info", "--format", "{{.ID}}").stdout.strip()
        docker_version = docker("info", "--format", "{{.ServerVersion}}").stdout.strip()
        docker_root = docker("info", "--format", "{{.DockerRootDir}}").stdout.strip()
        expect(docker_root == "/var/lib/docker", "Docker daemon uses guest-local storage")
        evidence.joinpath("docker-engine.json").write_text(json.dumps({
            "engine_id": engine_id,
            "version": docker_version,
            "root": docker_root,
            "kernel": command(["uname", "-r"]).stdout.strip(),
        }, indent=2) + "\n")
        bridge = json.loads(docker("network", "inspect", "bridge").stdout)[0]
        expect(bridge["Driver"] == "bridge", "guest Docker default bridge is present")
        docker("pull", image)

        web_id = run_container(
            "web",
            "--label", f"com.docker.compose.project={project}",
            "--label", "com.docker.compose.service=web",
            "--publish", "127.0.0.1::8080/tcp",
            "--publish", "[::1]::8080/tcp",
            "--publish", "127.0.0.1::5353/udp",
            image,
            "sh", "-c",
            'mkdir -p /tmp/www; printf "manyfw-docker-ok\\n" >/tmp/www/index.html; exec httpd -f -p 8080 -h /tmp/www',
        )
        created.append("web")
        replica_id = run_container(
            "replica",
            "--label", f"com.docker.compose.project={project}",
            "--label", "com.docker.compose.service=web", image,
            "sh", "-c", "while :; do sleep 3600; done",
        )
        created.append("replica")
        other_id = run_container(
            "other",
            "--label", f"com.docker.compose.project={other_project}",
            "--label", "com.docker.compose.service=web", image,
            "sh", "-c", "while :; do sleep 3600; done",
        )
        created.append("other")
        override_id = run_container(
            "override",
            "--label", f"com.manyfw.service-id={run_id}/explicit",
            "--label", f"com.docker.compose.project={run_id}-shadow",
            "--label", "com.docker.compose.service=shadow",
            "--publish", "127.0.0.1::8081/tcp", image,
            "sh", "-c",
            'mkdir -p /tmp/www; printf "override-ok\\n" >/tmp/www/index.html; exec httpd -f -p 8081 -h /tmp/www',
        )
        created.append("override")
        private_id = run_container(
            "private",
            "--label", f"com.docker.compose.project={run_id}",
            "--label", "com.docker.compose.service=private",
            "--expose", "9090/tcp", image, "sh", "-c", "while :; do sleep 3600; done",
        )
        created.append("private")
        unlabeled_id = run_container(
            "unlabeled", image, "sh", "-c", "while :; do sleep 3600; done"
        )
        created.append("unlabeled")
        incomplete_id = run_container(
            "incomplete",
            "--label", f"com.docker.compose.project={run_id}-incomplete",
            "--label", "com.manyfw.service-id=not a valid identity", image,
            "sh", "-c", "while :; do sleep 3600; done",
        )
        created.append("incomplete")
        stateful_id = run_container(
            "stateful",
            "--label", f"com.docker.compose.project={state_project}",
            "--label", "com.docker.compose.service=stateful",
            "--publish", "127.0.0.1::8082/tcp", image,
            "sh", "-c",
            'mkdir -p /tmp/www; printf "restart-ok\\n" >/tmp/www/index.html; exec httpd -f -p 8082 -h /tmp/www',
        )
        created.append("stateful")
        host_id = run_container(
            "host", "--network", "host",
            "--label", f"com.docker.compose.project={run_id}-host",
            "--label", "com.docker.compose.service=hostnet", image,
            "sh", "-c",
            'mkdir -p /tmp/www; printf "hostnet-ok\\n" >/tmp/www/index.html; exec httpd -f -p 18083 -h /tmp/www',
        )
        created.append("host")

        tcp_port = host_port(names["web"], "8080/tcp")
        udp_port = host_port(names["web"], "5353/udp")
        ipv6_web_binding = docker("port", names["web"], "8080/tcp").stdout.splitlines()
        ipv6_web_line = next((line for line in ipv6_web_binding if line.startswith("[::1]:")), None)
        ipv6_web_port = int(ipv6_web_line.rsplit(":", 1)[1]) if ipv6_web_line else None
        override_port = host_port(names["override"], "8081/tcp")
        state_port = host_port(names["stateful"], "8082/tcp")
        expect(http(f"http://127.0.0.1:{tcp_port}/", "manyfw-docker-ok") == "manyfw-docker-ok",
               "published IPv4 TCP port reaches the live container")
        if ipv6_web_port is not None:
            expect(http(f"http://[::1]:{ipv6_web_port}/", "manyfw-docker-ok") == "manyfw-docker-ok",
                   "same published service is reachable over IPv4 and IPv6")

        service_ip = docker(
            "inspect", "--format", "{{(index .NetworkSettings.Networks \"bridge\").IPAddress}}",
            names["web"],
        ).stdout.strip()
        command(["docker", "run", "--rm", "--network", "bridge", image,
                 "wget", "-qO-", f"http://{service_ip}:8080/"])
        expect(True, "container-to-container TCP works over the Docker bridge")

        host_rules = command(["iptables-save"], check=False).stdout
        iptables_version = command(["iptables", "--version"]).stdout.strip()
        evidence.joinpath("docker-iptables-version.txt").write_text(iptables_version + "\n")
        evidence.joinpath("docker-iptables-rules.txt").write_text(host_rules)
        expect(f"--dport {tcp_port}" in host_rules and f"--dport {udp_port}" in host_rules,
               "Docker installed guest-local NAT rules for published TCP and UDP ports")

        first = snapshot("initial")
        web = container_by_id(first, web_id)
        expect(web is not None and web["logical_identity"] == {
            "value": f"docker:{project}/web", "source": "ComposeLabels"
        }, "Compose project/service labels resolve to a stable identity")
        expect(endpoint(web, address="127.0.0.1", protocol="Tcp", host_port=tcp_port,
                        container_port=8080, family="Ipv4"),
               "ManyFW reports the real IPv4 TCP host binding and container port")
        if ipv6_web_port is not None:
            expect(endpoint(web, address="::1", protocol="Tcp", host_port=ipv6_web_port,
                            container_port=8080, family="Ipv6"),
                   "one Compose service preserves simultaneous IPv4/IPv6 bindings for the same container port")
        expect(endpoint(web, address="127.0.0.1", protocol="Udp", host_port=udp_port,
                        container_port=5353, family="Ipv4"),
               "ManyFW reports the real IPv4 UDP host binding separately")
        override = container_by_id(first, override_id)
        expect(override is not None and override["logical_identity"] == {
            "value": f"docker:{run_id}/explicit", "source": "ManyfwLabel"
        }, "explicit ManyFW service ID takes precedence over Compose labels")
        expect(any(d["code"] == "IdentityConflict" and d["instance_id"] == override_id
                   for d in first["docker"]["diagnostics"]),
               "conflicting identity labels remain diagnosed")
        private = container_by_id(first, private_id)
        expect(private is not None and private["configured_publications"]
               and not private["observed_endpoints"],
               "configured-only port is not reported as an active published endpoint")
        expect(container_by_id(first, unlabeled_id)["logical_identity"] is None
               and container_by_id(first, incomplete_id)["logical_identity"] is None,
               "missing or malformed identity metadata is left unresolved")
        expect(container_by_id(first, replica_id)["logical_identity"]["value"]
               == container_by_id(first, web_id)["logical_identity"]["value"]
               and replica_id != web_id,
               "replicas share logical service identity but retain distinct instances")
        expect(container_by_id(first, other_id)["logical_identity"]["value"]
               == f"docker:{other_project}/web",
               "same short service name in another project stays distinct")
        host_net = container_by_id(first, host_id)
        expect(host_net is not None and host_net["network_mode"] == "Host"
               and not host_net["observed_endpoints"],
               "host-network container has no invented published endpoint")
        expect(any(listener["port"] == 18083 for listener in first["host"]["listeners"]["records"]),
               "host-network service appears as a guest host listener")
        expect(container_by_id(first, stateful_id)["lifecycle"] == "Running",
               "running lifecycle is retained")

        policy = "/tmp/manyfw-policy.toml"
        explain_env = {
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "HOME": "/root", "DOCKER_HOST": "unix:///var/run/docker.sock",
        }
        explain = subprocess.run(
            [manyfw_path, "--color", "never", "explain", "web", "--file", policy,
             "--snapshot", str(evidence / "initial.json")],
            env=explain_env, text=True, capture_output=True,
        )
        expect(explain.returncode != 0 and "ambiguous service selector" in explain.stderr
               and f"docker:{project}/web" in explain.stderr
               and f"docker:{other_project}/web" in explain.stderr,
               "ambiguous short selector fails with both stable identity candidates")
        evidence.joinpath("ambiguous-explain.stdout").write_text(explain.stdout)
        evidence.joinpath("ambiguous-explain.stderr").write_text(explain.stderr)

        # Exercise the CLI's actionable unavailable-daemon path without
        # changing the guest Docker service or pointing at any host socket.
        unavailable_env = dict(explain_env, DOCKER_HOST="unix:///run/manyfw-does-not-exist.sock")
        unavailable = subprocess.run(
            [manyfw_path, "--color", "never", "discover", "--format", "json", "--output", "-"],
            env=unavailable_env, text=True, capture_output=True,
        )
        if unavailable.returncode != 0:
            fail(f"unavailable Docker daemon should produce a discovery report: {unavailable.stderr}")
        unavailable_report = json.loads(unavailable.stdout)
        evidence.joinpath("unavailable-daemon.json").write_text(unavailable.stdout)
        diagnostic_text = " ".join(d.get("message", "") for d in unavailable_report["docker"]["diagnostics"])
        expect(unavailable_report["docker"]["outcome"] == "Unavailable"
               and any(word in diagnostic_text.lower() for word in ("socket", "daemon", "connect")),
               "unavailable guest-local daemon remains explicit and actionable")

        permission_env = dict(explain_env, DOCKER_HOST="unix:///var/run/docker.sock")
        permission = subprocess.run(
            ["runuser", "-u", "nobody", "--", "env", *[f"{key}={value}" for key, value in permission_env.items()],
             manyfw_path, "--color", "never", "discover", "--format", "json", "--output", "-"],
            text=True, capture_output=True,
        )
        if permission.returncode != 0:
            fail(f"permission-denied Docker discovery should produce a report: {permission.stderr}")
        permission_report = json.loads(permission.stdout)
        evidence.joinpath("permission-denied.json").write_text(permission.stdout)
        permission_text = " ".join(d.get("message", "") for d in permission_report["docker"]["diagnostics"])
        expect(permission_report["docker"]["outcome"] == "PermissionDenied"
               and "permission denied" in permission_text.lower(),
               "Docker socket permission denial remains actionable without changing socket permissions")

        # IPv6 is exercised only when the guest kernel enables loopback IPv6
        # and Docker accepts an IPv6 host binding. Rejection is recorded.
        ipv6_status = "unsupported: guest IPv6 disabled"
        if pathlib.Path("/proc/sys/net/ipv6/conf/lo/disable_ipv6").read_text().strip() == "0":
            ipv6_create = docker(
                "run", "--detach", "--name", names["ipv6"],
                "--label", f"com.docker.compose.project={run_id}-ipv6",
                "--label", "com.docker.compose.service=v6",
                "--publish", "[::1]::8083/tcp", image, "sh", "-c",
                'mkdir -p /tmp/www; printf "ipv6-ok\\n" >/tmp/www/index.html; exec httpd -f -p 8083 -h /tmp/www',
                check=False,
            )
            if ipv6_create.returncode == 0:
                created.append("ipv6")
                ipv6_port = host_port(names["ipv6"], "8083/tcp")
                expect(http(f"http://[::1]:{ipv6_port}/", "ipv6-ok") == "ipv6-ok",
                       "published IPv6 TCP port reaches the live container")
                ipv6_id = docker("inspect", "--format", "{{.Id}}", names["ipv6"]).stdout.strip()
                ipv6_snapshot = snapshot("ipv6")
                expect(endpoint(container_by_id(ipv6_snapshot, ipv6_id), address="::1",
                                 protocol="Tcp", host_port=ipv6_port,
                                 container_port=8083, family="Ipv6"),
                       "ManyFW reports IPv6 host binding and family explicitly")
                ipv6_status = "passed"
            else:
                ipv6_status = "unsupported: Docker rejected IPv6 host binding: " + ipv6_create.stderr.strip()
                evidence.joinpath("ipv6-create.stderr").write_text(ipv6_create.stderr)
                print("SKIP: " + ipv6_status, flush=True)
        evidence.joinpath("ipv6-status.txt").write_text(ipv6_status + "\n")

        docker("stop", names["stateful"])
        stopped = snapshot("stopped")
        stopped_container = container_by_id(stopped, stateful_id)
        expect(stopped_container is not None and stopped_container["lifecycle"] == "Exited"
               and stopped_container["operational_status"] == "Stopped"
               and not stopped_container["observed_endpoints"],
               "stopped container remains visible without an active endpoint")
        docker("start", names["stateful"])
        docker("restart", names["stateful"])
        restarted = snapshot("restarted")
        restarted_container = container_by_id(restarted, stateful_id)
        restarted_port = host_port(names["stateful"], "8082/tcp")
        expect(restarted_container is not None and restarted_container["lifecycle"] == "Running"
               and restarted_container["logical_identity"]["value"] == f"docker:{state_project}/stateful"
               and endpoint(restarted_container, address="127.0.0.1", protocol="Tcp",
                            host_port=restarted_port, container_port=8082, family="Ipv4"),
               "restart preserves logical identity and reports Docker's current published mapping")

        repeat = snapshot("repeated")
        stable_fields = ("containers", "diagnostics", "outcome", "completeness")
        expect(all(restarted["docker"][field] == repeat["docker"][field] for field in stable_fields),
               "Docker discovery remains deterministic while Engine state is unchanged")

        # ManyFW discovery itself must not mutate the firewall state it observes.
        def normalized_firewall():
            iptables = command(["iptables-save"], check=False).stdout
            ip6tables = command(["ip6tables-save"], check=False).stdout
            nft = command(["nft", "list", "ruleset"], check=False).stdout
            return (
                re.sub(r"\[\d+:\d+\]", "[COUNTERS]", iptables),
                re.sub(r"\[\d+:\d+\]", "[COUNTERS]", ip6tables),
                re.sub(r"counter packets \d+ bytes \d+", "counter packets X bytes Y", nft),
            )

        before_firewall = normalized_firewall()
        snapshot("readonly-check")
        after_firewall = normalized_firewall()
        for name, before, after in zip(("iptables", "ip6tables", "nft"), before_firewall, after_firewall):
            evidence.joinpath(f"{name}-readonly-before.txt").write_text(before)
            evidence.joinpath(f"{name}-readonly-after.txt").write_text(after)
        expect(before_firewall == after_firewall,
               "ManyFW discovery leaves guest iptables and nftables configuration unchanged")

        docker("rm", "--force", names["web"])
        created.remove("web")
        removed = snapshot("removed")
        expect(container_by_id(removed, web_id) is None,
               "removed container disappears from the next real Docker observation")
        expect(container_by_id(removed, replica_id) is not None,
               "removing one replica retains the remaining service instance")

        firewall = command(["iptables", "--version"]).stdout.strip()
        nat_rules = command(["iptables-save", "-t", "nat"], check=False).stdout
        nft_rules = command(["nft", "list", "ruleset"], check=False).stdout
        if "DOCKER" in nat_rules and "--dport" in nat_rules:
            backend = "Docker iptables driver"
            if "nf_tables" in firewall:
                backend += " via nf_tables compatibility frontend"
        elif "docker-bridges" in nft_rules:
            backend = "Docker native nftables driver"
        else:
            fail("no guest Docker iptables or native nftables bridge rules were detected")
        evidence.joinpath("docker-firewall-backend.txt").write_text(
            f"{backend}\n{firewall}\n{nat_rules}\n"
        )
        os_release = pathlib.Path("/etc/os-release").read_text().splitlines()
        guest_os = next((line.split("=", 1)[1].strip('"') for line in os_release
                         if line.startswith("PRETTY_NAME=")), "unknown")
        result = {
            "issue": 3,
            "status": "Passed" if ipv6_status == "passed" and ipv6_web_port is not None else "PassedWithLimitations",
            "guest_run_id": run_id,
            "guest_virtualization": "kvm",
            "guest_os": guest_os,
            "docker_engine_id": engine_id,
            "docker_version": docker_version,
            "docker_root": docker_root,
            "docker_firewall_backend": backend,
            "ipv6_status": ipv6_status,
            "scenarios": {
                "compose_identity": "Passed",
                "explicit_label_precedence": "Passed",
                "tcp_ipv4_published_and_reachable": "Passed",
                "same_service_dual_stack_binding": "Passed" if ipv6_web_port is not None else "Unsupported",
                "udp_ipv4_published_and_inspected": "Passed",
                "ipv6_binding": ipv6_status,
                "bridge_and_container_to_container": "Passed",
                "host_network_and_unpublished_ports": "Passed",
                "missing_and_malformed_identity": "Passed",
                "replicas_and_short_selector_ambiguity": "Passed",
                "stop_start_restart_lifecycle": "Passed",
                "deterministic_discovery": "Passed",
                "removal_reconciliation": "Passed",
                "firewall_read_only_discovery": "Passed",
            },
        }
        evidence.joinpath("test-results.json").write_text(json.dumps(result, indent=2) + "\n")
        print("PASS: issue #3 real Docker Engine integration suite", flush=True)
    finally:
        for key in reversed(created):
            docker("rm", "--force", names[key], check=False)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:  # Keep a concise failure on stdout and nonzero status.
        print(f"FAIL: {error}", file=sys.stderr, flush=True)
        raise
