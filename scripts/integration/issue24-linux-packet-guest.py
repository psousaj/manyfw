#!/usr/bin/env python3
"""Test-only, fail-closed packet harness. Never run directly on a host."""
import copy
import errno
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import threading
import time


def command(*args, input=None, check=True):
    return subprocess.run(args, input=input, text=True, capture_output=True, check=check)


def endpoint():
    # Threads preserve accepted TCP sockets, so the same connection is probed
    # before and after apply (not a misleading second new connection).
    def tcp(sock):
        def echo(conn):
            with conn:
                while data := conn.recv(4096):
                    print(json.dumps({'received': 'tcp', 'bytes': len(data), 'peer': conn.getpeername()[0]}), flush=True)
                    conn.sendall(data)
        while True:
            conn, _ = sock.accept()
            threading.Thread(target=echo, args=(conn,), daemon=True).start()

    def udp(sock):
        while True:
            data, peer = sock.recvfrom(4096)
            print(json.dumps({'received': 'udp', 'bytes': len(data), 'peer': peer[0]}), flush=True)
            sent = sock.sendto(data, peer)
            print(json.dumps({'sent': 'udp', 'bytes': sent, 'local': sock.getsockname(),
                              'peer': peer}), flush=True)

    addresses = {socket.AF_INET: [], socket.AF_INET6: []}
    for link in json.loads(command('ip', '-j', 'address', 'show').stdout):
        for address in link['addr_info']:
            if address.get('scope') != 'global':
                continue
            family = socket.AF_INET if address['family'] == 'inet' else socket.AF_INET6
            addresses[family].append(address['local'])
    for family in (socket.AF_INET, socket.AF_INET6):
        for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
            for port in (65434, 65435, 65436):
                # TCP accepted sockets reply from their connected local address.
                # UDP sendto on a wildcard socket instead selects the newest
                # address on the egress interface; bind each observed address so
                # the echo reply uses the exact destination address of the probe.
                bind_addresses = ['::' if family == socket.AF_INET6 else '0.0.0.0']
                if kind == socket.SOCK_DGRAM:
                    bind_addresses = addresses[family]
                for bind_address in bind_addresses:
                    sock = socket.socket(family, kind)
                    if family == socket.AF_INET6:
                        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    sock.bind((bind_address, port))
                    if kind == socket.SOCK_STREAM:
                        sock.listen()
                    threading.Thread(target=tcp if kind == socket.SOCK_STREAM else udp,
                                     args=(sock,), daemon=True).start()
    print('ready', flush=True)
    threading.Event().wait()


def endpoint_probe(protocol, address, port, source):
    if protocol in ('Icmp', 'Icmpv6'):
        result = command('ping', '-6' if ':' in address else '-4', '-n', '-c', '1',
                         '-W', '1', '-I', source, address, check=False)
        text = result.stdout + result.stderr
        outcome = 'allow' if result.returncode == 0 else (
            'reject' if any(x in text.lower() for x in ('unreachable', 'prohibited')) else 'drop')
        return {'outcome': outcome, 'returncode': result.returncode, 'wire_error': text}
    sock = socket.socket(socket.AF_INET6 if ':' in address else socket.AF_INET,
                         socket.SOCK_STREAM if protocol == 'Tcp' else socket.SOCK_DGRAM)
    sock.settimeout(1.5)
    started = time.monotonic()
    try:
        sock.bind((source, 0))
        sock.connect((address, port))
        sock.send(b'issue24-positive-payload')
        assert sock.recv(128) == b'issue24-positive-payload'
        return {'outcome': 'allow', 'elapsed': time.monotonic() - started}
    except OSError as exc:
        outcome = 'reject' if exc.errno in (errno.ECONNREFUSED, errno.EACCES, errno.EHOSTUNREACH) else 'drop' if isinstance(exc, TimeoutError) else 'error'
        return {'outcome': outcome, 'errno': exc.errno, 'error': str(exc),
                'elapsed': time.monotonic() - started}
    finally:
        sock.close()


def probe(protocol, address, port, source):
    # Independent Ethernet capture proves whether rejection was an ICMP error
    # or a TCP reset; ECONNREFUSED alone cannot distinguish these wire events.
    routes = json.loads(command('ip', '-j', 'route', 'get', address, 'from', source).stdout)
    capture = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    capture.bind((routes[0]['dev'], 0))
    capture.settimeout(.1)
    stop = threading.Event()
    events = []

    def read():
        while not stop.is_set():
            try:
                frame = capture.recv(65535)
            except TimeoutError:
                continue
            if len(frame) < 54:
                continue
            ethertype = int.from_bytes(frame[12:14], 'big')
            packet = frame[14:]
            if ethertype == 0x0800:
                offset, transport = (packet[0] & 15)*4, packet[9]
                sender = socket.inet_ntop(socket.AF_INET, packet[12:16])
                receiver = socket.inet_ntop(socket.AF_INET, packet[16:20])
            elif ethertype == 0x86dd:
                offset, transport = 40, packet[6]
                sender = socket.inet_ntop(socket.AF_INET6, packet[8:24])
                receiver = socket.inet_ntop(socket.AF_INET6, packet[24:40])
            else:
                continue
            payload = packet[offset:]
            kind = None
            if transport == 17:
                kind = 'udp-frame'
            elif sender != address or receiver != source:
                continue
            elif transport == 6 and len(payload) > 13 and payload[13] & 4:
                kind = 'tcp-reset'
            elif transport == 1 and payload and payload[0] == 3:
                kind = 'icmp-unreachable'
            elif transport == 58 and payload and payload[0] == 1:
                kind = 'icmpv6-unreachable'
            if kind:
                events.append({'kind': kind, 'source': sender, 'destination': receiver,
                               'icmp_type': payload[0] if transport in (1, 58) else None,
                               'icmp_code': payload[1] if transport in (1, 58) else None,
                               'frame_hex': frame.hex()})
    thread = threading.Thread(target=read, daemon=True)
    thread.start()
    try:
        result = endpoint_probe(protocol, address, port, source)
        # Allow the capture thread to consume the error delivered to the socket.
        time.sleep(.1)
    finally:
        stop.set()
        thread.join(timeout=1)
        capture.close()
    result['wire_events'] = events
    return result


class Suite:
    def __init__(self, run_id, directory):
        assert os.geteuid() == 0
        assert command('systemd-detect-virt').stdout.strip() == 'kvm'
        assert Path('/etc/manyfw-disposable-vm').read_text().strip() == run_id
        self.run_id = run_id
        self.directory = Path(directory)
        self.seed = json.loads(Path('/tmp/issue24-linux-seed.json').read_text())['input']
        self.results = {
            'complete': False,
            'cases': {},
            'scope': 'INPUT only; no production protection claim',
            'limitations': {
                'packet_offload': 'unsupported and not disabled or exhaustively observed by this suite',
                'unobservable_or_bypass_paths': 'unknown/unsupported; no control claim',
                'other_hooks': 'OUTPUT and FORWARD unsupported',
            },
        }
        self.processes = []
        self.namespaces = []
        self.passed = set()
        self.expected = self.expected_cases()
        self.results.update(contract_version='issue24-linux-packets-v2', expected_cases=sorted(self.expected))
        self.results['missing_coverage'] = sorted(self.expected)
        self.results['passed_cases'] = []
        self.worker_started = False

    @staticmethod
    def expected_cases():
        names = {'source-cidr-match', 'source-cidr-mismatch', 'port-range-low', 'port-range-high',
                 'source-mismatch', 'port-mismatch', 'local-host-address-alias', 'interface-match',
                 'interface-mismatch', 'default-Allow', 'default-Deny', 'interface-timeout',
                 'established-stream', 'routed-nat-preserved', 'output-only-backend-refusal',
                 'forward-only-backend-refusal', 'default-Reject', 'unresolved-source-refusal',
                 'unknown-capability-refusal', 'arbitrary-destination-cidr-refusal',
                 'opt-in-bypass-refusal', 'non-systemd-refusal', 'incompatible-foreign-input-refusal',
                 'nft-flowtable-offload-refusal'}
        names.update(f'iptables-nft-{family}-{verdict}' for family in ('v4', 'v6') for verdict in ('ACCEPT', 'DROP'))
        names.update(f'{p}-{a}' for p in ('Tcp', 'Udp', 'Icmp', 'Icmpv6') for a in ('Deny', 'Reject', 'Allow'))
        names.update(f'{p}-ipv6-{a}' for p in ('Tcp', 'Udp') for a in ('Deny', 'Reject', 'Allow'))
        names.update(f'composition-{n}-{a}' for n in (-400, 100) for a in ('accept', 'drop'))
        names.update(f'composition-{family}-{protocol}-{priority}-{verdict}'
                     for family, protocol in (('v6', 'Tcp'), ('v4', 'Udp'))
                     for priority in (-400, 100) for verdict in ('accept', 'drop'))
        names.update(f'{family}-{name}' for family in ('v4', 'v6') for name in (
            'host-address-match', 'host-address-mismatch', 'interface-only-match', 'interface-only-mismatch',
            'source-match', 'source-mismatch', 'default-Allow', 'default-Deny',
            'family-isolation', 'precedence-allow-first', 'precedence-deny-first'))
        names.update(f'{family}-{protocol}-{name}' for family in ('v4', 'v6') for protocol in ('Tcp', 'Udp')
                     for name in ('any-port-low', 'any-port-high', 'any-port-outside',
                                  'range-low', 'range-high', 'range-outside'))
        return names

    def passed_case(self, name):
        assert name in self.expected, 'case not registered: '+name
        self.passed.add(name)
        self.results['passed_cases'] = sorted(self.passed)
        self.results['missing_coverage'] = sorted(self.expected-self.passed)
        self.save()

    def save(self):
        temporary = self.directory/'evidence.tmp'
        temporary.write_text(json.dumps(self.results, indent=2)+'\n')
        temporary.replace(self.directory/'evidence.json')

    def ns(self, namespace, *args, **kwargs):
        return command('ip', 'netns', 'exec', namespace, *args, **kwargs)

    def nft(self, text):
        self.ns('m24target', 'nft', '-f', '-', input=text)

    def setup(self):
        for name in ('m24target', 'm24peer', 'm24remote'):
            # Never adopt an existing namespace.
            command('ip', 'netns', 'add', name)
            self.namespaces.append(name)
            self.ns(name, 'ip', 'link', 'set', 'lo', 'up')
        for index in (0, 1):
            a, b = f'm24in{index}', f'm24out{index}'
            command('ip', 'link', 'add', a, 'type', 'veth', 'peer', 'name', b)
            command('ip', 'link', 'set', a, 'netns', 'm24target')
            command('ip', 'link', 'set', b, 'netns', 'm24peer')
            for ns, dev, host in (('m24target', a, 1), ('m24peer', b, 2)):
                self.ns(ns, 'ip', 'address', 'add', f'192.0.{2+index}.{host}/24', 'dev', dev)
                self.ns(ns, 'ip', '-6', 'address', 'add', f'fd24:{index}::{host}/64', 'dev', dev, 'nodad')
                self.ns(ns, 'ip', 'link', 'set', dev, 'up')
        self.ns('m24target', 'ip', 'address', 'add', '192.0.2.9/24', 'dev', 'm24in0')
        self.ns('m24peer', 'ip', 'address', 'add', '192.0.2.3/24', 'dev', 'm24out0')
        self.ns('m24target', 'ip', '-6', 'address', 'add', 'fd24:0::9/64', 'dev', 'm24in0', 'nodad')
        self.ns('m24peer', 'ip', '-6', 'address', 'add', 'fd24:0::3/64', 'dev', 'm24out0', 'nodad')
        command('ip', 'link', 'add', 'm24route', 'type', 'veth', 'peer', 'name', 'm24remote0')
        command('ip', 'link', 'set', 'm24route', 'netns', 'm24target')
        command('ip', 'link', 'set', 'm24remote0', 'netns', 'm24remote')
        for ns, dev, host in (('m24target', 'm24route', 1), ('m24remote', 'm24remote0', 2)):
            self.ns(ns, 'ip', 'address', 'add', f'198.51.100.{host}/24', 'dev', dev)
            self.ns(ns, 'ip', 'link', 'set', dev, 'up')
        self.ns('m24peer', 'ip', 'route', 'add', '198.51.100.0/24', 'via', '192.0.2.1')
        self.ns('m24target', 'sysctl', '-w', 'net.ipv4.ip_forward=1')
        self.nft('add table ip m24nat\nadd chain ip m24nat post { type nat hook postrouting priority srcnat; policy accept; }\nadd rule ip m24nat post ip saddr 192.0.2.0/24 ip daddr 198.51.100.0/24 counter masquerade\n')
        # Move the installed, enabled production supervisor into the isolated
        # target namespace so its recovery commands operate on the same kernel
        # firewall state as Apply. This is a real systemd service, independent
        # of the applying CLI and SSH session.
        unit_dropin = Path('/etc/systemd/system/manyfw-recovery.service.d/packet-namespace.conf')
        unit_dropin.parent.mkdir(parents=True, exist_ok=True)
        unit_dropin.write_text('[Service]\nNetworkNamespacePath=/run/netns/m24target\n')
        unit_dropin.chmod(0o644)
        command('systemctl', 'daemon-reload')
        command('systemctl', 'restart', 'manyfw-recovery.service')
        self.worker_started = True
        command('systemctl', 'is-active', '--quiet', 'manyfw-recovery.service')
        log = open(self.directory/'listeners.log', 'w')
        self.processes.append(subprocess.Popen(['ip', 'netns', 'exec', 'm24target',
            sys.executable, __file__, 'endpoint'], stdout=log, stderr=log))
        remote_log = open(self.directory/'remote-listeners.log', 'w')
        self.processes.append(subprocess.Popen(['ip', 'netns', 'exec', 'm24remote',
            sys.executable, __file__, 'endpoint'], stdout=remote_log, stderr=remote_log))
        for _ in range(50):
            if all((self.directory/name).read_text().startswith('ready') for name in ('listeners.log', 'remote-listeners.log')):
                break
            time.sleep(.1)
        else:
            raise AssertionError('listener startup failed')

    def packet(self, protocol='Tcp', address='192.0.2.1', port=65434, source='192.0.2.2'):
        return json.loads(self.ns('m24peer', sys.executable, __file__, 'probe', protocol,
                                 address, str(port), source).stdout)

    def bundle(self, protocol='Tcp', action='Deny', interface=False, default='Allow'):
        data = copy.deepcopy(self.seed)
        policy = data['policy']
        policy['default_action'] = default
        policy['zones'] = {'peer': {'interfaces': [{'Exact': 'm24in0'}] if interface else [],
                                    'subnets': ['fd24::2/128'] if protocol == 'Icmpv6' else ['192.0.2.2/32']}}
        rule = policy['rules'][0]
        rule.update(id='issue24-packet', source={'Zone': 'peer'}, protocol=protocol, action=action)
        if protocol in ('Icmp', 'Icmpv6'):
            rule['ports'] = 'NotApplicable'
        return data

    def apply(self, data, name, timeout=60, refusal=False, optional_refusal=False, opt_in=True,
              no_systemctl_path=None):
        path = self.directory/(name+'.input.json')
        path.write_text(json.dumps(data))
        planned = self.ns('m24target', 'manyfw', 'plan', '--diagnostic-input', str(path))
        generated = json.loads(planned.stdout)
        assert generated['input'] == data, 'CLI changed diagnostic input'
        bundle = self.directory/(name+'.bundle.json')
        bundle.write_text(json.dumps(generated))
        before = self.state()
        executable = (('env', 'PATH='+str(no_systemctl_path), '/usr/bin/manyfw')
                      if no_systemctl_path else ('manyfw',))
        result = self.ns('m24target', *executable, 'apply', *(['--experimental'] if opt_in else []), '--timeout', str(timeout),
                         '--file', str(bundle), check=False)
        if refusal or (optional_refusal and result.returncode != 0):
            assert result.returncode != 0, 'unsupported path unexpectedly applied'
            assert before == self.state(), 'refusal mutated firewall state'
            evidence = {'stage': 'apply', 'returncode': result.returncode, 'error': result.stderr,
                        'before': before, 'after': self.state(), 'plan_applicability': generated['plan']['applicability']}
            assert result.returncode > 0 and result.stderr.strip(), 'crash/empty diagnostic is not refusal'
            self.results['cases'][name] = evidence
            return evidence
        assert result.returncode == 0, result.stderr
        applied = json.loads(result.stdout)
        applied.pop('confirmation_token', None)
        self.results['cases'][name+'-apply'] = applied
        return applied['transaction_id']

    def state(self):
        def clean(value):
            if isinstance(value, dict):
                return {k: clean(v) for k, v in value.items() if k not in ('handle', 'packets', 'bytes', 'metainfo')}
            if isinstance(value, list):
                return [clean(v) for v in value]
            return value
        return clean(json.loads(self.ns('m24target', 'nft', '-j', 'list', 'ruleset').stdout))

    def rollback(self, transaction):
        self.ns('m24target', 'manyfw', 'recover', '--rollback', transaction)

    def ruleset_evidence(self, name, stage):
        path = self.directory/f'{name}.{stage}.nft.json'
        path.write_text(self.ns('m24target', 'nft', '-j', 'list', 'ruleset').stdout)
        self.results['cases'].setdefault(name+'-rulesets', {})[stage] = path.name
        self.save()

    @staticmethod
    def verify_reject(result, ipv6=False):
        assert result['outcome'] == 'reject', result
        # Current generic reject contract is ICMP[x] port-unreachable, including
        # TCP; a reset or unrelated unreachable is not equivalent evidence.
        kind, message_type, code = ('icmpv6-unreachable', 1, 4) if ipv6 else ('icmp-unreachable', 3, 3)
        assert any(event['kind'] == kind and event['icmp_type'] == message_type
                   and event['icmp_code'] == code for event in result['wire_events']), result

    def case(self, name, data, expected, **packet):
        control = self.packet(**packet)
        self.results['cases'][name+'-precontrol'] = control
        self.save()
        assert control['outcome'] == 'allow', f'missing positive control for {name}: {control}'
        before = self.state()
        transaction = self.apply(data, name)
        result = self.packet(**packet)
        self.results['cases'][name+'-nft'] = self.ns('m24target', 'nft', '-j', 'list', 'ruleset').stdout
        self.results['cases'][name] = result
        self.save()
        assert result['outcome'] == expected, (name, expected, result)
        if expected == 'reject':
            self.verify_reject(result, ':' in packet.get('address', '192.0.2.1'))
        self.rollback(transaction)
        assert before == self.state(), 'checkpoint not restored'
        assert self.packet(**packet)['outcome'] == 'allow', 'post-rollback positive control failed'
        self.passed_case(name)

    def refuse(self, name, data, terms, **kwargs):
        evidence = self.apply(data, name, refusal=True, **kwargs)
        assert any(term in evidence['error'].lower() for term in terms), evidence
        self.passed_case(name)
        return evidence

    def extended_cases(self):
        for family, address, source, other, alternate in (
            ('v4', '192.0.2.1', '192.0.2.2', '192.0.2.3', '192.0.2.9'),
            ('v6', 'fd24::1', 'fd24::2', 'fd24::3', 'fd24::9')):
            packet = {'address': address, 'source': source}
            subnet = source+('/32' if family == 'v4' else '/128')
            for protocol in ('Tcp', 'Udp'):
                for scope, ports in (('any-port', 'Any'), ('range', {'Specific': [{'start': 65434, 'end': 65435}]})):
                    data = self.bundle(protocol)
                    data['policy']['zones']['peer']['subnets'] = [subnet]
                    data['policy']['rules'][0]['ports'] = ports
                    for suffix, port in (('low', 65434), ('high', 65435), ('outside', 65436)):
                        expected = 'allow' if scope == 'range' and suffix == 'outside' else 'drop'
                        self.case(f'{family}-{protocol}-{scope}-{suffix}', data, expected, protocol=protocol, port=port, **packet)
            data = self.bundle()
            data['policy']['rules'][0]['source'] = {'Cidr': subnet}
            self.case(f'{family}-source-match', data, 'drop', **packet)
            self.case(f'{family}-source-mismatch', data, 'allow', address=address, source=other)
            data = self.bundle(interface=True)
            data['policy']['zones']['peer']['subnets'] = []
            self.case(f'{family}-interface-only-match', data, 'drop', **packet)
            self.case(f'{family}-interface-only-mismatch', data, 'allow',
                      address='192.0.3.1' if family == 'v4' else 'fd24:1::1',
                      source='192.0.3.2' if family == 'v4' else 'fd24:1::2')
            for action, expected in (('Allow', 'allow'), ('Deny', 'drop')):
                data = self.bundle(default=action)
                data['policy']['rules'] = []
                self.case(f'{family}-default-{action}', data, expected, **packet)
            data = self.bundle()
            data['policy']['zones']['peer']['subnets'] = [subnet]
            self.case(f'{family}-family-isolation', data, 'allow',
                      address='fd24::1' if family == 'v4' else '192.0.2.1',
                      source='fd24::2' if family == 'v4' else '192.0.2.2')
            for first, second, expected in (('Allow', 'Deny', 'allow'), ('Deny', 'Allow', 'drop')):
                data = self.bundle(action=first)
                data['policy']['zones']['peer']['subnets'] = [subnet]
                rule = copy.deepcopy(data['policy']['rules'][0])
                rule.update(id='overlapping-second', action=second, priority=20)
                data['policy']['rules'].append(rule)
                self.case(f'{family}-precedence-{first.lower()}-first', data, expected, **packet)
            # Fixture must resolve through the actual planner, not hand-edited
            # PlanOperation JSON. Fail closed until the generator supports it.
            fixture = json.loads(Path(f'/tmp/issue24-host-binding-{family}.json').read_text())
            bound = fixture['input']
            operations = [op['EnsureRule'] for op in fixture['plan']['operations'] if 'EnsureRule' in op]
            assert any(op['host_address'] == address and 'Host' in op['destination'] for op in operations), (
                f'Rust coordination required: host-binding-{family} must generate local Host host_address={address}')
            self.case(f'{family}-host-address-match', bound, 'drop', **packet)
            self.case(f'{family}-host-address-mismatch', bound, 'allow', address=alternate, source=source)

    def run(self):
        self.setup()
        for protocol in ('Tcp', 'Udp', 'Icmp', 'Icmpv6'):
            packet = {'protocol': protocol}
            if protocol == 'Icmpv6':
                packet.update(address='fd24::1', source='fd24::2')
            for action, expected in (('Deny', 'drop'), ('Reject', 'reject'), ('Allow', 'allow')):
                self.case(protocol+'-'+action, self.bundle(protocol, action), expected, **packet)
        for protocol in ('Tcp', 'Udp'):
            for action, expected in (('Deny', 'drop'), ('Reject', 'reject'), ('Allow', 'allow')):
                data = self.bundle(protocol, action)
                data['policy']['zones']['peer']['subnets'] = ['fd24::2/128']
                self.case(protocol+'-ipv6-'+action, data, expected, protocol=protocol, address='fd24::1', source='fd24::2')
        data = self.bundle()
        data['policy']['rules'][0]['source'] = {'Cidr': '192.0.2.2/32'}
        self.case('source-cidr-match', data, 'drop')
        self.case('source-cidr-mismatch', data, 'allow', source='192.0.2.3')
        data = self.bundle()
        data['policy']['rules'][0]['ports'] = {'Specific': [{'start': 65434, 'end': 65435}]}
        self.case('port-range-low', data, 'drop')
        self.case('port-range-high', data, 'drop', port=65435)
        self.case('source-mismatch', self.bundle(), 'allow', source='192.0.2.3')
        self.case('port-mismatch', self.bundle(), 'allow', port=65435)
        # Host(local-host), with no host_address constraint, denotes all local
        # destinations. A second assigned local address must match too.
        self.case('local-host-address-alias', self.bundle(), 'drop', address='192.0.2.9')
        self.results['cases']['host-address-contract'] = {'host_address': None,
            'meaning': 'all resolved local Host addresses; no fabricated CIDR destination'}
        self.case('interface-match', self.bundle(interface=True), 'drop')
        data = self.bundle(interface=True)
        data['policy']['zones']['peer']['subnets'] = []
        self.case('interface-mismatch', data, 'allow', address='192.0.3.1', source='192.0.3.2')
        for action, expected in (('Allow', 'allow'), ('Deny', 'drop')):
            data = self.bundle(default=action)
            data['policy']['rules'] = []
            self.case('default-'+action, data, expected)
        # Separate base chains: accept is nonterminal across hooks; drop is final.
        for priority in (-400, 100):
            for foreign, own, expected in (('accept', 'Deny', 'drop'), ('drop', 'Allow', 'drop')):
                assert self.packet()['outcome'] == 'allow'
                self.nft(f'add table inet m24foreign\nadd chain inet m24foreign input {{ type filter hook input priority {priority}; policy accept; }}\nadd rule inet m24foreign input tcp dport 65434 counter {foreign}\n')
                assert self.packet()['outcome'] == ('allow' if foreign == 'accept' else 'drop')
                before = self.state()
                name = f'composition-{priority}-{foreign}'
                self.ruleset_evidence(name, 'foreign-checkpoint')
                transaction = self.apply(self.bundle(action=own), name)
                self.ruleset_evidence(name, 'applied')
                result = self.packet()
                self.results['cases'][name] = result
                self.save()
                assert result['outcome'] == expected, result
                self.rollback(transaction)
                self.ruleset_evidence(name, 'restored')
                assert self.state() == before, 'foreign chain changed'
                self.nft('delete table inet m24foreign\n')
                assert self.packet()['outcome'] == 'allow'
                self.passed_case(name)
        # Repeat both foreign verdict orderings across the other IP family and
        # transport protocol. This is eight additional real packet scenarios:
        # IPv6/TCP and IPv4/UDP, each before and after ManyFW.
        for family, protocol, address, source in (
            ('v6', 'Tcp', 'fd24::1', 'fd24::2'),
            ('v4', 'Udp', '192.0.2.1', '192.0.2.2'),
        ):
            packet = {'protocol': protocol, 'address': address, 'source': source}
            for priority in (-400, 100):
                for foreign, own in (('accept', 'Deny'), ('drop', 'Allow')):
                    assert self.packet(**packet)['outcome'] == 'allow'
                    self.nft(
                        f'add table inet m24foreign\n'
                        f'add chain inet m24foreign input {{ type filter hook input priority {priority}; policy accept; }}\n'
                        f'add rule inet m24foreign input {protocol.lower()} dport 65434 counter {foreign}\n'
                    )
                    before = self.packet(**packet)['outcome']
                    assert before == ('allow' if foreign == 'accept' else 'drop'), (family, priority, foreign, before)
                    data = self.bundle(protocol=protocol, action=own)
                    data['policy']['zones']['peer']['subnets'] = [
                        source+('/128' if family == 'v6' else '/32')]
                    name = f'composition-{family}-{protocol}-{priority}-{foreign}'
                    self.ruleset_evidence(name, 'foreign-checkpoint')
                    transaction = self.apply(data, name)
                    self.ruleset_evidence(name, 'applied')
                    result = self.packet(**packet)
                    self.results['cases'][name] = result
                    self.save()
                    assert result['outcome'] == 'drop', (family, priority, foreign, result)
                    self.rollback(transaction)
                    self.ruleset_evidence(name, 'restored')
                    self.nft('delete table inet m24foreign\n')
                    assert self.packet(**packet)['outcome'] == 'allow'
                    self.passed_case(name)
        # Scoped loss of the packet channel: independent worker restores ingress.
        checkpoint = self.state()
        assert self.packet()['outcome'] == 'allow'
        transaction = self.apply(self.bundle(interface=True), 'interface-timeout', timeout=8)
        assert self.packet()['outcome'] == 'drop'
        for _ in range(25):
            if self.packet()['outcome'] == 'allow':
                break
            time.sleep(1)
        else:
            raise AssertionError('independent recovery did not restore ingress')
        records = [json.loads(p.read_text()) for p in Path('/var/lib/manyfw/transactions').glob('*.json')]
        record = next(r for r in records if r['plan']['transaction_id'] == transaction)
        assert record['state'] == 'rolled_back', record['state']
        assert self.state() == checkpoint, 'interface checkpoint differs after independent recovery'
        self.results['cases']['interface-timeout'] = 'Passed'
        self.passed_case('interface-timeout')
        # Existing TCP connection, not merely conntrack inferred from rules.
        stream = subprocess.Popen(['ip', 'netns', 'exec', 'm24peer', sys.executable,
                                   __file__, 'stream'], stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE, text=True)
        self.processes.append(stream)
        assert stream.stdout.readline().strip() == 'ready'
        checkpoint = self.state()
        transaction = self.apply(self.bundle(), 'established-stream')
        stream.stdin.write('probe\n')
        stream.stdin.flush()
        result = json.loads(stream.stdout.readline())
        self.results['cases']['established-stream'] = result
        assert result['outcome'] == 'drop', result
        self.rollback(transaction)
        assert self.state() == checkpoint, 'established-stream checkpoint differs'
        stream.terminate()
        stream.wait(timeout=3)
        self.processes.remove(stream)
        self.passed_case('established-stream')
        # Real routed flow and source NAT remain outside INPUT, including while
        # ManyFW's INPUT default is deny. Preserve the foreign NAT checkpoint.
        for protocol in ('Tcp', 'Udp', 'Icmp'):
            assert self.packet(protocol=protocol, address='198.51.100.2')['outcome'] == 'allow'
        before = self.state()
        nat_before = self.nat_packets()
        data = self.bundle(default='Deny')
        data['policy']['rules'] = []
        transaction = self.apply(data, 'routed-nat-preserved')
        # Byte boundary is taken after apply and all prepositive controls. Only
        # endpoint receives generated during the applied-policy probes count.
        remote_path = self.directory/'remote-listeners.log'
        remote_start = remote_path.stat().st_size
        for protocol in ('Tcp', 'Udp', 'Icmp'):
            result = self.packet(protocol=protocol, address='198.51.100.2')
            self.results['cases']['routed-nat-'+protocol] = result
            assert result['outcome'] == 'allow', result
        self.results['cases']['routed-nat-counters'] = self.ns('m24target', 'nft', '-j', 'list', 'table', 'ip', 'm24nat').stdout
        nat_after = self.nat_packets()
        assert nat_after > nat_before, ('NAT counter did not increase', nat_before, nat_after)
        # The remote endpoint has no return route to the original peer subnet;
        # the logged translated source is independent evidence, not only nft text.
        with remote_path.open('rb') as log:
            log.seek(remote_start)
            remote_log = log.read().decode()
        received = [json.loads(line) for line in remote_log.splitlines() if line.startswith('{')]
        assert all(any(event.get('peer') == '198.51.100.1' and event.get('received') == protocol
                       for event in received) for protocol in ('tcp', 'udp')), received
        self.results['cases']['routed-nat-proof'] = {'before_packets': nat_before, 'after_packets': nat_after,
            'remote_translated_source': '198.51.100.1', 'remote_log_start_byte': remote_start,
            'post_apply_remote_events': received}
        self.rollback(transaction)
        assert self.state() == before, 'NAT/foreign state changed'
        self.passed_case('routed-nat-preserved')
        # The diagnostic schema has no OUTPUT PacketPath. Supply only the
        # unsupported hook capability instead of inventing an OUTPUT policy or
        # editing generated operations. Both lack the required INPUT contract.
        for hook in ('output', 'forward'):
            data = self.bundle()
            backend = data['backend']
            backend['capabilities']['input_hook'] = 'unsupported'
            backend['observation']['hooks'] = [{'hook': hook, 'priority': -300,
                                               'present': 'supported'}]
            for resource in backend['observation']['resources']:
                resource['hook'] = hook
                if hook == 'forward':
                    resource['path'] = 'forward'
            name = hook+'-only-backend-refusal'
            result = self.apply(data, name, refusal=True)
            assert any(word in result['error'].lower() for word in ('unsupported', 'blocked', 'applicable', 'input')), result
            self.results['cases'][name] = result
            self.passed_case(name)
        data = self.bundle(default='Reject')
        data['policy']['rules'] = []
        # Capture the actual CLI stage/status and before/after firewall state.
        # Never reinterpret an assertion or verification failure as a refusal.
        assert self.packet()['outcome'] == 'allow'
        reject_checkpoint = self.state()
        transaction = self.apply(data, 'default-Reject', optional_refusal=True)
        if isinstance(transaction, dict):
            error = transaction['error'].lower()
            assert ('default' in error and 'reject' in error and any(t in error for t in ('unsupported', 'not supported', 'not a valid'))) or 'unsupported typed operation' in error, transaction
        else:
            result = self.packet()
            self.verify_reject(result)
            self.results['cases']['default-Reject'] = {'stage': 'apply-and-packet-verification',
                'packet': result, 'before': reject_checkpoint, 'after': self.state()}
            self.rollback(transaction)
        assert self.state() == reject_checkpoint
        assert self.packet()['outcome'] == 'allow'
        self.passed_case('default-Reject')
        self.refusal_cases()
        self.extended_cases()
        self.results['limitations'].update({
            'additional_scope_notes': [
            'OUTPUT has no PacketPath schema; tested output-only backend refusal, not a fabricated OUTPUT policy',
            'FORWARD-only backend refusal and routed/NAT preservation do not imply FORWARD enforcement',
            'existing 32-scenario recovery suite must be supplied separately to aggregate gate']
        })
        self.results['missing_coverage'] = sorted(self.expected-self.passed)
        self.results['complete'] = self.passed == self.expected

    def nat_packets(self):
        value = json.loads(self.ns('m24target', 'nft', '-j', 'list', 'table', 'ip', 'm24nat').stdout)
        return sum(expression['counter']['packets'] for item in value['nftables']
                   for expression in item.get('rule', {}).get('expr', []) if 'counter' in expression)

    def refusal_cases(self):
        # A valid kernel NAT INPUT base chain is deliberately outside the
        # adapter's supported foreign filter-chain composition contract.
        # Creating it must succeed; an invalid nft fixture is not a refusal.
        name = 'incompatible-foreign-input-refusal'
        self.nft('add table inet m24incompatible\nadd chain inet m24incompatible input { type nat hook input priority 100; policy accept; }\n')
        try:
            self.ruleset_evidence(name, 'foreign-checkpoint')
            self.refuse(name, self.bundle(), ('unsupported foreign input chain structure',))
            self.ruleset_evidence(name, 'after-refusal')
        finally:
            self.nft('delete table inet m24incompatible\n')
        name = 'nft-flowtable-offload-refusal'
        self.nft('add table inet m24flow\n'
                 'add flowtable inet m24flow ft { hook ingress priority 0; devices = { "m24in0" }; }\n')
        try:
            self.ruleset_evidence(name, 'flowtable-checkpoint')
            self.refuse(name, self.bundle(), ('flowtable/offload',))
            self.ruleset_evidence(name, 'after-refusal')
        finally:
            self.nft('delete table inet m24flow\n')
        data = self.bundle()
        data['policy']['rules'][0]['source'] = {'Zone': 'unresolved-peer'}
        self.refuse('unresolved-source-refusal', data, ('unsupported', 'unknown', 'blocked', 'applicable', 'unresolved'))
        data = self.bundle()
        data['backend']['capabilities']['input_hook'] = 'unknown'
        self.refuse('unknown-capability-refusal', data, ('unknown', 'blocked', 'applicable'))
        data = self.bundle()
        data['policy']['rules'][0]['destination'] = {'Cidr': '192.0.2.1/32'}
        self.refuse('arbitrary-destination-cidr-refusal', data, ('unsupported typed operation', 'destination', 'unsupported'))
        self.refuse('opt-in-bypass-refusal', self.bundle(), ('--experimental',), opt_in=False)
        # Exercise the fail-closed readiness check with a restricted executable
        # PATH that contains the real nft binary but no systemctl. No production
        # tool is stubbed or replaced.
        no_systemctl = Path('/run')/('mfw-no-systemctl-'+self.run_id)
        no_systemctl.mkdir(mode=0o700)
        for executable in ('nft', 'systemd-detect-virt'):
            binary = shutil.which(executable)
            assert binary, f'{executable} unavailable for isolated no-systemctl test'
            os.symlink(binary, no_systemctl/executable)
        try:
            evidence = self.refuse('non-systemd-refusal', self.bundle(),
                                   ('enabled and active manyfw recovery supervisor is required',),
                                   no_systemctl_path=no_systemctl)
            evidence['environment'] = 'test-only child PATH omits systemctl; real CLI and nft binary'
            self.save()
        finally:
            shutil.rmtree(no_systemctl)
        # Relevant supported interoperability path is iptables-nft's ordinary
        # filter INPUT base chain, not an invented iptables execution backend.
        for family, tool, address, source in (
            ('v4', 'iptables-nft', '192.0.2.1', '192.0.2.2'),
            ('v6', 'ip6tables-nft', 'fd24::1', 'fd24::2')):
            version = self.ns('m24target', tool, '--version', check=False)
            self.results['cases'][f'iptables-{family}-diagnostic'] = {'returncode': version.returncode, 'stdout': version.stdout, 'stderr': version.stderr}
            assert version.returncode == 0 and 'nf_tables' in version.stdout, 'supported iptables-nft fixture unavailable'
            for verdict, own in (('ACCEPT', 'Deny'), ('DROP', 'Allow')):
                args = ('INPUT', '-p', 'tcp', '-s', source, '--dport', '65434', '-j', verdict)
                self.ns('m24target', tool, '-A', *args)
                try:
                    before = self.ns('m24target', tool, '-S').stdout
                    data = self.bundle(action=own)
                    data['policy']['zones']['peer']['subnets'] = [source+('/32' if family == 'v4' else '/128')]
                    name = f'iptables-nft-{family}-{verdict}'
                    self.ruleset_evidence(name, 'foreign-checkpoint')
                    (self.directory/f'{name}.foreign-checkpoint.iptables.txt').write_text(before)
                    transaction = self.apply(data, name)
                    self.ruleset_evidence(name, 'applied')
                    result = self.packet(address=address, source=source)
                    assert result['outcome'] == 'drop', result
                    self.rollback(transaction)
                    self.ruleset_evidence(name, 'restored')
                    assert self.ns('m24target', tool, '-S').stdout == before
                    self.results['cases'][name] = result
                    self.passed_case(name)
                finally:
                    self.ns('m24target', tool, '-D', *args)
                assert self.packet(address=address, source=source)['outcome'] == 'allow'

    def cleanup(self):
        failures = []
        if self.worker_started and command('systemctl', 'stop', 'manyfw-recovery.service', check=False).returncode:
            failures.append('recovery service stop failed')
        for process in self.processes:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        for namespace in reversed(self.namespaces):
            if command('ip', 'netns', 'delete', namespace, check=False).returncode:
                failures.append('namespace cleanup failed: '+namespace)
        self.results['cleanup_failures'] = failures
        if failures:
            self.results['complete'] = False


if __name__ == '__main__':
    if sys.argv[1] == 'endpoint':
        endpoint()
    elif sys.argv[1] == 'probe':
        print(json.dumps(probe(sys.argv[2], sys.argv[3], int(sys.argv[4]), sys.argv[5])))
    elif sys.argv[1] == 'stream':
        with socket.create_connection(('192.0.2.1', 65434), timeout=1.5) as connection:
            connection.sendall(b'before')
            assert connection.recv(32) == b'before'
            print('ready', flush=True)
            sys.stdin.readline()
            try:
                connection.sendall(b'after')
                assert connection.recv(32) == b'after'
                result = {'outcome': 'allow'}
            except TimeoutError:
                result = {'outcome': 'drop', 'error': 'established echo timed out'}
            print(json.dumps(result), flush=True)
    elif sys.argv[1] == 'run':
        suite = Suite(sys.argv[2], sys.argv[3])
        try:
            suite.run()
            if not suite.results['complete']:
                raise RuntimeError('coverage incomplete; see missing_coverage (gate remains blocked)')
        except BaseException as exc:
            suite.results['error'] = repr(exc)
            raise
        finally:
            try:
                suite.cleanup()
            finally:
                suite.save()
    else:
        raise SystemExit('unknown mode')
