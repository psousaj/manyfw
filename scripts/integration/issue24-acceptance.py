#!/usr/bin/env python3
"""Read-only evidence receipt, not architecture review or operational authorization.

Usage: issue24-acceptance.py RECOVERY_DIR PACKET_DIR OUTPUT_JSON
SHA-256 receipts detect corruption; they do not authenticate evidence producers.
"""
import argparse
import hashlib
import io
import json
import pathlib
import re
import subprocess
import tarfile

CONTRACT = 'issue24-linux-packets-v2'
RECOVERY = set('''partial_apply ambiguous_apply_commit_recovered cli_kill_after_batch
ssh_loss_and_recovery successful_confirmation rollback_failure_and_retry
ambiguous_rollback_commit_retry corrupt_checkpoint_refusal_and_retry
supervisor_loss_and_restart recovery_arm_mismatch_fails_closed
recovery_arm_missing_fails_closed orphaned_arm_blocks_new_apply
corrupt_transaction_store_blocks_apply reboot_before_apply wrong_token_refused
expired_token_refused reboot_during_applying reboot_during_verifying
reboot_during_confirmation reboot_restores_nonempty_checkpoint
timeout_automatic_recovery wall_clock_rollback_monotonic_recovery reboot_pending_apply
concurrent_manyfw_transaction ipv4_real_loopback ipv6_real_loopback docker_iptables
docker_native_nftables ufw_coexistence firewalld_coexistence
concurrent_external_manager_divergence no_global_or_table_flush'''.split())


def packet_cases():
    names = set('''source-cidr-match source-cidr-mismatch port-range-low port-range-high
source-mismatch port-mismatch local-host-address-alias interface-match interface-mismatch
default-Allow default-Deny interface-timeout established-stream routed-nat-preserved
output-only-backend-refusal forward-only-backend-refusal default-Reject
unresolved-source-refusal unknown-capability-refusal arbitrary-destination-cidr-refusal
opt-in-bypass-refusal non-systemd-refusal incompatible-foreign-input-refusal
nft-flowtable-offload-refusal'''.split())
    names.update(f'iptables-nft-{f}-{v}' for f in ('v4', 'v6') for v in ('ACCEPT', 'DROP'))
    names.update(f'{p}-{a}' for p in ('Tcp', 'Udp', 'Icmp', 'Icmpv6') for a in ('Deny', 'Reject', 'Allow'))
    names.update(f'{p}-ipv6-{a}' for p in ('Tcp', 'Udp') for a in ('Deny', 'Reject', 'Allow'))
    names.update(f'composition-{n}-{a}' for n in (-400, 100) for a in ('accept', 'drop'))
    names.update(f'composition-{family}-{protocol}-{priority}-{verdict}'
                 for family, protocol in (('v6', 'Tcp'), ('v4', 'Udp'))
                 for priority in (-400, 100) for verdict in ('accept', 'drop'))
    names.update(f'{f}-{n}' for f in ('v4', 'v6') for n in (
        'host-address-match', 'host-address-mismatch', 'interface-only-match',
        'interface-only-mismatch', 'source-match', 'source-mismatch', 'default-Allow',
        'default-Deny', 'family-isolation', 'precedence-allow-first', 'precedence-deny-first'))
    names.update(f'{f}-{p}-{n}' for f in ('v4', 'v6') for p in ('Tcp', 'Udp')
                 for n in ('any-port-low', 'any-port-high', 'any-port-outside',
                           'range-low', 'range-high', 'range-outside'))
    return names


def require(condition, message):
    if not condition:
        raise ValueError(message)


def pairs(rows):
    result = {}
    for key, value in rows:
        require(key not in result, 'duplicate entry: ' + key)
        result[key] = value
    return result


def sha(value):
    require(isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value), 'invalid SHA256')
    return value


def hashes(text):
    return pairs((name, sha(digest)) for digest, name in
                 (line.split('  ', 1) for line in text.splitlines()))


def production_path(name):
    return (name.startswith(('crates/', 'src/', '.cargo/')) or
            pathlib.PurePosixPath(name).name in ('Cargo.toml', 'Cargo.lock') or
            name in ('build.rs', 'rust-toolchain', 'rust-toolchain.toml'))


def production_inventory(root):
    """Include every crate file, not just Rust: build scripts may read fixtures."""
    names = subprocess.check_output([
        'git', '-C', str(root), 'ls-files', '-z', '--cached', '--others',
        '--exclude-standard']).decode().split('\0')
    return {name for name in names if name and production_path(name)}


def safe_relative(name):
    path = pathlib.PurePosixPath(name)
    require(bool(name) and not path.is_absolute() and '..' not in path.parts and
            '\\' not in name and '\x00' not in name, 'unsafe evidence path: ' + name)
    return path


def expected_outcome(name):
    if name.startswith('composition-'):
        return 'drop'
    if name.startswith('iptables-nft-'):
        # Both variants compose an external ACCEPT with ManyFW Deny, or an
        # external DROP with ManyFW Allow. Either must be observed as drop.
        return 'drop'
    if name.endswith(('-Reject',)):
        return 'reject'
    if name.endswith(('-Allow', '-mismatch', '-family-isolation',
                      '-precedence-allow-first', '-range-outside')):
        return 'allow'
    return 'drop'


def archive_evidence(data, results):
    """Inspect in memory; never extract or follow archive links."""
    files = {}
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
        for member in archive:
            path = safe_relative(member.name)
            if member.isdir():
                continue
            require(member.isfile(), 'non-regular archive member: ' + member.name)
            name = str(path)
            require(name not in files, 'duplicate archive member: ' + name)
            stream = archive.extractfile(member)
            require(stream is not None, 'unreadable archive member: ' + name)
            files[name] = stream.read()
            require(len(files[name]) == member.size, 'truncated archive member: ' + name)
    require(json.loads(files['evidence.json']) == results, 'archive evidence mismatch')
    cases = results['cases']
    require(isinstance(cases, dict), 'missing packet case evidence')
    rules = 0
    wire = 0
    for name, value in cases.items():
        if name.endswith('-nft'):
            require(isinstance(json.loads(value).get('nftables'), list), 'invalid effective rules: ' + name)
            rules += 1
        if name.endswith('-rulesets'):
            require(isinstance(value, dict) and bool(value), 'empty ruleset references')
            for reference in value.values():
                path = str(safe_relative(reference))
                require(isinstance(json.loads(files[path]).get('nftables'), list),
                        'invalid archived ruleset: ' + path)
                rules += 1
        packet = value.get('packet', value) if isinstance(value, dict) else None
        if isinstance(packet, dict) and 'wire_events' in packet:
            require(packet.get('outcome') in ('allow', 'drop', 'reject') and
                    isinstance(packet['wire_events'], list) and
                    all(isinstance(event, dict) for event in packet['wire_events']),
                    'invalid wire packet evidence: ' + name)
            wire += 1
    # Each ordinary case captures effective rules and its observed packet. Refusal,
    # timeout, NAT and established-stream cases have separate producer contracts.
    ordinary = {name for name in packet_cases() if name not in {
        'interface-timeout', 'established-stream', 'routed-nat-preserved', 'default-Reject'}
        and not name.endswith('-refusal')}
    for name in ordinary:
        value = cases[name]
        require(isinstance(value, dict) and 'wire_events' in value,
                'missing case wire evidence: ' + name)
        require(value.get('outcome') == expected_outcome(name), 'case outcome mismatch: ' + name)
        if value['outcome'] == 'reject':
            ipv6 = 'ipv6' in name or name.startswith('Icmpv6')
            require(any(event.get('kind') == ('icmpv6-unreachable' if ipv6 else 'icmp-unreachable')
                        and event.get('icmp_type') == (1 if ipv6 else 3)
                        and event.get('icmp_code') == (4 if ipv6 else 3) for event in value['wire_events']),
                    'missing reject wire proof: ' + name)
        require(name + '-nft' in cases or name + '-rulesets' in cases,
                'missing case effective rules: ' + name)
        if name + '-rulesets' in cases:
            require('applied' in cases[name + '-rulesets'], 'missing applied ruleset: ' + name)
    default_reject = cases['default-Reject']
    if default_reject.get('stage') == 'apply':
        error = default_reject.get('error', '').lower()
        require(default_reject.get('returncode', 0) > 0 and
                (('default' in error and 'reject' in error and
                  any(term in error for term in ('unsupported', 'not supported', 'not a valid'))) or
                 'unsupported typed operation' in error) and
                default_reject.get('before') == default_reject.get('after'),
                'default Reject refusal was not a pre-mutation refusal')
    else:
        require(default_reject.get('stage') == 'apply-and-packet-verification' and
                default_reject.get('before') == default_reject.get('after'),
                'default Reject lacks refusal or applied-state evidence')
        packet = default_reject.get('packet', {})
        require(packet.get('outcome') == 'reject' and any(
                    event.get('kind') == 'icmp-unreachable' and
                    event.get('icmp_type') == 3 and event.get('icmp_code') == 3
                    for event in packet.get('wire_events', [])),
                'default Reject lacks IPv4 reject packet proof')
    require(rules > 0 and wire > 0, 'missing effective rules or wire packets')


def aggregate(recovery, packet):
    # This tool verifies producer evidence only. The dedicated review and its
    # approval record are an independent acceptance gate, not caller-supplied
    # booleans in an evidence bundle.
    receipt = {'contract_version': CONTRACT, 'evidence_gates_passed': False,
               'generic_linux_accepted': False,
               'production_authorized': False, 'source_runtime_review': 'pending',
               'compatibility_scenarios': {}, 'evidence': [], 'blockers': []}

    def read_bytes(root, name):
        require(not root.is_symlink(), 'symlink evidence directory: ' + str(root))
        relative = safe_relative(name)
        path = root
        for part in relative.parts:
            path = path / part
            require(not path.is_symlink(), 'symlink evidence: ' + str(path))
        data = path.read_bytes()
        receipt['evidence'].append({'path': str(path.resolve()),
                                    'sha256': hashlib.sha256(data).hexdigest()})
        return data

    def read(root, name):
        return read_bytes(root, name).decode('utf-8')

    def document(root, name):
        return json.loads(read(root, name), object_pairs_hook=lambda rows: pairs(rows))

    def manifest(root):
        value = document(root, 'source-manifest.json')
        require(value['contract_version'] == CONTRACT, 'source manifest contract mismatch')
        sources = pairs((e['path'], e) for e in value['sources'])
        require({name for name in sources if production_path(name)} == inventory,
                'production manifest inventory mismatch')
        selected = {}
        for name in inventory:
            entry = sources[name]
            require(set(entry) == {'path', 'sha256'}, 'non-regular production source: ' + name)
            selected[name] = sha(entry['sha256'])
        require('Cargo.toml' in selected and 'Cargo.lock' in selected and
                any(n.endswith('.rs') for n in selected), 'incomplete production source manifest')
        return selected

    try:
        inventory = production_inventory(pathlib.Path(__file__).resolve().parents[2])
        rg = document(recovery, 'issue24-release-gate.json')
        pg = document(packet, 'gate.json')
        receipt['compatibility_scenarios'] = rg.get('compatibility_scenarios', {})
        require(rg.get('recovery_eligible') is True and rg.get('release_eligible') is False,
                'recovery gate eligibility is inconsistent')
        tailscale = receipt['compatibility_scenarios'].get('tailscale_interoperability', {})
        require(tailscale.get('status') == 'NotApplicable' and
                tailscale.get('deferred_contract') == 'docs/specs/issue-24-linux-enforcement.md',
                'separate Tailscale compatibility contract is not retained')
        for root, gate in ((recovery, rg), (packet, pg)):
            require(gate['contract_version'] == CONTRACT, 'gate contract mismatch')
            require(gate['teardown'] == 'destroyed', 'guest not destroyed: ' + str(root))
            require('Stopped and removed disposable guest state.' in read(root, 'vm-down.log'),
                    'missing successful teardown log')
        require(rg['suite_type'] == 'production_recovery', 'wrong recovery suite')
        statuses = pairs(line.split('\t', 1) for line in read(recovery, 'status.tsv').splitlines() if line)
        for name in sorted(RECOVERY):
            require(statuses.get(name) == 'Passed' and rg['critical_scenarios'].get(name) == 'Passed',
                    'recovery scenario not passed: ' + name)
        require(all(value == 'Passed' for value in rg['critical_scenarios'].values()),
                'additional recovery critical scenario not passed')
        require(rg['critical_scenarios'].get('harness_completion') == 'Passed', 'recovery incomplete')
        require(pg['suite'] == 'linux-input-packets', 'wrong packet suite')
        require(pg.get('packet_eligible') is True, 'packet producer not eligible')
        require(pg.get('release_eligible') is False,
                'packet suite cannot authorize production release')
        results = document(packet, 'evidence.json')
        require(pg['results'] == results, 'packet embedded evidence mismatch')
        require(results['contract_version'] == CONTRACT and results['complete'] is True,
                'packet incomplete or wrong contract')
        limitations = results.get('limitations', {})
        require(limitations.get('packet_offload') ==
                'unsupported and not disabled or exhaustively observed by this suite' and
                limitations.get('unobservable_or_bypass_paths') ==
                'unknown/unsupported; no control claim' and
                limitations.get('other_hooks') == 'OUTPUT and FORWARD unsupported',
                'packet evidence omits unsupported/offload limitations')
        for key in ('expected_cases', 'passed_cases'):
            ledger = results[key]
            require(isinstance(ledger, list) and len(ledger) == len(set(ledger)) and
                    set(ledger) == packet_cases(), 'packet ledger mismatch: ' + key)
        require(results['missing_coverage'] == [], 'packet missing coverage')
        metadata = pairs(line.split('=', 1) for line in read(recovery, 'metadata.txt').splitlines())
        commit = read(packet, 'commit.txt').strip()
        require(re.fullmatch('[0-9a-f]{40}|[0-9a-f]{64}', commit) and
                metadata['candidate_commit'] == commit, 'candidate HEAD mismatch')
        require(manifest(recovery) == manifest(packet), 'production source manifest mismatch')
        binary = sha(metadata['binary_sha256'])
        for root in (recovery, packet):
            require(hashes(read(root, 'installed-binary.sha256')).get('/usr/bin/manyfw') == binary,
                    'installed guest binary mismatch')
        artifacts = hashes(read(packet, 'artifacts.sha256'))
        helpers = [v for n, v in artifacts.items() if n.endswith('/issue24-linux-packet-guest.py')]
        installed_helpers = hashes(read(packet, 'installed-binary.sha256'))
        require(len(helpers) == 1 and installed_helpers.get('/tmp/issue24-linux-packet-guest.py') == helpers[0],
                'installed packet helper mismatch')
        binaries = [v for n, v in artifacts.items() if not n.endswith('/issue24-linux-packet-guest.py')]
        require(binaries == [binary], 'packet built binary mismatch')
        sums = hashes(read(packet, 'SHA256SUMS'))
        require({'guest-artifacts.tar.gz', 'run.log', 'gate.json', 'evidence.json',
                 'vm-down.log', 'source-manifest.json', 'installed-binary.sha256',
                 'artifacts.sha256', 'commit.txt'} <= sums.keys(), 'missing mandatory checksummed artifacts')
        for name, expected in sums.items():
            require(name != 'SHA256SUMS', 'self-referential checksum manifest')
            data = read_bytes(packet, name)
            require(hashlib.sha256(data).hexdigest() == expected, 'packet checksum mismatch: ' + name)
        archive_evidence(read_bytes(packet, 'guest-artifacts.tar.gz'), results)
        for entry in receipt['evidence'][:]:
            path = pathlib.Path(entry['path'])
            if path.parent == packet.resolve() and path.name != 'SHA256SUMS':
                require(sums.get(path.name) == entry['sha256'], 'packet checksum mismatch: ' + path.name)
        receipt.update(evidence_gates_passed=True, candidate_commit=commit,
                       binary_sha256=binary)
        receipt['blockers'].append(
            'dedicated post-remediation source/runtime review and approval record required')
    except (OSError, ValueError, KeyError, TypeError, AttributeError,
            tarfile.TarError, EOFError, subprocess.SubprocessError) as error:
        receipt['blockers'].append(str(error))
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('recovery_dir', type=pathlib.Path)
    parser.add_argument('packet_dir', type=pathlib.Path)
    parser.add_argument('output_json', type=pathlib.Path)
    args = parser.parse_args()
    output = args.output_json.resolve()
    for root in (args.recovery_dir.resolve(), args.packet_dir.resolve()):
        require(not output.is_relative_to(root), 'output must not overwrite input evidence')
    result = aggregate(args.recovery_dir, args.packet_dir)
    args.output_json.write_text(json.dumps(result, indent=2) + '\n')
    return 0 if result['evidence_gates_passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
