#!/usr/bin/env python3
"""Read-only evidence receipt, not architecture review or operational authorization.

Usage: issue24-acceptance.py RECOVERY_DIR PACKET_DIR OUTPUT_JSON
SHA-256 receipts detect corruption; they do not authenticate evidence producers.
"""
import argparse
import hashlib
import ipaddress
import io
import json
import pathlib
import re
import subprocess
import tarfile

PACKET_CONTRACT = 'issue24-linux-packets-v4'
RECOVERY_CONTRACT = 'issue24-linux-packets-v2'
CONTRACT = PACKET_CONTRACT
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
default-Allow default-Deny interface-timeout established-stream
outbound-return-default-deny loopback-default-deny
icmpv6-neighbor-discovery-default-deny routed-nat-preserved
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


def validate_default_deny_exceptions(document, submitted):
    entries = []
    for item in document.get('nftables', []):
        rule = item.get('add', {}).get('rule') if submitted else item.get('rule')
        if isinstance(rule, dict):
            entries.append((rule.get('comment', ''), rule.get('expr')))
    comments = [comment for comment, _ in entries]
    exception_names = (
        'manyfw-exception-v1-established-related',
        'manyfw-exception-v1-loopback',
        'manyfw-exception-v1-icmpv6-control',
    )
    require(all(comments.count(name) == 1 for name in exception_names),
            'missing or duplicate default-deny exception rules')
    expected_types = {
        'nd-neighbor-solicit', 'nd-neighbor-advert',
        'nd-router-solicit', 'nd-router-advert',
    }

    def exact_set(value, values):
        return (isinstance(value, dict) and set(value) == {'set'} and
                isinstance(value.get('set'), list) and
                all(isinstance(item, str) for item in value['set']) and
                len(value['set']) == len(set(value['set'])) and set(value['set']) == values)

    def exact_match(expression):
        if not isinstance(expression, dict) or set(expression) != {'match'}:
            return None
        predicate = expression['match']
        if not isinstance(predicate, dict) or set(predicate) != {'left', 'op', 'right'}:
            return None
        return predicate

    def valid(comment, expression):
        if not isinstance(expression, list) or not expression or expression[-1] != {'accept': None}:
            return False
        predicates = expression[:-1]
        if comment == 'manyfw-exception-v1-established-related':
            if len(predicates) != 1:
                return False
            predicate = exact_match(predicates[0])
            if predicate is None:
                return False
            return (predicate.get('left') == {'ct': {'key': 'state'}} and
                    predicate.get('op') in ('in', '==') and
                    exact_set(predicate.get('right'), {'established', 'related'}))
        if comment == 'manyfw-exception-v1-loopback':
            if len(predicates) != 1:
                return False
            predicate = exact_match(predicates[0])
            if predicate is None:
                return False
            return (predicate.get('left') == {'meta': {'key': 'iifname'}} and
                    predicate.get('op') == '==' and predicate.get('right') == 'lo')
        if comment != 'manyfw-exception-v1-icmpv6-control':
            return False
        payload_type = {'payload': {'protocol': 'icmpv6', 'field': 'type'}}
        if len(predicates) == 2:
            protocol = exact_match(predicates[0])
            types = exact_match(predicates[1])
            if protocol is None or types is None:
                return False
            return (protocol.get('left') == {'meta': {'key': 'l4proto'}} and
                    protocol.get('op') == '==' and protocol.get('right') == 'ipv6-icmp' and
                    types.get('left') == payload_type and types.get('op') == 'in' and
                    exact_set(types.get('right'), expected_types))
        if len(predicates) == 1:
            predicate = exact_match(predicates[0])
            if predicate is None:
                return False
            return (predicate.get('left') == payload_type and predicate.get('op') == '==' and
                    exact_set(predicate.get('right'), expected_types))
        return False

    for comment, expression in entries:
        if comment in exception_names:
            require(valid(comment, expression),
                    'invalid default-deny exception expression: ' + comment)
        elif comment.startswith('manyfw-exception-v1-'):
            require(False, 'unexpected default-deny exception rule: ' + comment)
    positions = [comments.index(name) for name in exception_names]
    defaults = [(index, comment, expression)
                for index, (comment, expression) in enumerate(entries)
                if comment.startswith('manyfw-default-v1-')]
    require(len({comment for _, comment, _ in defaults}) == len(defaults),
            'duplicate managed default-deny rule')
    for _, _, expression in defaults:
        predicate = exact_match(expression[0]) if isinstance(expression, list) and expression else None
        require(
            isinstance(expression, list) and len(expression) == 2 and predicate is not None and
            predicate.get('op') == '==' and
            predicate.get('left') == {'meta': {'key': 'nfproto'}} and
            predicate.get('right') in ('ipv4', 'ipv6') and
            expression[1] == {'drop': None},
            'invalid managed default-deny expression',
        )
    require(defaults and max(positions) < min(index for index, _, _ in defaults),
            'default-deny exceptions are not ordered before family drops')


def ipv6_equal(address, expected):
    try:
        return ipaddress.IPv6Address(address) == ipaddress.IPv6Address(expected)
    except (ipaddress.AddressValueError, TypeError):
        return False


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
    if name in {
        'outbound-return-default-deny',
        'loopback-default-deny',
        'icmpv6-neighbor-discovery-default-deny',
    }:
        return 'allow'
    if name.startswith('composition-'):
        return 'drop'
    if name.startswith('iptables-nft-'):
        # External ACCEPT composes with a ManyFW deny; external DROP must refuse
        # the ManyFW allow before mutation. Both packet outcomes remain drops.
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
        if name.endswith('-submitted-json'):
            path = str(safe_relative(value))
            require(isinstance(json.loads(files[path]).get('nftables'), list),
                    'invalid submitted nftables JSON: ' + name)
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
    exception_cases = {
        'outbound-return-default-deny',
        'loopback-default-deny',
        'icmpv6-neighbor-discovery-default-deny',
    }
    ordinary = {name for name in packet_cases() if name not in {
        'interface-timeout', 'established-stream', 'routed-nat-preserved', 'default-Reject'}
        and name not in exception_cases
        and not (name.startswith('composition-') and name.endswith('-drop'))
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
    foreign_drop_refusals = {
        name for name in packet_cases()
        if name.startswith('composition-') and name.endswith('-drop')
    }
    for name in foreign_drop_refusals:
        value = cases[name]
        try:
            error = json.loads(value.get('error', ''))['diagnostic']
        except (json.JSONDecodeError, KeyError, TypeError):
            error = ''
        if error.startswith('backend: '):
            error = error.removeprefix('backend: ')
        require(
            value.get('stage') == 'apply' and value.get('returncode', 0) > 0 and
            value.get('before') == value.get('after') and
            value.get('outcome') == 'drop' and value.get('packet_before') == 'drop' and
            value.get('packet_after') == 'drop' and
            isinstance(value.get('observed_plan_applicability'), dict) and
            'Blocked' in value['observed_plan_applicability'] and
            value.get('observed_plan_diagnostic') == error and
            isinstance(value.get('observed_plan_fingerprint'), str) and
            bool(value['observed_plan_fingerprint']) and
            all(term in error for term in (
                'allow rule issue24-packet', 'table m24foreign', 'chain input',
                'hook Input', 'priority ', 'handle ', 'owner unknown',
                'resolve the foreign rule in its owning tool',
            )),
            'foreign-drop allow was not refused before mutation: ' + name,
        )
        after = value.get('after', {})
        require(
            not any(
                item.get('table', {}).get('family') == 'inet' and
                item.get('table', {}).get('name') == 'manyfw'
                for item in after.get('nftables', [])
            ),
            'foreign-drop refusal left a ManyFW table: ' + name,
        )
    for family in ('v4', 'v6'):
        name = f'iptables-nft-{family}-DROP'
        refusal = cases.get(name + '-refusal', {})
        try:
            diagnostic = json.loads(refusal.get('error', ''))['diagnostic']
        except (json.JSONDecodeError, KeyError, TypeError):
            diagnostic = ''
        require(
            refusal.get('stage') == 'apply' and refusal.get('returncode', 0) > 0 and
            refusal.get('before') == refusal.get('after') and
            refusal.get('iptables_before') == refusal.get('iptables_after') and
            'table filter chain INPUT hook Input' in diagnostic and
            'resolve the foreign rule in its owning tool' in diagnostic and
            name + '-nft' in cases and
            not any(
                item.get('table', {}).get('family') == 'inet' and
                item.get('table', {}).get('name') == 'manyfw'
                for item in refusal.get('after', {}).get('nftables', [])
            ),
            'iptables-nft foreign DROP was not refused without mutation: ' + name,
        )
    for name in ('outbound-return-default-deny', 'loopback-default-deny'):
        value = cases[name]
        exchange = value.get('exchange', {})
        require(value.get('outcome') == 'allow' and
                exchange.get('sent') == exchange.get('received') and
                isinstance(exchange.get('sent'), str) and bool(exchange['sent']),
                'missing successful payload round-trip: ' + name)
        references = cases.get(name + '-rulesets', {})
        require('applied' in references and 'restored' in references,
                'missing applied/restored ruleset evidence: ' + name)
        submitted_path = cases.get(name + '-submitted-json')
        require(isinstance(submitted_path, str),
                'missing exact submitted JSON artifact: ' + name)
        submitted = json.loads(files[str(safe_relative(submitted_path))])
        validate_default_deny_exceptions(submitted, submitted=True)
        applied = json.loads(files[str(safe_relative(references['applied']))])
        validate_default_deny_exceptions(applied, submitted=False)
    nd = cases['icmpv6-neighbor-discovery-default-deny']
    nd_events = nd.get('wire_events', [])
    solicit = any(
        event.get('kind') == 'icmpv6-neighbor-solicit' and
        ipv6_equal(event.get('source'), 'fd24:0::2') and
        ipv6_equal(event.get('target'), 'fd24:0::1') and
        ipv6_equal(event.get('destination'), 'ff02::1:ff00:1')
        for event in nd_events
    )
    advert = any(
        event.get('kind') == 'icmpv6-neighbor-advert' and
        ipv6_equal(event.get('source'), 'fd24:0::1') and
        ipv6_equal(event.get('target'), 'fd24:0::1') and
        ipv6_equal(event.get('destination'), 'fd24:0::2')
        for event in nd_events
    )
    require(
        nd.get('outcome') == 'allow' and nd.get('echo_outcome') == 'drop' and
        solicit and advert and
        nd.get('neighbor', {}).get('lladdr') and
        'FAILED' not in nd.get('neighbor', {}).get('state', []),
        'missing IPv6 neighbor-discovery packet proof',
    )
    nd_references = cases.get('icmpv6-neighbor-discovery-default-deny-rulesets', {})
    require('applied' in nd_references and 'restored' in nd_references,
            'missing applied/restored neighbor-discovery ruleset evidence')
    nd_submitted_path = cases.get('icmpv6-neighbor-discovery-default-deny-submitted-json')
    require(isinstance(nd_submitted_path, str),
            'missing exact submitted JSON for neighbor discovery')
    nd_submitted = json.loads(files[str(safe_relative(nd_submitted_path))])
    validate_default_deny_exceptions(nd_submitted, submitted=True)
    nd_applied = json.loads(files[str(safe_relative(nd_references['applied']))])
    validate_default_deny_exceptions(nd_applied, submitted=False)
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

    def manifest(root, expected_contract):
        value = document(root, 'source-manifest.json')
        require(value['contract_version'] == expected_contract,
                'source manifest contract mismatch: ' + str(root))
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
        for root, gate, expected_contract in (
            (recovery, rg, RECOVERY_CONTRACT),
            (packet, pg, PACKET_CONTRACT),
        ):
            require(gate['contract_version'] == expected_contract, 'gate contract mismatch')
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
        require(results['contract_version'] == PACKET_CONTRACT and results['complete'] is True,
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
        require(manifest(recovery, RECOVERY_CONTRACT) ==
                manifest(packet, PACKET_CONTRACT), 'production source manifest mismatch')
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
