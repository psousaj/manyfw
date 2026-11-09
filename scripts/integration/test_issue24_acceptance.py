"""Synthetic receipts only; never runs a guest or firewall command."""
import hashlib
import ast
import io
import importlib.util
import json
import pathlib
import tempfile
import tarfile
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location('acceptance', pathlib.Path(__file__).with_name('issue24-acceptance.py'))
acceptance = importlib.util.module_from_spec(spec)
spec.loader.exec_module(acceptance)
REAL_INVENTORY = acceptance.production_inventory


class AcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.recovery = pathlib.Path(self.temp.name) / 'recovery'
        self.packet = pathlib.Path(self.temp.name) / 'packet'
        self.inventory = {'Cargo.toml', 'Cargo.lock', 'crates/demo/src/main.rs',
                          'crates/demo/build.rs', 'crates/demo/policy.template'}
        patcher = mock.patch.object(acceptance, 'production_inventory', return_value=self.inventory)
        patcher.start()
        self.addCleanup(patcher.stop)
        for root in (self.recovery, self.packet):
            root.mkdir()
            (root / 'vm-down.log').write_text('Stopped and removed disposable guest state.\n')
            self.write(root, 'source-manifest.json', {'contract_version': acceptance.CONTRACT,
                       'sources': [{'path': p, 'sha256': 'a' * 64}
                                   for p in sorted(self.inventory)]})
            (root / 'installed-binary.sha256').write_text('b' * 64 + '  /usr/bin/manyfw\n')
        statuses = {name: 'Passed' for name in acceptance.RECOVERY}
        (self.recovery / 'status.tsv').write_text(''.join(f'{n}\t{s}\n' for n, s in statuses.items()))
        self.rg = {'contract_version': acceptance.CONTRACT, 'suite_type': 'production_recovery',
                   'teardown': 'destroyed', 'critical_scenarios': dict(statuses, harness_completion='Passed'),
                   'recovery_eligible': True, 'release_eligible': False, 'compatibility_scenarios': {
                       'tailscale_interoperability': {
                           'status': 'NotApplicable',
                           'deferred_contract': 'docs/specs/issue-24-linux-enforcement.md'}}}
        self.write(self.recovery, 'issue24-release-gate.json', self.rg)
        (self.recovery / 'metadata.txt').write_text('candidate_commit=' + 'c' * 40 + '\nbinary_sha256=' + 'b' * 64 + '\n')
        (self.packet / 'commit.txt').write_text('c' * 40 + '\n')
        (self.packet / 'installed-binary.sha256').write_text('b' * 64 + '  /usr/bin/manyfw\n' + 'd' * 64 + '  /tmp/issue24-linux-packet-guest.py\n')
        (self.packet / 'artifacts.sha256').write_text('b' * 64 + '  /build/manyfw\n' + 'd' * 64 + '  /repo/issue24-linux-packet-guest.py\n')
        self.results = {'contract_version': acceptance.CONTRACT, 'complete': True,
                        'expected_cases': sorted(acceptance.packet_cases()),
                        'passed_cases': sorted(acceptance.packet_cases()), 'missing_coverage': [],
                        'limitations': {
                            'packet_offload': 'unsupported and not disabled or exhaustively observed by this suite',
                            'unobservable_or_bypass_paths': 'unknown/unsupported; no control claim',
                            'other_hooks': 'OUTPUT and FORWARD unsupported',
                        },
                        'cases': {}}
        for name in acceptance.packet_cases():
            ipv6 = 'ipv6' in name or name.startswith('Icmpv6')
            self.results['cases'][name] = {'outcome': acceptance.expected_outcome(name),
                'wire_events': [{'kind': 'icmpv6-unreachable' if ipv6 else 'icmp-unreachable',
                                 'icmp_type': 1 if ipv6 else 3, 'icmp_code': 4 if ipv6 else 3}]}
            self.results['cases'][name + '-nft'] = json.dumps({'nftables': [{'rule': {'comment': 'test only'}}]})
        self.results['cases']['default-Reject'] = {
            'stage': 'apply', 'returncode': 2, 'error': 'default Reject is unsupported',
            'before': {'nftables': []}, 'after': {'nftables': []}}
        (self.packet / 'run.log').write_text('synthetic test run only\n')
        self.sync_packet()

    @staticmethod
    def write(root, name, value):
        (root / name).write_text(json.dumps(value))

    def sync_packet(self):
        self.write(self.packet, 'evidence.json', self.results)
        self.write(self.packet, 'gate.json', {'contract_version': acceptance.CONTRACT,
                   'suite': 'linux-input-packets', 'teardown': 'destroyed',
                   'packet_eligible': True, 'release_eligible': False, 'results': self.results})
        self.archive()
        self.checksums()

    def archive(self, extra=None):
        with tarfile.open(self.packet / 'guest-artifacts.tar.gz', 'w:gz') as archive:
            data = json.dumps(self.results).encode()
            member = tarfile.TarInfo('./evidence.json')
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))
            for name, data in (extra or {}).items():
                member = tarfile.TarInfo(name)
                member.size = len(data)
                archive.addfile(member, io.BytesIO(data))

    def checksums(self):
        (self.packet / 'SHA256SUMS').write_text(''.join(
            hashlib.sha256(p.read_bytes()).hexdigest() + '  ' + p.name + '\n'
            for p in sorted(self.packet.iterdir()) if p.name != 'SHA256SUMS'))

    def result(self):
        return acceptance.aggregate(self.recovery, self.packet)

    def test_iptables_composition_cases_both_require_drop(self):
        for family in ('v4', 'v6'):
            for external in ('ACCEPT', 'DROP'):
                self.assertEqual(
                    acceptance.expected_outcome(f'iptables-nft-{family}-{external}'), 'drop')

    def test_cross_family_and_protocol_composition_cases_are_required(self):
        cases = {f'composition-{family}-{protocol}-{priority}-{verdict}'
                 for family, protocol in (('v6', 'Tcp'), ('v4', 'Udp'))
                 for priority in (-400, 100) for verdict in ('accept', 'drop')}
        self.assertTrue(cases <= acceptance.packet_cases())
        self.assertEqual(len(cases), 8)
        self.assertEqual(len(acceptance.packet_cases()), 104)
        self.assertTrue(all(acceptance.expected_outcome(case) == 'drop' for case in cases))

    def test_success_receipt_never_authorizes_production(self):
        result = self.result()
        self.assertTrue(result['evidence_gates_passed'], result)
        self.assertFalse(result['generic_linux_accepted'])
        self.assertFalse(result['production_authorized'])
        self.assertEqual(result['source_runtime_review'], 'pending')
        self.assertEqual(result['compatibility_scenarios'], self.rg['compatibility_scenarios'])
        for item in result['evidence']:
            self.assertEqual(item['sha256'], hashlib.sha256(pathlib.Path(item['path']).read_bytes()).hexdigest())

    def test_default_reject_requires_pre_mutation_refusal_or_wire_proof(self):
        result = self.result()
        self.assertTrue(result['evidence_gates_passed'], result)
        self.assertFalse(result['generic_linux_accepted'])
        self.results['cases']['default-Reject']['after'] = {'nftables': [{'table': 'mutated'}]}
        self.sync_packet()
        result = self.result()
        self.assertFalse(result['generic_linux_accepted'])
        self.assertTrue(any('pre-mutation refusal' in blocker for blocker in result['blockers']))

    def test_every_bad_recovery_status_blocks_even_with_eligible_true(self):
        for name in acceptance.RECOVERY:
            for status in ('Failed', 'NotRun', 'NotApplicable'):
                with self.subTest(name=name, status=status):
                    self.rg['critical_scenarios'][name] = status
                    self.write(self.recovery, 'issue24-release-gate.json', self.rg)
                    self.assertFalse(self.result()['generic_linux_accepted'])
            self.rg['critical_scenarios'][name] = 'Passed'

    def test_missing_case_even_if_self_reported_expected_reduced(self):
        self.results['passed_cases'].pop()
        self.results['expected_cases'] = self.results['passed_cases'][:]
        self.sync_packet()
        self.assertFalse(self.result()['generic_linux_accepted'])

    def test_incomplete(self):
        self.results['complete'] = False
        self.sync_packet()
        self.assertFalse(self.result()['generic_linux_accepted'])

    def test_mismatch_and_missing_matrix(self):
        changes = [('commit.txt', 'e' * 40), ('installed-binary.sha256', 'e' * 64 + '  /usr/bin/manyfw\n'),
                   ('source-manifest.json', '{}'), ('vm-down.log', 'failed'), ('evidence.json', '{bad')]
        for name, content in changes:
            path = self.packet / name
            original = path.read_bytes()
            with self.subTest(name=name):
                path.write_text(content)
                self.checksums()
                self.assertFalse(self.result()['generic_linux_accepted'])
                path.unlink()
                self.assertFalse(self.result()['generic_linux_accepted'])
            path.write_bytes(original)
            self.checksums()

    def test_corrupt_checksum(self):
        (self.packet / 'commit.txt').write_text('c' * 40 + '\n\n')
        self.assertFalse(self.result()['generic_linux_accepted'])

    def test_producer_false_overrides_complete_case_ledger(self):
        path = self.packet / 'gate.json'
        gate = json.loads(path.read_text())
        gate['packet_eligible'] = False
        self.write(self.packet, path.name, gate)
        self.checksums()
        self.assertFalse(self.result()['generic_linux_accepted'])

    def test_recovery_and_packet_eligibility_metadata_must_be_consistent(self):
        cases = [
            (self.recovery, 'issue24-release-gate.json', 'recovery_eligible', False),
            (self.recovery, 'issue24-release-gate.json', 'release_eligible', True),
            (self.packet, 'gate.json', 'release_eligible', True),
        ]
        for root, name, key, value in cases:
            with self.subTest(name=name, key=key):
                gate_path = root/name
                original = json.loads(gate_path.read_text())
                changed = dict(original)
                changed[key] = value
                self.write(root, name, changed)
                if root == self.packet:
                    self.checksums()
                self.assertFalse(self.result()['generic_linux_accepted'])
                self.write(root, name, original)
                if root == self.packet:
                    self.checksums()
        original = json.loads((self.recovery/'issue24-release-gate.json').read_text())
        changed = dict(original)
        changed['compatibility_scenarios'] = {}
        self.write(self.recovery, 'issue24-release-gate.json', changed)
        self.assertFalse(self.result()['generic_linux_accepted'])
        self.write(self.recovery, 'issue24-release-gate.json', original)

    def test_unknown_offload_or_bypass_scope_blocks_evidence_gate(self):
        original = self.results['limitations']
        self.results['limitations'] = {}
        self.sync_packet()
        result = self.result()
        self.assertFalse(result['evidence_gates_passed'])
        self.assertTrue(any('unsupported/offload limitations' in item
                            for item in result['blockers']))
        self.results['limitations'] = original
        self.sync_packet()

    def test_archive_and_run_log_required(self):
        for name in ('guest-artifacts.tar.gz', 'run.log'):
            with self.subTest(name=name):
                path = self.packet / name
                original = path.read_bytes()
                path.unlink()
                self.assertFalse(self.result()['generic_linux_accepted'])
                self.checksums()
                self.assertFalse(self.result()['generic_linux_accepted'])
                path.write_bytes(original)
                self.checksums()

    def test_invalid_archive_even_with_fresh_checksum(self):
        (self.packet / 'guest-artifacts.tar.gz').write_bytes(b'corrupted')
        self.checksums()
        self.assertFalse(self.result()['generic_linux_accepted'])

    def test_every_checksum_entry_is_verified(self):
        path = self.packet / 'previously-unread.bin'
        path.write_bytes(b'original')
        self.checksums()
        path.write_bytes(b'corrupted')
        self.assertFalse(self.result()['generic_linux_accepted'])
        path.unlink()
        self.assertFalse(self.result()['generic_linux_accepted'])

    def test_checksum_unsafe_paths_and_symlinks(self):
        for name in ('../outside', '/absolute', 'linked', 'linked-dir/file'):
            with self.subTest(name=name):
                self.checksums()
                if name == 'linked':
                    (self.packet / name).symlink_to(self.recovery / 'vm-down.log')
                if name == 'linked-dir/file':
                    (self.packet / 'linked-dir').symlink_to(self.recovery, target_is_directory=True)
                with (self.packet / 'SHA256SUMS').open('a') as stream:
                    stream.write('a' * 64 + '  ' + name + '\n')
                self.assertFalse(self.result()['generic_linux_accepted'])
                for link in ('linked', 'linked-dir'):
                    if (self.packet / link).is_symlink():
                        (self.packet / link).unlink()

    def test_archive_unsafe_members(self):
        for name in ('../outside', '/absolute'):
            with self.subTest(name=name):
                self.archive({name: b'bad'})
                self.checksums()
                self.assertFalse(self.result()['generic_linux_accepted'])
        self.archive()
        with tarfile.open(self.packet / 'guest-artifacts.tar.gz', 'w:gz') as archive:
            member = tarfile.TarInfo('symlink')
            member.type = tarfile.SYMTYPE
            member.linkname = 'evidence.json'
            archive.addfile(member)
        self.checksums()
        self.assertFalse(self.result()['generic_linux_accepted'])

    def test_missing_wire_and_rules_evidence(self):
        for suffix in ('', '-nft'):
            name = 'Tcp-Allow' + suffix
            original = self.results['cases'].pop(name)
            self.sync_packet()
            self.assertFalse(self.result()['generic_linux_accepted'])
            self.results['cases'][name] = original

    def test_archived_ruleset_reference_must_exist(self):
        self.results['cases']['Tcp-Allow-rulesets'] = {'applied': 'missing.applied.nft.json'}
        self.sync_packet()
        self.assertFalse(self.result()['generic_linux_accepted'])

    def test_archive_evidence_inconsistent_with_results(self):
        self.results['cases']['Tcp-Allow']['outcome'] = 'drop'
        self.archive()
        self.checksums()
        self.assertFalse(self.result()['generic_linux_accepted'])

    def test_case_outcome_and_reject_wire_must_match_contract(self):
        self.results['cases']['Tcp-Allow']['outcome'] = 'drop'
        self.sync_packet()
        self.assertFalse(self.result()['generic_linux_accepted'])
        self.results['cases']['Tcp-Allow']['outcome'] = 'allow'
        self.results['cases']['Tcp-Reject']['wire_events'] = []
        self.sync_packet()
        self.assertFalse(self.result()['generic_linux_accepted'])

    def test_production_inventory_covers_non_rust_tracked_and_untracked_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            acceptance.subprocess.run(['git', 'init', '-q', directory], check=True)
            for name in ('Cargo.toml', 'Cargo.lock', 'crates/demo/build.rs',
                         'crates/demo/data.txt', '.cargo/config.toml', 'docs/example.md'):
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('test only')
            acceptance.subprocess.run(['git', '-C', directory, 'add', 'Cargo.toml'], check=True)
            # Bypass only this test's inventory mock; the function itself is tested.
            actual = REAL_INVENTORY(root)
            self.assertEqual(actual, {'Cargo.toml', 'Cargo.lock', 'crates/demo/build.rs',
                                      'crates/demo/data.txt', '.cargo/config.toml'})

    def test_reject_wrong_code_fails_for_each_family(self):
        for name, wrong_code, correct_code in (('Tcp-Reject', 4, 3),
                                                ('Tcp-ipv6-Reject', 3, 4)):
            with self.subTest(name=name):
                event = self.results['cases'][name]['wire_events'][0]
                event['icmp_code'] = wrong_code
                self.sync_packet()
                result = self.result()
                self.assertFalse(result['generic_linux_accepted'])
                self.assertIn('missing reject wire proof: ' + name, result['blockers'])
                event['icmp_code'] = correct_code

    def test_producer_reject_json_accepted_for_both_families(self):
        # Synthetic producer-shaped JSON, checked against the producer's actual
        # pure verifier as well as the aggregate; no guest/runtime claim.
        source = pathlib.Path(__file__).with_name('issue24-linux-packet-guest.py').read_text()
        method = next(n for n in ast.walk(ast.parse(source)) if isinstance(n, ast.FunctionDef)
                      and n.name == 'verify_reject')
        method.decorator_list = []
        namespace = {}
        exec(compile(ast.fix_missing_locations(ast.Module(body=[method], type_ignores=[])),
                     '<producer reject verifier>', 'exec'), namespace)
        for name, ipv6, payload in (
            ('Tcp-Reject', False,
             '{"outcome":"reject","wire_events":[{"kind":"icmp-unreachable","icmp_type":3,"icmp_code":3}]}'),
            ('Tcp-ipv6-Reject', True,
             '{"outcome":"reject","wire_events":[{"kind":"icmpv6-unreachable","icmp_type":1,"icmp_code":4}]}'),
        ):
            value = json.loads(payload)
            namespace['verify_reject'](value, ipv6)
            self.results['cases'][name] = value
        self.sync_packet()
        result = self.result()
        self.assertTrue(result['evidence_gates_passed'], result)
        self.assertFalse(result['generic_linux_accepted'])

    def test_identical_truncated_production_manifests(self):
        for missing in ('Cargo.toml', 'crates/demo/src/main.rs', 'crates/demo/build.rs',
                        'crates/demo/policy.template'):
            with self.subTest(missing=missing):
                for root in (self.recovery, self.packet):
                    self.write(root, 'source-manifest.json', {'contract_version': acceptance.CONTRACT,
                               'sources': [{'path': p, 'sha256': 'a' * 64}
                                           for p in self.inventory if p != missing]})
                self.checksums()
                self.assertFalse(self.result()['generic_linux_accepted'])

    def test_required_packet_ledger_matches_producer_without_running_it(self):
        source = pathlib.Path(__file__).with_name('issue24-linux-packet-guest.py').read_text()
        tree = ast.parse(source)
        method = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)
                      and n.name == 'expected_cases')
        method.decorator_list = []
        namespace = {}
        exec(compile(ast.fix_missing_locations(ast.Module(body=[method], type_ignores=[])),
                     '<expected packet cases>', 'exec'), namespace)
        self.assertEqual(acceptance.packet_cases(), namespace['expected_cases']())


if __name__ == '__main__':
    unittest.main()
