"""Independent tests for identity matching and missing-data semantics."""
import unittest
import csv
import json
import tempfile
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from parse import Identities, compare, normalise, osv_called, add_ranks, comparison_rows, run, write_csv, REMEDIATION_FIELDS, execution_evidence, publish

class NormalisationTests(unittest.TestCase):
    def test_should_distinguish_sbom_components_from_unique_maven_coordinates(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            raw = root / 'raw/p'
            raw.mkdir(parents=True)
            (raw / 'c3.json').write_text(json.dumps({'scannedArtifacts': ['g:a:1'], 'findings': []}))
            (raw / 'bom.json').write_text(json.dumps({'components': [
                {'group': 'g', 'name': 'a', 'version': '1', 'purl': 'pkg:maven/g/a@1'},
                {'group': 'g', 'name': 'a', 'version': '1', 'purl': 'pkg:maven/g/a@1?classifier=data'}]}))
            result = run(root, root / 'normalised', configs=['c3'])
        control = result['projects']['p']['cyclonedx_control']
        self.assertEqual((2, 1), (control['components'], control['inventory_entries']))

    def test_should_normalise_potentially_addressed_risk_from_current_reports(self):
        document = {'scannedArtifacts': ['g:a:1'], 'findings': [
            {'artifact': 'g:a:1', 'vulnerabilities': [], 'remediation': {'potentialRiskAddressed': 0.4}}]}
        _, _, remediation = normalise('project', 'c3', document, Identities(), 'c3.json')
        self.assertEqual(0.4, remediation[0]['potential_risk_addressed'])

    def test_should_read_legacy_risk_reduction_as_potentially_addressed_risk(self):
        document = {'scannedArtifacts': ['g:a:1'], 'findings': [
            {'artifact': 'g:a:1', 'vulnerabilities': [], 'remediation': {'riskReduction': 0.4}}]}
        _, _, remediation = normalise('project', 'c3', document, Identities(), 'c3.json')
        self.assertEqual(0.4, remediation[0]['potential_risk_addressed'])

    def test_should_preserve_original_and_contextual_compatibility_separately(self):
        document = {'scannedArtifacts': ['g:a:1'], 'findings': [
            {'artifact': 'g:a:1', 'vulnerabilities': [],
             'compatibility': {'status': 'BINARY_INCOMPATIBLE', 'contextualStatus': 'COMPATIBLE'}}]}
        _, _, remediation = normalise('project', 'c3', document, Identities(), 'c3.json')
        self.assertEqual(('BINARY_INCOMPATIBLE', 'COMPATIBLE'),
                         (remediation[0]['compatibility'], remediation[0]['contextual_compatibility']))

    def test_should_export_potential_risk_and_both_compatibility_states_to_csv(self):
        document = {'scannedArtifacts': ['g:a:1'], 'findings': [
            {'artifact': 'g:a:1', 'vulnerabilities': [],
             'remediation': {'potentialRiskAddressed': 0.4},
             'compatibility': {'status': 'BINARY_INCOMPATIBLE', 'contextualStatus': 'COMPATIBLE'}}]}
        _, _, remediation = normalise('project', 'c3', document, Identities(), 'c3.json')
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / 'remediation.csv'
            write_csv(target, remediation, REMEDIATION_FIELDS)
            with target.open() as stream:
                row = next(csv.DictReader(stream))
        self.assertEqual(('0.4', 'BINARY_INCOMPATIBLE', 'COMPATIBLE'),
                         (row['potential_risk_addressed'], row['compatibility'], row['contextual_compatibility']))

    def test_should_exclude_normal_unreachable_results_from_diagnostics(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            raw = root / 'raw/p'
            raw.mkdir(parents=True)
            (raw / 'c3.log').write_text('[INFO] dependency is UNREACHABLE\n[WARNING] graph unavailable\nfailed to download package\n$ mvn -Dcontextframework.callGraphTimeoutSeconds=600\n')
            warnings, _, _ = execution_evidence(root)
        self.assertEqual([2, 3], [r['line'] for r in warnings])

    def test_should_separate_project_summaries_from_execution_provenance(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            raw = root / 'raw/p'
            raw.mkdir(parents=True)
            (raw / 'c3.json').write_text(json.dumps({'scannedArtifacts': ['g:a:1'], 'findings': []}))
            result = run(root, root / 'normalised', configs=['c3'])
            detail = json.loads((root / 'summaries/p.json').read_text())
            self.assertNotIn('executions', result)
            self.assertNotIn('provenance', result)
            self.assertNotIn('warnings', result)
            self.assertIn('c3', detail)
            self.assertFalse((root / 'integrity.json').exists())
            self.assertFalse((root / 'diagnostics/warnings.csv').exists())
            self.assertFalse((root / 'normalised/summary.json').exists())

    def test_should_export_private_evidence_only_when_explicitly_requested(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            raw = root / 'raw/p'
            raw.mkdir(parents=True)
            (raw / 'c3.json').write_text(json.dumps({'scannedArtifacts': ['g:a:1'], 'findings': []}))
            run(root, root / 'normalised', configs=['c3'], private_evidence=True)
            self.assertTrue((root / 'integrity.json').exists())
            self.assertTrue((root / 'diagnostics/warnings.csv').exists())

    def test_should_publish_without_local_paths_or_execution_dates(self):
        with tempfile.TemporaryDirectory() as tmp:
            data, out = Path(tmp) / 'private', Path(tmp) / 'public'
            raw = data / 'raw/p'
            raw.mkdir(parents=True)
            document = {'results': [{'source': {'path': '/Users/person/run/target/app.jar'},
                                    'packages': []}]}
            (raw / 'c1.json').write_text(json.dumps(document))
            (raw / 'bom.json').write_text(json.dumps({'components': [], 'metadata': {'timestamp': '2000-01-01T10:00:00Z'}}))
            (data / 'projects.csv').write_text('project_id,repo_url\np,https://example.org/p.git\n')
            command = ['/private/tmp/osv', 'scan', '--output-file', '/Users/person/run/raw/p/c1.json', 'target/app.jar']
            with (data / 'runs.csv').open('w', newline='') as stream:
                fields = ['project_id', 'commit', 'step', 'command', 'duration_s', 'exit_code', 'status', 'raw_path', 'started_at_utc']
                writer = csv.DictWriter(stream, fieldnames=fields)
                writer.writeheader()
                writer.writerow(dict(project_id='p', commit='fixed', step='c1', command=json.dumps(command),
                                     duration_s=1, exit_code=0, status='OK', raw_path='raw/p/c1.json', started_at_utc='2000-01-01'))
            publish(data, out)
            self.assertEqual('/Users/person/run/target/app.jar', json.loads((raw / 'c1.json').read_text())['results'][0]['source']['path'])
            self.assertEqual('target/app.jar', json.loads((out / 'raw/p/c1.json').read_text())['results'][0]['source']['path'])
            self.assertNotIn('timestamp', json.loads((out / 'raw/p/bom.json').read_text())['metadata'])
            self.assertNotIn('/Users/', (out / 'runs.csv').read_text())
            self.assertNotIn('started_at_utc', (out / 'runs.csv').read_text())

    def test_should_refuse_to_overwrite_a_published_collection(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'existing').write_text('preserve')
            with self.assertRaises(ValueError):
                publish(root / 'input', root)

    def test_should_preserve_published_diagnostics_when_logs_are_not_distributed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'raw/p').mkdir(parents=True)
            (root / 'diagnostics').mkdir()
            (root / 'diagnostics/warnings.csv').write_text('project_id,step,source_path,line,severity,message\np,c2,raw/p/c2.log,7,ERROR,download failed\n')
            (root / 'integrity.json').write_text(json.dumps({'inputs': [{'path': 'raw/p/c2.log', 'sha256': 'recorded'}]}))
            warnings, hashes, _ = execution_evidence(root)
        self.assertEqual('download failed', warnings[0]['message'])
        self.assertEqual([{'path': 'raw/p/c2.log', 'sha256': 'recorded'}], hashes)

    def test_should_preserve_null_epss_as_missing(self):
        identities = Identities()
        identities.add(['CVE-2026-1234'])
        document = {'scannedArtifacts': ['g:a:1'], 'findings': [
            {'artifact': 'g:a:1', 'vulnerabilities': [{'id': 'CVE-2026-1234', 'epss': None}]}]}
        findings, _, _ = normalise('project', 'c3', document, identities, 'c3.json')
        self.assertIsNone(next(iter(findings.values()))['epss'])

    def test_should_join_transitive_aliases_across_reports(self):
        identities = Identities()
        identities.add(['GHSA-aaaa-bbbb-cccc', 'CVE-2026-1234'])
        identities.add(['OSV-123', 'ghsa-aaaa-bbbb-cccc'])
        self.assertEqual('CVE-2026-1234', identities.canonical('OSV-123'))

    def test_should_preserve_missing_called_as_unknown(self):
        identities = Identities()
        identities.add(['CVE-2026-1234'])
        self.assertIsNone(osv_called({'groups': []}, {'id': 'CVE-2026-1234'}, identities))

    def test_should_preserve_explicit_false_called(self):
        identities = Identities()
        identities.add(['CVE-2026-1234', 'GHSA-aaaa-bbbb-cccc'])
        package = {'groups': [{'experimental_analysis': {'GHSA-aaaa-bbbb-cccc': {'called': False}}}]}
        self.assertIs(False, osv_called(package, {'id': 'CVE-2026-1234'}, identities))

    def test_should_count_alias_records_as_one_occurrence(self):
        identities = Identities()
        identities.add(['CVE-2026-1234', 'GHSA-aaaa-bbbb-cccc'])
        document = {'results': [{'packages': [{'package': {'name': 'g:a', 'version': '1'},
                    'vulnerabilities': [{'id': 'CVE-2026-1234'}, {'id': 'GHSA-aaaa-bbbb-cccc'}]}]}]}
        findings, _, _ = normalise('project', 'c1', document, identities, 'c1.json')
        self.assertEqual(1, len(findings))

    def test_should_distinguish_inventory_presence_from_vulnerability_presence(self):
        key = ('g:a', '1', 'CVE-2026-1234')
        right = {key: {'osv_called': None, 'crbf_reachability': 'UNKNOWN'}}
        rows = compare({}, right, {key[:2]}, {key[:2]}, 'project', 'c2_c3')
        self.assertEqual(('RIGHT_ONLY', True), (rows[0]['presence'], rows[0]['dependency_in_left_inventory']))

class InterpretationTests(unittest.TestCase):
    def test_should_ignore_called_values_from_sbom(self):
        identities = Identities()
        identities.add(['CVE-2026-1234'])
        document = {'results': [{'packages': [{'package': {'name': 'g:a', 'version': '1'},
            'groups': [{'ids': ['CVE-2026-1234'], 'experimental_analysis': {'CVE-2026-1234': {'called': True}}}],
            'vulnerabilities': [{'id': 'CVE-2026-1234'}]}]}]}
        findings, _, _ = normalise('p', 'sbom', document, identities, 'osv-sbom.json')
        self.assertIsNone(next(iter(findings.values()))['osv_called'])

    def test_should_not_rank_unknown_cvss_zero_as_a_known_score(self):
        identities = Identities()
        identities.add(['CVE-2026-1234'])
        document = {'scannedArtifacts': ['g:a:1'], 'findings': [{'artifact': 'g:a:1',
            'vulnerabilities': [{'id': 'CVE-2026-1234', 'cvss': {'score': 0.0, 'vector': 'UNKNOWN'}}]}]}
        findings, _, _ = normalise('p', 'c3', document, identities, 'c3.json')
        self.assertIsNone(next(iter(findings.values()))['cvss_rank'])

    def test_should_give_equal_scores_equal_priority(self):
        rows = [{'cvss_score': score, 'contextual_risk': None} for score in [9, 9, 5]]
        add_ranks(rows)
        self.assertEqual([1, 1, 3], [r['cvss_rank'] for r in rows])

    def test_should_leave_missing_cvss_unranked(self):
        rows = [{'cvss_score': None, 'contextual_risk': None}]
        add_ranks(rows)
        self.assertIsNone(rows[0]['cvss_rank'])

    def test_should_use_only_common_occurrences_for_comparable_ranks(self):
        a = ('g:a', '1', 'CVE-2026-1')
        b = ('g:b', '1', 'CVE-2026-2')
        def row(score):
            return {'osv_called': None, 'crbf_reachability': None, 'cvss_score': score, 'contextual_risk': None}
        left = {a: row(5), b: row(10)}
        right = {a: row(5)}
        rows = comparison_rows('p', 'c1_c2', left, right, {a[:2], b[:2]}, {a[:2]})
        common = next(r for r in rows if r['presence'] == 'BOTH')
        self.assertEqual(1, common['left_cvss_rank_shared'])

    def test_should_exclude_missing_cvss_from_both_compared_rank_populations(self):
        a, b = ('g:a', '1', 'CVE-1'), ('g:b', '1', 'CVE-2')
        left = {a: {'osv_called': None, 'cvss_score': 5},
                b: {'osv_called': None, 'cvss_score': None}}
        right = {a: {'osv_called': None, 'crbf_reachability': 'UNKNOWN', 'cvss_score': 5, 'contextual_risk': 0.1},
                 b: {'osv_called': None, 'crbf_reachability': 'UNKNOWN', 'cvss_score': None, 'contextual_risk': 0.9}}
        rows = comparison_rows('p', 'sbom_c3', left, right, {a[:2], b[:2]}, {a[:2], b[:2]})
        self.assertEqual([1, None], [r['right_contextual_rank_shared'] for r in rows])

    def test_should_exclude_missing_context_from_both_compared_rank_populations(self):
        a, b = ('g:a', '1', 'CVE-1'), ('g:b', '1', 'CVE-2')
        left = {a: {'osv_called': None, 'cvss_score': 5}, b: {'osv_called': None, 'cvss_score': 9}}
        right = {a: {'osv_called': None, 'crbf_reachability': 'UNKNOWN', 'cvss_score': 5, 'contextual_risk': 0.1},
                 b: {'osv_called': None, 'crbf_reachability': 'UNKNOWN', 'cvss_score': 9, 'contextual_risk': None}}
        rows = comparison_rows('p', 'sbom_c3', left, right, {a[:2], b[:2]}, {a[:2], b[:2]})
        self.assertEqual([1, None], [r['left_cvss_rank_shared'] for r in rows])

    def test_should_refuse_normalised_output_inside_raw_inputs(self):
        with self.assertRaises(ValueError):
            run(Path('/tmp/audit-data'), Path('/tmp/audit-data/raw/output'))

    def test_should_preserve_contextual_zero_as_available(self):
        identities = Identities()
        identities.add(['CVE-2026-1234'])
        document = {'scannedArtifacts': ['g:a:1'], 'findings': [{'artifact': 'g:a:1',
            'vulnerabilities': [{'id': 'CVE-2026-1234', 'contextualRisk': {'value': 0, 'reachabilityStatus': 'UNKNOWN'}}]}]}
        findings, _, _ = normalise('p', 'c3', document, identities, 'c3.json')
        self.assertEqual(1, next(iter(findings.values()))['contextual_rank'])


if __name__ == '__main__':
    unittest.main()
