"""Deterministic checks of experimental configuration and result validation."""
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import hashlib

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from run import build_commands, step_status, validate_report, Recorder, source_repository, software_snapshot


class CollectionTests(unittest.TestCase):
    def test_should_resolve_local_clone_path_before_changing_working_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / 'subject'
            source.mkdir()
            relative = Path(os.path.relpath(tmp, Path.cwd()))
            self.assertEqual(str(source.resolve()), source_repository({'project_id': 'subject'}, relative))

    def setUp(self):
        self.project = {'project_id': 'subject', 'commit_hash': 'a' * 40,
                        'uberjar_path': 'target/application.jar', 'plugin_goal': 'org.crbf:plugin:analyse'}

    def test_should_preserve_source_patch_bytes_for_reproduction(self):
        source_patch = 'diff --git a/pom.xml b/pom.xml\n context with trailing space \n'
        with patch('run.subprocess.check_output', side_effect=['', source_patch]):
            snapshot = software_snapshot(Path('/tmp/repository'))
        self.assertEqual(source_patch, snapshot['crbf_source_patch'])
        self.assertEqual(hashlib.sha256(source_patch.encode()).hexdigest(), snapshot['crbf_source_patch_sha256'])

    def test_should_reject_untracked_source_not_included_in_the_snapshot(self):
        with patch('run.subprocess.check_output', return_value='risk-based-framework-core/src/New.java\n'):
            with self.assertRaisesRegex(ValueError, 'Untracked CRBF source'):
                software_snapshot(Path('/tmp/repository'))

    def test_should_apply_fixed_effort_budget_to_crbf(self):
        command = build_commands(self.project, Path('/tmp/raw'), '/tmp/osv')['c3']
        self.assertIn('-Dcontextframework.effortBudget=30', command)

    def test_should_reject_a_crbf_report_with_a_different_budget(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'c3.json'
            path.write_text('{"findings": [], "scannedArtifacts": [], "availableEffortBudget": 10}')
            self.assertIn('budget must be 30', validate_report(path, 'c3'))

    def test_should_accept_a_crbf_report_with_the_fixed_budget(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'c3.json'
            path.write_text('{"findings": [], "scannedArtifacts": [], "availableEffortBudget": 30}')
            self.assertEqual('', validate_report(path, 'c3'))

    def test_should_differ_only_by_call_analysis_after_output_paths_are_excluded(self):
        commands = build_commands(self.project, Path('/tmp/raw'), '/tmp/osv')
        c1 = commands['c1'][:]
        c2 = commands['c2'][:]
        for cmd in (c1, c2):
            i = cmd.index('--output-file')
            del cmd[i:i + 2]
        c2.remove('--call-analysis=jar')
        self.assertEqual(c1, c2)

    def test_should_keep_uncalled_vulnerabilities_in_both_configurations(self):
        commands = build_commands(self.project, Path('/tmp/raw'), '/tmp/osv')
        self.assertTrue(all('--all-vulns' in commands[c] for c in ('c1', 'c2')))

    def test_should_exclude_test_dependencies_from_cyclonedx_control(self):
        command = build_commands(self.project, Path('/tmp/raw'), '/tmp/osv')['cyclonedx']
        self.assertIn('-DincludeTestScope=false', command)

    def test_should_not_activate_java_analysis_for_sbom_control(self):
        command = build_commands(self.project, Path('/tmp/raw'), '/tmp/osv')['sbom']
        self.assertNotIn('--call-analysis=jar', command)

    def test_should_accept_osv_exit_one_when_a_valid_report_exists(self):
        self.assertEqual('OK', step_status('c2', 1))

    def test_should_reject_osv_exit_one_with_a_missing_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            error = validate_report(Path(tmp) / 'missing.json', 'c2')
            self.assertEqual('ERROR', step_status('c2', 1, error))

    def test_should_reject_a_malformed_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'report.json'
            path.write_text('{broken')
            self.assertTrue(validate_report(path, 'c3'))

    def test_should_refuse_to_overwrite_raw_logs(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            raw = out / 'raw/subject'
            raw.mkdir(parents=True)
            (raw / 'c1.log').write_text('Original evidence')
            with self.assertRaises(FileExistsError):
                Recorder(out, {}).execute(self.project, 'c1', ['unused-command'], out)


if __name__ == '__main__':
    unittest.main()
