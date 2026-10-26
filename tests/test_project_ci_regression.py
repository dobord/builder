"""Release-scoped owner permissions never waive non-timing evidence failures."""
import copy
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from secure_release import project_ci_regression as regression
from secure_release import crypto, project_ci as ci, project_ci_runner as runner
from tests.test_project_ci_baseline import fixture


COMMAND = ('python3 scripts/compare-benchmarks.py out/performance/baseline/queue.json '
           'out/performance/current/queue.json --max-regression-percent 10 '
           '--output out/performance/queue-comparison.json')


def approval_fixture():
    value, policy = fixture()
    entry = {"candidate_sha": value["source_sha"], "baseline_sha": value["baseline_sha"],
             "baseline_tag": value["baseline_tag"], "release_tag": "v1.2.0",
             "approved_by": value["operator_id"], "reason": "Owner accepts slower timing for this release"}
    policy["release_regression_approvals"] = [entry]
    return value, policy, entry


def report_fixture():
    row = {"name": "Synthetic/Timing", "timing_status": "regressed", "inconclusive_reasons": [],
           "raw_sample_count": 10, "sample_count": 10, "retained_indices": list(range(10)),
           "baseline_samples": [100.0] * 10, "candidate_samples": [125.0] * 10,
           "baseline_cv_percent": 0.0, "candidate_cv_percent": 0.0,
           "budget_margin_ci": [15.0, 15.0], "change_percent": 25.0}
    return {"schema": 3, "aggregation": "iterative_sigma_clipped_paired_mean", "confidence_level": 0.95,
            "repetitions": 10, "max_regression_percent": 10, "max_cv_percent": 20,
            "metric": "real_time", "missing_benchmarks": [], "unexpected_benchmarks": [],
            "comparisons": [row], "regressions": [copy.deepcopy(row)], "inconclusive": [], "status": "regressed"}


def inconclusive_fixture():
    report = report_fixture()
    row = report['comparisons'][0]
    row.update(timing_status='inconclusive', inconclusive_reasons=['excessive_cv', 'budget_interval_overlap'],
               baseline_cv_percent=70.0, candidate_cv_percent=45.0, budget_margin_ci=[-10.0, 30.0])
    report.update(status='inconclusive', regressions=[], inconclusive=[copy.deepcopy(row)])
    return report


class RegressionApprovalTests(unittest.TestCase):
    def setUp(self):
        context = patch.object(regression.ci, 'builder_context', return_value={'synthetic': 'run-context'})
        context.start()
        self.addCleanup(context.stop)

    def test_exact_release_policy_and_default_denial(self):
        value, policy, entry = approval_fixture()
        self.assertEqual(regression.approval(value, policy), entry)
        self.assertIsNone(regression.approval(value, dict(policy, release_regression_approvals=[])))
        for change in ({"source_sha": "0" * 40}, {"baseline_sha": "0" * 40}, {"baseline_tag": "v0.1.0"},
                       {"suite": "performance"}, {"schema": 1}, {"source_id": 7}, {"operator_id": 7}):
            with self.subTest(change=change):
                self.assertIsNone(regression.approval(dict(value, **change), policy))

    def test_uncertainty_requires_explicit_boolean_policy_and_bound_receipt(self):
        value, policy, entry = approval_fixture()
        approved = dict(entry, allow_timing_inconclusive=True)
        policy['release_regression_approvals'] = [approved]
        self.assertEqual(regression.approval(value, policy), approved)
        record = regression.receipt(value, policy)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'receipt.json'
            path.write_bytes(crypto.canonical(record))
            self.assertTrue(regression.read_receipt(path, value)['allow_timing_inconclusive'])
        for flag in (1, 'true', None, [], {}):
            with self.subTest(flag=flag), self.assertRaises(ValueError):
                regression.approval(value, dict(policy, release_regression_approvals=[
                    dict(entry, allow_timing_inconclusive=flag)]))

    def test_only_explicitly_approved_timing_uncertainty_can_waive_exit_two(self):
        value, _, entry = approval_fixture()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / 'out/performance/queue-comparison.json'
            path.parent.mkdir(parents=True)
            audit = root / 'audit'
            audit.mkdir()
            path.write_bytes(crypto.canonical(inconclusive_fixture()))
            for approval in (None, entry, dict(entry, allow_timing_inconclusive=False)):
                self.assertFalse(regression.waive(root, COMMAND, 2, approval, value, audit))
            approved = dict(entry, allow_timing_inconclusive=True)
            self.assertFalse(regression.waive(root, COMMAND, 1, approved, value, audit))
            before = path.read_bytes()
            self.assertTrue(regression.waive(root, COMMAND, 2, approved, value, audit))
            self.assertEqual(path.read_bytes(), before)
            record = json.loads((audit / path.name).read_text())
            self.assertEqual(record['original_exit_code'], 2)
            self.assertEqual(record['inconclusive'], inconclusive_fixture()['inconclusive'])

    def test_mixed_timing_findings_are_audited_but_variant_allocation_failures_remain_fatal(self):
        value, _, entry = approval_fixture()
        command = ('python3 scripts/compare-variant-benchmarks.py out/performance/baseline/variant.json '
                   'out/performance/current/variant.json --max-regression-percent 10 --max-cv-percent 20 '
                   '--output out/performance/variant-comparison.json')
        approved = dict(entry, allow_timing_inconclusive=True)
        report = inconclusive_fixture()
        regressed = report_fixture()['comparisons'][0]
        regressed['name'] = 'Synthetic/Regressed'
        report['comparisons'].append(regressed)
        report.update(status='regressed', regressions=[dict(regressed, metric='real_time')])
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / 'out/performance/variant-comparison.json'
            path.parent.mkdir(parents=True)
            audit = root / 'audit'
            audit.mkdir()
            path.write_bytes(crypto.canonical(report))
            self.assertFalse(regression.waive(root, command, 1, entry, value, audit))
            report['regressions'].append({'name': 'Synthetic/Leak', 'metric': 'cpp_live_bytes_end'})
            path.write_bytes(crypto.canonical(report))
            self.assertFalse(regression.waive(root, command, 1, approved, value, audit))
            report['regressions'].pop()
            path.write_bytes(crypto.canonical(report))
            self.assertTrue(regression.waive(root, command, 1, approved, value, audit))
            record = json.loads((audit / path.name).read_text())
            self.assertEqual(record['regressions'], report['regressions'])
            self.assertEqual(record['inconclusive'], report['inconclusive'])

    def test_uncertainty_approval_never_waives_missing_pairs_invalid_data_or_non_timing_contracts(self):
        value, _, entry = approval_fixture()
        approved = dict(entry, allow_timing_inconclusive=True)
        reports = []
        for change in ({'sample_count': 4}, {'raw_sample_count': 9},
                       {'inconclusive_reasons': ['insufficient_retained_pairs']},
                       {'inconclusive_reasons': ['unknown_future_reason']},
                       {'baseline_samples': [100.0] * 9}, {'candidate_cv_percent': -1},
                       {'candidate_samples': [0.0] * 10},
                       {'candidate_cv_percent': float('inf')}):
            report = inconclusive_fixture()
            report['comparisons'][0].update(change)
            report['inconclusive'] = copy.deepcopy(report['comparisons'])
            reports.append(report)
        for change in ({'missing_benchmarks': ['missing']}, {'unexpected_benchmarks': ['extra']},
                       {'regressions': [{'name': 'Synthetic/Timing', 'metric': 'cpp_live_bytes_end'}]},
                       {'comparisons': []}, {'inconclusive': []}, {'repetitions': 9}):
            reports.append(dict(inconclusive_fixture(), **change))
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / 'out/performance/queue-comparison.json'
            path.parent.mkdir(parents=True)
            audit = root / 'audit'
            audit.mkdir()
            for report in reports:
                with self.subTest(report=report):
                    path.write_text(json.dumps(report))
                    self.assertFalse(regression.waive(root, COMMAND, 2, approved, value, audit))
            self.assertEqual(list(audit.iterdir()), [])

    def test_malformed_duplicate_or_unbounded_policy_fails_closed(self):
        value, policy, entry = approval_fixture()
        for change in ({"approved_by": True}, {"approved_by": 7}, {"release_tag": "latest"},
                       {"candidate_sha": "*"}, {"baseline_sha": "*"}, {"reason": ""},
                       {"reason": "bad\nreason"}, {"reason": "x" * 1025}, {"extra": True}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                regression.approval(value, dict(policy, release_regression_approvals=[dict(entry, **change)]))
        for entries in (None, [entry] * 2, [entry] * 9):
            with self.subTest(entries=entries), self.assertRaises(ValueError):
                regression.approval(value, dict(policy, release_regression_approvals=entries))

    def test_only_exact_comparator_commands_are_eligible(self):
        self.assertIsNotNone(regression.comparison(COMMAND))
        for command in (COMMAND + '; false', COMMAND + '\nfalse', COMMAND.replace('10', '99'),
                        COMMAND.replace('queue-comparison', '../escape'), 'ctest --timeout 20'):
            with self.subTest(command=command):
                self.assertIsNone(regression.comparison(command))

    def test_receipt_binds_request_run_source_candidate_baseline_and_release(self):
        value, policy, entry = approval_fixture()
        record = regression.receipt(value, policy)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'receipt.json'
            self.assertIsNone(regression.read_receipt(path, value))
            path.write_bytes(crypto.canonical(record))
            self.assertEqual(regression.read_receipt(path, value), entry)
            for change in ({'request_id': 'different'}, {'source_id': 7}, {'context': {'different': 'run'}},
                           {'approval': dict(entry, candidate_sha='0' * 40)},
                           {'approval': dict(entry, baseline_sha='0' * 40)}, {'extra': True}):
                with self.subTest(change=change), self.assertRaises(ValueError):
                    path.write_bytes(crypto.canonical(dict(record, **change)))
                    regression.read_receipt(path, value)

    def test_runner_waives_comparator_but_preserves_other_failures_and_stale_report_denial(self):
        value, policy, _ = approval_fixture()
        scenarios = [(failure, uncertainty) for failure in ('none', 'build', 'later', 'inconclusive', 'stale')
                     for uncertainty in (False, True)]
        for failure, uncertainty in scenarios:
            with self.subTest(failure=failure, uncertainty=uncertainty), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                source = root / 'workspace/private-source'
                source.mkdir(parents=True)
                work = root / 'runner/project-ci'
                work.mkdir(parents=True)
                (work / 'request.json').write_bytes(crypto.canonical(value))
                policy['release_regression_approvals'][0]['allow_timing_inconclusive'] = uncertainty
                (work / 'regression-approval.json').write_bytes(crypto.canonical(regression.receipt(value, policy)))
                lane = {'id': 'synthetic', 'profile': 'performance', 'matrix': {}, 'runner': 'ubuntu-24.04',
                        'job': {'steps': [{'run': 'build'}, {'run': COMMAND, 'if': 'always()'},
                                          {'run': 'later', 'if': 'always()'}]}}
                report = source / 'out/performance/queue-comparison.json'
                report.parent.mkdir(parents=True)
                if failure == 'stale':
                    report.write_bytes(crypto.canonical(report_fixture()))
                def execute(command, cwd, env, log, timeout):
                    self.assertNotIn('GH_TOKEN', env)
                    body = Path(command[-1]).read_text().strip()
                    if body == COMMAND:
                        data = inconclusive_fixture() if uncertainty else report_fixture()
                        if failure == 'inconclusive':
                            data['inconclusive'] = [{'name': 'noisy'}]
                        report.write_bytes(crypto.canonical(data))
                        return 2 if uncertainty else 1
                    return 7 if body == failure else 0
                environment = {'GITHUB_WORKSPACE': str(root / 'workspace'), 'RUNNER_TEMP': str(root / 'runner'),
                               'CI_LANE': 'synthetic', 'GITHUB_RUN_ID': '1', 'GITHUB_RUN_NUMBER': '1',
                               'GITHUB_RUN_ATTEMPT': '1', 'RUNNER_OS': 'Linux', 'GH_TOKEN': 'SYNTHETIC'}
                with patch.dict(os.environ, environment), patch.object(ci, 'recipes', return_value=[lane]), \
                        patch.object(ci, 'quiet', side_effect=execute):
                    if failure == 'none':
                        runner.run()
                    else:
                        with self.assertRaises(ValueError):
                            runner.run()

    def test_conclusive_timing_failure_keeps_original_report_and_private_audit(self):
        value, _, entry = approval_fixture()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / 'out/performance/queue-comparison.json'
            path.parent.mkdir(parents=True)
            path.write_text(json.dumps(report_fixture()))
            before = path.read_bytes()
            audit = root / 'audit'
            audit.mkdir()
            self.assertTrue(regression.waive(root, COMMAND, 1, entry, value, audit))
            self.assertEqual(path.read_bytes(), before)
            record = json.loads((audit / 'queue-comparison.json').read_text())
            self.assertEqual(record['approval'], entry)
            self.assertEqual(record['original_exit_code'], 1)
            self.assertEqual(record['regressions'][0]['change_percent'], 25.0)
            for result in (0, 2, 124, -9):
                self.assertFalse(regression.waive(root, COMMAND, result, entry, value, audit))
            self.assertFalse(regression.waive(root, COMMAND, 1, None, value, audit))

    def test_missing_inconclusive_bad_inventory_and_allocation_failures_are_not_waived(self):
        value, _, entry = approval_fixture()
        reports = []
        for change in ({"inconclusive": [{"name": "noisy"}]}, {"missing_benchmarks": ["missing"]},
                       {"unexpected_benchmarks": ["extra"]}, {"comparisons": []}, {"seeded_baseline": True},
                       {"status": "inconclusive"}, {"schema": 2}):
            reports.append(dict(report_fixture(), **change))
        for change in ({"timing_status": "inconclusive"}, {"sample_count": 4},
                       {"baseline_cv_percent": 21}, {"candidate_cv_percent": float('nan')},
                       {"inconclusive_reasons": ["budget_interval_overlap"]},
                       {"budget_margin_ci": [-1, 2]}):
            report = report_fixture()
            report['comparisons'][0].update(change)
            reports.append(report)
        report = report_fixture()
        report['regressions'].append({"name": "Synthetic/Timing", "metric": "cpp_live_bytes_end"})
        reports.append(report)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / 'out/performance/queue-comparison.json'
            path.parent.mkdir(parents=True)
            audit = root / 'audit'
            audit.mkdir()
            self.assertFalse(regression.waive(root, COMMAND, 1, entry, value, audit))
            for report in reports:
                with self.subTest(report=report):
                    path.write_text(json.dumps(report))
                    self.assertFalse(regression.waive(root, COMMAND, 1, entry, value, audit))
            self.assertEqual(list(audit.iterdir()), [])


if __name__ == '__main__':
    unittest.main()
