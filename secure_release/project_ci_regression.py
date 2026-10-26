"""Trusted, exact-release timing exceptions; never a failed-lane override.

Only prepare reads independently provisioned policy. Its approval receipt travels
inside the existing run/attempt-authenticated encrypted input, never recipe env.
Reports and their original decisions stay unchanged; private audit records name
the owner approval, request and measured deltas used for the narrow exception.
"""
import math
import os
from pathlib import Path
import re
import stat

from . import crypto, project_ci as ci


def approval(payload, policy):
    entries = policy.get('release_regression_approvals', [])
    if not isinstance(entries, list) or len(entries) > 8:
        raise ValueError('invalid release regression approval')
    seen, selected = set(), None
    for entry in entries:
        fields = {'candidate_sha', 'baseline_sha', 'baseline_tag', 'release_tag', 'approved_by', 'reason'}
        if (not isinstance(entry, dict)
                or set(entry) not in (fields, fields | {'allow_timing_inconclusive'})
                or ('allow_timing_inconclusive' in entry and type(entry['allow_timing_inconclusive']) is not bool)):
            raise ValueError('invalid release regression approval')
        reason = entry['reason']
        if (any(not isinstance(entry[name], str) or not ci.SHA.fullmatch(entry[name])
                for name in ('candidate_sha', 'baseline_sha'))
                or not isinstance(entry['release_tag'], str)
                or not re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+', entry['release_tag'])
                or not isinstance(entry['baseline_tag'], str)
                or not (re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+', entry['baseline_tag'])
                        or ci.owner_baseline_sha(entry['baseline_tag']) == entry['baseline_sha'])
                or type(entry['approved_by']) is not int
                or entry['approved_by'] != policy.get('operator_id')
                or not isinstance(reason, str) or not 1 <= len(reason) <= 1024
                or not reason.strip() or any(ord(c) < 32 or ord(c) == 127 for c in reason)):
            raise ValueError('invalid release regression approval')
        identity = (entry['candidate_sha'], entry['baseline_sha'], entry['baseline_tag'])
        if identity in seen:
            raise ValueError('duplicate release regression approval')
        seen.add(identity)
        if (payload['schema'] == 2 and payload['suite'] == 'release'
                and policy.get('operator_origin') == 'local-operator'
                and type(policy.get('operator_id')) is int
                and payload.get('operator_id') == policy['operator_id']
                and payload['source'] == policy['repository']
                and payload['source_id'] == policy['repository_id']
                and identity == (payload['source_sha'], payload['baseline_sha'], payload['baseline_tag'])):
            selected = dict(entry)
    return selected


def receipt(payload, policy):
    entry = approval(payload, policy)
    if entry is None:
        return None
    return {'schema': 1, 'context': ci.builder_context('sources'), 'request_id': payload['request_id'],
            'source': payload['source'], 'source_id': payload['source_id'], 'approval': entry}


def read_receipt(path, payload):
    if not path.exists():
        return None
    record = read_json(path, 16384)
    if (not isinstance(record, dict)
            or set(record) != {'schema', 'context', 'request_id', 'source', 'source_id', 'approval'}
            or record['schema'] != 1 or record['context'] != ci.builder_context('sources')
            or record['request_id'] != payload['request_id'] or record['source'] != payload['source']
            or record['source_id'] != payload['source_id']):
        raise ValueError('release regression receipt identity mismatch')
    policy = {'repository': payload['source'], 'repository_id': payload['source_id'],
              'operator_origin': 'local-operator', 'operator_id': payload.get('operator_id'),
              'release_regression_approvals': [record['approval']]}
    entry = approval(payload, policy)
    if entry is None:
        raise ValueError('release regression receipt identity mismatch')
    return entry


def comparison(command):
    """Match whole reviewed comparator steps, with fixed input/output and budgets."""
    specifications = [(name, 'real_time', 10, name) for name in
                      ('queue', 'runtime', 'scheduler-submission-epoll', 'scheduler-submission-io-uring', 'filesystem')]
    specifications += [(f'scheduler-submission-{backend}', f'submit_{p}_ns', 10,
                        f'scheduler-submission-{backend}-{p}')
                       for backend in ('epoll', 'io-uring') for p in ('p50', 'p95', 'p99')]
    specifications += [('timer-wheel', f'{kind}_lateness_us', 50, f'timer-wheel-{kind}')
                       for kind in ('mean', 'max')]
    for suite, metric, budget, output in specifications:
        expected = (f'python3 scripts/compare-benchmarks.py out/performance/baseline/{suite}.json '
                    f'out/performance/current/{suite}.json '
                    + (f'--metric {metric} ' if metric != 'real_time' else '')
                    + f'--max-regression-percent {budget} --output out/performance/{output}-comparison.json')
        if command.strip() == expected:
            return f'out/performance/{output}-comparison.json', metric, budget, False
    expected = ('python3 scripts/compare-variant-benchmarks.py out/performance/baseline/variant.json '
                'out/performance/current/variant.json --max-regression-percent 10 --max-cv-percent 20 '
                '--output out/performance/variant-comparison.json')
    if command.strip() == expected:
        return 'out/performance/variant-comparison.json', 'real_time', 10, True
    return None


def read_json(path, limit):
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or not 0 < metadata.st_size <= limit:
        raise ValueError('invalid release regression evidence file')
    return crypto.parse(path.read_bytes())


def finite(value):
    return type(value) in (int, float) and math.isfinite(value)


def finite_report(report):
    """Reject overflowed JSON statistics too, including fields outside raw pairs."""
    pending, count = [report], 0
    while pending:
        value = pending.pop()
        count += 1
        if count > 1000000:
            return False
        if isinstance(value, float) and not math.isfinite(value):
            return False
        if isinstance(value, dict):
            pending.extend(value.values())
        elif isinstance(value, list):
            pending.extend(value)
    return True


def eligible_timing(report, metric, budget, variant, *, allow_inconclusive=False):
    """Validate timing-only evidence, retaining every non-waivable quality check.

The optional owner permission applies only to CV/interval uncertainty. Missing
pairs, undersized retained groups, nonfinite data, unknown uncertainty reasons,
inventory drift and deterministic allocation/layout contracts remain failures.
    """
    if (not finite_report(report)
            or report.get('schema') != 3 or report.get('aggregation') != 'iterative_sigma_clipped_paired_mean'
            or report.get('confidence_level') != 0.95 or report.get('repetitions') != 10
            or report.get('max_regression_percent') != budget or report.get('max_cv_percent') != 20
            or report.get('status') not in {'regressed', 'inconclusive'}
            or (not allow_inconclusive and report.get('inconclusive') != [])
            or 'seeded_baseline' in report
            or (not variant and (report.get('metric') != metric or report.get('missing_benchmarks') != []
                                 or report.get('unexpected_benchmarks') != []))):
        return False
    rows, failures = report.get('comparisons'), report.get('regressions')
    if not isinstance(rows, list) or not 1 <= len(rows) <= 10000 or not isinstance(failures, list):
        return False
    names, regressed, inconclusive = set(), [], []
    for row in rows:
        if not isinstance(row, dict):
            return False
        name = row.get('name')
        count, indices = row.get('sample_count'), row.get('retained_indices')
        interval = row.get('budget_margin_ci')
        uncertain = row.get('timing_status') == 'inconclusive'
        reasons = row.get('inconclusive_reasons')
        if (not isinstance(name, str) or not name or name in names
                or row.get('timing_status') not in {'passed', 'regressed', 'inconclusive'}
                or (uncertain and not allow_inconclusive)
                or not isinstance(reasons, list)
                or (uncertain and (not reasons or any(r not in {'excessive_cv', 'budget_interval_overlap'} for r in reasons)))
                or (not uncertain and reasons != []) or row.get('raw_sample_count') != 10
                or type(count) is not int or not 5 <= count <= 10
                or not isinstance(indices, list) or len(indices) != count
                or any(type(i) is not int or i not in range(10) for i in indices)
                or indices != sorted(set(indices))
                or any(not finite(row.get(key)) or row[key] < 0 or (not uncertain and row[key] > 20)
                       for key in ('baseline_cv_percent', 'candidate_cv_percent'))
                or not isinstance(interval, list) or len(interval) != 2
                or not all(finite(v) for v in interval) or interval[0] > interval[1]):
            return False
        for key in ('baseline_samples', 'candidate_samples'):
            values = row.get(key)
            if (not isinstance(values, list) or len(values) != 10
                    or any(not finite(v) or v < 0 or (metric == 'real_time' and v == 0) for v in values)):
                return False
        if row['timing_status'] == 'regressed':
            if interval[0] <= 0 or (row.get('change_percent') is not None and not finite(row['change_percent'])):
                return False
            regressed.append(dict(row, metric='real_time') if variant else row)
        elif uncertain:
            inconclusive.append(row)
        elif interval[1] > 1e-12:
            return False
        names.add(name)
    # Allocation/leak/layout regressions are not timing-budget failures. Requiring
    # exact lists also reject hidden inventory failures or omitted uncertainty.
    status = 'regressed' if regressed else 'inconclusive' if inconclusive else 'passed'
    return (bool(regressed or inconclusive) and failures == regressed
            and report.get('inconclusive') == inconclusive and report['status'] == status)


def waive(root, command, result, entry, payload, audit):
    selected = comparison(command)
    if type(result) is not int or result not in {1, 2} or entry is None or selected is None:
        return False
    relative, metric, budget, variant = selected
    path = root / relative
    try:
        if any(parent.is_symlink() for parent in (path.parent, path.parent.parent)):
            return False
        report = read_json(path, 16 * 1024**2)
        if (not isinstance(report, dict)
                or result != {'regressed': 1, 'inconclusive': 2}.get(report.get('status'))
                or not eligible_timing(report, metric, budget, variant,
                                       allow_inconclusive=entry.get('allow_timing_inconclusive') is True)):
            return False
    except (OSError, ValueError, KeyError, TypeError, OverflowError):
        return False
    record = {'schema': 1, 'context': ci.builder_context('sources'), 'request_id': payload['request_id'],
              'source_sha': payload['source_sha'], 'baseline_sha': payload['baseline_sha'],
              'approval': entry, 'report_sha256': crypto.digest(path), 'original_exit_code': result,
              'regressions': report['regressions'], 'inconclusive': report['inconclusive']}
    with os.fdopen(os.open(audit / Path(relative).name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb') as out:
        out.write(crypto.canonical(record))
    return True
