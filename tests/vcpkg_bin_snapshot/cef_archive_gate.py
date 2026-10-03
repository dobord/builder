#!/usr/bin/env python3
"""Recompute CEF target archive evidence in the private publisher.

The approved builder checkout supplies the non-executing parser. No module is
loaded from the SDK or staging directory. Non-CEF publication is unchanged.
"""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import cef_publication as metadata


def inspect(staging: Path, expected: str, policy: dict) -> dict:
    report = metadata.inspect(staging, expected, policy)
    report['archive_audits'] = {}
    if not report['cef_present']:
        return report
    try:
        from secure_release import static_audit
    except ImportError:
        report['reasons'].append('Approved builder revision lacks the non-executing archive auditor')
        report['publication_allowed'] = False
        return report
    manifest = metadata.decode((staging / 'release-manifest.json').read_bytes())
    for platform, record in manifest['platforms'].items():
        path = staging / f"vcpkg-{manifest['source_tag']}-{platform}-x64-static-release.zip"
        full = static_audit.inspect_sdk(path, platform)
        actual = static_audit.summarize(full)
        report['archive_audits'][platform] = actual
        evidence = record['cef']['consumer'].get('target_archive_audit')
        if actual != evidence:
            report['reasons'].append(platform + ': target archive evidence is missing or differs from the verified ZIP')
        if not actual['target_archives_static']:
            report['reasons'].append(platform + ': target archive audit found shared, import or unqualified libraries')
        metadata.require(actual['sdk_sha256'] == record['sdk_sha256'], 'SDK changed during independent archive inspection')
    report['publication_allowed'] = not report['reasons']
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--staging', type=Path, required=True)
    parser.add_argument('--policy', type=Path, required=True)
    parser.add_argument('--publish', action='store_true')
    args = parser.parse_args()
    report = inspect(args.staging, os.environ.get('STAGING_DIGEST', ''), metadata.decode(args.policy.read_bytes()))
    print(json.dumps(report, sort_keys=True))
    if 'GITHUB_OUTPUT' in os.environ:
        with open(os.environ['GITHUB_OUTPUT'], 'a', encoding='utf-8') as output:
            output.write('cef_publication_allowed=' + str(report['publication_allowed']).lower() + '\n')
    if args.publish:
        metadata.require(report['publication_allowed'], 'CEF publication requires qualified runtime and independently audited target archives')


if __name__ == '__main__':
    main()
