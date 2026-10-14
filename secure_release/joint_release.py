"""Two platform-scoped signed requests, one atomic qualified SDK publication."""
import hashlib
import os
from pathlib import Path
import time
import uuid

from . import crypto
from .github import Client
from .protocol import *

WORKFLOW = 'build-combined-release.yml'
REQUEST_WORKFLOW = 'release-combined-request.yml'


def identity(payload: dict) -> bytes:
    """Only acquisition contracts differ; source/version/graph/authorization do not."""
    keys = ('release_id', 'salt', 'source_sha', 'source_tag', 'request_run', 'request_attempt',
            'builder_sha', 'input_key', 'output_key', 'created', 'expires', 'source_id', 'builder_id', 'bin_id')
    value = {k: payload[k] for k in keys}
    value['release_tag'] = payload.get('release_tag', payload['source_tag'])
    value['graph'] = {k: payload['plan'][k] for k in ('version', 'upstream_sha', 'ports', 'platforms', 'smoke_path')}
    return crypto.canonical(value)


def request():
    from .tasks import event
    guard(SOURCE)
    data = event()
    if (not data['repository']['private'] or env('GITHUB_REF_TYPE') != 'tag'
            or not TAG.fullmatch(env('GITHUB_REF_NAME')) or env('GITHUB_REF_NAME').endswith('-windows')):
        raise ValueError('Joint request requires an immutable private source release tag')
    if env('GITHUB_EVENT_NAME') == 'push':
        if not data.get('created') or data.get('deleted'):
            raise ValueError('Joint request requires a newly created tag')
    elif env('GITHUB_EVENT_NAME') == 'workflow_dispatch':
        if data.get('inputs', {}).get('source_tag') != env('GITHUB_REF_NAME'):
            raise ValueError('Joint retry must run from the exact source tag')
    else:
        raise ValueError('Unsupported joint request event')
    api = Client(env('SOURCE_TOKEN'))
    created = int(time.time())
    rid, salt = str(uuid.uuid4()), crypto.b64(os.urandom(32))
    inputs = {'release_id': rid, 'salt': salt}
    common = None
    for platform in ('linux', 'windows'):
        name = 'release-plan.json' if platform == 'linux' else 'release-windows-plan.json'
        record = api.get(f'/repos/{SOURCE}/contents/ci/{name}?ref={sha(env("GITHUB_SHA"))}')
        plan = crypto.parse(crypto.unb64(record['content'].replace('\n', '')))
        validate_plan(plan)
        payload = {'version': 2, 'platforms': [platform], 'release_id': rid, 'salt': salt,
                   'source_sha': sha(env('GITHUB_SHA')), 'source_tag': env('GITHUB_REF_NAME'),
                   'request_run': number(env('GITHUB_RUN_ID')), 'request_attempt': number(env('GITHUB_RUN_ATTEMPT')),
                   'builder_sha': sha(env('BUILDER_COMMIT_SHA')), 'input_key': crypto.fingerprint(env('BUILDER_INPUT_PUBLIC_KEY')),
                   'output_key': crypto.fingerprint(env('ARTIFACT_ENCRYPTION_PUBLIC_KEY')), 'created': created,
                   'expires': created + 172800, 'source_id': IDS[SOURCE], 'builder_id': IDS[BUILDER], 'bin_id': IDS[BIN], 'plan': plan}
        current = identity(payload)
        if '-rc.' in payload['source_tag']:
            payload.update(version=4, release_tag=payload['source_tag'].split('-rc.', 1)[0])
            current = identity(payload)
        if common is not None and current != common:
            raise ValueError('Joint platform plans select different source/package graphs')
        common = current
        signed = crypto.sign(payload, env('REQUEST_SIGNING_PRIVATE_KEY'))
        inputs[platform + '_request'] = crypto.seal_message(crypto.canonical(signed), env('BUILDER_INPUT_PUBLIC_KEY'),
                                                          message_context(rid, salt))
    answer = Client(env('BUILDER_DISPATCH_TOKEN')).dispatch(BUILDER, WORKFLOW, inputs)
    with Path(env('GITHUB_STEP_SUMMARY')).open('a', encoding='utf-8') as output:
        output.write(f'Accepted joint SDK request `{rid}`. Builder run: {answer["workflow_run_id"]}\n')
