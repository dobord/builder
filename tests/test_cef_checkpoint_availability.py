"""A deleted/expired checkpoint must stop CI before costly native preparation."""
from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone
import json
import os
import shutil
import textwrap
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import urllib.error

from secure_release import cef_checkpoint_availability as subject

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 10, 2, tzinfo=timezone.utc)
SELECTOR = dict(run=12345, attempt=1, producer_sha="a"*40, artifact_id=34567,
                artifact_sha256="b"*64, summary_artifact_id=23456,
                summary_artifact_sha256="c"*64, build_key="d"*64, platform_sha256="e"*64)


def responses():
    root = "/repos/dobord/builder/actions"
    result = {root+"/runs/12345": dict(id=12345, run_attempt=1, head_sha="a"*40,
        repository=dict(full_name="dobord/builder"), head_repository=dict(full_name="dobord/builder"),
        path=subject.WORKFLOW, event="push", status="completed", conclusion="success")}
    for role, number, digest, prefix in (
        ("summary", 23456, "c"*64, "cef-strict-iteration-summary"),
        ("checkpoint", 34567, "b"*64, "cef-strict-checkpoint-linux"),
    ):
        result[root+"/artifacts/"+str(number)] = dict(
            id=number, name=prefix+"-12345-1", digest="sha256:"+digest, expired=False,
            size_in_bytes=1024 if role == "summary" else 12*1024**3,
            expires_at="2026-12-01T00:00:00Z", workflow_run=dict(id=12345, head_sha="a"*40))
    return result


class API:
    def __init__(self):
        self.data = responses()
        self.calls = []

    def get(self, path):
        self.calls.append(path)
        value = self.data.get(path)
        if value is None:
            raise urllib.error.HTTPError("https://api.github.com"+path,404,"missing",{},None)
        if isinstance(value, Exception):
            raise value
        return copy.deepcopy(value)

    def download(self, *args, **kwargs):
        raise AssertionError("availability must not download, decrypt or restore")


class AvailabilityTests(unittest.TestCase):
    def test_exact_metadata_only_never_authorizes_or_modifies_checkpoint(self):
        api = API()
        selected = copy.deepcopy(SELECTOR)
        initial = copy.deepcopy(api.data)
        result = subject.verify_available(selected, api, now=NOW)
        self.assertEqual(selected, SELECTOR)
        self.assertEqual(api.data, initial)
        self.assertEqual(len(api.calls), 3)
        self.assertEqual(result["artifact_count"], 2)
        self.assertTrue(result["checkpoint_artifacts_available"])
        self.assertNotIn("runtime_verified", result)
        self.assertNotIn("checkpoint_ready", result)
        self.assertEqual(result["min_remaining_seconds"], 60*86400)

    def test_each_original_artifact_missing_or_gone_stops_without_fallback(self):
        for number, role in ((23456,"summary"),(34567,"checkpoint")):
            for code in (404,410):
                api=API(); path=f"/repos/dobord/builder/actions/artifacts/{number}"
                api.data[path]=urllib.error.HTTPError("private-url",code,"private-body",{},None)
                with self.subTest(role=role,code=code),self.assertRaisesRegex(
                        ValueError, "CEF_CHECKPOINT_ARTIFACT_UNAVAILABLE: "+role):
                    subject.verify_available(SELECTOR,api,now=NOW)
                self.assertEqual(api.calls[-1],path)

    def test_wrong_identity_digest_expired_and_empty_are_rejected(self):
        changes=(('id',1),('name','matching-name-is-not-provenance'),('digest','sha256:'+'f'*64),
                 ('expired',True),('expired',None),('size_in_bytes',0),('size_in_bytes',True),
                 ('workflow_run',dict(id=1,head_sha='a'*40)),
                 ('workflow_run',dict(id=12345,head_sha='f'*40)))
        for number in (23456,34567):
            for field,value in changes:
                api=API();api.data[f"/repos/dobord/builder/actions/artifacts/{number}"][field]=value
                with self.subTest(number=number,field=field,value=value),self.assertRaises(ValueError):
                    subject.verify_available(SELECTOR,api,now=NOW)

    def test_minimum_window_covers_existing_350_minute_job(self):
        self.assertGreaterEqual(subject.MIN_REMAINING,timedelta(minutes=350))
        for seconds in (-1,0,350*60,6*3600-1,6*3600):
            api=API()
            for key,value in api.data.items():
                if '/artifacts/' in key:
                    value['expires_at']=(NOW+timedelta(seconds=seconds)).strftime('%Y-%m-%dT%H:%M:%SZ')
            if seconds < 6*3600:
                with self.subTest(seconds=seconds),self.assertRaisesRegex(ValueError,'RETENTION_TOO_SHORT'):
                    subject.verify_available(SELECTOR,api,now=NOW)
            else:
                self.assertEqual(subject.verify_available(SELECTOR,api,now=NOW)['min_remaining_seconds'],seconds)

    def test_invalid_or_naive_expiry_is_not_guessed(self):
        for expiry in (None,'', '2026-12-01','2026-12-01T00:00:00','2026-13-01T00:00:00Z'):
            api=API();api.data['/repos/dobord/builder/actions/artifacts/23456']['expires_at']=expiry
            with self.subTest(expiry=expiry),self.assertRaisesRegex(ValueError,'EXPIRY_INVALID'):
                subject.verify_available(SELECTOR,api,now=NOW)
        with self.assertRaisesRegex(ValueError,'CLOCK_INVALID'):
            subject.verify_available(SELECTOR,API(),now=NOW.replace(tzinfo=None))

    def test_rerun_changed_origin_and_unfinished_producer_fail(self):
        for field,value in (('run_attempt',2),('head_sha','f'*40),('path','.github/workflows/other.yml'),
                            ('event','pull_request'),('status','in_progress'),('conclusion','failure'),
                            ('repository',None),('repository',dict(full_name='other/builder')),
                            ('head_repository',dict(full_name='fork/builder'))):
            api=API();api.data['/repos/dobord/builder/actions/runs/12345'][field]=value
            with self.subTest(field=field),self.assertRaisesRegex(ValueError,'PRODUCER_UNAVAILABLE_OR_CHANGED'):
                subject.verify_available(SELECTOR,api,now=NOW)
            self.assertEqual(len(api.calls),1)

    def test_engine_resumable_failure_is_not_combined_runtime_success(self):
        api=API();api.data['/repos/dobord/builder/actions/runs/12345']['conclusion']='failure'
        with self.assertRaises(ValueError):subject.verify_available(SELECTOR,api,now=NOW)
        result=subject.verify_available(SELECTOR,api,now=NOW,require_success=False)
        self.assertTrue(result['checkpoint_artifacts_available'])
        self.assertNotIn('runtime_verified',result)

    def test_selector_validation_precedes_api_and_large_work(self):
        for field,value in (('run',True),('attempt',0),('artifact_id',23456),
                            ('producer_sha','../wrong'),('artifact_sha256','not-a-hash')):
            selected=dict(SELECTOR);selected[field]=value;api=API()
            with self.subTest(field=field),self.assertRaisesRegex(ValueError,'SELECTOR_INVALID'):
                subject.verify_available(selected,api,now=NOW)
            self.assertEqual(api.calls,[])
        with self.assertRaises(ValueError):subject.verify_available(None,API(),now=NOW)

    def test_api_failure_is_not_retention_recovery_or_a_token_leak(self):
        for code in (401,403,429,500,503):
            api=API();api.data['/repos/dobord/builder/actions/runs/12345']=urllib.error.HTTPError(
                'secret-url',code,'secret-token-in-untrusted-body',{},None)
            with self.subTest(code=code),self.assertRaises(ValueError) as error:
                subject.verify_available(SELECTOR,api,now=NOW)
            self.assertEqual(str(error.exception),'CEF_CHECKPOINT_API_FAILED: producer')
            self.assertEqual(len(api.calls),1)

    def test_oversized_summary_cannot_be_an_availability_receipt(self):
        api=API();api.data['/repos/dobord/builder/actions/artifacts/23456']['size_in_bytes']=4*1024**2+1
        with self.assertRaisesRegex(ValueError,'ARTIFACT_INVALID: summary'):
            subject.verify_available(SELECTOR,api,now=NOW)

    def test_explicit_fresh_selector_only_for_engine_not_missing_checkpoint_fallback(self):
        with tempfile.TemporaryDirectory() as name:
            root=Path(name);(root/'ci').mkdir()
            for kind in ('engine','combined'):
                path=root/f'ci/cef-strict-{kind}-lock.json'
                path.write_text(json.dumps(dict(schema=1,platform='linux',checkpoint=None)))
            script=ROOT/'secure_release/cef_checkpoint_availability.py'
            command=[sys.executable,'-S',str(script),'--lock']
            engine=subprocess.run(command+['ci/cef-strict-engine-lock.json'],cwd=root,
                                  capture_output=True,text=True,timeout=10)
            self.assertEqual(engine.returncode,0,engine.stderr)
            combined=subprocess.run(command+['ci/cef-strict-combined-lock.json'],cwd=root,
                                    capture_output=True,text=True,timeout=10)
            self.assertNotEqual(combined.returncode,0)
            self.assertIn('SELECTOR_INVALID',combined.stderr)

    def test_duplicate_lock_fields_rejected(self):
        with self.assertRaisesRegex(ValueError,'LOCK_INVALID'):
            json.loads('{"checkpoint":null,"checkpoint":{}}',object_pairs_hook=subject._unique)


class WorkflowTests(unittest.TestCase):
    def test_combined_gate_checks_availability_before_marking_ready(self):
        source=(ROOT/'.github/workflows/cef-strict-combined.yml').read_text()
        gate=source.split('\n  gate:',1)[1].split('\n  linux:',1)[0]
        self.assertIn('GITHUB_TOKEN: ${{ github.token }}',gate)
        self.assertIn('verify_available(value["checkpoint"], Client(os.environ["GITHUB_TOKEN"]))',gate)
        self.assertLess(gate.index('verify_available('),gate.index('stream.write("ready="'))
        self.assertIn('needs: gate',source)
        self.assertIn("if: needs.gate.outputs.ready == 'true'",source)
        self.assertIn('test_cef_checkpoint_availability.py',gate)
        self.assertNotIn('BUILDER_INPUT_PRIVATE_KEY',gate)
        self.assertNotIn('pip install',gate)

    def test_real_python_shell_script_imports_checkout_from_runner_temp(self):
        # Unlike exec() inside the test process, an actual script located in
        # RUNNER_TEMP does not put cwd on sys.path. Reproduce Actions faithfully.
        workflow=(ROOT/'.github/workflows/cef-strict-combined.yml').read_text()
        gate=workflow.split('      - name: Require an explicit reviewed checkpoint before expensive work',1)[1]
        body=textwrap.dedent(gate.split('        run: |\n',1)[1].split('\n  linux:',1)[0])
        with tempfile.TemporaryDirectory() as name:
            root=Path(name).resolve();checkout=root/'checkout';scratch=root/'runner-temp'
            checkout.mkdir();scratch.mkdir();(checkout/'ci').mkdir();(checkout/'secure_release').mkdir()
            (checkout/'secure_release/__init__.py').write_text('')
            for module in ('cef_checkpoint_availability.py', 'cef_checkpoint_backup.py',
                           'crypto.py', 'protocol.py', 'cef_contract.py'):
                shutil.copyfile(ROOT/'secure_release'/module, checkout/'secure_release'/module)
            (checkout/'ci/cef-strict-combined-lock.json').write_text(json.dumps({'checkpoint':SELECTOR}))
            output=root/'github-output'
            metadata=responses()
            # Far-future fake metadata only. No real token or network is used.
            for path,value in metadata.items():
                if '/artifacts/' in path:value['expires_at']='2999-01-01T00:00:00Z'
            bootstrap=("import sys, types, urllib.error\n"
                       "api=types.ModuleType('secure_release.github')\n"
                       "class Client:\n"
                       "    def __init__(self, token): self.token=token\n"
                       "    def get(self, path):\n"
                       "        if path not in DATA: raise urllib.error.HTTPError('public-fixture',404,'missing',{},None)\n"
                       "        return DATA[path]\n"
                       "api.Client=Client\n"
                       "sys.modules['secure_release.github']=api\n")
            env={k:v for k,v in os.environ.items() if k not in ('PYTHONPATH','PYTHONHOME')}
            env.update(GITHUB_TOKEN='public-fixture-only',GITHUB_OUTPUT=str(output))
            script=scratch/'step.py'
            for mode in ('old-import','available','missing-summary','missing-checkpoint'):
                data=copy.deepcopy(metadata);source=body
                if mode=='old-import':
                    source=source.replace('sys.path.insert(0, str(pathlib.Path.cwd()))','pass')
                elif mode.startswith('missing-'):
                    number=23456 if mode=='missing-summary' else 34567
                    del data[f'/repos/dobord/builder/actions/artifacts/{number}']
                script.write_text(bootstrap+'DATA='+repr(data)+'\n'+source)
                output.unlink(missing_ok=True)
                run=subprocess.run([sys.executable,'-S',str(script)],cwd=checkout,env=env,
                                   capture_output=True,text=True,timeout=10)
                with self.subTest(mode=mode):
                    if mode=='available':
                        self.assertEqual(run.returncode,0,run.stderr)
                        self.assertEqual(output.read_text(),'ready=true\n')
                    else:
                        self.assertNotEqual(run.returncode,0)
                        self.assertFalse(output.exists())
                        expected=('ModuleNotFoundError' if mode=='old-import'
                                  else 'CEF_CHECKPOINT_ARTIFACT_UNAVAILABLE: '+mode[8:])
                        self.assertIn(expected,run.stderr)

    def test_engine_checks_selected_checkpoint_before_checkout_and_tools(self):
        source=(ROOT/'.github/workflows/cef-strict-engine-iteration.yml').read_text()
        probe='python -m secure_release.cef_checkpoint_availability --lock ci/cef-strict-engine-lock.json'
        self.assertIn(probe,source)
        self.assertLess(source.index(probe),source.index('repository: dobord/vcpkg'))
        self.assertLess(source.index(probe),source.index('apt-get'))
        self.assertIn('secure_release/cef_checkpoint_availability.py',source)

    def test_checkpoint_and_evidence_have_matching_90_day_retention(self):
        source=(ROOT/'.github/workflows/cef-strict-engine-iteration.yml').read_text()
        for title in ('Upload encrypted strict checkpoint','Upload non-sensitive iteration summary'):
            step=source.split('      - name: '+title,1)[1].split('      - name:',1)[0]
            self.assertIn('retention-days: 90',step)
            self.assertNotIn('retention-days: 7',step)
        for name in ('combined','engine'):
            source=(ROOT/f'.github/workflows/cef-strict-{name if name=="combined" else "engine-iteration"}.yml').read_text()
            self.assertIn('actions: read',source)
            self.assertNotIn('actions: write',source)


def load_tests(loader, tests, pattern):
    if pattern == 'test_cef_checkpoint_availability.py':
        from test_cef_checkpoint_backup import MetadataTests
        tests.addTests(loader.loadTestsFromTestCase(MetadataTests))
    return tests


if __name__=='__main__':
    unittest.main()
