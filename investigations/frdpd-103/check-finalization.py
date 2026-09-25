"""Static integration and log-order regression checks; never a Windows acceptance claim."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import re
import unittest


def function(source: str, name: str) -> str:
    match = re.search(r'\b' + re.escape(name) + r'\([^;{}]*\)\s*\{', source)
    if not match:
        raise ValueError(f'Missing function definition: {name}')
    start = match.end()
    depth = 1
    for offset in range(start, len(source)):
        if source[offset] == '{':
            depth += 1
        elif source[offset] == '}':
            depth -= 1
            if depth == 0:
                return source[start:offset]
    raise ValueError(f'Unclosed function: {name}')


def source_contract(source: str) -> None:
    for name, operation in (
        ('frdpd_service_vcm', 'WTSVirtualChannelManagerCheckFileDescriptorEx('),
        ('frdpd_service_layered', 'rail_server_context_new('),
    ):
        body = function(source, name)
        guard = body.find('!frdpd_peer_channels_ready(context->_p.peer)')
        side_effect = body.find(operation)
        if not 0 <= guard < side_effect or 'return TRUE;' not in body[guard:side_effect]:
            raise ValueError(f'Missing pre-activation no-op gate: {name}')
    loop = function(source, 'frdpd_peer_mainloop')
    # No VCM/backend signalled event may cause an inactive busy loop.
    for marker in (
        'if (channels_ready && context->vcm)',
        'if (channels_ready && context->gfx)',
        'if (channels_ready && context->rail_runtime.event)',
        'graphics_notify_event = channels_ready ? context->graphics_notify_event : NULL;',
        ': FRDPD_PEER_IDLE_WAIT_TIMEOUT_MS',
    ):
        if marker not in loop:
            raise ValueError('Inactive wait-set invariant missing')
    compact = re.sub(r'/\*.*?\*/|//[^\n]*', '', loop, flags=re.S)
    compact = re.sub(r'\s+', ' ', compact)
    if 'if (!client->CheckFileDescriptor(client)) break; if (!frdpd_peer_channels_ready(client)) continue;' not in compact:
        raise ValueError('Core receive must execute before the fresh activation gate')
    timeout = re.search(r'if \(status == WAIT_TIMEOUT\)\s*\{\s*if \(!frdpd_peer_channels_ready\(client\)\)\s*continue;', compact)
    if not timeout:
        raise ValueError('Timeout path can service channels before activation')


def log_contract(text: str) -> dict:
    activated = set()
    rail = set()
    graphics = set()
    observed = 0
    events = ('empty RAIL desktop initialized before EXEC', 'RAIL EXEC_RESULT sent',
              'RDPGFX DVC opened', 'Display Control DVC ready', 'layered first frame ')
    for number, line in enumerate(text.splitlines(), 1):
        match = re.search(r'correlation_id=([A-Za-z0-9-]+)\s+(.*)', line)
        if not match:
            continue
        session, message = match.groups()
        if re.search(r'\bclient\s+.*\s+activated\s*$', message):
            activated.add(session)
        if any(event in message for event in events):
            if session not in activated:
                raise ValueError(f'Channel work precedes activation at line {number}')
            observed += 1
        if 'empty RAIL desktop initialized before EXEC' in message:
            rail.add(session)
        if 'RDPGFX DVC opened' in message:
            graphics.add(session)
        if re.search(r'\bclient\s+.*\s+disconnected\s*$', message):
            activated.discard(session)
    if not rail or not graphics or not observed or not rail.intersection(graphics):
        raise ValueError('Missing same-session RemoteApp activation evidence')
    return {'rail_sessions': len(rail), 'graphics_sessions': len(graphics),
            'ordered_channel_events': observed, 'scope': 'server log order; not wire or Windows acceptance'}


class LogTests(unittest.TestCase):
    active = 'correlation_id=a client test activated\n'
    rail = 'correlation_id=a empty RAIL desktop initialized before EXEC\n'
    gfx = 'correlation_id=a RDPGFX DVC opened\n'
    def test_valid(self):
        self.assertEqual(log_contract(self.active + self.rail + self.gfx)['rail_sessions'], 1)
    def test_early_rail(self):
        with self.assertRaises(ValueError): log_contract(self.rail + self.active + self.gfx)
    def test_early_graphics(self):
        with self.assertRaises(ValueError): log_contract(self.gfx + self.active + self.rail)
    def test_interleaved_identity(self):
        with self.assertRaises(ValueError): log_contract(self.active.replace('=a ', '=b ') + self.rail + self.gfx)
    def test_missing(self):
        with self.assertRaises(ValueError): log_contract(self.active)
    def test_different_sessions(self):
        with self.assertRaises(ValueError): log_contract(self.active + self.active.replace('=a ', '=b ') + self.rail + self.gfx.replace('=a ', '=b '))
    def test_after_disconnect(self):
        with self.assertRaises(ValueError): log_contract(self.active + self.rail + self.gfx + 'correlation_id=a client test disconnected\n' + self.gfx)
    def test_reactivation(self):
        log_contract(self.active + self.rail + self.gfx + self.active + self.gfx)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', type=Path)
    parser.add_argument('--log', type=Path, action='append', default=[])
    parser.add_argument('--self-test', action='store_true')
    args = parser.parse_args()
    if args.self_test:
        result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(LogTests))
        if not result.wasSuccessful(): raise SystemExit(1)
    if args.source:
        source = args.source.read_text()
        source_contract(source)
        # Mutation controls verify that these are not merely unused predicate tests.
        for name in ('frdpd_service_vcm', 'frdpd_service_layered'):
            body = function(source, name)
            mutant = source.replace(body, body.replace('!frdpd_peer_channels_ready(context->_p.peer)', 'FALSE', 1), 1)
            try:
                source_contract(mutant)
            except ValueError:
                pass
            else:
                raise RuntimeError(f'Removed {name} gate escaped the regression check')
        print('Source integration contract PASS; both removed-guard controls rejected')
    for logfile in args.log:
        print(json.dumps(log_contract(logfile.read_text(errors='replace')), sort_keys=True))
