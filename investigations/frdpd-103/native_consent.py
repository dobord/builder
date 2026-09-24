"""Consent automation limited to the owned mstsc process on a disposable CI runner.

Does not bypass authentication, certificate errors, or consent for other applications.
The RDP first-use verification checkbox is a windowless TaskDialog control.
"""
from __future__ import annotations
import ctypes
from ctypes import wintypes as W
import json
import os
from pathlib import Path
import subprocess
import time

U = ctypes.WinDLL('user32', use_last_error=True)
CALLBACK = ctypes.WINFUNCTYPE(W.BOOL, W.HWND, W.LPARAM)
U.GetWindowTextLengthW.argtypes = [W.HWND]
U.GetWindowTextW.argtypes = [W.HWND, W.LPWSTR, ctypes.c_int]
U.GetClassNameW.argtypes = [W.HWND, W.LPWSTR, ctypes.c_int]
U.GetWindowThreadProcessId.argtypes = [W.HWND, ctypes.POINTER(W.DWORD)]
U.IsWindowVisible.argtypes = [W.HWND]
U.IsWindowEnabled.argtypes = [W.HWND]
U.SetForegroundWindow.argtypes = [W.HWND]
U.SendMessageTimeoutW.argtypes = [W.HWND, W.UINT, W.WPARAM, W.LPARAM, W.UINT, W.UINT, ctypes.POINTER(ctypes.c_size_t)]
U.SendMessageTimeoutW.restype = ctypes.c_ssize_t
U.EnumChildWindows.argtypes = [W.HWND, CALLBACK, W.LPARAM]
U.EnumWindows.argtypes = [CALLBACK, W.LPARAM]


def windows(parent: int | None = None) -> list[dict]:
    result = []
    @CALLBACK
    def visit(hwnd, unused):
        if U.IsWindowVisible(hwnd):
            title = ctypes.create_unicode_buffer(U.GetWindowTextLengthW(hwnd) + 1)
            U.GetWindowTextW(hwnd, title, len(title))
            kind = ctypes.create_unicode_buffer(256)
            U.GetClassNameW(hwnd, kind, len(kind))
            pid = W.DWORD()
            U.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
            result.append({'hwnd': int(hwnd), 'title': title.value, 'class': kind.value, 'pid': pid.value})
        return True
    if parent:
        U.EnumChildWindows(parent, visit, 0)
    else:
        U.EnumWindows(visit, 0)
    return result


def send(hwnd: int, message: int, wparam: int = 0, lparam: int = 0) -> bool:
    result = ctypes.c_size_t()
    return bool(U.SendMessageTimeoutW(hwnd, message, wparam, lparam, 2, 1000, ctypes.byref(result)))


def handle(current: list[dict], client_pid: int, report: dict, root: Path) -> None:
    for window in current:
        if window['pid'] != client_pid or window['class'] != '#32770':
            continue
        controls = windows(window['hwnd'])
        text = '\n'.join(item['title'] for item in controls)
        buttons = {item['title'].replace('&', ''): item for item in controls if item['class'] == 'Button'}
        educational = (window['title'] == 'Opening Remote Desktop Connection' and
                       'You are opening an RDP file which will establish a connection to another computer.' in text)
        if educational:
            U.SetForegroundWindow(window['hwnd'])
            # CommCtrl.h: TDM_CLICK_VERIFICATION = WM_USER + 113.
            # This sets the checkbox, unlike BM_CLICK on nonexistent HWND children.
            checked = send(window['hwnd'], 0x400 + 113, 1, 1)
            time.sleep(0.15)
            if checked and 'OK' in buttons and U.IsWindowEnabled(buttons['OK']['hwnd']):
                send(buttons['OK']['hwnd'], 0x00F5)
                report['fixture_rdp_consent'] = True
            else:
                report['verification_message_sent'] = checked
        elif 'Disposable RemoteApp test' in text and 'localhost' in text:
            for label in ('Connect', 'Continue'):
                if label in buttons and U.IsWindowEnabled(buttons[label]['hwnd']):
                    U.SetForegroundWindow(window['hwnd'])
                    send(buttons[label]['hwnd'], 0x00F5)
                    report['fixture_publisher_consent'] = True
                    break
        (root / 'last-dialog.json').write_text(json.dumps({'window': window, 'controls': controls}, indent=2))


def preflight(root: Path) -> dict:
    root.mkdir(parents=True, exist_ok=True)
    rdp = root / 'consent-preflight.rdp'
    rdp.write_text('full address:s:localhost:39999\nprompt for credentials:i:1\nauthentication level:i:2\nenablecredsspsupport:i:1\nredirectclipboard:i:0\nredirectprinters:i:0\n', encoding='utf-16')
    report = {'passed': False}
    process = subprocess.Popen([str(Path(os.environ['WINDIR']) / 'System32' / 'mstsc.exe'), str(rdp)])
    try:
        for tick in range(60):
            time.sleep(0.5)
            current = windows()
            handle(current, process.pid, report, root)
            owned = [w for w in current if w['pid'] == process.pid]
            report['windows'] = owned
            education = [w for w in owned if w['title'] == 'Opening Remote Desktop Connection']
            if tick > 3 and not education and (owned or process.poll() is not None):
                report['passed'] = True
                break
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
        rdp.unlink(missing_ok=True)
        (root / 'consent-preflight.json').write_text(json.dumps(report, indent=2))
    if not report['passed']:
        raise RuntimeError('Disposable mstsc first-use consent was not dismissed')
    return report


if __name__ == '__main__':
    preflight(Path(os.environ['RUNNER_TEMP']) / 'consent-private')
