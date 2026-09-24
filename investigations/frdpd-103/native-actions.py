"""Exercise only the disposable mstsc fixture's own calculator window.

The initial offscreen-window stability gate must pass before these actions run.
No credentials, policy settings or server code are changed here. All screenshots
and detailed action results belong in the encrypted diagnostic archive.
"""
import ctypes
from ctypes import wintypes as W
import hashlib
import time


def exercise(namespace, client_pid):
    root = namespace['ROOT']
    report = namespace['REPORT']
    windows = namespace['windows']
    ps = namespace['ps']
    screenshot = namespace['screenshot']
    if report.get('stable_window_seconds', 0) < 30:
        raise RuntimeError('Native interaction requires the initial stability gate')
    u = ctypes.WinDLL('user32', use_last_error=True)
    u.GetWindowThreadProcessId.argtypes = [W.HWND, ctypes.POINTER(W.DWORD)]
    u.GetWindowRect.argtypes = [W.HWND, ctypes.POINTER(W.RECT)]
    u.GetClientRect.argtypes = [W.HWND, ctypes.POINTER(W.RECT)]
    u.ClientToScreen.argtypes = [W.HWND, ctypes.POINTER(W.POINT)]
    u.MoveWindow.argtypes = [W.HWND, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int, W.BOOL]
    u.SetForegroundWindow.argtypes = [W.HWND]
    u.PostMessageW.argtypes = [W.HWND, W.UINT, W.WPARAM, W.LPARAM]
    u.IsIconic.argtypes = [W.HWND]
    u.IsWindow.argtypes = [W.HWND]
    u.SetCursorPos.argtypes = [ctypes.c_int, ctypes.c_int]

    def matches():
        return [w for w in windows() if w['pid'] == client_pid and
                w['class'] == 'RAIL_WINDOW' and 'FRDP xcalc' in w['title']]

    found = matches()
    if len(found) != 1:
        raise RuntimeError('Calculator window is not uniquely identified')
    hwnd = found[0]['hwnd']

    def owned():
        pid = W.DWORD()
        u.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        if not u.IsWindow(hwnd) or pid.value != client_pid:
            raise RuntimeError('Fixture window ownership changed')

    def rect():
        owned()
        r = W.RECT()
        if not u.GetWindowRect(hwnd, ctypes.byref(r)):
            raise ctypes.WinError(ctypes.get_last_error())
        return [r.left, r.top, r.right, r.bottom]

    def wait_for(predicate, name, seconds=15):
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            if predicate():
                return
            time.sleep(0.2)
        raise RuntimeError('Native interaction timeout: ' + name)

    def screen_region(name):
        owned()
        r, p = W.RECT(), W.POINT(0, 0)
        if not u.GetClientRect(hwnd, ctypes.byref(r)) or not u.ClientToScreen(hwnd, ctypes.byref(p)):
            raise RuntimeError('Client rectangle unavailable')
        width, height = r.right - r.left - 8, min(90, r.bottom - r.top - 8)
        if width <= 0 or height <= 0 or p.x < 0 or p.y < 0:
            raise RuntimeError('Invalid visible calculator rectangle')
        path = root / name
        ps("Add-Type -AssemblyName System.Drawing; "
           f"$b=New-Object Drawing.Bitmap({width},{height}); "
           "$g=[Drawing.Graphics]::FromImage($b); "
           f"$g.CopyFromScreen({p.x+4},{p.y+4},0,0,$b.Size); "
           f"$b.Save('{path}',[Drawing.Imaging.ImageFormat]::Png); $g.Dispose(); $b.Dispose()")
        return hashlib.sha256(path.read_bytes()).hexdigest()

    class Mouse(ctypes.Structure):
        _fields_ = [('dx', W.LONG), ('dy', W.LONG), ('mouseData', W.DWORD),
                    ('dwFlags', W.DWORD), ('time', W.DWORD), ('extra', ctypes.c_size_t)]
    class Keyboard(ctypes.Structure):
        _fields_ = [('vk', W.WORD), ('scan', W.WORD), ('flags', W.DWORD),
                    ('time', W.DWORD), ('extra', ctypes.c_size_t)]
    class Hardware(ctypes.Structure):
        _fields_ = [('msg', W.DWORD), ('low', W.WORD), ('high', W.WORD)]
    class Payload(ctypes.Union):
        _fields_ = [('mouse', Mouse), ('keyboard', Keyboard), ('hardware', Hardware)]
    class Input(ctypes.Structure):
        _fields_ = [('type', W.DWORD), ('payload', Payload)]
    u.SendInput.argtypes = [W.UINT, ctypes.POINTER(Input), ctypes.c_int]
    u.SendInput.restype = W.UINT

    def key(vk):
        owned()
        events = (Input * 2)()
        events[0].type = events[1].type = 1
        events[0].payload.keyboard = Keyboard(vk, 0, 0, 0, 0)
        events[1].payload.keyboard = Keyboard(vk, 0, 2, 0, 0)
        if u.SendInput(2, events, ctypes.sizeof(Input)) != 2:
            raise RuntimeError('SendInput did not submit both keyboard events')
        time.sleep(0.3)

    actions = report['native_actions'] = {'initial_rect': rect()}
    r = rect()
    if not u.MoveWindow(hwnd, 80, 100, r[2]-r[0], r[3]-r[1], True):
        raise RuntimeError('Unable to move fixture window')
    wait_for(lambda: abs(rect()[0]-80) <= 5 and abs(rect()[1]-100) <= 5, 'move')
    time.sleep(2)
    actions['moved_rect'] = rect()
    screenshot('native-moved.png')
    owned()
    if not u.SetForegroundWindow(hwnd):
        raise RuntimeError('Unable to focus the calculator for input')
    u.SetCursorPos(30, 30)
    time.sleep(1)
    actions['display_before_sha256'] = screen_region('native-display-before.png')
    # Physical virtual keys: 7 + 2 Enter. Keep this separate from clipboard/Unicode paths.
    for vk in (0x37, 0x6B, 0x32, 0x0D):
        key(vk)
    time.sleep(3)
    actions['display_after_sha256'] = screen_region('native-display-after.png')
    actions['input_pixels_changed'] = actions['display_before_sha256'] != actions['display_after_sha256']
    screenshot('native-calculation.png')
    if not actions['input_pixels_changed']:
        raise RuntimeError('Keyboard input produced no visible calculator change')

    owned()
    if not u.PostMessageW(hwnd, 0x0112, 0xF020, 0):
        raise RuntimeError('Minimize command was not posted')
    wait_for(lambda: bool(u.IsIconic(hwnd)), 'minimize')
    actions['minimized'] = True
    time.sleep(3)
    owned()
    if not u.PostMessageW(hwnd, 0x0112, 0xF120, 0):
        raise RuntimeError('Restore command was not posted')
    wait_for(lambda: bool(matches()) and not u.IsIconic(hwnd), 'restore')
    time.sleep(3)
    actions['restored'] = True
    screenshot('native-restored.png')

    owned()
    if not u.PostMessageW(hwnd, 0x0112, 0xF060, 0):
        raise RuntimeError('Close command was not posted')
    wait_for(lambda: not matches(), 'close')
    actions['closed'] = True
    actions['interaction_pass'] = True
