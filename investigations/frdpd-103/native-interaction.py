"""Native interaction gate for the disposable mstsc fixture only.

Retain the initial offscreen geometry. Exercise genuine SendInput mouse/keyboard
traffic, not MoveWindow on the local RAIL surrogate. Reject an obscured capture
or stolen foreground instead of misreporting unchanged pixels as a codec error.
All generated images and details belong in the encrypted diagnostic archive.
"""
import ctypes
from ctypes import wintypes as W
import hashlib
import time


def exercise(namespace, client_pid):
    root, report = namespace['ROOT'], namespace['REPORT']
    windows, ps, screenshot = namespace['windows'], namespace['ps'], namespace['screenshot']
    if report.get('stable_window_seconds', 0) < 30:
        raise RuntimeError('Initial thirty-second RemoteApp stability gate did not pass')
    u = ctypes.WinDLL('user32', use_last_error=True)
    u.GetWindowThreadProcessId.argtypes = [W.HWND, ctypes.POINTER(W.DWORD)]
    u.GetWindowRect.argtypes = [W.HWND, ctypes.POINTER(W.RECT)]
    u.GetClientRect.argtypes = [W.HWND, ctypes.POINTER(W.RECT)]
    u.ClientToScreen.argtypes = [W.HWND, ctypes.POINTER(W.POINT)]
    u.SetForegroundWindow.argtypes = [W.HWND]
    u.GetForegroundWindow.restype = W.HWND
    u.WindowFromPoint.argtypes = [W.POINT]
    u.WindowFromPoint.restype = W.HWND
    u.GetAncestor.argtypes = [W.HWND, W.UINT]
    u.GetAncestor.restype = W.HWND
    u.PostMessageW.argtypes = [W.HWND, W.UINT, W.WPARAM, W.LPARAM]
    u.IsIconic.argtypes = [W.HWND]
    u.IsWindow.argtypes = [W.HWND]
    u.SetCursorPos.argtypes = [ctypes.c_int, ctypes.c_int]

    def matches():
        return [w for w in windows() if w['pid'] == client_pid and
                w['class'] == 'RAIL_WINDOW' and 'FRDP xcalc' in w['title']]
    found = matches()
    if len(found) != 1:
        raise RuntimeError('Calculator surrogate is not uniquely identified')
    hwnd = found[0]['hwnd']
    actions = report['native_actions'] = {}

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

    def wait_for(predicate, name, seconds=20):
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            if predicate():
                return
            time.sleep(0.2)
        raise RuntimeError('Native interaction timeout: ' + name)

    def visible_at(x, y):
        at = u.WindowFromPoint(W.POINT(x, y))
        return at == hwnd or u.GetAncestor(at, 2) == hwnd

    def focus():
        owned()
        u.SetForegroundWindow(hwnd)
        wait_for(lambda: u.GetForegroundWindow() == hwnd, 'calculator foreground', 5)

    class Mouse(ctypes.Structure):
        _fields_ = [('dx', W.LONG), ('dy', W.LONG), ('mouseData', W.DWORD),
                    ('flags', W.DWORD), ('time', W.DWORD), ('extra', ctypes.c_size_t)]
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

    def mouse_button(down):
        owned()
        event = Input()
        event.type = 0
        event.payload.mouse = Mouse(0, 0, 0, 2 if down else 4, 0, 0)
        if u.SendInput(1, ctypes.byref(event), ctypes.sizeof(Input)) != 1:
            raise RuntimeError('Mouse input was not submitted')

    def key(vk):
        owned()
        if u.GetForegroundWindow() != hwnd:
            raise RuntimeError('Foreground changed before keyboard input')
        events = (Input * 2)()
        events[0].type = events[1].type = 1
        events[0].payload.keyboard = Keyboard(vk, 0, 0, 0, 0)
        events[1].payload.keyboard = Keyboard(vk, 0, 2, 0, 0)
        if u.SendInput(2, events, ctypes.sizeof(Input)) != 2:
            raise RuntimeError('Keyboard input was not submitted')
        time.sleep(0.3)

    def screen_region(name):
        owned()
        r, p = W.RECT(), W.POINT(0, 0)
        if not u.GetClientRect(hwnd, ctypes.byref(r)) or not u.ClientToScreen(hwnd, ctypes.byref(p)):
            raise RuntimeError('Client rectangle unavailable')
        width, height = r.right-r.left-8, min(90, r.bottom-r.top-8)
        if width <= 0 or height <= 0 or p.x < 0 or p.y < 0:
            raise RuntimeError('Calculator capture bounds invalid')
        for x,y in [(p.x+8,p.y+8),(p.x+width-4,p.y+8),(p.x+width//2,p.y+height//2)]:
            if not visible_at(x,y):
                raise RuntimeError('Calculator display is obscured by another window')
        path = root/name
        ps('Add-Type -AssemblyName System.Drawing; '
           f'$b=New-Object Drawing.Bitmap({width},{height}); '
           '$g=[Drawing.Graphics]::FromImage($b); '
           f'$g.CopyFromScreen({p.x+4},{p.y+4},0,0,$b.Size); '
           f"$b.Save('{path}',[Drawing.Imaging.ImageFormat]::Png); $g.Dispose(); $b.Dispose()")
        return hashlib.sha256(path.read_bytes()).hexdigest()

    actions['initial_rect'] = rect()
    focus()
    r=rect();start=(r[0]+90,r[1]+9);target=(90+80,100+9)
    if not visible_at(*start):
        raise RuntimeError('Calculator caption is not available for a real drag')
    u.SetCursorPos(*start);time.sleep(.3);mouse_button(True)
    try:
        for i in range(1,17):
            u.SetCursorPos(round(start[0]+(target[0]-start[0])*i/16),
                           round(start[1]+(target[1]-start[1])*i/16))
            time.sleep(.12)
    finally:
        mouse_button(False)
    wait_for(lambda: abs(rect()[0]-80)<=12 and abs(rect()[1]-100)<=12,'real mouse drag')
    time.sleep(3)
    actions['moved_rect']=rect();actions['move_used_sendinput']=True
    screenshot('native-moved.png')
    focus();u.SetCursorPos(20,20);time.sleep(.5)
    actions['display_before_sha256']=screen_region('native-display-before.png')
    focus()
    for vk in (0x37,0x6B,0x32,0x0D):key(vk)
    time.sleep(3)
    actions['display_after_sha256']=screen_region('native-display-after.png')
    actions['input_pixels_changed']=actions['display_before_sha256']!=actions['display_after_sha256']
    screenshot('native-calculation.png')
    if not actions['input_pixels_changed']:
        raise RuntimeError('Focused visible calculator did not change after keyboard input')
    for command,name,predicate in [
        (0xF020,'minimized',lambda: bool(u.IsIconic(hwnd))),
        (0xF120,'restored',lambda: bool(matches()) and not u.IsIconic(hwnd))]:
        owned()
        if not u.PostMessageW(hwnd,0x0112,command,0):
            raise RuntimeError(name+' command was not posted')
        wait_for(predicate,name);time.sleep(3);actions[name]=True
        screenshot('native-'+name+'.png')
    owned()
    if not u.PostMessageW(hwnd,0x0112,0xF060,0):
        raise RuntimeError('Close command was not posted')
    wait_for(lambda: not matches(),'close');actions['closed']=True
    actions['interaction_pass']=True
