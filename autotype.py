"""OttoVault auto-type: types a login into whichever window has focus, using
Windows SendInput with Unicode key events (no extra packages). No GUI code.

The sequence building and event building are plain functions so they can be
unit-tested on any OS; only the final SendInput call is Windows-only."""
import ctypes
import os
import sys
import time

KEYEVENTF_KEYUP = 0x0002
KEYEVENTF_UNICODE = 0x0004
INPUT_KEYBOARD = 1
VK_TAB = 0x09
VK_RETURN = 0x0D
SCAN_TAB = 0x0F
SCAN_RETURN = 0x1C

MODES = ("both", "password", "username")


class AutoTypeError(Exception):
    pass


def is_supported():
    return sys.platform == "win32"


def build_sequence(username, password, mode="both"):
    """Tokens: ("text", str) / ("key", "tab"|"enter").
    both     -> username, Tab, password, Enter
    password -> password, Enter
    username -> username, Enter"""
    if mode not in MODES:
        raise ValueError("unknown auto-type mode: %r" % (mode,))
    tokens = []
    if mode == "both":
        if username:
            tokens += [("text", username), ("key", "tab")]
        if password:
            tokens.append(("text", password))
        if tokens:
            tokens.append(("key", "enter"))
    elif mode == "password":
        if password:
            tokens += [("text", password), ("key", "enter")]
    else:
        if username:
            tokens += [("text", username), ("key", "enter")]
    return tokens


def _utf16_units(ch):
    b = ch.encode("utf-16-le")
    return [int.from_bytes(b[i:i + 2], "little") for i in range(0, len(b), 2)]


def text_events(text):
    """(wVk, wScan, flags) tuples: a Unicode key down+up per UTF-16 unit.
    Newline / tab characters become real Enter / Tab keys."""
    ev = []
    for ch in text.replace("\r\n", "\n").replace("\r", "\n"):
        if ch == "\t":
            ev += _vk_events(VK_TAB, SCAN_TAB)
        elif ch == "\n":
            ev += _vk_events(VK_RETURN, SCAN_RETURN)
        else:
            for unit in _utf16_units(ch):
                ev.append((0, unit, KEYEVENTF_UNICODE))
                ev.append((0, unit, KEYEVENTF_UNICODE | KEYEVENTF_KEYUP))
    return ev


def _vk_events(vk, scan):
    return [(vk, scan, 0), (vk, scan, KEYEVENTF_KEYUP)]


def build_events(tokens):
    ev = []
    for kind, val in tokens:
        if kind == "text":
            ev += text_events(val)
        elif val == "tab":
            ev += _vk_events(VK_TAB, SCAN_TAB)
        elif val == "enter":
            ev += _vk_events(VK_RETURN, SCAN_RETURN)
        else:
            raise ValueError("bad token %r" % ((kind, val),))
    return ev


# ---- Windows plumbing (structures are plain ctypes, so they build anywhere)
class _KEYBDINPUT(ctypes.Structure):
    _fields_ = [("wVk", ctypes.c_uint16), ("wScan", ctypes.c_uint16),
                ("dwFlags", ctypes.c_uint32), ("time", ctypes.c_uint32),
                ("dwExtraInfo", ctypes.c_size_t)]


class _MOUSEINPUT(ctypes.Structure):
    _fields_ = [("dx", ctypes.c_int32), ("dy", ctypes.c_int32),
                ("mouseData", ctypes.c_uint32), ("dwFlags", ctypes.c_uint32),
                ("time", ctypes.c_uint32), ("dwExtraInfo", ctypes.c_size_t)]


class _HARDWAREINPUT(ctypes.Structure):
    _fields_ = [("uMsg", ctypes.c_uint32), ("wParamL", ctypes.c_uint16),
                ("wParamH", ctypes.c_uint16)]


class _INPUTUNION(ctypes.Union):
    _fields_ = [("ki", _KEYBDINPUT), ("mi", _MOUSEINPUT), ("hi", _HARDWAREINPUT)]


class INPUT(ctypes.Structure):
    _fields_ = [("type", ctypes.c_uint32), ("u", _INPUTUNION)]


def _win_sender(events):
    """Send a list of (vk, scan, flags) via user32.SendInput (Windows only)."""
    if not is_supported():
        raise AutoTypeError("Auto-type only works on Windows.")
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    user32.SendInput.argtypes = (ctypes.c_uint, ctypes.POINTER(INPUT), ctypes.c_int)
    user32.SendInput.restype = ctypes.c_uint
    n = len(events)
    arr = (INPUT * n)()
    for i, (vk, scan, flags) in enumerate(events):
        arr[i].type = INPUT_KEYBOARD
        arr[i].u.ki = _KEYBDINPUT(vk, scan, flags, 0, 0)
    sent = user32.SendInput(n, arr, ctypes.sizeof(INPUT))
    if sent != n:
        raise AutoTypeError(
            "Windows did not accept the keystrokes (the target window may be "
            "running as administrator).")


def send_events(events, sender=None, sleep=time.sleep, delay=0.004):
    """Send events one key (down+up pair) at a time with a tiny pause."""
    sender = sender or _win_sender
    for i in range(0, len(events), 2):
        sender(events[i:i + 2])
        if delay:
            sleep(delay)


def type_tokens(tokens, sender=None, sleep=time.sleep, delay=0.004):
    send_events(build_events(tokens), sender=sender, sleep=sleep, delay=delay)


def foreground_is_own_process():
    """True if the active window belongs to this program (so we must NOT type)."""
    if not is_supported():
        return False
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    user32.GetForegroundWindow.restype = ctypes.c_void_p
    user32.GetWindowThreadProcessId.argtypes = (ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32))
    hwnd = user32.GetForegroundWindow()
    if not hwnd:
        return False
    pid = ctypes.c_uint32(0)
    user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
    return pid.value == os.getpid()
