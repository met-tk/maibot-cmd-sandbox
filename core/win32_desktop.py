# -*- coding: utf-8 -*-
"""Win32 锁屏探测、多粒度截图、窗口控制与受控键鼠交互模块。"""

from __future__ import annotations

import base64
import ctypes
from ctypes import wintypes
import io
import os
import re
import threading
import time
from pathlib import Path
from typing import Any, Callable

from .security_audit import PROTECTED_HARD_PROCESSES, PROTECTED_SOFT_PROCESSES


_ULONG_PTR = ctypes.c_uint64 if ctypes.sizeof(ctypes.c_void_p) == 8 else ctypes.c_uint32

_GUI_BLOCKED_FG_PROCESSES: frozenset[str] = frozenset(
    {
        "consent.exe",
        "lockapp.exe",
        "logonui.exe",
        "taskmgr.exe",
        "regedit.exe",
        "mmc.exe",
    }
)

_BLOCKED_HOTKEY_COMBOS: frozenset[frozenset[str]] = frozenset(
    {
        frozenset({"ctrl", "alt", "del"}),
        frozenset({"win", "l"}),
        frozenset({"win", "r"}),
        frozenset({"ctrl", "shift", "esc"}),
    }
)

_KEY_ALIAS_MAP: dict[str, str] = {
    "control": "ctrl",
    "lctrl": "ctrl",
    "rctrl": "ctrl",
    "menu": "alt",
    "lalt": "alt",
    "ralt": "alt",
    "lshift": "shift",
    "rshift": "shift",
    "lwin": "win",
    "rwin": "win",
    "super": "win",
    "meta": "win",
    "escape": "esc",
    "return": "enter",
    "delete": "del",
    "spacebar": "space",
    "pageup": "pgup",
    "pagedown": "pgdn",
}

_MODIFIER_VK: dict[str, int] = {
    "ctrl": 0x11,
    "shift": 0x10,
    "alt": 0x12,
    "win": 0x5B,
}

_SPECIAL_VK: dict[str, int] = {
    "backspace": 0x08,
    "tab": 0x09,
    "enter": 0x0D,
    "pause": 0x13,
    "capslock": 0x14,
    "esc": 0x1B,
    "space": 0x20,
    "pgup": 0x21,
    "pgdn": 0x22,
    "end": 0x23,
    "home": 0x24,
    "left": 0x25,
    "up": 0x26,
    "right": 0x27,
    "down": 0x28,
    "printscreen": 0x2C,
    "insert": 0x2D,
    "del": 0x2E,
    "volume_mute": 0xAD,
    "volume_down": 0xAE,
    "volume_up": 0xAF,
    "media_next": 0xB0,
    "media_prev": 0xB1,
    "media_stop": 0xB2,
    "media_play_pause": 0xB3,
}
for _fn_idx in range(1, 13):
    _SPECIAL_VK[f"f{_fn_idx}"] = 0x6F + _fn_idx


class _WTSINFOEX_LEVEL1(ctypes.Structure):
    _fields_ = [
        ("SessionId", wintypes.DWORD),
        ("SessionState", wintypes.DWORD),
        ("SessionFlags", wintypes.LONG),
        ("WinStationName", wintypes.WCHAR * 33),
        ("UserName", wintypes.WCHAR * 21),
        ("DomainName", wintypes.WCHAR * 18),
        ("LogonTime", wintypes.LARGE_INTEGER),
        ("ConnectTime", wintypes.LARGE_INTEGER),
        ("DisconnectTime", wintypes.LARGE_INTEGER),
        ("LastInputTime", wintypes.LARGE_INTEGER),
        ("CurrentTime", wintypes.LARGE_INTEGER),
        ("IncomingBytes", wintypes.DWORD),
        ("OutgoingBytes", wintypes.DWORD),
        ("IncomingFrames", wintypes.DWORD),
        ("OutgoingFrames", wintypes.DWORD),
        ("IncomingCompressedBytes", wintypes.DWORD),
        ("OutgoingCompressedBytes", wintypes.DWORD),
    ]


class _WTSINFOEX_LEVEL(ctypes.Union):
    _fields_ = [("WTSInfoExLevel1", _WTSINFOEX_LEVEL1)]


class _WTSINFOEXW(ctypes.Structure):
    _fields_ = [
        ("Level", wintypes.DWORD),
        ("Reserved", wintypes.DWORD),
        ("Data", _WTSINFOEX_LEVEL),
    ]


class _BITMAPINFOHEADER(ctypes.Structure):
    _fields_ = [
        ("biSize", wintypes.DWORD),
        ("biWidth", wintypes.LONG),
        ("biHeight", wintypes.LONG),
        ("biPlanes", wintypes.WORD),
        ("biBitCount", wintypes.WORD),
        ("biCompression", wintypes.DWORD),
        ("biSizeImage", wintypes.DWORD),
        ("biXPelsPerMeter", wintypes.LONG),
        ("biYPelsPerMeter", wintypes.LONG),
        ("biClrUsed", wintypes.DWORD),
        ("biClrImportant", wintypes.DWORD),
    ]


class _MOUSEINPUT(ctypes.Structure):
    _fields_ = [
        ("dx", wintypes.LONG),
        ("dy", wintypes.LONG),
        ("mouseData", wintypes.DWORD),
        ("dwFlags", wintypes.DWORD),
        ("time", wintypes.DWORD),
        ("dwExtraInfo", _ULONG_PTR),
    ]


class _KEYBDINPUT(ctypes.Structure):
    _fields_ = [
        ("wVk", wintypes.WORD),
        ("wScan", wintypes.WORD),
        ("dwFlags", wintypes.DWORD),
        ("time", wintypes.DWORD),
        ("dwExtraInfo", _ULONG_PTR),
    ]


class _HARDWAREINPUT(ctypes.Structure):
    _fields_ = [
        ("uMsg", wintypes.DWORD),
        ("wParamL", wintypes.WORD),
        ("wParamH", wintypes.WORD),
    ]


class _INPUT_UNION(ctypes.Union):
    _fields_ = [
        ("mi", _MOUSEINPUT),
        ("ki", _KEYBDINPUT),
        ("hi", _HARDWAREINPUT),
    ]


class _INPUT(ctypes.Structure):
    _fields_ = [
        ("type", wintypes.DWORD),
        ("union", _INPUT_UNION),
    ]


class Win32DesktopController:
    """Windows 桌面状态探测、多粒度截图、窗口控制与受控键鼠交互控制器。"""

    def __init__(self, logger_cb: Callable[[str, str, Any], None] | None = None) -> None:
        self._logger_cb = logger_cb
        self._win32_cache: dict[str, Any] | None = None
        self._win32_lock = threading.Lock()
        self._dpi_aware_initialized = False

    def _log(self, level: str, msg: str, *args: Any) -> None:
        if self._logger_cb is not None:
            try:
                self._logger_cb(level, msg, *args)
            except Exception:
                pass

    def get_win32_apis(self) -> dict[str, Any] | None:
        """延迟初始化并缓存带有完整 64 位签名类型的 Win32 DLL 接口。"""
        if os.name != "nt":
            return None
        with self._win32_lock:
            if self._win32_cache is not None:
                return self._win32_cache

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            user32 = ctypes.WinDLL("user32", use_last_error=True)
            gdi32 = ctypes.WinDLL("gdi32", use_last_error=True)
            wtsapi32 = ctypes.WinDLL("wtsapi32", use_last_error=True)
            try:
                dwmapi = ctypes.WinDLL("dwmapi", use_last_error=True)
            except Exception:
                dwmapi = None

            kernel32.GetCurrentProcessId.argtypes = []
            kernel32.GetCurrentProcessId.restype = wintypes.DWORD
            kernel32.GetCurrentThreadId.argtypes = []
            kernel32.GetCurrentThreadId.restype = wintypes.DWORD
            kernel32.ProcessIdToSessionId.argtypes = [wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
            kernel32.ProcessIdToSessionId.restype = wintypes.BOOL
            kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
            kernel32.OpenProcess.restype = wintypes.HANDLE
            kernel32.QueryFullProcessImageNameW.argtypes = [
                wintypes.HANDLE,
                wintypes.DWORD,
                wintypes.LPWSTR,
                ctypes.POINTER(wintypes.DWORD),
            ]
            kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL
            kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
            kernel32.CloseHandle.restype = wintypes.BOOL

            wtsapi32.WTSQuerySessionInformationW.argtypes = [
                wintypes.HANDLE,
                wintypes.DWORD,
                wintypes.DWORD,
                ctypes.POINTER(ctypes.c_void_p),
                ctypes.POINTER(wintypes.DWORD),
            ]
            wtsapi32.WTSQuerySessionInformationW.restype = wintypes.BOOL
            wtsapi32.WTSFreeMemory.argtypes = [ctypes.c_void_p]
            wtsapi32.WTSFreeMemory.restype = None

            user32.OpenInputDesktop.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
            user32.OpenInputDesktop.restype = wintypes.HANDLE
            user32.GetUserObjectInformationW.argtypes = [
                wintypes.HANDLE,
                ctypes.c_int,
                ctypes.c_void_p,
                wintypes.DWORD,
                ctypes.POINTER(wintypes.DWORD),
            ]
            user32.GetUserObjectInformationW.restype = wintypes.BOOL
            user32.CloseDesktop.argtypes = [wintypes.HANDLE]
            user32.CloseDesktop.restype = wintypes.BOOL
            user32.SystemParametersInfoW.argtypes = [wintypes.UINT, wintypes.UINT, ctypes.c_void_p, wintypes.UINT]
            user32.SystemParametersInfoW.restype = wintypes.BOOL
            user32.GetForegroundWindow.argtypes = []
            user32.GetForegroundWindow.restype = wintypes.HWND
            user32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
            user32.GetWindowThreadProcessId.restype = wintypes.DWORD
            user32.IsWindow.argtypes = [wintypes.HWND]
            user32.IsWindow.restype = wintypes.BOOL
            user32.IsWindowVisible.argtypes = [wintypes.HWND]
            user32.IsWindowVisible.restype = wintypes.BOOL
            user32.IsIconic.argtypes = [wintypes.HWND]
            user32.IsIconic.restype = wintypes.BOOL
            user32.IsZoomed.argtypes = [wintypes.HWND]
            user32.IsZoomed.restype = wintypes.BOOL
            user32.GetWindowLongW.argtypes = [wintypes.HWND, ctypes.c_int]
            user32.GetWindowLongW.restype = ctypes.c_long
            user32.GetWindowTextLengthW.argtypes = [wintypes.HWND]
            user32.GetWindowTextLengthW.restype = ctypes.c_int
            user32.GetWindowTextW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
            user32.GetWindowTextW.restype = ctypes.c_int
            user32.GetWindowRect.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.RECT)]
            user32.GetWindowRect.restype = wintypes.BOOL
            user32.GetWindowDC.argtypes = [wintypes.HWND]
            user32.GetWindowDC.restype = wintypes.HDC
            user32.ReleaseDC.argtypes = [wintypes.HWND, wintypes.HDC]
            user32.ReleaseDC.restype = ctypes.c_int
            user32.PrintWindow.argtypes = [wintypes.HWND, wintypes.HDC, wintypes.UINT]
            user32.PrintWindow.restype = wintypes.BOOL
            user32.ShowWindow.argtypes = [wintypes.HWND, ctypes.c_int]
            user32.ShowWindow.restype = wintypes.BOOL
            user32.SetForegroundWindow.argtypes = [wintypes.HWND]
            user32.SetForegroundWindow.restype = wintypes.BOOL
            user32.BringWindowToTop.argtypes = [wintypes.HWND]
            user32.BringWindowToTop.restype = wintypes.BOOL
            user32.AttachThreadInput.argtypes = [wintypes.DWORD, wintypes.DWORD, wintypes.BOOL]
            user32.AttachThreadInput.restype = wintypes.BOOL
            user32.SetWindowPos.argtypes = [
                wintypes.HWND,
                wintypes.HWND,
                ctypes.c_int,
                ctypes.c_int,
                ctypes.c_int,
                ctypes.c_int,
                wintypes.UINT,
            ]
            user32.SetWindowPos.restype = wintypes.BOOL
            user32.PostMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
            user32.PostMessageW.restype = wintypes.BOOL
            user32.GetSystemMetrics.argtypes = [ctypes.c_int]
            user32.GetSystemMetrics.restype = ctypes.c_int
            user32.SendInput.argtypes = [wintypes.UINT, ctypes.POINTER(_INPUT), ctypes.c_int]
            user32.SendInput.restype = wintypes.UINT
            enum_proc_type = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
            user32.EnumWindows.argtypes = [enum_proc_type, wintypes.LPARAM]
            user32.EnumWindows.restype = wintypes.BOOL

            gdi32.CreateCompatibleDC.argtypes = [wintypes.HDC]
            gdi32.CreateCompatibleDC.restype = wintypes.HDC
            gdi32.CreateDIBSection.argtypes = [
                wintypes.HDC,
                ctypes.c_void_p,
                wintypes.UINT,
                ctypes.POINTER(ctypes.c_void_p),
                wintypes.HANDLE,
                wintypes.DWORD,
            ]
            gdi32.CreateDIBSection.restype = wintypes.HBITMAP
            gdi32.SelectObject.argtypes = [wintypes.HDC, wintypes.HGDIOBJ]
            gdi32.SelectObject.restype = wintypes.HGDIOBJ
            gdi32.DeleteObject.argtypes = [wintypes.HGDIOBJ]
            gdi32.DeleteObject.restype = wintypes.BOOL
            gdi32.DeleteDC.argtypes = [wintypes.HDC]
            gdi32.DeleteDC.restype = wintypes.BOOL

            if dwmapi is not None:
                dwmapi.DwmGetWindowAttribute.argtypes = [
                    wintypes.HWND,
                    wintypes.DWORD,
                    ctypes.c_void_p,
                    wintypes.DWORD,
                ]
                # 使用 c_long 避免负 HRESULT 值触发 ctypes 自动抛 OSError
                dwmapi.DwmGetWindowAttribute.restype = ctypes.c_long

            self._win32_cache = {
                "kernel32": kernel32,
                "user32": user32,
                "gdi32": gdi32,
                "wtsapi32": wtsapi32,
                "dwmapi": dwmapi,
                "enum_proc_type": enum_proc_type,
            }
            return self._win32_cache

    def ensure_dpi_aware(self) -> None:
        """统一进程 DPI 感知，避免高分屏下窗口矩形坐标与 mss 物理像素不一致。"""
        if os.name != "nt" or self._dpi_aware_initialized:
            return
        self._dpi_aware_initialized = True
        try:
            user32 = ctypes.WinDLL("user32", use_last_error=True)
            user32.SetProcessDpiAwarenessContext.argtypes = [ctypes.c_void_p]
            user32.SetProcessDpiAwarenessContext.restype = wintypes.BOOL
            if user32.SetProcessDpiAwarenessContext(ctypes.c_void_p(-4)):
                return
        except Exception:
            pass
        try:
            ctypes.WinDLL("shcore", use_last_error=True).SetProcessDpiAwareness(2)
            return
        except Exception:
            pass
        try:
            ctypes.WinDLL("user32", use_last_error=True).SetProcessDPIAware()
        except Exception:
            pass

    def get_process_name_by_pid(self, pid: int) -> str:
        """根据 PID 获取进程可执行文件名（失败返回空串）。"""
        if not pid or os.name != "nt":
            return ""
        apis = self.get_win32_apis()
        if not apis:
            return ""
        kernel32 = apis["kernel32"]
        handle = kernel32.OpenProcess(0x1000, False, int(pid))
        if not handle:
            return ""
        try:
            buf_len = wintypes.DWORD(512)
            buf = ctypes.create_unicode_buffer(buf_len.value)
            if kernel32.QueryFullProcessImageNameW(handle, 0, buf, ctypes.byref(buf_len)):
                return Path(buf.value).name
        except Exception:
            pass
        finally:
            kernel32.CloseHandle(handle)
        return ""

    def detect_screen_lock_state(self) -> tuple[bool, str]:
        """精确探测当前 Windows 会话是否处于锁屏、屏保或安全桌面隔离状态。"""
        apis = self.get_win32_apis()
        if not apis:
            return False, ""

        kernel32 = apis["kernel32"]
        user32 = apis["user32"]
        wtsapi32 = apis["wtsapi32"]

        try:
            session_id = wintypes.DWORD(0)
            if kernel32.ProcessIdToSessionId(kernel32.GetCurrentProcessId(), ctypes.byref(session_id)):
                pp_buf = ctypes.c_void_p()
                bytes_ret = wintypes.DWORD(0)
                if (
                    wtsapi32.WTSQuerySessionInformationW(
                        None, session_id.value, 25, ctypes.byref(pp_buf), ctypes.byref(bytes_ret)
                    )
                    and pp_buf.value
                ):
                    try:
                        if bytes_ret.value >= ctypes.sizeof(_WTSINFOEXW):
                            info = ctypes.cast(pp_buf, ctypes.POINTER(_WTSINFOEXW)).contents
                            if info.Level == 1:
                                lvl1 = info.Data.WTSInfoExLevel1
                                if lvl1.SessionState == 4:
                                    return True, "当前 Windows 桌面会话已断开（无活跃显示输出）"
                                if lvl1.SessionFlags == 0:
                                    return True, "当前电脑处于 Windows 锁屏状态（会话已锁定）"
                    finally:
                        wtsapi32.WTSFreeMemory(pp_buf)
        except Exception as exc:
            self._log("debug", "WTS 锁屏状态探测异常: %s", exc)

        try:
            hdesk = user32.OpenInputDesktop(0, False, 0x0001)
            if not hdesk:
                return True, "当前系统处于安全桌面隔离状态（锁屏密码界面或系统 UAC 弹窗）"
            try:
                name_buf = ctypes.create_unicode_buffer(256)
                needed = wintypes.DWORD(0)
                if user32.GetUserObjectInformationW(hdesk, 2, name_buf, ctypes.sizeof(name_buf), ctypes.byref(needed)):
                    desk_name = name_buf.value.strip()
                    if desk_name and desk_name.lower() != "default":
                        return True, f"当前输入桌面已切换为「{desk_name}」（锁屏或系统安全桌面）"
            finally:
                user32.CloseDesktop(hdesk)
        except Exception as exc:
            self._log("debug", "OpenInputDesktop 探测异常: %s", exc)

        try:
            saver_running = wintypes.BOOL(False)
            if user32.SystemParametersInfoW(114, 0, ctypes.byref(saver_running), 0) and saver_running.value:
                return True, "当前电脑正在运行屏幕保护程序"
        except Exception:
            pass

        try:
            fg_hwnd = user32.GetForegroundWindow()
            if fg_hwnd:
                fg_pid = wintypes.DWORD(0)
                user32.GetWindowThreadProcessId(fg_hwnd, ctypes.byref(fg_pid))
                proc_name = self.get_process_name_by_pid(fg_pid.value).lower()
                if proc_name in ("lockapp.exe", "logonui.exe"):
                    return True, f"当前前台为 Windows 锁屏界面（{proc_name}）"
        except Exception:
            pass

        return False, ""

    def get_window_bounds(self, hwnd: int) -> tuple[tuple[int, int, int, int], tuple[int, int, int, int]]:
        """获取窗口的 (GetWindowRect物理外框, DWM实际可见边框)。"""
        apis = self.get_win32_apis()
        assert apis is not None
        user32 = apis["user32"]
        dwmapi = apis["dwmapi"]

        wr = wintypes.RECT()
        user32.GetWindowRect(hwnd, ctypes.byref(wr))
        win_rect = (wr.left, wr.top, wr.right, wr.bottom)

        ext = wintypes.RECT()
        ext_rect = win_rect
        if dwmapi is not None:
            try:
                hr = dwmapi.DwmGetWindowAttribute(hwnd, 9, ctypes.byref(ext), ctypes.sizeof(ext))
                if hr == 0 and ext.right > ext.left and ext.bottom > ext.top:
                    ext_rect = (ext.left, ext.top, ext.right, ext.bottom)
            except OSError:
                pass

        return win_rect, ext_rect

    def get_monitors_info(self) -> tuple[dict[str, int] | None, list[dict[str, Any]]]:
        """获取虚拟桌面总范围与各物理显示器坐标信息。"""
        self.ensure_dpi_aware()
        try:
            from mss import MSS

            with MSS() as sct:
                mons = sct.monitors
                virtual = None
                if mons:
                    virtual = {
                        "left": int(mons[0]["left"]),
                        "top": int(mons[0]["top"]),
                        "width": int(mons[0]["width"]),
                        "height": int(mons[0]["height"]),
                    }
                physical = [
                    {
                        "index": idx,
                        "is_primary": bool(m.get("is_primary", False)),
                        "left": int(m["left"]),
                        "top": int(m["top"]),
                        "width": int(m["width"]),
                        "height": int(m["height"]),
                    }
                    for idx, m in enumerate(mons[1:], start=1)
                ]
                return virtual, physical
        except Exception as exc:
            self._log("warning", "读取显示器列表失败: %s", exc)
            return None, []

    def enumerate_windows(self, query: str = "") -> list[dict[str, Any]]:
        """枚举当前桌面可见顶层窗口（按 Z-order 排序，前台窗口置前）。"""
        apis = self.get_win32_apis()
        if not apis:
            return []
        self.ensure_dpi_aware()

        user32 = apis["user32"]
        dwmapi = apis["dwmapi"]
        enum_proc_type = apis["enum_proc_type"]

        fg_hwnd = user32.GetForegroundWindow()
        q_lower = str(query or "").strip().lower()
        results: list[dict[str, Any]] = []
        excluded_procs = {"lockapp.exe", "logonui.exe", "textinputhost.exe"}

        def _enum_cb(hwnd: int, _lparam: int) -> bool:
            try:
                if not user32.IsWindowVisible(hwnd):
                    return True

                if dwmapi is not None:
                    cloaked = wintypes.DWORD(0)
                    try:
                        if dwmapi.DwmGetWindowAttribute(hwnd, 14, ctypes.byref(cloaked), ctypes.sizeof(cloaked)) == 0:
                            if cloaked.value != 0:
                                return True
                    except OSError:
                        pass

                ex_style = user32.GetWindowLongW(hwnd, -20)
                if ex_style & 0x00000080:
                    return True

                title_len = user32.GetWindowTextLengthW(hwnd)
                if title_len <= 0:
                    return True
                title_buf = ctypes.create_unicode_buffer(title_len + 1)
                user32.GetWindowTextW(hwnd, title_buf, title_len + 1)
                title = title_buf.value.strip()
                if not title or title == "Program Manager":
                    return True

                pid = wintypes.DWORD(0)
                user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
                proc_name = self.get_process_name_by_pid(pid.value)
                if proc_name.lower() in excluded_procs:
                    return True

                is_minimized = bool(user32.IsIconic(hwnd))
                is_maximized = bool(user32.IsZoomed(hwnd))
                _, ext_rect = self.get_window_bounds(hwnd)
                width = ext_rect[2] - ext_rect[0]
                height = ext_rect[3] - ext_rect[1]

                if not is_minimized and (width <= 1 or height <= 1):
                    return True

                if q_lower:
                    if q_lower not in title.lower() and q_lower not in proc_name.lower() and q_lower != str(hwnd):
                        return True

                results.append(
                    {
                        "hwnd": int(hwnd),
                        "title": title[:160],
                        "process": proc_name or "unknown",
                        "pid": int(pid.value),
                        "left": int(ext_rect[0]),
                        "top": int(ext_rect[1]),
                        "width": int(width),
                        "height": int(height),
                        "minimized": is_minimized,
                        "maximized": is_maximized,
                        "foreground": int(hwnd) == int(fg_hwnd or 0),
                    }
                )
            except Exception:
                return True
            return True

        cb_ref = enum_proc_type(_enum_cb)
        user32.EnumWindows(cb_ref, 0)

        results.sort(key=lambda item: (not item["foreground"], item["minimized"]))
        return results

    def resolve_target_window(self, window_spec: str) -> tuple[dict[str, Any] | None, str]:
        """根据 HWND、进程名或标题关键字解析目标窗口。"""
        spec = str(window_spec or "").strip()
        if not spec:
            return None, "未指定目标窗口名称或 HWND。"

        windows = self.enumerate_windows()

        hwnd_val: int | None = None
        if spec.isdigit():
            hwnd_val = int(spec)
        elif spec.lower().startswith("0x"):
            try:
                hwnd_val = int(spec, 16)
            except ValueError:
                hwnd_val = None

        if hwnd_val is not None:
            for w in windows:
                if w["hwnd"] == hwnd_val:
                    return w, ""
            apis = self.get_win32_apis()
            if apis and apis["user32"].IsWindow(hwnd_val):
                user32 = apis["user32"]
                title_len = user32.GetWindowTextLengthW(hwnd_val)
                title_buf = ctypes.create_unicode_buffer(max(1, title_len + 1))
                if title_len > 0:
                    user32.GetWindowTextW(hwnd_val, title_buf, title_len + 1)
                pid = wintypes.DWORD(0)
                user32.GetWindowThreadProcessId(hwnd_val, ctypes.byref(pid))
                _, ext_rect = self.get_window_bounds(hwnd_val)
                return (
                    {
                        "hwnd": hwnd_val,
                        "title": title_buf.value.strip() or f"HWND {hwnd_val}",
                        "process": self.get_process_name_by_pid(pid.value) or "unknown",
                        "pid": int(pid.value),
                        "left": int(ext_rect[0]),
                        "top": int(ext_rect[1]),
                        "width": int(ext_rect[2] - ext_rect[0]),
                        "height": int(ext_rect[3] - ext_rect[1]),
                        "minimized": bool(user32.IsIconic(hwnd_val)),
                        "maximized": bool(user32.IsZoomed(hwnd_val)),
                        "foreground": False,
                    },
                    "",
                )
            return None, f"未找到句柄为 {spec} 的有效窗口。"

        spec_lower = spec.lower()
        exact_matches = []
        fuzzy_matches = []
        for w in windows:
            proc_l = w["process"].lower()
            proc_stem = proc_l[:-4] if proc_l.endswith(".exe") else proc_l
            title_l = w["title"].lower()
            if spec_lower in (proc_l, proc_stem, title_l):
                exact_matches.append(w)
            elif spec_lower in proc_l or spec_lower in title_l:
                fuzzy_matches.append(w)

        candidates = exact_matches or fuzzy_matches
        if not candidates:
            return None, f"未找到匹配「{spec}」的桌面窗口，可先调用 list_desktop_windows 查看当前打开的窗口。"

        for w in candidates:
            if not w["minimized"]:
                return w, ""
        return candidates[0], ""

    @staticmethod
    def is_image_all_black(img: Any) -> bool:
        """检查图像是否所有 RGB 像素均为纯黑。"""
        try:
            extrema = img.convert("RGB").getextrema()
            return all(hi == 0 for _, hi in extrema)
        except Exception:
            return False

    @staticmethod
    def parse_region(region_str: str) -> tuple[tuple[int, int, int, int] | None, str]:
        """解析 'x,y,width,height' 格式的区域裁剪参数。"""
        clean = str(region_str or "").strip().strip("[]()")
        if not clean:
            return None, ""
        parts = [p for p in re.split(r"[,\s]+", clean) if p]
        if len(parts) != 4:
            return None, f"区域参数格式错误：'{region_str}'，应为 'x,y,width,height'（四个整数）。"
        try:
            x, y, w, h = (int(float(p)) for p in parts)
        except ValueError:
            return None, f"区域参数包含非数字内容：'{region_str}'。"
        if w <= 0 or h <= 0:
            return None, f"区域宽高必须大于 0（当前: width={w}, height={h}）。"
        return (x, y, w, h), ""

    def capture_window_image(self, win_info: dict[str, Any]) -> tuple[bool, Any, str, dict[str, Any]]:
        """使用 PrintWindow(PW_RENDERFULLCONTENT) 独立捕获指定窗口内容（可穿透遮挡）。"""
        apis = self.get_win32_apis()
        if not apis:
            return False, None, "当前系统不支持 Win32 窗口级捕获。", {}

        if win_info.get("minimized"):
            return (
                False,
                None,
                f"窗口「{win_info['title']}」（{win_info['process']}）当前处于最小化状态，系统未渲染其画面，可先调用 control_window(action='restore') 恢复后再试。",
                {},
            )

        hwnd = int(win_info["hwnd"])
        user32 = apis["user32"]
        gdi32 = apis["gdi32"]
        win_rect, ext_rect = self.get_window_bounds(hwnd)
        gw = win_rect[2] - win_rect[0]
        gh = win_rect[3] - win_rect[1]

        if gw <= 0 or gh <= 0 or gw > 16384 or gh > 16384:
            return False, None, f"目标窗口「{win_info['title']}」尺寸异常 ({gw}x{gh})，无法截图。", {}

        from PIL import Image

        hdc_win = user32.GetWindowDC(hwnd)
        if not hdc_win:
            return False, None, f"无法获取窗口「{win_info['title']}」的设备上下文。", {}

        mem_dc = None
        hbmp = None
        old_bmp = None
        try:
            mem_dc = gdi32.CreateCompatibleDC(hdc_win)
            if not mem_dc:
                return False, None, "创建内存绘制上下文失败。", {}

            bmi = _BITMAPINFOHEADER()
            bmi.biSize = ctypes.sizeof(_BITMAPINFOHEADER)
            bmi.biWidth = gw
            bmi.biHeight = -gh
            bmi.biPlanes = 1
            bmi.biBitCount = 32
            bmi.biCompression = 0

            bits = ctypes.c_void_p()
            hbmp = gdi32.CreateDIBSection(mem_dc, ctypes.byref(bmi), 0, ctypes.byref(bits), None, 0)
            if not hbmp or not bits.value:
                return False, None, "创建窗口位图缓冲区失败。", {}

            old_bmp = gdi32.SelectObject(mem_dc, hbmp)

            ok = user32.PrintWindow(hwnd, mem_dc, 2)
            raw = ctypes.string_at(bits.value, gw * gh * 4)
            img = Image.frombytes("RGB", (gw, gh), raw, "raw", "BGRX")

            if not ok or self.is_image_all_black(img):
                ok_fallback = user32.PrintWindow(hwnd, mem_dc, 0)
                if ok_fallback:
                    raw = ctypes.string_at(bits.value, gw * gh * 4)
                    img = Image.frombytes("RGB", (gw, gh), raw, "raw", "BGRX")

            if self.is_image_all_black(img):
                return (
                    False,
                    None,
                    f"窗口「{win_info['title']}」（{win_info['process']}）捕获结果为空白或纯黑，可能因窗口启用了硬件受保护渲染（DRM）或处于挂起状态。",
                    {},
                )

            crop_left = max(0, ext_rect[0] - win_rect[0])
            crop_top = max(0, ext_rect[1] - win_rect[1])
            crop_right = min(gw, ext_rect[2] - win_rect[0])
            crop_bottom = min(gh, ext_rect[3] - win_rect[1])
            if (
                crop_right > crop_left
                and crop_bottom > crop_top
                and (crop_left > 0 or crop_top > 0 or crop_right < gw or crop_bottom < gh)
            ):
                img = img.crop((crop_left, crop_top, crop_right, crop_bottom))

            desc = f"窗口「{win_info['title']}」({win_info['process']}, HWND: {hwnd}, 分辨率: {img.width}x{img.height})"
            meta = {
                "mode": "window",
                "hwnd": hwnd,
                "title": win_info["title"],
                "process": win_info["process"],
                "bounds": {
                    "left": int(ext_rect[0]),
                    "top": int(ext_rect[1]),
                    "width": int(img.width),
                    "height": int(img.height),
                },
            }
            return True, img, desc, meta
        except Exception as exc:
            return False, None, f"窗口捕获过程中出现异常: {exc}", {}
        finally:
            if mem_dc and old_bmp:
                gdi32.SelectObject(mem_dc, old_bmp)
            if hbmp:
                gdi32.DeleteObject(hbmp)
            if mem_dc:
                gdi32.DeleteDC(mem_dc)
            user32.ReleaseDC(hwnd, hdc_win)

    def capture_desktop_image(
        self,
        screen: str = "primary",
        window: str = "",
        region: str = "",
    ) -> tuple[bool, Any, str, dict[str, Any]]:
        """统一抓取桌面、指定窗口或局部区域图像（含锁屏拦截）。"""
        is_locked, lock_reason = self.detect_screen_lock_state()
        if is_locked:
            return (
                False,
                None,
                f"电脑当前处于锁屏状态（{lock_reason}），无法获取实时桌面画面，已中止截图（未返回锁屏图片）。",
                {"locked": True, "lock_reason": lock_reason},
            )

        parsed_region, reg_err = self.parse_region(region)
        if reg_err:
            return False, None, reg_err, {}

        img = None
        desc = ""
        meta: dict[str, Any] = {"locked": False}

        win_clean = str(window or "").strip()
        if win_clean:
            win_info, win_err = self.resolve_target_window(win_clean)
            if not win_info:
                return False, None, win_err, {}
            ok, img, desc, meta = self.capture_window_image(win_info)
            if not ok or img is None:
                return False, None, desc, meta
        else:
            self.ensure_dpi_aware()
            try:
                from PIL import Image
                from mss import MSS

                with MSS() as sct:
                    monitors = sct.monitors
                    target_monitor = None
                    screen_lower = str(screen or "primary").lower().strip()

                    if screen_lower in ("all", "0", "全屏", "全部", "全景"):
                        target_monitor = monitors[0]
                        desc = f"全部屏幕全景 (合并分辨率: {target_monitor['width']}x{target_monitor['height']})"
                    elif screen_lower in ("primary", "main", "主屏", "主屏幕"):
                        for idx, m in enumerate(monitors[1:], start=1):
                            if m.get("is_primary"):
                                target_monitor = m
                                desc = f"主显示器 (屏幕 {idx}, 分辨率: {m['width']}x{m['height']})"
                                break
                        if not target_monitor:
                            target_monitor = monitors[1] if len(monitors) > 1 else monitors[0]
                            desc = f"主显示器 (默认屏幕, 分辨率: {target_monitor['width']}x{target_monitor['height']})"
                    else:
                        try:
                            idx = int(screen_lower)
                            if 0 <= idx < len(monitors):
                                target_monitor = monitors[idx]
                                desc = f"显示器 {idx} (分辨率: {target_monitor['width']}x{target_monitor['height']})"
                        except ValueError:
                            pass

                    if not target_monitor:
                        target_monitor = monitors[1] if len(monitors) > 1 else monitors[0]
                        desc = f"默认显示器 (分辨率: {target_monitor['width']}x{target_monitor['height']})"

                    sct_img = sct.grab(target_monitor)
                    img = Image.frombytes("RGB", sct_img.size, sct_img.bgra, "raw", "BGRX")
                    meta = {
                        "mode": "screen",
                        "bounds": {
                            "left": int(target_monitor["left"]),
                            "top": int(target_monitor["top"]),
                            "width": int(target_monitor["width"]),
                            "height": int(target_monitor["height"]),
                        },
                    }
            except Exception as exc:
                self._log("warning", "使用 mss 多屏抓取失败，尝试回退: %s", exc)

            if img is None:
                try:
                    from PIL import ImageGrab

                    all_scr = str(screen or "").lower().strip() in ("all", "0", "全屏", "全部", "全景")
                    img = ImageGrab.grab(all_screens=all_scr).convert("RGB")
                    desc = f"屏幕截图 (回退模式, 分辨率: {img.width}x{img.height})"
                    meta = {"mode": "screen_fallback"}
                except Exception:
                    pass

            if img is None:
                return (
                    False,
                    None,
                    "截图失败：当前 Windows 桌面图形输出受限（可能处于息屏或会话隔离状态），请在桌面解锁且显示器点亮状态下重试。",
                    {},
                )

        if parsed_region is not None:
            rx, ry, rw, rh = parsed_region
            left = max(0, rx)
            top = max(0, ry)
            right = min(img.width, rx + rw)
            bottom = min(img.height, ry + rh)
            if right <= left or bottom <= top:
                return (
                    False,
                    None,
                    f"裁剪区域 ({rx}, {ry}, {rw}x{rh}) 超出当前图像有效范围 (0, 0, {img.width}x{img.height})。",
                    {},
                )
            img = img.crop((left, top, right, bottom))
            desc = f"{desc} -> 区域裁剪 ({left}, {top}, {img.width}x{img.height})"
            meta["crop_region"] = {
                "x": int(left),
                "y": int(top),
                "width": int(img.width),
                "height": int(img.height),
            }

        meta["image_size"] = {"width": int(img.width), "height": int(img.height)}
        return True, img, desc, meta

    def capture_and_encode(
        self,
        screen: str = "primary",
        save_path: Path | None = None,
        window: str = "",
        region: str = "",
    ) -> tuple[bool, str, str, dict[str, Any]]:
        """统一执行抓图、落盘与 Base64 PNG 编码，并返回扩展元信息。"""
        ok, img, desc, meta = self.capture_desktop_image(screen=screen, window=window, region=region)
        if not ok or img is None:
            return False, "", desc, meta

        try:
            if save_path:
                save_path.parent.mkdir(parents=True, exist_ok=True)
                img.save(str(save_path), format="PNG")

            buf = io.BytesIO()
            img.save(buf, format="PNG")
            b64 = base64.b64encode(buf.getvalue()).decode("ascii")
            return True, b64, f"截图成功：{desc}", meta
        except Exception as exc:
            return False, "", f"图像处理编码失败: {exc}", {}

    @staticmethod
    def _parse_int(value: Any, name: str) -> tuple[int | None, str]:
        """将外部传入的可选数值安全转换为整数。"""
        if value is None or isinstance(value, bool):
            return None, f"参数 {name} 必须为有效整数。"
        try:
            return int(value), ""
        except (TypeError, ValueError):
            return None, f"参数 {name} 格式无效: {value!r}，必须为整数。"

    def _is_protected_window_proc(
        self,
        win_info: dict[str, Any],
        self_pid: int | None = None,
        parent_pid: int | None = None,
        for_close_or_input: bool = False,
    ) -> str | None:
        proc_l = str(win_info.get("process") or "").strip().lower()
        pid = int(win_info.get("pid") or 0)
        if self_pid and pid == self_pid and for_close_or_input:
            return "禁止关闭或向宿主自身进程窗口注入操作。"
        if parent_pid and pid == parent_pid and for_close_or_input:
            return "禁止关闭或向父级守护进程窗口注入操作。"
        if proc_l in PROTECTED_HARD_PROCESSES or proc_l in ("lockapp.exe", "logonui.exe"):
            return f"安全拦截：禁止操作受保护系统关键窗口 ({proc_l})。"
        if for_close_or_input and proc_l in PROTECTED_SOFT_PROCESSES:
            return f"安全拦截：禁止直接关闭桌面核心进程窗口 ({proc_l})。"
        return None

    def control_window(
        self,
        window_spec: str,
        action: str,
        x: int | None = None,
        y: int | None = None,
        width: int | None = None,
        height: int | None = None,
        self_pid: int | None = None,
        parent_pid: int | None = None,
    ) -> tuple[bool, str, dict[str, Any]]:
        """控制指定窗口状态（恢复、最小化、最大化、置前、置顶切换、移动缩放、温和关闭）。"""
        apis = self.get_win32_apis()
        if not apis:
            return False, "当前操作系统不支持 Win32 窗口控制。", {}

        is_locked, lock_reason = self.detect_screen_lock_state()
        if is_locked:
            return False, f"操作拒绝：{lock_reason}，锁屏状态下禁止操控桌面窗口。", {"locked": True}

        self.ensure_dpi_aware()
        win_info, err = self.resolve_target_window(window_spec)
        if not win_info:
            return False, err, {}

        act = str(action or "").lower().strip()
        block_msg = self._is_protected_window_proc(
            win_info,
            self_pid=self_pid,
            parent_pid=parent_pid,
            for_close_or_input=(act in ("close", "关闭")),
        )
        if block_msg:
            return False, block_msg, {}

        hwnd = int(win_info["hwnd"])
        user32 = apis["user32"]
        kernel32 = apis["kernel32"]

        if act in ("restore", "恢复"):
            user32.ShowWindow(hwnd, 9)
            msg = f"已恢复窗口「{win_info['title']}」({win_info['process']})"
        elif act in ("minimize", "min", "最小化"):
            user32.ShowWindow(hwnd, 6)
            msg = f"已最小化窗口「{win_info['title']}」({win_info['process']})"
        elif act in ("maximize", "max", "最大化"):
            user32.ShowWindow(hwnd, 3)
            msg = f"已最大化窗口「{win_info['title']}」({win_info['process']})"
        elif act in ("focus", "activate", "置前", "激活"):
            if user32.IsIconic(hwnd):
                user32.ShowWindow(hwnd, 9)
            fg_hwnd = user32.GetForegroundWindow()
            cur_tid = kernel32.GetCurrentThreadId()
            fg_tid = user32.GetWindowThreadProcessId(fg_hwnd, None) if fg_hwnd else 0
            attached = False
            try:
                if fg_tid and fg_tid != cur_tid:
                    attached = bool(user32.AttachThreadInput(cur_tid, fg_tid, True))
                user32.BringWindowToTop(hwnd)
                user32.SetForegroundWindow(hwnd)
            finally:
                if attached:
                    user32.AttachThreadInput(cur_tid, fg_tid, False)
            msg = f"已激活并置前窗口「{win_info['title']}」({win_info['process']})"
        elif act in ("topmost", "topmost_on", "topmost_off", "置顶"):
            # GWL_EXSTYLE = -20, WS_EX_TOPMOST = 0x00000008
            ex_style = user32.GetWindowLongW(hwnd, -20)
            currently_top = bool(ex_style & 0x00000008)
            if act == "topmost_on":
                enable_top = True
            elif act == "topmost_off":
                enable_top = False
            else:
                enable_top = not currently_top
            hwnd_insert = wintypes.HWND(-1 if enable_top else -2)
            # SWP_NOMOVE | SWP_NOSIZE = 0x0002 | 0x0001
            ok = user32.SetWindowPos(hwnd, hwnd_insert, 0, 0, 0, 0, 0x0003)
            if not ok:
                return False, f"切换窗口置顶状态失败（可能需要更高权限）。", {}
            state_txt = "置顶" if enable_top else "取消置顶"
            msg = f"已将窗口「{win_info['title']}」设为{state_txt}"
        elif act in ("move_resize", "move", "resize", "移动", "调整大小"):
            if user32.IsIconic(hwnd):
                user32.ShowWindow(hwnd, 9)
            cur_rect, _ = self.get_window_bounds(hwnd)
            parsed_coords: dict[str, int] = {}
            defaults = {
                "x": int(cur_rect[0]),
                "y": int(cur_rect[1]),
                "width": int(cur_rect[2] - cur_rect[0]),
                "height": int(cur_rect[3] - cur_rect[1]),
            }
            for fname, fval in (("x", x), ("y", y), ("width", width), ("height", height)):
                if fval is None:
                    parsed_coords[fname] = defaults[fname]
                else:
                    ival, p_err = self._parse_int(fval, fname)
                    if ival is None:
                        return False, p_err, {}
                    parsed_coords[fname] = ival
            nx, ny = parsed_coords["x"], parsed_coords["y"]
            nw, nh = parsed_coords["width"], parsed_coords["height"]
            if nw < 50 or nh < 50 or nw > 16384 or nh > 16384:
                return False, f"目标窗口尺寸不合法 ({nw}x{nh})，宽高需在 50~16384 像素之间。", {}
            # SWP_NOZORDER = 0x0004
            ok = user32.SetWindowPos(hwnd, None, nx, ny, nw, nh, 0x0004)
            if not ok:
                return False, "移动或调整窗口尺寸失败（可能受权限隔离限制）。", {}
            msg = f"已调整窗口「{win_info['title']}」位置与尺寸为 ({nx}, {ny}, {nw}x{nh})"
        elif act in ("close", "关闭"):
            # WM_CLOSE = 0x0010
            ok = user32.PostMessageW(hwnd, 0x0010, 0, 0)
            if not ok:
                return False, f"向窗口「{win_info['title']}」发送关闭信号失败。", {}
            msg = f"已向窗口「{win_info['title']}」({win_info['process']}) 发送温和关闭请求 (WM_CLOSE)"
        else:
            return (
                False,
                f"不支持的窗口控制动作: {action}。支持: restore、minimize、maximize、focus、topmost、topmost_on、topmost_off、move_resize、close。",
                {},
            )

        if user32.IsWindow(hwnd):
            _, new_ext = self.get_window_bounds(hwnd)
        else:
            new_ext = (
                int(win_info.get("left", 0)),
                int(win_info.get("top", 0)),
                int(win_info.get("left", 0)) + int(win_info.get("width", 0)),
                int(win_info.get("top", 0)) + int(win_info.get("height", 0)),
            )
        return (
            True,
            msg,
            {
                "hwnd": hwnd,
                "title": win_info["title"],
                "process": win_info["process"],
                "action": act,
                "bounds": {
                    "left": int(new_ext[0]),
                    "top": int(new_ext[1]),
                    "width": int(new_ext[2] - new_ext[0]),
                    "height": int(new_ext[3] - new_ext[1]),
                },
            },
        )

    def _check_blocked_foreground(
        self,
        self_pid: int | None = None,
        parent_pid: int | None = None,
    ) -> tuple[int, str, str | None]:
        """检查当前前台窗口是否属于受保护系统界面、宿主进程或父进程。"""
        apis = self.get_win32_apis()
        if not apis:
            return 0, "", None
        user32 = apis["user32"]
        fg_hwnd = user32.GetForegroundWindow()
        if not fg_hwnd:
            return 0, "", None
        fg_pid = wintypes.DWORD(0)
        user32.GetWindowThreadProcessId(fg_hwnd, ctypes.byref(fg_pid))
        pid_val = int(fg_pid.value)
        fg_proc = self.get_process_name_by_pid(pid_val).lower() if pid_val else ""
        blocked_pids = {p for p in (self_pid, parent_pid) if p}
        blocked_procs = _GUI_BLOCKED_FG_PROCESSES | PROTECTED_HARD_PROCESSES | {"maibot onekey.exe"}
        if pid_val in blocked_pids or fg_proc in blocked_procs:
            return int(fg_hwnd), fg_proc, f"安全拦截：当前前台为受保护或宿主进程窗口 ({fg_proc or pid_val})，拒绝注入键鼠事件。"
        return int(fg_hwnd), fg_proc, None

    @staticmethod
    def _make_mouse_input(dx: int, dy: int, flags: int, mouse_data: int = 0) -> _INPUT:
        inp = _INPUT()
        inp.type = 0  # INPUT_MOUSE
        inp.union.mi = _MOUSEINPUT(
            dx=dx,
            dy=dy,
            mouseData=ctypes.c_uint32(mouse_data).value,
            dwFlags=flags,
            time=0,
            dwExtraInfo=0,
        )
        return inp

    @staticmethod
    def _make_key_input(vk: int = 0, scan: int = 0, flags: int = 0) -> _INPUT:
        inp = _INPUT()
        inp.type = 1  # INPUT_KEYBOARD
        inp.union.ki = _KEYBDINPUT(
            wVk=vk,
            wScan=scan,
            dwFlags=flags,
            time=0,
            dwExtraInfo=0,
        )
        return inp

    def _dispatch_inputs(self, inputs: list[_INPUT]) -> bool:
        if not inputs:
            return True
        apis = self.get_win32_apis()
        assert apis is not None
        user32 = apis["user32"]
        arr = (_INPUT * len(inputs))(*inputs)
        sent = user32.SendInput(len(inputs), arr, ctypes.sizeof(_INPUT))
        return sent == len(inputs)

    @staticmethod
    def _parse_hotkey(keys_str: str) -> tuple[list[int], list[int], str]:
        """解析组合键字符串（如 'ctrl+s', 'alt+tab', 'volume_up'），返回 (修饰键VK列表, 主键VK列表, 错误)。"""
        raw = str(keys_str or "").strip().lower()
        if not raw:
            return [], [], "快捷键参数 keys 不能为空。"
        tokens = [t.strip() for t in re.split(r"[+\s]+", raw) if t.strip()]
        if not tokens:
            return [], [], "快捷键参数解析为空。"

        normalized = [_KEY_ALIAS_MAP.get(t, t) for t in tokens]
        combo_set = frozenset(normalized)
        for blocked in _BLOCKED_HOTKEY_COMBOS:
            if blocked.issubset(combo_set):
                return [], [], f"安全拦截：禁止注入高危系统级热键 ({keys_str})。"

        mod_vks: list[int] = []
        main_vks: list[int] = []
        for tok in normalized:
            if tok in _MODIFIER_VK:
                vk = _MODIFIER_VK[tok]
                if vk not in mod_vks:
                    mod_vks.append(vk)
            elif tok in _SPECIAL_VK:
                main_vks.append(_SPECIAL_VK[tok])
            elif len(tok) == 1 and ("a" <= tok <= "z" or "0" <= tok <= "9"):
                main_vks.append(ord(tok.upper()))
            else:
                return [], [], f"不支持的按键标识: '{tok}'。"

        if not main_vks and not mod_vks:
            return [], [], "未解析到有效按键。"
        if len(main_vks) > 2:
            return [], [], "单次 hotkey 最多允许组合 2 个非修饰主键。"
        return mod_vks, main_vks, ""

    def send_gui_input(
        self,
        action: str,
        x: int | None = None,
        y: int | None = None,
        text: str = "",
        keys: str = "",
        delta: int = 0,
        window: str = "",
        max_text_len: int = 500,
        self_pid: int | None = None,
        parent_pid: int | None = None,
    ) -> tuple[bool, str, dict[str, Any]]:
        """受控键鼠交互（强制锁屏拦截、宿主/系统安全窗口隔离、焦点切换核验与危险热键拦截）。"""
        apis = self.get_win32_apis()
        if not apis:
            return False, "当前操作系统不支持 Win32 键鼠交互。", {}

        is_locked, lock_reason = self.detect_screen_lock_state()
        if is_locked:
            return False, f"安全拦截：{lock_reason}，锁屏状态下严禁注入键鼠操作。", {"locked": True}

        self.ensure_dpi_aware()
        _, _, fg_err = self._check_blocked_foreground(self_pid=self_pid, parent_pid=parent_pid)
        if fg_err:
            return False, fg_err, {}

        win_clean = str(window or "").strip()
        win_bounds: tuple[int, int, int, int] | None = None
        if win_clean:
            target_info, target_err = self.resolve_target_window(win_clean)
            if not target_info:
                return False, target_err, {}
            prot_err = self._is_protected_window_proc(
                target_info,
                self_pid=self_pid,
                parent_pid=parent_pid,
                for_close_or_input=True,
            )
            if prot_err:
                return False, prot_err, {}

            ok_focus, focus_msg, focus_meta = self.control_window(
                str(target_info["hwnd"]),
                "focus",
                self_pid=self_pid,
                parent_pid=parent_pid,
            )
            if not ok_focus:
                return False, focus_msg, {}
            time.sleep(0.06)
            fg_hwnd_after, _, fg_err_after = self._check_blocked_foreground(self_pid=self_pid, parent_pid=parent_pid)
            if fg_err_after:
                return False, fg_err_after, {}
            if fg_hwnd_after != int(focus_meta["hwnd"]):
                return (
                    False,
                    f"操作中止：未能成功将焦点切换至目标窗口「{target_info['title']}」（受 Windows 前台焦点锁定保护），为防止误操作已取消键鼠注入。",
                    {},
                )
            b = focus_meta.get("bounds") or {}
            win_bounds = (
                int(b.get("left", 0)),
                int(b.get("top", 0)),
                int(b.get("width", 0)),
                int(b.get("height", 0)),
            )

        user32 = apis["user32"]
        act = str(action or "").lower().strip()

        def _compute_abs_mouse_norm() -> tuple[int, int, int, int] | tuple[None, None, None, str]:
            # SM_XVIRTUALSCREEN=76, SM_YVIRTUALSCREEN=77, SM_CXVIRTUALSCREEN=78, SM_CYVIRTUALSCREEN=79
            vleft = user32.GetSystemMetrics(76)
            vtop = user32.GetSystemMetrics(77)
            vw = user32.GetSystemMetrics(78)
            vh = user32.GetSystemMetrics(79)
            if vw <= 1 or vh <= 1:
                return None, None, None, "无法获取有效的虚拟桌面屏幕尺寸。"

            if win_bounds is not None:
                wx, wy, ww, wh = win_bounds
                if x is None and y is None:
                    abs_x = wx + max(0, ww // 2)
                    abs_y = wy + max(0, wh // 2)
                elif x is None or y is None:
                    return None, None, None, "使用坐标操作时请同时提供 x 和 y。"
                else:
                    ix, err_x = self._parse_int(x, "x")
                    iy, err_y = self._parse_int(y, "y")
                    if ix is None or iy is None:
                        return None, None, None, err_x or err_y
                    abs_x = wx + ix
                    abs_y = wy + iy
            else:
                if x is None or y is None:
                    return None, None, None, "未指定目标窗口时，鼠标坐标操作必须提供 x 与 y。"
                ix, err_x = self._parse_int(x, "x")
                iy, err_y = self._parse_int(y, "y")
                if ix is None or iy is None:
                    return None, None, None, err_x or err_y
                abs_x = ix
                abs_y = iy

            if not (vleft <= abs_x < vleft + vw and vtop <= abs_y < vtop + vh):
                return (
                    None,
                    None,
                    None,
                    f"目标坐标 ({abs_x}, {abs_y}) 超出虚拟桌面范围 ({vleft},{vtop} {vw}x{vh})。",
                )
            norm_x = int(((abs_x - vleft) * 65535) / max(1, vw - 1))
            norm_y = int(((abs_y - vtop) * 65535) / max(1, vh - 1))
            return norm_x, norm_y, abs_x, abs_y

        if act in ("move", "click", "double_click", "right_click", "middle_click", "scroll"):
            if act == "scroll" and x is None and y is None and win_bounds is None:
                idelta, err_d = self._parse_int(delta, "delta")
                if idelta is None:
                    return False, err_d, {}
                steps = max(-50, min(50, idelta))
                if steps == 0:
                    return False, "滚轮操作 scroll 的 delta 不能为 0。", {}
                ok_s = self._dispatch_inputs([self._make_mouse_input(0, 0, 0x0800, steps * 120)])
                if not ok_s:
                    return False, "SendInput 滚轮事件注入失败（可能受 UIPI 权限隔离）。", {}
                return True, f"已发送鼠标滚轮滚动 delta={steps}", {"action": act, "delta": steps}

            res = _compute_abs_mouse_norm()
            if res[0] is None:
                return False, str(res[3]), {}
            norm_x, norm_y, abs_x, abs_y = res  # type: ignore[misc]
            move_flags = 0x0001 | 0x8000 | 0x4000  # MOVE | ABSOLUTE | VIRTUALDESK

            events: list[_INPUT] = [self._make_mouse_input(norm_x, norm_y, move_flags)]
            if act == "click":
                events.extend(
                    [
                        self._make_mouse_input(norm_x, norm_y, move_flags | 0x0002),
                        self._make_mouse_input(norm_x, norm_y, move_flags | 0x0004),
                    ]
                )
            elif act == "double_click":
                for _ in range(2):
                    events.extend(
                        [
                            self._make_mouse_input(norm_x, norm_y, move_flags | 0x0002),
                            self._make_mouse_input(norm_x, norm_y, move_flags | 0x0004),
                        ]
                    )
            elif act == "right_click":
                events.extend(
                    [
                        self._make_mouse_input(norm_x, norm_y, move_flags | 0x0008),
                        self._make_mouse_input(norm_x, norm_y, move_flags | 0x0010),
                    ]
                )
            elif act == "middle_click":
                events.extend(
                    [
                        self._make_mouse_input(norm_x, norm_y, move_flags | 0x0020),
                        self._make_mouse_input(norm_x, norm_y, move_flags | 0x0040),
                    ]
                )
            elif act == "scroll":
                idelta, err_d = self._parse_int(delta, "delta")
                if idelta is None:
                    return False, err_d, {}
                steps = max(-50, min(50, idelta))
                if steps == 0:
                    return False, "滚轮操作 scroll 的 delta 不能为 0。", {}
                events.append(self._make_mouse_input(0, 0, 0x0800, steps * 120))

            if not self._dispatch_inputs(events):
                return False, "SendInput 鼠标操作注入失败（目标窗口可能处于管理员提权级别 UIPI 隔离中）。", {}
            return True, f"已执行鼠标操作 {act} 坐标 ({abs_x}, {abs_y})", {"action": act, "x": abs_x, "y": abs_y}

        if act == "type_text":
            txt = str(text or "")
            if not txt:
                return False, "type_text 的 text 内容不能为空。", {}
            if len(txt) > max_text_len:
                return False, f"输入文本过长（{len(txt)} 字符），单次上限为 {max_text_len} 字符。", {}
            events = []
            for ch in txt:
                if ch == "\r":
                    continue
                if ch == "\n":
                    events.append(self._make_key_input(vk=0x0D, flags=0))
                    events.append(self._make_key_input(vk=0x0D, flags=0x0002))
                elif ch == "\t":
                    events.append(self._make_key_input(vk=0x09, flags=0))
                    events.append(self._make_key_input(vk=0x09, flags=0x0002))
                else:
                    utf16 = ch.encode("utf-16-le")
                    for idx in range(0, len(utf16), 2):
                        code_unit = int.from_bytes(utf16[idx : idx + 2], "little")
                        events.append(self._make_key_input(vk=0, scan=code_unit, flags=0x0004))
                        events.append(self._make_key_input(vk=0, scan=code_unit, flags=0x0004 | 0x0002))
            if not self._dispatch_inputs(events):
                return False, "SendInput 文本输入失败（目标窗口可能受 UIPI 隔离）。", {}
            return True, f"已向当前焦点输入 {len(txt)} 个字符", {"action": act, "length": len(txt)}

        if act == "hotkey":
            mod_vks, main_vks, err_hk = self._parse_hotkey(keys)
            if err_hk:
                return False, err_hk, {}
            events = []
            for vk in mod_vks:
                events.append(self._make_key_input(vk=vk, flags=0))
            for vk in main_vks:
                events.append(self._make_key_input(vk=vk, flags=0))
            for vk in reversed(main_vks):
                events.append(self._make_key_input(vk=vk, flags=0x0002))
            for vk in reversed(mod_vks):
                events.append(self._make_key_input(vk=vk, flags=0x0002))
            if not self._dispatch_inputs(events):
                return False, "SendInput 快捷键注入失败（目标窗口可能受 UIPI 隔离）。", {}
            return True, f"已发送组合快捷键: {keys}", {"action": act, "keys": keys}

        return (
            False,
            f"不支持的键鼠动作: {action}。支持: click、double_click、right_click、middle_click、move、scroll、type_text、hotkey。",
            {},
        )
