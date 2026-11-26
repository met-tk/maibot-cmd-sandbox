# -*- coding: utf-8 -*-
"""扩展硬件/网络/端口状态探测与后台轻量看门狗告警模块。"""

from __future__ import annotations

import asyncio
import ctypes
from ctypes import wintypes
import math
import os
import shutil
import socket
import string
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Awaitable, Callable

from .win32_desktop import Win32DesktopController


class _MEMORYSTATUSEX(ctypes.Structure):
    _fields_ = [
        ("dwLength", ctypes.c_ulong),
        ("dwMemoryLoad", ctypes.c_ulong),
        ("ullTotalPhys", ctypes.c_ulonglong),
        ("ullAvailPhys", ctypes.c_ulonglong),
        ("ullTotalPageFile", ctypes.c_ulonglong),
        ("ullAvailPageFile", ctypes.c_ulonglong),
        ("ullTotalVirtual", ctypes.c_ulonglong),
        ("ullAvailVirtual", ctypes.c_ulonglong),
        ("sullAvailExtendedVirtual", ctypes.c_ulonglong),
    ]


class _FILETIME(ctypes.Structure):
    _fields_ = [
        ("dwLowDateTime", wintypes.DWORD),
        ("dwHighDateTime", wintypes.DWORD),
    ]


class _SYSTEM_POWER_STATUS(ctypes.Structure):
    _fields_ = [
        ("ACLineStatus", ctypes.c_ubyte),
        ("BatteryFlag", ctypes.c_ubyte),
        ("BatteryLifePercent", ctypes.c_ubyte),
        ("SystemStatusFlag", ctypes.c_ubyte),
        ("BatteryLifeTime", wintypes.DWORD),
        ("BatteryFullLifeTime", wintypes.DWORD),
    ]


def _filetime_to_int(ft: _FILETIME) -> int:
    return (int(ft.dwHighDateTime) << 32) | int(ft.dwLowDateTime)


def _sample_cpu_usage() -> dict[str, Any]:
    info: dict[str, Any] = {"logical_cores": os.cpu_count() or 0}
    if os.name != "nt":
        return info
    try:
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        k32.GetSystemTimes.argtypes = [
            ctypes.POINTER(_FILETIME),
            ctypes.POINTER(_FILETIME),
            ctypes.POINTER(_FILETIME),
        ]
        k32.GetSystemTimes.restype = wintypes.BOOL
        idle1, kern1, user1 = _FILETIME(), _FILETIME(), _FILETIME()
        idle2, kern2, user2 = _FILETIME(), _FILETIME(), _FILETIME()
        if not k32.GetSystemTimes(ctypes.byref(idle1), ctypes.byref(kern1), ctypes.byref(user1)):
            return info
        time.sleep(0.2)
        if not k32.GetSystemTimes(ctypes.byref(idle2), ctypes.byref(kern2), ctypes.byref(user2)):
            return info

        idle_delta = _filetime_to_int(idle2) - _filetime_to_int(idle1)
        total_delta = (
            (_filetime_to_int(kern2) - _filetime_to_int(kern1))
            + (_filetime_to_int(user2) - _filetime_to_int(user1))
        )
        if total_delta > 0:
            busy = max(0.0, float(total_delta - idle_delta))
            pct = min(100.0, round((busy / float(total_delta)) * 100.0, 1))
            info["usage_percent"] = f"{pct}%"
            info["usage_value"] = pct
    except Exception as exc:
        info["error"] = str(exc)
    return info


def _get_battery_status() -> dict[str, Any]:
    if os.name != "nt":
        return {"has_battery": False}
    try:
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        k32.GetSystemPowerStatus.argtypes = [ctypes.POINTER(_SYSTEM_POWER_STATUS)]
        k32.GetSystemPowerStatus.restype = wintypes.BOOL
        sps = _SYSTEM_POWER_STATUS()
        if not k32.GetSystemPowerStatus(ctypes.byref(sps)):
            return {"has_battery": False}
        ac_online = sps.ACLineStatus == 1
        no_battery = bool(sps.BatteryFlag & 128) or sps.BatteryLifePercent == 255
        if no_battery:
            return {
                "has_battery": False,
                "ac_online": ac_online,
                "description": "台式机或未检测到电池（外接电源供电）",
            }
        return {
            "has_battery": True,
            "ac_online": ac_online,
            "percent": int(sps.BatteryLifePercent),
            "charging": bool(sps.BatteryFlag & 8),
        }
    except Exception as exc:
        return {"has_battery": False, "error": str(exc)}


def _get_nvidia_gpus() -> list[dict[str, Any]]:
    exe = shutil.which("nvidia-smi")
    if not exe:
        return []
    try:
        res = subprocess.run(
            [
                exe,
                "--query-gpu=name,utilization.gpu,memory.used,memory.total,temperature.gpu",
                "--format=csv,noheader,nounits",
            ],
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
        if res.returncode != 0 or not res.stdout.strip():
            return []
        gpus = []
        for idx, line in enumerate(res.stdout.strip().splitlines()):
            parts = [p.strip() for p in line.split(",")]
            if len(parts) >= 5:
                gpus.append(
                    {
                        "index": idx,
                        "name": parts[0],
                        "utilization_percent": f"{parts[1]}%",
                        "memory_used_mb": parts[2],
                        "memory_total_mb": parts[3],
                        "temperature_c": parts[4],
                    }
                )
        return gpus
    except Exception:
        return []


def _get_network_overview() -> dict[str, Any]:
    hostname = socket.gethostname()
    ips: list[str] = []
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.connect(("8.8.8.8", 80))
            primary_ip = sock.getsockname()[0]
            if primary_ip and not primary_ip.startswith("127."):
                ips.append(primary_ip)
        finally:
            sock.close()
    except Exception:
        pass

    try:
        for res in socket.getaddrinfo(hostname, None, socket.AF_INET):
            ip = res[4][0]
            if ip and not ip.startswith("127.") and ip not in ips:
                ips.append(ip)
    except Exception:
        pass

    return {"hostname": hostname, "ipv4_addresses": ips[:8]}


def _query_ports(port_query: str, desktop_ctrl: Win32DesktopController | None) -> list[dict[str, Any]]:
    q = str(port_query or "").strip().lower()
    if not q:
        return []
    try:
        res = subprocess.run(["netstat", "-ano"], capture_output=True, text=True, timeout=5, check=False)
        if res.returncode != 0:
            return []
        matches: list[dict[str, Any]] = []
        for line in res.stdout.splitlines():
            parts = line.split()
            if len(parts) < 4:
                continue
            proto = parts[0].upper()
            if proto not in ("TCP", "UDP"):
                continue
            local_addr = parts[1]
            foreign_addr = parts[2]
            state = parts[3] if proto == "TCP" and len(parts) >= 5 else ""
            pid_str = parts[-1] if parts[-1].isdigit() else "0"
            if q != "all" and q not in line.lower():
                continue
            proc_name = ""
            if desktop_ctrl is not None and pid_str.isdigit() and int(pid_str) > 0:
                proc_name = desktop_ctrl.get_process_name_by_pid(int(pid_str))
            matches.append(
                {
                    "proto": proto,
                    "local": local_addr,
                    "foreign": foreign_addr,
                    "state": state,
                    "pid": int(pid_str),
                    "process": proc_name or "unknown",
                }
            )
            if len(matches) >= 25:
                break
        return matches
    except Exception:
        return []


def list_local_disks() -> list[dict[str, Any]]:
    drives_info: list[dict[str, Any]] = []
    if os.name == "nt":
        candidates = [f"{letter}:\\" for letter in string.ascii_uppercase if os.path.exists(f"{letter}:\\")]
    else:
        candidates = ["/"]

    for drive_path in candidates:
        try:
            total, used, free = shutil.disk_usage(drive_path)
            total_gb = total / (1024**3)
            free_gb = free / (1024**3)
            used_pct = round((used / total) * 100, 1) if total > 0 else 0.0
            drives_info.append(
                {
                    "drive": drive_path.rstrip("\\") if os.name == "nt" else drive_path,
                    "total_gb": round(total_gb, 1),
                    "free_gb": round(free_gb, 1),
                    "used_percent": f"{used_pct}%",
                }
            )
        except Exception:
            continue
    return drives_info


def get_running_process_names() -> set[str]:
    """返回当前活跃进程名集合（全部小写）。"""
    names: set[str] = set()
    if os.name != "nt":
        return names
    try:
        res = subprocess.run(["tasklist", "/FO", "CSV", "/NH"], capture_output=True, text=True, timeout=5, check=False)
        for line in res.stdout.strip().splitlines():
            parts = line.split('","')
            if parts:
                name = parts[0].replace('"', "").strip().lower()
                if name:
                    names.add(name)
    except Exception:
        pass
    return names


def get_hardware_status_summary(
    workspace_path: Path,
    port_query: str = "",
    desktop_ctrl: Win32DesktopController | None = None,
) -> dict[str, Any]:
    """获取 Windows 系统实时硬件、网络、电源、GPU 与可选端口状态概览。"""
    summary: dict[str, Any] = {}

    summary["cpu"] = _sample_cpu_usage()

    try:
        stat = _MEMORYSTATUSEX()
        stat.dwLength = ctypes.sizeof(_MEMORYSTATUSEX)
        ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat))
        total_gb = stat.ullTotalPhys / (1024**3)
        avail_gb = stat.ullAvailPhys / (1024**3)
        used_gb = total_gb - avail_gb
        summary["memory"] = {
            "load_percent": f"{stat.dwMemoryLoad}%",
            "total_gb": round(total_gb, 2),
            "used_gb": round(used_gb, 2),
            "available_gb": round(avail_gb, 2),
        }
    except Exception as exc:
        summary["memory_error"] = str(exc)

    try:
        k32 = ctypes.windll.kernel32
        k32.GetTickCount64.argtypes = []
        k32.GetTickCount64.restype = ctypes.c_uint64
        uptime_ms = k32.GetTickCount64()
        uptime_sec = uptime_ms // 1000
        hours = uptime_sec // 3600
        mins = (uptime_sec % 3600) // 60
        summary["system"] = {
            "os": sys.platform,
            "uptime": f"{hours} 小时 {mins} 分钟",
        }
    except Exception as exc:
        summary["system_error"] = str(exc)

    summary["disks"] = list_local_disks()
    summary["battery"] = _get_battery_status()
    gpus = _get_nvidia_gpus()
    if gpus:
        summary["gpus"] = gpus
    summary["network"] = _get_network_overview()
    if str(port_query or "").strip():
        summary["ports"] = _query_ports(port_query, desktop_ctrl)
    summary["sandbox_workspace"] = str(workspace_path)
    return summary


class SystemWatchdog:
    """后台轻量运维看门狗：监控磁盘剩余空间、关键进程退出与锁屏状态变化并带冷却告警。"""

    def __init__(
        self,
        desktop_ctrl: Win32DesktopController,
        notify_callback: Callable[[str, str], Awaitable[None]],
    ) -> None:
        self._desktop_ctrl = desktop_ctrl
        self._notify_callback = notify_callback
        self.enabled = False
        self.interval_seconds = 60
        self.cooldown_seconds = 300
        self.disk_min_free_gb = 10.0
        self.watched_processes: list[str] = []
        self.watch_lock_state = False
        self.notify_stream_id = ""

        self._task: asyncio.Task[Any] | None = None
        self._last_lock_state: bool | None = None
        self._seen_running_procs: set[str] = set()
        self._last_alert_ts: dict[str, float] = {}

    def configure(
        self,
        enabled: bool | None = None,
        interval_seconds: int | None = None,
        cooldown_seconds: int | None = None,
        disk_min_free_gb: float | None = None,
        watched_processes: list[str] | None = None,
        watch_lock_state: bool | None = None,
        notify_stream_id: str | None = None,
    ) -> None:
        if enabled is not None:
            self.enabled = bool(enabled)
        if interval_seconds is not None:
            self.interval_seconds = max(10, int(interval_seconds))
        if cooldown_seconds is not None:
            self.cooldown_seconds = max(30, int(cooldown_seconds))
        if disk_min_free_gb is not None:
            val = float(disk_min_free_gb)
            if math.isfinite(val):
                self.disk_min_free_gb = max(0.0, val)
        if watched_processes is not None:
            cleaned = []
            for p in watched_processes:
                norm = str(p or "").strip().lower()
                if norm:
                    if not norm.endswith(".exe") and os.name == "nt":
                        norm = f"{norm}.exe"
                    if norm not in cleaned:
                        cleaned.append(norm)
            self.watched_processes = cleaned
        if watch_lock_state is not None:
            self.watch_lock_state = bool(watch_lock_state)
        if notify_stream_id is not None:
            self.notify_stream_id = str(notify_stream_id).strip()

    async def start(self) -> None:
        if self._task is not None and not self._task.done():
            return
        self.enabled = True
        self._last_lock_state = None
        self._seen_running_procs.clear()
        self._task = asyncio.create_task(self._run_loop())

    async def stop(self) -> None:
        self.enabled = False
        if self._task is not None and not self._task.done():
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):
                pass
        self._task = None

    def _can_alert(self, key: str, now: float) -> bool:
        prev = self._last_alert_ts.get(key, 0.0)
        if now - prev >= self.cooldown_seconds:
            self._last_alert_ts[key] = now
            return True
        return False

    async def run_single_check(self) -> list[str]:
        """执行单轮检测并返回需要推送的告警消息列表（便于直接测试与轮询复用）。"""
        now = time.time()
        alerts: list[str] = []

        if self.disk_min_free_gb > 0:
            disks = await asyncio.to_thread(list_local_disks)
            for d in disks:
                if float(d["free_gb"]) < self.disk_min_free_gb:
                    if self._can_alert(f"disk:{d['drive']}", now):
                        alerts.append(
                            f"【看门狗告警 - 磁盘空间不足】驱动器 {d['drive']} 仅剩 {d['free_gb']} GB（低于阈值 {self.disk_min_free_gb} GB）。"
                        )

        if self.watched_processes:
            running = await asyncio.to_thread(get_running_process_names)
            for proc in self.watched_processes:
                if proc in running:
                    self._seen_running_procs.add(proc)
                elif proc in self._seen_running_procs:
                    self._seen_running_procs.discard(proc)
                    if self._can_alert(f"proc:{proc}", now):
                        alerts.append(f"【看门狗告警 - 进程退出】受监控进程 {proc} 已不在活跃进程列表中。")

        if self.watch_lock_state:
            is_locked, reason = await asyncio.to_thread(self._desktop_ctrl.detect_screen_lock_state)
            if self._last_lock_state is not None and is_locked != self._last_lock_state:
                if self._can_alert("lock_state", now):
                    state_txt = f"已锁屏 ({reason})" if is_locked else "已解锁恢复桌面"
                    alerts.append(f"【看门狗通知 - 锁屏状态变更】电脑当前{state_txt}。")
            self._last_lock_state = is_locked

        return alerts

    async def _run_loop(self) -> None:
        try:
            while self.enabled:
                try:
                    alerts = await self.run_single_check()
                    for text in alerts:
                        await self._notify_callback(text, self.notify_stream_id)
                except asyncio.CancelledError:
                    raise
                except Exception:
                    pass
                await asyncio.sleep(self.interval_seconds)
        except asyncio.CancelledError:
            pass

    def get_status(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "running": self._task is not None and not self._task.done(),
            "interval_seconds": self.interval_seconds,
            "cooldown_seconds": self.cooldown_seconds,
            "disk_min_free_gb": self.disk_min_free_gb,
            "watched_processes": list(self.watched_processes),
            "observed_alive_processes": sorted(self._seen_running_procs),
            "watch_lock_state": self.watch_lock_state,
            "notify_stream_id": self.notify_stream_id,
        }
