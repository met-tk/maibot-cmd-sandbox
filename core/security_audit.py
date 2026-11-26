# -*- coding: utf-8 -*-
"""安全风控判定、二次确认票据管理与结构化审计日志模块。"""

from __future__ import annotations

import json
import os
import re
import threading
import time
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Callable


PROTECTED_HARD_PROCESSES: frozenset[str] = frozenset(
    {
        "csrss.exe",
        "wininit.exe",
        "winlogon.exe",
        "lsass.exe",
        "smss.exe",
        "services.exe",
        "system",
        "registry",
        "ntoskrnl.exe",
    }
)

PROTECTED_SOFT_PROCESSES: frozenset[str] = frozenset(
    {
        "explorer.exe",
        "dwm.exe",
        "svchost.exe",
        "maibot onekey.exe",
    }
)

_SENSITIVE_KEY_RE = re.compile(
    r"(password|passwd|pwd|token|secret|api[_-]?key|authorization|cookie|credential)",
    re.IGNORECASE,
)

_CMD_SECRET_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"(Bearer\s+)([A-Za-z0-9\-._~+/]+=*)", re.IGNORECASE), r"\1[REDACTED]"),
    (re.compile(r"(Authorization\s*:\s*(?:Basic|Token)\s+)([^\s\"']+)", re.IGNORECASE), r"\1[REDACTED]"),
    (re.compile(r"(X-Api-Key\s*:\s*)([^\s\"']+)", re.IGNORECASE), r"\1[REDACTED]"),
    (re.compile(r"(https?://[^/\s:@]+:)([^/\s@]+)(@)", re.IGNORECASE), r"\1[REDACTED]\3"),
    (
        re.compile(
            r"((?:--?|/)(?:password|passwd|pwd|token|secret|api[-_]?key|key)(?:\s*[=:]\s*|\s+))(\"[^\"]*\"|'[^']*'|[^\s]+)",
            re.IGNORECASE,
        ),
        r"\1[REDACTED]",
    ),
    (
        re.compile(
            r"(\b[A-Z0-9_]*(?:PASSWORD|PASSWD|PWD|TOKEN|SECRET|API_KEY|APIKEY)\s*[=:]\s*)(\"[^\"]*\"|'[^']*'|[^\s;]+)",
            re.IGNORECASE,
        ),
        r"\1[REDACTED]",
    ),
    (re.compile(r"\b(sk-[A-Za-z0-9_-]{12,}|gh[pou]_[A-Za-z0-9]{16,}|AKIA[0-9A-Z]{16})\b"), "[REDACTED]"),
)

_HIGH_RISK_COMMAND_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(r"(?:^|[\s;|&])rm\s+-[a-z]*r[a-z]*f|\brm\s+-rf\b|\brm\s+-r\b", re.IGNORECASE),
        "包含递归强制删除指令 (rm -r/-rf)",
    ),
    (
        re.compile(r"\bRemove-Item\b(?=.*(?:-Recurse|-Force))", re.IGNORECASE | re.DOTALL),
        "包含递归或强制删除指令 (Remove-Item -Recurse/-Force)",
    ),
    (
        re.compile(r"(?:^|[\s;|&])(?:del|erase)\s+[^\r\n]*(?:/s|/q)", re.IGNORECASE),
        "包含批量静默或递归删除指令 (del /s 或 /q)",
    ),
    (
        re.compile(r"(?:^|[\s;|&])(?:rd|rmdir)\s+[^\r\n]*/s", re.IGNORECASE),
        "包含递归目录删除指令 (rd/rmdir /s)",
    ),
    (
        re.compile(r"(?:^|[\s;|&])format(?:\.com)?\s+[a-z]:|\bFormat-Volume\b|\bdiskpart\b|\bClear-Disk\b", re.IGNORECASE),
        "包含磁盘格式化或分区破坏指令",
    ),
    (
        re.compile(r"\bcipher\s+/w|\bbcdedit\b|\bvssadmin\s+delete\b", re.IGNORECASE),
        "包含引导配置、卷影删除或磁盘擦除指令",
    ),
    (
        re.compile(r"\breg(?:\.exe)?\s+(?:add|delete|import)\b", re.IGNORECASE),
        "包含注册表写入或删除操作 (reg add/delete/import)",
    ),
    (
        re.compile(
            r"\b(?:Set-ItemProperty|New-ItemProperty|Remove-ItemProperty)\b[^\r\n]*(?:HKLM:|HKCU:|HKCR:|Registry::)",
            re.IGNORECASE,
        ),
        "包含 PowerShell 注册表修改操作",
    ),
    (
        re.compile(r"\bsc(?:\.exe)?\s+(?:create|config|delete|stop)\b", re.IGNORECASE),
        "包含系统服务变更操作 (sc)",
    ),
    (
        re.compile(r"\bschtasks(?:\.exe)?\s+/(?:create|delete|change)\b", re.IGNORECASE),
        "包含计划任务变更操作 (schtasks)",
    ),
    (
        re.compile(r"\bnet(?:\.exe)?\s+(?:user|localgroup)\b", re.IGNORECASE),
        "包含系统账户或用户组变更操作 (net user/localgroup)",
    ),
    (
        re.compile(r"\b(?:Set-MpPreference|Add-MpPreference)\b|\bnetsh\s+advfirewall\b", re.IGNORECASE),
        "包含安全防护或防火墙规则修改",
    ),
    (
        re.compile(r"\btakeown\b|\bicacls\b", re.IGNORECASE),
        "包含文件所有权或权限 ACL 变更 (takeown/icacls)",
    ),
    (
        re.compile(r"\bshutdown(?:\.exe)?\b|\bStop-Computer\b|\bRestart-Computer\b", re.IGNORECASE),
        "包含系统关机或重启指令",
    ),
    (
        re.compile(
            r"(?:^|\s)-(?:e|en|enc|ec|encodedcommand)(?:\s+|:)|\bFromBase64String\b|\b(?:iex|Invoke-Expression)\b|\bDownloadString\b|\bDownloadFile\b|\b(?:Invoke-WebRequest|iwr|irm|Invoke-RestMethod)\b|\bcertutil(?:\.exe)?\s+-urlcache\b",
            re.IGNORECASE,
        ),
        "包含编码混淆、远程下载或动态脚本执行特征",
    ),
)

_WRITE_OP_RE = re.compile(
    r"(?:>>?|\b(?:Out-File|Set-Content|Add-Content|Tee-Object|Copy-Item|Move-Item|New-Item|Remove-Item|Clear-Content|Rename-Item|Set-Item|del|erase|ri|ren|xcopy|robocopy)\b)",
    re.IGNORECASE,
)
_QUOTED_DRIVE_PATH_RE = re.compile(r"['\"]([A-Za-z]:[\\/][^'\"]+)['\"]")
_BARE_DRIVE_PATH_RE = re.compile(r"([A-Za-z]:[\\/][^\s\"'`;|&><]+)")
_UNC_PATH_RE = re.compile(r"(\\\\[A-Za-z0-9_.-]+\\[^\s\"'`;|&><]+)")
_REL_ESCAPE_RE = re.compile(r"(?:^|[\s'\"=>(])(?:\.\.[\\/])+")
_ENV_HOME_ESCAPE_RE = re.compile(r"(?:\$env:|\$HOME\b|%[A-Za-z0-9_]+%|~[\\/])", re.IGNORECASE)


def sanitize_command_text(text: str) -> str:
    """对命令文本中的常见凭据与令牌进行正则脱敏。"""
    cleaned = str(text or "")
    for pat, repl in _CMD_SECRET_PATTERNS:
        cleaned = pat.sub(repl, cleaned)
    return cleaned


def sanitize_value(value: Any, key_hint: str = "", max_str_len: int = 400) -> Any:
    """递归脱敏并截断审计记录中的参数对象。"""
    if key_hint and _SENSITIVE_KEY_RE.search(key_hint):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {
            str(k): sanitize_value(v, key_hint=str(k), max_str_len=max_str_len)
            for k, v in list(value.items())[:40]
        }
    if isinstance(value, (list, tuple, set)):
        return [sanitize_value(v, key_hint=key_hint, max_str_len=max_str_len) for v in list(value)[:40]]
    if isinstance(value, Path):
        value = str(value)
    if isinstance(value, str):
        text = sanitize_command_text(value)
        if len(text) > max_str_len:
            return text[:max_str_len] + "...[truncated]"
        return text
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    text = sanitize_command_text(str(value))
    if len(text) > max_str_len:
        return text[:max_str_len] + "...[truncated]"
    return text


def _path_within_workspace(raw_path: str, workspace_dir: Path) -> bool:
    """判断路径字符串（解析符号链接与相对段后）是否落在沙盒工作区内部。"""
    from .file_ops import is_path_in_sandbox

    return is_path_in_sandbox(Path(raw_path), workspace_dir)


def assess_process_kill_risk(
    query: str,
    self_pid: int,
    parent_pid: int | None = None,
    resolved_process_name: str = "",
    self_proc_name: str = "",
    parent_proc_name: str = "",
) -> tuple[str, list[str]]:
    """评估终止进程的风险等级：blocked（禁止）、high（需确认）、low（常规）。"""
    q = str(query or "").strip()
    reasons: list[str] = []

    if q.isdigit():
        pid_val = int(q)
        if pid_val in (0, 4):
            return "blocked", ["禁止终止 Windows 内核系统进程 (PID 0/4)"]
        if pid_val == self_pid:
            return "blocked", ["禁止终止当前插件宿主自身进程"]
        if parent_pid is not None and pid_val == parent_pid:
            return "blocked", ["禁止终止当前插件的父级守护进程"]

    candidates = []
    if q and not q.isdigit():
        q_low = q.lower()
        candidates.append(q_low if q_low.endswith(".exe") else f"{q_low}.exe")
        candidates.append(q_low)
    if resolved_process_name:
        r_low = resolved_process_name.strip().lower()
        candidates.append(r_low)
        if not r_low.endswith(".exe"):
            candidates.append(f"{r_low}.exe")

    for name in candidates:
        if name in PROTECTED_HARD_PROCESSES:
            reasons.append(f"进程 {name} 属于系统核心关键进程，绝对禁止终止")
            return "blocked", reasons

    host_names = {n.strip().lower() for n in (self_proc_name, parent_proc_name) if n and n.strip()}
    if not q.isdigit():
        for name in candidates:
            if name in host_names:
                reasons.append(f"按进程名强杀 {name} 可能会连带终止当前宿主或父进程自身")
                return "high", reasons

    for name in candidates:
        if name in PROTECTED_SOFT_PROCESSES:
            reasons.append(f"进程 {name} 属于桌面关键服务进程，需要管理员二次确认")
            return "high", reasons

    return "low", reasons


def assess_command_risk(
    command: str,
    workspace_dir: Path,
    sandbox_only_write: bool = True,
    working_dir: Path | None = None,
) -> tuple[str, list[str]]:
    """评估终端命令风险等级：high（需二次确认）或 low（可直接执行）。"""
    cmd = str(command or "").strip()
    if not cmd:
        return "low", []

    reasons: list[str] = []
    for pat, desc in _HIGH_RISK_COMMAND_PATTERNS:
        if pat.search(cmd):
            reasons.append(desc)

    if re.search(r"\b(?:taskkill|Stop-Process|kill)\b", cmd, re.IGNORECASE):
        all_protected = PROTECTED_HARD_PROCESSES | PROTECTED_SOFT_PROCESSES
        for proc in all_protected:
            stem = proc[:-4] if proc.endswith(".exe") else proc
            if re.search(rf"(?<![\w.-]){re.escape(stem)}(?:\.exe)?(?![\w.-])", cmd, re.IGNORECASE):
                reasons.append(f"命令试图终止受保护系统或宿主进程 ({proc})")
                break

    if sandbox_only_write:
        if working_dir is not None and not _path_within_workspace(str(working_dir), workspace_dir):
            reasons.append(f"命令工作目录位于沙盒工作区外部: {working_dir}")
        if _WRITE_OP_RE.search(cmd):
            candidate_paths = (
                _QUOTED_DRIVE_PATH_RE.findall(cmd)
                + _BARE_DRIVE_PATH_RE.findall(cmd)
                + _UNC_PATH_RE.findall(cmd)
            )
            outside_hits: list[str] = []
            for raw_p in candidate_paths:
                if not _path_within_workspace(raw_p, workspace_dir):
                    outside_hits.append(raw_p)
            if outside_hits:
                reasons.append(f"检测到疑似向沙盒工作区外部写入或变更路径: {outside_hits[0]}")
            elif _REL_ESCAPE_RE.search(cmd):
                reasons.append("检测到写入操作中包含相对上级路径逃逸特征 (..)")
            elif _ENV_HOME_ESCAPE_RE.search(cmd):
                reasons.append("检测到写入操作中包含环境变量或家目录路径引用，需确认边界")

    return ("high", reasons) if reasons else ("low", [])


class AuditLogger:
    """按天落盘的线程安全 JSONL 审计日志器（自动脱敏与过期清理）。"""

    def __init__(
        self,
        workspace_provider: Callable[[], Path],
        enabled: bool = True,
        retention_days: int = 30,
    ) -> None:
        self._workspace_provider = workspace_provider
        self.enabled = bool(enabled)
        self.retention_days = max(1, int(retention_days))
        self._lock = threading.Lock()
        self._last_cleanup_date = ""

    def configure(self, enabled: bool, retention_days: int = 30) -> None:
        with self._lock:
            self.enabled = bool(enabled)
            self.retention_days = max(1, int(retention_days))

    def _audit_dir(self) -> Path:
        return self._workspace_provider() / "audit_logs"

    def _cleanup_expired_locked(self, audit_dir: Path, today_str: str) -> None:
        if self._last_cleanup_date == today_str:
            return
        self._last_cleanup_date = today_str
        cutoff = datetime.now() - timedelta(days=self.retention_days)
        for item in audit_dir.glob("audit_*.jsonl"):
            stem = item.stem
            date_part = stem.replace("audit_", "", 1)
            try:
                file_dt = datetime.strptime(date_part, "%Y%m%d")
                if file_dt < cutoff:
                    item.unlink(missing_ok=True)
            except Exception:
                continue

    def log(
        self,
        source: str,
        action: str,
        user_id: str,
        stream_id: str,
        group_id: str,
        params: dict[str, Any] | None,
        risk_level: str,
        success: bool,
        detail: str = "",
    ) -> None:
        if not self.enabled:
            return

        now = datetime.now()
        today_str = now.strftime("%Y%m%d")
        record = {
            "timestamp": now.isoformat(timespec="seconds"),
            "source": str(source),
            "action": str(action),
            "user_id": str(user_id or ""),
            "stream_id": str(stream_id or ""),
            "group_id": str(group_id or ""),
            "risk_level": str(risk_level or "low"),
            "success": bool(success),
            "params": sanitize_value(params or {}),
            "detail": sanitize_value(detail, max_str_len=400),
        }

        try:
            line = json.dumps(record, ensure_ascii=False)
            with self._lock:
                audit_dir = self._audit_dir()
                audit_dir.mkdir(parents=True, exist_ok=True)
                log_file = audit_dir / f"audit_{today_str}.jsonl"
                with open(log_file, "a", encoding="utf-8") as fh:
                    fh.write(line + "\n")
                self._cleanup_expired_locked(audit_dir, today_str)
        except Exception:
            # 审计落盘异常不得阻断正常业务执行
            pass

    def read_recent(self, limit: int = 10) -> list[dict[str, Any]]:
        """倒序读取最近的审计记录条目（按末尾分块读取，避免大文件全量加载）。"""
        cap = max(1, min(int(limit), 50))
        entries: list[dict[str, Any]] = []
        max_tail_bytes = 512 * 1024
        try:
            with self._lock:
                audit_dir = self._audit_dir()
                if not audit_dir.is_dir():
                    return []
                files = sorted(audit_dir.glob("audit_*.jsonl"), reverse=True)
                for fpath in files:
                    try:
                        fsize = fpath.stat().st_size
                        with open(fpath, "rb") as fh:
                            if fsize > max_tail_bytes:
                                fh.seek(fsize - max_tail_bytes)
                                fh.readline()  # 丢弃可能被从中间截断的首行
                            raw_bytes = fh.read()
                        lines = raw_bytes.decode("utf-8", errors="replace").splitlines()
                    except Exception:
                        continue
                    for raw_line in reversed(lines):
                        raw_line = raw_line.strip()
                        if not raw_line:
                            continue
                        try:
                            entries.append(json.loads(raw_line))
                        except Exception:
                            continue
                        if len(entries) >= cap:
                            return entries
        except Exception:
            return []
        return entries


class PendingConfirmationStore:
    """统一管理高危操作与沙盒外写入的二次确认票据（绑定会话与发起人）。"""

    def __init__(self, ttl_seconds: int = 60, max_pending: int = 20) -> None:
        self.ttl_seconds = max(10, int(ttl_seconds))
        self.max_pending = max(1, int(max_pending))
        self._lock = threading.Lock()
        self._items: dict[str, dict[str, Any]] = {}

    @staticmethod
    def _norm_uid(user_id: str | None) -> str:
        raw = str(user_id or "").strip()
        if not raw:
            return ""
        return raw.split(":")[-1].strip() if ":" in raw else raw

    @classmethod
    def _identity_matches(cls, stored_raw: str, stored_bare: str, caller_raw: str, caller_bare: str) -> bool:
        if not stored_bare or not caller_bare:
            return False
        if ":" in stored_raw and ":" in caller_raw:
            return stored_raw == caller_raw
        return stored_bare == caller_bare

    def _purge_expired_locked(self, now: float) -> None:
        expired = [k for k, v in self._items.items() if now - v["timestamp"] > self.ttl_seconds]
        for k in expired:
            self._items.pop(k, None)

    def add(
        self,
        kind: str,
        payload: dict[str, Any],
        requester_user_id: str,
        stream_id: str,
        summary: str = "",
    ) -> dict[str, Any]:
        now = time.time()
        with self._lock:
            self._purge_expired_locked(now)
            while len(self._items) >= self.max_pending:
                oldest_key = min(self._items.keys(), key=lambda k: self._items[k]["timestamp"])
                self._items.pop(oldest_key, None)

            req_id = str(uuid.uuid4())[:8]
            ticket = {
                "req_id": req_id,
                "kind": str(kind),
                "payload": payload,
                "requester_user_id": self._norm_uid(requester_user_id),
                "raw_user_id": str(requester_user_id or "").strip(),
                "stream_id": str(stream_id or "").strip(),
                "summary": str(summary or ""),
                "timestamp": now,
            }
            self._items[req_id] = ticket
            return ticket

    def consume(
        self,
        req_id: str,
        caller_user_id: str,
        stream_id: str,
        allowed_kinds: tuple[str, ...] | None = None,
    ) -> tuple[dict[str, Any] | None, str]:
        now = time.time()
        clean_id = str(req_id or "").strip()
        caller_raw = str(caller_user_id or "").strip()
        caller_norm = self._norm_uid(caller_raw)
        sid = str(stream_id or "").strip()

        with self._lock:
            self._purge_expired_locked(now)
            if not self._items:
                return None, "当前没有任何待授权确认的请求，或请求已超过 60 秒超时失效。"

            if not sid or not caller_norm:
                return None, "安全拒绝：缺少有效的当前会话或管理员身份标识，无法核销确认请求。"

            if clean_id:
                ticket = self._items.get(clean_id)
                if ticket is None:
                    return None, f"未找到待确认请求 [{clean_id}]，可能已被核销或超时失效。"
                if ticket["stream_id"] != sid:
                    return None, "安全拒绝：该待确认请求属于其他会话，禁止跨会话核销。"
                if not self._identity_matches(
                    ticket.get("raw_user_id", ""),
                    ticket.get("requester_user_id", ""),
                    caller_raw,
                    caller_norm,
                ):
                    return None, "安全拒绝：仅原发起操作请求的管理员本人有权确认执行。"
                return self._items.pop(clean_id), ""

            matching = [
                t
                for t in self._items.values()
                if t["stream_id"] == sid
                and self._identity_matches(
                    t.get("raw_user_id", ""),
                    t.get("requester_user_id", ""),
                    caller_raw,
                    caller_norm,
                )
            ]
            if not matching:
                return None, "当前会话下没有待您授权确认的请求（不支持跨会话或代他人确认）。"

            if allowed_kinds:
                kind_matched = [t for t in matching if t.get("kind") in allowed_kinds]
                if not kind_matched:
                    return None, "当前会话下没有对应类型的待确认请求，请核对指令或指定 8 位请求 ID。"
                matching = kind_matched

            distinct_kinds = {t.get("kind") for t in matching}
            if len(distinct_kinds) > 1:
                ids_hint = "、".join(f"{t['req_id']}({t['kind']})" for t in sorted(matching, key=lambda i: i["timestamp"], reverse=True)[:5])
                return None, f"当前会话存在多类待确认请求（{ids_hint}），请指定 ID 确认，例如：/确认执行 <req_id>。"

            latest = max(matching, key=lambda item: item["timestamp"])
            return self._items.pop(latest["req_id"]), ""

    def clear(self) -> None:
        with self._lock:
            self._items.clear()
