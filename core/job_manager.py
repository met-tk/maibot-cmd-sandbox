# -*- coding: utf-8 -*-
"""异步后台长任务池与进程树回收管理模块。"""

from __future__ import annotations

import asyncio
import os
import subprocess
import time
import uuid
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Awaitable, Callable


MAX_LOG_FILE_BYTES = 5 * 1024 * 1024
MAX_JOB_HISTORY = 50


@dataclass
class ManagedJob:
    job_id: str
    command: str
    cwd: str
    stream_id: str
    user_id: str
    status: str
    pid: int | None
    started_at: float
    log_path: Path
    timeout_seconds: int
    returncode: int | None = None
    finished_at: float | None = None
    bytes_written: int = 0
    log_truncated_on_disk: bool = False
    tail_lines: deque[str] = field(default_factory=lambda: deque(maxlen=1000))
    process: asyncio.subprocess.Process | None = None
    monitor_task: asyncio.Task[Any] | None = None

    def to_summary(self) -> dict[str, Any]:
        end_ts = self.finished_at or time.time()
        return {
            "job_id": self.job_id,
            "status": self.status,
            "pid": self.pid,
            "returncode": self.returncode,
            "cwd": self.cwd,
            "command": self.command[:200],
            "elapsed_seconds": round(max(0.0, end_ts - self.started_at), 2),
            "log_path": str(self.log_path),
            "stream_id": self.stream_id,
        }


def _decode_chunk(raw: bytes) -> str:
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("gbk", errors="replace")


def _kill_pid_tree_sync(pid: int) -> None:
    if pid <= 0:
        return
    if os.name == "nt":
        try:
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(pid)],
                capture_output=True,
                check=False,
                timeout=10,
            )
        except Exception:
            pass
    else:
        try:
            os.kill(pid, 9)
        except Exception:
            pass


class BackgroundJobManager:
    """托管长耗时 PowerShell/CMD 后台子进程，支持实时尾部日志、强杀进程树与卸载回收。"""

    def __init__(
        self,
        workspace_provider: Callable[[], Path],
        max_concurrent_jobs: int = 5,
        default_max_runtime_seconds: int = 3600,
    ) -> None:
        self._workspace_provider = workspace_provider
        self.max_concurrent_jobs = max(1, int(max_concurrent_jobs))
        self.default_max_runtime_seconds = max(30, int(default_max_runtime_seconds))
        self._jobs: dict[str, ManagedJob] = {}
        self._slot_lock = asyncio.Lock()

    def configure(self, max_concurrent_jobs: int, default_max_runtime_seconds: int) -> None:
        self.max_concurrent_jobs = max(1, int(max_concurrent_jobs))
        self.default_max_runtime_seconds = max(30, int(default_max_runtime_seconds))

    def _prune_history(self) -> None:
        if len(self._jobs) <= MAX_JOB_HISTORY:
            return
        finished = [j for j in self._jobs.values() if j.status != "running"]
        finished.sort(key=lambda item: item.finished_at or item.started_at)
        for j in finished[: max(0, len(self._jobs) - MAX_JOB_HISTORY)]:
            self._jobs.pop(j.job_id, None)

    def _running_count(self) -> int:
        return sum(1 for j in self._jobs.values() if j.status == "running")

    async def start_job(
        self,
        command: str,
        cwd: str,
        stream_id: str,
        user_id: str,
        timeout_seconds: int | None = None,
        notify_callback: Callable[[dict[str, Any]], Awaitable[None]] | None = None,
    ) -> tuple[bool, dict[str, Any] | str]:
        cmd = str(command or "").strip()
        if not cmd:
            return False, "启动后台任务失败：命令不能为空。"

        async with self._slot_lock:
            if self._running_count() >= self.max_concurrent_jobs:
                return (
                    False,
                    f"后台任务并发已达上限（当前运行 {self._running_count()}/{self.max_concurrent_jobs}），请等待任务结束或先终止旧任务。",
                )

            job_id = str(uuid.uuid4())[:8]
            jobs_dir = self._workspace_provider() / "jobs"
            jobs_dir.mkdir(parents=True, exist_ok=True)
            log_path = jobs_dir / f"job_{job_id}.log"

            runtime_limit = (
                max(10, min(int(timeout_seconds), self.default_max_runtime_seconds))
                if timeout_seconds is not None and int(timeout_seconds) > 0
                else self.default_max_runtime_seconds
            )

            shell_exe = "powershell.exe" if os.name == "nt" else "/bin/bash"
            args = (
                ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", cmd]
                if os.name == "nt"
                else ["-c", cmd]
            )

            try:
                proc = await asyncio.create_subprocess_exec(
                    shell_exe,
                    *args,
                    cwd=cwd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
            except Exception as exc:
                return False, f"后台进程启动失败: {exc}"

            job = ManagedJob(
                job_id=job_id,
                command=cmd,
                cwd=cwd,
                stream_id=str(stream_id or ""),
                user_id=str(user_id or ""),
                status="running",
                pid=proc.pid,
                started_at=time.time(),
                log_path=log_path,
                timeout_seconds=runtime_limit,
                process=proc,
            )
            self._jobs[job_id] = job
            self._prune_history()
            job.monitor_task = asyncio.create_task(self._monitor_job(job, notify_callback))
            return True, job.to_summary()

    async def _monitor_job(
        self,
        job: ManagedJob,
        notify_callback: Callable[[dict[str, Any]], Awaitable[None]] | None,
    ) -> None:
        proc = job.process
        assert proc is not None

        log_fh = None
        try:
            log_fh = open(job.log_path, "a", encoding="utf-8", errors="replace")
            log_fh.write(f"[START] job_id={job.job_id} pid={job.pid} cwd={job.cwd}\n")
            log_fh.flush()
        except Exception:
            log_fh = None

        def _append_text(tag: str, chunk: str) -> None:
            for line in chunk.splitlines():
                formatted = f"[{tag}] {line}" if tag else line
                job.tail_lines.append(formatted)
                if log_fh is not None and not job.log_truncated_on_disk:
                    encoded_len = len(formatted.encode("utf-8", errors="replace")) + 1
                    if job.bytes_written + encoded_len > MAX_LOG_FILE_BYTES:
                        try:
                            log_fh.write("\n[SYSTEM] 日志达到 5MB 上限，后续输出仅保留内存尾部缓冲。\n")
                            log_fh.flush()
                        except Exception:
                            pass
                        job.log_truncated_on_disk = True
                    else:
                        try:
                            log_fh.write(formatted + "\n")
                            log_fh.flush()
                            job.bytes_written += encoded_len
                        except Exception:
                            pass

        async def _drain(stream: asyncio.StreamReader | None, tag: str) -> None:
            if stream is None:
                return
            byte_buf = bytearray()
            max_line_bytes = 16384
            while True:
                chunk = await stream.read(4096)
                if not chunk:
                    if byte_buf:
                        _append_text(tag, _decode_chunk(bytes(byte_buf)))
                    break
                byte_buf.extend(chunk)
                while True:
                    nl_idx = byte_buf.find(b"\n")
                    if nl_idx == -1:
                        break
                    line_bytes = bytes(byte_buf[:nl_idx]).rstrip(b"\r")
                    del byte_buf[: nl_idx + 1]
                    _append_text(tag, _decode_chunk(line_bytes))
                if len(byte_buf) >= max_line_bytes:
                    flush_bytes = bytes(byte_buf)
                    byte_buf.clear()
                    _append_text(tag, _decode_chunk(flush_bytes) + "...[line truncated]")

        try:
            await asyncio.wait_for(
                asyncio.gather(
                    _drain(proc.stdout, ""),
                    _drain(proc.stderr, "ERR"),
                    proc.wait(),
                ),
                timeout=job.timeout_seconds,
            )
            job.returncode = proc.returncode
            if job.status == "running":
                job.status = "completed" if (proc.returncode or 0) == 0 else "failed"
        except asyncio.TimeoutError:
            if job.pid:
                await asyncio.to_thread(_kill_pid_tree_sync, job.pid)
            try:
                await asyncio.wait_for(proc.wait(), timeout=3)
            except Exception:
                pass
            job.returncode = proc.returncode if proc.returncode is not None else -1
            if job.status == "running":
                job.status = "timeout"
            _append_text("SYSTEM", f"后台任务超出 {job.timeout_seconds} 秒上限，已强制终止进程树。")
        except asyncio.CancelledError:
            if job.pid and job.status == "running":
                await asyncio.to_thread(_kill_pid_tree_sync, job.pid)
                job.status = "killed"
            raise
        except Exception as exc:
            job.status = "failed"
            _append_text("SYSTEM", f"后台监控异常: {exc}")
        finally:
            job.finished_at = time.time()
            if log_fh is not None:
                try:
                    log_fh.write(f"[END] status={job.status} returncode={job.returncode}\n")
                    log_fh.close()
                except Exception:
                    pass

        if notify_callback is not None:
            summary = job.to_summary()
            summary["tail_output"] = "\n".join(list(job.tail_lines)[-15:])
            try:
                await notify_callback(summary)
            except Exception:
                pass

    def get_job_status(self, job_id: str) -> dict[str, Any] | None:
        job = self._jobs.get(str(job_id or "").strip())
        return job.to_summary() if job else None

    def get_job_logs(self, job_id: str, tail_lines: int = 50, max_chars: int = 2000) -> tuple[bool, dict[str, Any] | str]:
        job = self._jobs.get(str(job_id or "").strip())
        if job is None:
            return False, f"未找到任务 ID: {job_id}"
        count = max(1, min(int(tail_lines), 300))
        lines = list(job.tail_lines)[-count:]
        text = "\n".join(lines)
        if len(text) > max_chars:
            text = "...[前面日志已截断]\n" + text[-max_chars:]
        summary = job.to_summary()
        summary["logs"] = text or "(暂无控制台输出)"
        return True, summary

    def list_jobs(self, limit: int = 20) -> list[dict[str, Any]]:
        items = sorted(self._jobs.values(), key=lambda j: j.started_at, reverse=True)
        return [j.to_summary() for j in items[: max(1, min(int(limit), 50))]]

    async def kill_job(self, job_id: str) -> tuple[bool, str]:
        job = self._jobs.get(str(job_id or "").strip())
        if job is None:
            return False, f"未找到任务 ID: {job_id}"
        if job.status != "running":
            return False, f"任务 [{job.job_id}] 当前已处于结束状态 ({job.status})，无需终止。"
        job.status = "killed"
        if job.pid:
            await asyncio.to_thread(_kill_pid_tree_sync, job.pid)
        if job.monitor_task is not None and not job.monitor_task.done():
            try:
                await asyncio.wait_for(job.monitor_task, timeout=3)
            except Exception:
                job.monitor_task.cancel()
        return True, f"已强杀后台任务 [{job.job_id}] (PID: {job.pid}) 及其派生子进程树。"

    async def shutdown_all(self) -> None:
        """插件卸载时清理全部正在运行的后台任务与监控协程。"""
        running = [j for j in self._jobs.values() if j.status == "running"]
        for job in running:
            job.status = "killed"
            if job.pid:
                await asyncio.to_thread(_kill_pid_tree_sync, job.pid)
        for job in running:
            if job.monitor_task is not None and not job.monitor_task.done():
                job.monitor_task.cancel()
                try:
                    await job.monitor_task
                except (asyncio.CancelledError, Exception):
                    pass
