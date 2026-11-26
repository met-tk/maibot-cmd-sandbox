# -*- coding: utf-8 -*-
"""maibot-cmd-sandbox 核心模块导出包。"""

from .file_ops import (
    find_files,
    is_path_in_sandbox,
    load_local_image_base64,
    read_file_lines,
    resolve_safe_path,
    search_text_in_path,
)
from .job_manager import BackgroundJobManager
from .security_audit import (
    PROTECTED_HARD_PROCESSES,
    PROTECTED_SOFT_PROCESSES,
    AuditLogger,
    PendingConfirmationStore,
    assess_command_risk,
    assess_process_kill_risk,
    sanitize_command_text,
    sanitize_value,
)
from .system_monitor import (
    SystemWatchdog,
    get_hardware_status_summary,
    get_running_process_names,
    list_local_disks,
)
from .win32_desktop import Win32DesktopController

__all__ = [
    "AuditLogger",
    "BackgroundJobManager",
    "PROTECTED_HARD_PROCESSES",
    "PROTECTED_SOFT_PROCESSES",
    "PendingConfirmationStore",
    "SystemWatchdog",
    "Win32DesktopController",
    "assess_command_risk",
    "assess_process_kill_risk",
    "find_files",
    "get_hardware_status_summary",
    "get_running_process_names",
    "is_path_in_sandbox",
    "list_local_disks",
    "load_local_image_base64",
    "read_file_lines",
    "resolve_safe_path",
    "sanitize_command_text",
    "sanitize_value",
    "search_text_in_path",
]
