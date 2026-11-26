# -*- coding: utf-8 -*-
import asyncio
import math
import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

from maibot_sdk import Command, Field, MaiBotPlugin, PluginConfigBase, Tool
from maibot_sdk.types import ToolParamType, ToolParameterInfo

try:
    from .core import (
        AuditLogger,
        BackgroundJobManager,
        PendingConfirmationStore,
        SystemWatchdog,
        Win32DesktopController,
        assess_command_risk,
        assess_process_kill_risk,
        find_files,
        get_hardware_status_summary,
        is_path_in_sandbox,
        load_local_image_base64,
        read_file_lines,
        resolve_safe_path,
        search_text_in_path,
    )
except ImportError:
    _PLUGIN_ROOT = str(Path(__file__).resolve().parent)
    if _PLUGIN_ROOT not in sys.path:
        sys.path.insert(0, _PLUGIN_ROOT)
    from core import (
        AuditLogger,
        BackgroundJobManager,
        PendingConfirmationStore,
        SystemWatchdog,
        Win32DesktopController,
        assess_command_risk,
        assess_process_kill_risk,
        find_files,
        get_hardware_status_summary,
        is_path_in_sandbox,
        load_local_image_base64,
        read_file_lines,
        resolve_safe_path,
        search_text_in_path,
    )


# ----------------------------------------------------------------------
# 配置结构定义
# ----------------------------------------------------------------------


class PluginSection(PluginConfigBase):
    """插件启用状态与配置版本元数据。"""

    __ui_label__ = "基础设置"
    __ui_order__ = 0

    enabled: bool = Field(
        default=True,
        description="是否启用沙盒终端与全能系统控制插件",
        json_schema_extra={
            "label": "启用插件",
            "hint": "是否启用沙盒终端与全能系统控制插件。",
        },
    )
    config_version: str = Field(
        default="1.5.0",
        description="配置文件结构版本号",
        json_schema_extra={
            "label": "配置版本",
            "hint": "内部配置文件结构版本号，通常无需手动修改。",
            "hidden": True,
        },
    )


class SecuritySection(PluginConfigBase):
    """配置管理员账号、群聊执行白名单、大模型自然语言工具开关及越权拦截提示。"""

    __ui_label__ = "安全与权限控制"
    __ui_order__ = 1

    admin_users: list[str] = Field(
        default_factory=list,
        description="管理员账号列表，仅允许管理员执行系统控制与终端命令",
        json_schema_extra={
            "label": "管理员账号列表",
            "group": "身份鉴权",
            "placeholder": "例如 123456789 或 qq:123456789",
            "hint": "允许调用本插件所有命令与工具的管理员账号。支持填纯账号（如 123456789）或带平台前缀（如 qq:123456789）。",
        },
    )
    unauthorized_message: str = Field(
        default="权限不足：该系统控制与截图命令仅允许管理员执行。",
        description="非管理员触发命令时的拦截回复（留空则静默不回复）",
        json_schema_extra={
            "label": "非管理员拦截提示",
            "group": "身份鉴权",
            "placeholder": "留空则在拦截时不回复",
            "hint": "当非管理员尝试触发插件命令时的拒绝回复；清空留白则改为静默拦截。",
        },
    )
    enable_llm_tools: bool = Field(
        default=True,
        description="是否允许大模型通过自然语言调用系统控制与终端工具",
        json_schema_extra={
            "label": "启用大模型工具调用",
            "group": "身份鉴权",
            "hint": "开启后，麦麦可通过自然语言自主调用截图、终端执行、文件检索、窗口控制和系统监控等内置工具（仍受管理员权限校验）。",
        },
    )
    allow_in_groups: bool = Field(
        default=False,
        description="是否允许在指定的群聊中执行系统控制与终端命令（总开关）",
        json_schema_extra={
            "label": "允许群聊执行（总开关）",
            "group": "群聊权限",
            "hint": "群聊环境总开关。仅当此项开启且目标群号位于下方白名单内时，管理员才可在该群触发命令与工具。",
        },
    )
    allowed_groups: list[str] = Field(
        default_factory=list,
        description="允许执行系统控制与终端命令的群聊白名单列表（支持纯群号或如 qq:12345678）",
        json_schema_extra={
            "label": "授权群聊白名单",
            "group": "群聊权限",
            "placeholder": "例如 12345678 或 qq:12345678",
            "hint": "允许执行系统控制与终端命令的群聊列表（需同时开启上方群聊总开关）。支持填纯群号或带平台前缀。",
        },
    )
    unauthorized_group_message: str = Field(
        default="未授权群聊：当前群未开启系统命令执行权限，仅在管理员授权的指定群聊或私聊中可用。",
        description="未授权群聊触发命令时的提示回复（留空则静默不回复）",
        json_schema_extra={
            "label": "未授权群聊拦截提示",
            "group": "群聊权限",
            "placeholder": "留空则未授权群聊静默拦截",
            "hint": "在未授权群聊中触发命令时的回复文本；若不希望打扰群成员可清空留白。",
        },
    )


class SandboxSection(PluginConfigBase):
    """配置沙盒工作区路径、命令超时与确认门禁、桌面与键鼠权限、图片外发、后台长任务、审计日志及看门狗告警。"""

    __ui_label__ = "沙盒、控制与运维监控"
    __ui_order__ = 2

    workspace_dir: str = Field(
        default="D:\\Agentworkspace",
        description="默认沙盒工作区目录，Agent 在此路径下编写脚本、搭建工具套件与执行命令",
        json_schema_extra={
            "label": "沙盒工作区目录",
            "group": "沙盒与终端限制",
            "placeholder": "例如 D:\\Agentworkspace",
            "hint": "终端命令默认所在的工作目录，也是脚本文件、审计日志与后台任务日志的根目录（不存在时会自动创建）。",
        },
    )
    sandbox_only_write: bool = Field(
        default=True,
        description="写入权限约束：是否默认仅允许在沙盒工作区内进行文件写入",
        json_schema_extra={
            "label": "严格限制沙盒内写入",
            "group": "沙盒与终端限制",
            "hint": "开启后，通过插件写文件或改文件仅允许落在沙盒工作区目录以内，关闭后才允许涉及工作区外部路径。",
        },
    )
    allow_write_outside_with_confirm: bool = Field(
        default=True,
        description="沙盒外写入双重确认门禁：在沙盒外写入时，是否必须经管理员显式双重确认才允许写入",
        json_schema_extra={
            "label": "沙盒外写入需二次确认",
            "group": "沙盒与终端限制",
            "hint": "当放开纯沙盒写入约束后，针对沙盒工作区以外的文件写入仍强制要求管理员先回复确认口令再执行。",
        },
    )
    timeout_seconds: int = Field(
        default=30,
        description="终端命令单次执行超时秒数",
        json_schema_extra={
            "label": "单次命令超时（秒）",
            "group": "沙盒与终端限制",
            "placeholder": "默认 30",
            "hint": "同步终端命令单次执行的最长等待秒数，超时将被强行终止；耗时较长的任务建议使用后台任务工具。",
        },
    )
    max_output_chars: int = Field(
        default=2000,
        description="命令输出最大截断字符数",
        json_schema_extra={
            "label": "命令输出最大字符数",
            "group": "沙盒与终端限制",
            "placeholder": "默认 2000",
            "hint": "单次命令回传给聊天的最大字符数上限，超出部分将被截断以防消息刷屏。",
        },
    )
    allow_system_control: bool = Field(
        default=True,
        description="是否允许执行系统电源控制（关机/重启）",
        json_schema_extra={
            "label": "允许系统电源控制",
            "group": "桌面控制与系统电源",
            "hint": "开启后才允许通过指令或大模型工具执行关机、重启等电源控制操作。",
        },
    )
    shutdown_delay_seconds: int = Field(
        default=60,
        description="关机/重启默认延时秒数",
        json_schema_extra={
            "label": "关机/重启延时（秒）",
            "group": "桌面控制与系统电源",
            "placeholder": "默认 60",
            "hint": "触发关机或重启时的默认倒计时秒数，用于预留取消与保存工作现场的缓冲时间。",
        },
    )
    allow_window_control: bool = Field(
        default=True,
        description="是否允许控制桌面窗口状态（恢复、最小化、最大化、置前、移动缩放、温和关闭）",
        json_schema_extra={
            "label": "允许桌面窗口控制",
            "group": "桌面控制与系统电源",
            "hint": "开启后允许枚举桌面窗口，并执行还原、最小化、最大化、置前、移动缩放及温和关闭窗口等操作。",
        },
    )
    allow_gui_input: bool = Field(
        default=False,
        description="是否允许受控 GUI 键鼠交互（高敏感能力，默认关闭）",
        json_schema_extra={
            "label": "允许模拟键鼠交互（高危）",
            "group": "桌面控制与系统电源",
            "hint": "高敏感能力开关，默认关闭。开启后才允许向目标窗口或桌面发送鼠标点击、移动或键盘按键操作。",
        },
    )
    require_confirm_gui_input: bool = Field(
        default=True,
        description="开启 GUI 键鼠交互后，每次键鼠动作是否需要管理员二次确认",
        json_schema_extra={
            "label": "键鼠交互需二次确认",
            "group": "桌面控制与系统电源",
            "hint": "开启模拟键鼠交互后，每次动作是否必须生成待确认口令，由管理员二次确认后才真正执行。",
        },
    )
    confirm_high_risk_commands: bool = Field(
        default=True,
        description="命中高危特征的终端命令、后台任务与关键进程终止是否强制要求二次确认",
        json_schema_extra={
            "label": "高危操作二次确认",
            "group": "高危确认与文件外发",
            "hint": "命中危险特征的终端命令、关键系统进程终止及高危后台任务会先被拦截并生成确认口令，确认后才执行。",
        },
    )
    allow_send_image_outside_sandbox: bool = Field(
        default=False,
        description="是否允许发送沙盒工作区外部的本地图片文件",
        json_schema_extra={
            "label": "允许发送沙盒外本地图片",
            "group": "高危确认与文件外发",
            "hint": "开启后允许直接读取并发送沙盒目录以外的本地图片；默认关闭，仅限发送沙盒内图片或即时桌面截图。",
        },
    )
    max_send_image_mb: int = Field(
        default=15,
        description="本地直发图片允许的最大体积（MB）",
        json_schema_extra={
            "label": "单张图片外发上限（MB）",
            "group": "高危确认与文件外发",
            "placeholder": "默认 15",
            "hint": "通过本地直发图片功能发送单张图片时允许的最大文件大小（单位：MB）。",
        },
    )
    max_concurrent_jobs: int = Field(
        default=5,
        description="后台长任务最大同时运行数",
        json_schema_extra={
            "label": "后台任务最大并发数",
            "group": "后台任务与审计日志",
            "placeholder": "默认 5",
            "hint": "异步后台长任务池允许同时运行的最大任务数量。",
        },
    )
    max_job_runtime_seconds: int = Field(
        default=3600,
        description="单个后台长任务最长运行时长（秒）",
        json_schema_extra={
            "label": "单个后台任务超时（秒）",
            "group": "后台任务与审计日志",
            "placeholder": "默认 3600",
            "hint": "单个后台长任务允许持续运行的最长秒数，超时后自动结束进程以防长期占用系统资源。",
        },
    )
    enable_audit_log: bool = Field(
        default=True,
        description="是否启用本地结构化操作审计日志（落盘至沙盒 audit_logs 目录）",
        json_schema_extra={
            "label": "启用本地审计日志",
            "group": "后台任务与审计日志",
            "hint": "记录权限校验、命令执行、文件读写、窗口与键鼠等关键操作到沙盒 audit_logs/ 目录，并自动脱敏敏感凭据。",
        },
    )
    audit_retention_days: int = Field(
        default=30,
        description="审计日志保留天数",
        json_schema_extra={
            "label": "审计日志保留天数",
            "group": "后台任务与审计日志",
            "placeholder": "默认 30",
            "hint": "按天写入的审计日志文件最多保留的天数，过期旧日志会在写入新日志时自动清理。",
        },
    )
    watchdog_enabled: bool = Field(
        default=False,
        description="是否启用后台运维看门狗（磁盘空间、关键进程、锁屏变更告警）",
        json_schema_extra={
            "label": "启用后台运维看门狗",
            "group": "运维看门狗告警",
            "hint": "总开关，默认关闭。开启后在插件运行期间定时巡检磁盘空间、关键进程存活与锁屏变化，并主动推送告警。",
        },
    )
    watchdog_interval_seconds: int = Field(
        default=60,
        description="看门狗轮询间隔秒数（最小 10 秒）",
        json_schema_extra={
            "label": "看门狗巡检间隔（秒）",
            "group": "运维看门狗告警",
            "placeholder": "默认 60，最小 10",
            "hint": "后台看门狗每轮检查状态的时间间隔（单位：秒，运行时最小限制为 10 秒）。",
        },
    )
    watchdog_cooldown_seconds: int = Field(
        default=300,
        description="同类型看门狗告警最小冷却秒数（防刷屏）",
        json_schema_extra={
            "label": "同类型告警冷却（秒）",
            "group": "运维看门狗告警",
            "placeholder": "默认 300，最小 30",
            "hint": "同一类异常在冷却时间内不会重复触发推送，用于防止持续刷屏（运行时最小限制为 30 秒）。",
        },
    )
    watchdog_disk_min_free_gb: float = Field(
        default=10.0,
        description="磁盘剩余空间告警阈值（GB，设为 0 则关闭磁盘告警）",
        json_schema_extra={
            "label": "磁盘剩余空间告警阈值（GB）",
            "group": "运维看门狗告警",
            "placeholder": "默认 10.0（填 0 关闭）",
            "hint": "当任意本地固定磁盘剩余可用空间低于该值（单位：GB）时触发告警；设为 0 则关闭磁盘空间检查。",
        },
    )
    watchdog_processes: list[str] = Field(
        default_factory=list,
        description="看门狗监控的进程名列表（当曾活跃的进程退出时发出告警）",
        json_schema_extra={
            "label": "受监控进程列表",
            "group": "运维看门狗告警",
            "placeholder": "例如 QQ.exe 或 python.exe",
            "hint": "填写需盯防的程序可执行文件名（如 QQ.exe、WeChat.exe、python.exe，不区分大小写，可省略 .exe；勿填窗口标题或完整路径）。当曾检测到运行的进程退出时推送告警。",
        },
    )
    watchdog_lock_state: bool = Field(
        default=False,
        description="是否监控锁屏与解锁状态变化并通知管理员",
        json_schema_extra={
            "label": "监控锁屏与解锁状态",
            "group": "运维看门狗告警",
            "hint": "开启后，当宿主电脑发生锁屏或解锁状态切换时自动向管理员推送一条变更提醒。",
        },
    )
    watchdog_notify_stream_id: str = Field(
        default="",
        description="看门狗主动告警默认推送会话 stream_id（留空则尝试发给首位管理员私聊）",
        json_schema_extra={
            "label": "告警推送会话 ID",
            "group": "运维看门狗告警",
            "placeholder": "留空则自动发给首位管理员私聊",
            "hint": "看门狗主动发出告警时推送的目标会话 stream_id（如 qq:123456:private）；留空时默认尝试发给首位管理员私聊。",
        },
    )


class SandboxPluginConfig(PluginConfigBase):
    plugin: PluginSection = Field(default_factory=PluginSection)
    security: SecuritySection = Field(default_factory=SecuritySection)
    sandbox: SandboxSection = Field(default_factory=SandboxSection)


# ----------------------------------------------------------------------
# 核心插件类实现
# ----------------------------------------------------------------------


class SandboxCommandPlugin(MaiBotPlugin):
    """为麦麦提供多粒度桌面截图、窗口与键鼠控制、异步后台任务、沙盒文件检索、系统监控与安全审计"""

    config_model = SandboxPluginConfig

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._custom_config: SandboxPluginConfig | None = None
        self._desktop = Win32DesktopController(logger_cb=self._log)
        self._confirm_store = PendingConfirmationStore(ttl_seconds=60, max_pending=20)
        self._audit = AuditLogger(
            workspace_provider=self._get_workspace_path,
            enabled=True,
            retention_days=30,
        )
        self._job_manager = BackgroundJobManager(
            workspace_provider=self._get_workspace_path,
            max_concurrent_jobs=5,
            default_max_runtime_seconds=3600,
        )
        self._watchdog = SystemWatchdog(
            desktop_ctrl=self._desktop,
            notify_callback=self._send_watchdog_alert,
        )
        self._components_synced = False

    @property
    def _cfg(self) -> SandboxPluginConfig:
        if self._custom_config is not None:
            return self._custom_config
        try:
            cfg = super().config
            if isinstance(cfg, SandboxPluginConfig):
                return cfg
        except Exception:
            pass
        cfg_path = Path(__file__).parent / "config.toml"
        if cfg_path.exists():
            try:
                import tomllib

                data = tomllib.loads(cfg_path.read_text(encoding="utf-8"))
                self._custom_config = SandboxPluginConfig.model_validate(data)
                return self._custom_config
            except Exception:
                pass
        self._custom_config = SandboxPluginConfig()
        return self._custom_config

    def _sync_runtime_components(self) -> None:
        """将当前配置同步至审计器、任务池与看门狗实例。"""
        sb = self._cfg.sandbox
        self._audit.configure(
            enabled=sb.enable_audit_log,
            retention_days=sb.audit_retention_days,
        )
        self._job_manager.configure(
            max_concurrent_jobs=sb.max_concurrent_jobs,
            default_max_runtime_seconds=sb.max_job_runtime_seconds,
        )
        self._watchdog.configure(
            enabled=sb.watchdog_enabled,
            interval_seconds=sb.watchdog_interval_seconds,
            cooldown_seconds=sb.watchdog_cooldown_seconds,
            disk_min_free_gb=sb.watchdog_disk_min_free_gb,
            watched_processes=list(sb.watchdog_processes),
            watch_lock_state=sb.watchdog_lock_state,
            notify_stream_id=sb.watchdog_notify_stream_id,
        )
        self._components_synced = True

    def _ensure_components_synced(self) -> None:
        if not self._components_synced:
            self._sync_runtime_components()

    def _log(self, level: str, msg: str, *args: Any) -> None:
        """安全输出日志，支持离线测试与未注入 Context 回退"""
        try:
            logger = getattr(self.ctx, "logger", None)
            if logger:
                fn = getattr(logger, level, None)
                if fn:
                    fn(msg, *args)
                    return
        except Exception:
            pass

    # ------------------------------------------------------------------
    # 抽象生命周期方法实现
    # ------------------------------------------------------------------

    async def on_load(self) -> None:
        ws = self._get_workspace_path()
        self._sync_runtime_components()
        if self._cfg.sandbox.watchdog_enabled:
            await self._watchdog.start()
        self._log(
            "info",
            "沙盒终端与全能系统控制插件(v%s)已成功加载，沙盒工作区: %s",
            self._cfg.plugin.config_version,
            ws,
        )

    async def on_unload(self) -> None:
        await self._watchdog.stop()
        await self._job_manager.shutdown_all()
        self._confirm_store.clear()
        self._log("info", "沙盒终端与全能系统控制插件已安全卸载（后台任务与看门狗已全部清理）。")

    async def on_config_update(self, scope: str, config_data: dict[str, Any], version: str) -> None:
        try:
            self._custom_config = SandboxPluginConfig.model_validate(config_data)
            self._plugin_config_instance = self._custom_config
            self._get_workspace_path()
            self._sync_runtime_components()
            if self._cfg.sandbox.watchdog_enabled:
                await self._watchdog.start()
            else:
                await self._watchdog.stop()
            self._log("info", "沙盒控制插件配置已动态更新至版本 %s", version)
        except Exception as exc:
            self._log("error", "沙盒控制插件配置更新校验失败: %s", exc)

    # ------------------------------------------------------------------
    # 鉴权与身份核验辅助
    # ------------------------------------------------------------------

    @staticmethod
    def _match_configured_identity(target_id: str | None, configured_list: list[str]) -> bool:
        if not target_id:
            return False
        raw_id = str(target_id).strip()
        if not raw_id:
            return False
        bare_id = raw_id.split(":")[-1].strip() if ":" in raw_id else raw_id
        if not bare_id:
            return False
        for cfg_raw in configured_list:
            if not cfg_raw:
                continue
            cfg_str = str(cfg_raw).strip()
            if not cfg_str:
                continue
            cfg_bare = cfg_str.split(":")[-1].strip() if ":" in cfg_str else cfg_str
            if not cfg_bare:
                continue
            if raw_id == cfg_str:
                return True
            if ":" in raw_id and ":" in cfg_str:
                continue
            if bare_id == cfg_bare:
                return True
        return False

    def _is_admin(self, user_id: str | None) -> bool:
        return self._match_configured_identity(user_id, self._cfg.security.admin_users)

    def _is_group_allowed(self, group_id: str | None) -> bool:
        """检查群聊是否被允许执行系统控制与终端命令（总开关开启且在白名单中）"""
        if not self._cfg.security.allow_in_groups:
            return False
        return self._match_configured_identity(group_id, self._cfg.security.allowed_groups)

    def _extract_caller_info(self, kwargs: dict[str, Any]) -> tuple[str, str, str]:
        """从宿主指令事件中提取可靠的 (user_id, group_id, stream_id)"""
        stream_id = str(kwargs.get("stream_id", "") or "").strip()
        user_id = ""
        group_id = ""

        msg = kwargs.get("message")
        if isinstance(msg, dict):
            msg_info = msg.get("message_info") or {}
            if isinstance(msg_info, dict):
                g_info = msg_info.get("group_info") or {}
                if isinstance(g_info, dict):
                    gid = g_info.get("group_id") or g_info.get("id")
                    if gid and not isinstance(gid, (dict, list, set)):
                        group_id = str(gid).strip()

                u_info = msg_info.get("user_info") or {}
                if isinstance(u_info, dict):
                    for k in ("user_id", "sender_id", "id"):
                        v = u_info.get(k)
                        if v and not isinstance(v, (dict, list, set)):
                            user_id = str(v).strip()
                            break

            if not user_id:
                sender = msg.get("sender") or {}
                if isinstance(sender, dict):
                    v = sender.get("user_id") or sender.get("id")
                    if v and not isinstance(v, (dict, list, set)):
                        user_id = str(v).strip()

            if not group_id:
                grp = msg.get("group") or {}
                if isinstance(grp, dict):
                    gid = grp.get("id") or grp.get("group_id")
                    if gid and not isinstance(gid, (dict, list, set)):
                        group_id = str(gid).strip()

        if not user_id and "from_user_id" in kwargs:
            user_id = str(kwargs.get("from_user_id") or "").strip()

        return user_id, group_id, stream_id

    def _extract_command_context(self, kwargs: dict[str, Any]) -> tuple[str, str]:
        user_id, _, stream_id = self._extract_caller_info(kwargs)
        return user_id, stream_id

    def _extract_command_text(self, kwargs: dict[str, Any]) -> str:
        msg = kwargs.get("message")
        if isinstance(msg, dict):
            for k in ("plain_text", "text", "raw_message", "content"):
                v = msg.get(k)
                if isinstance(v, str) and v.strip():
                    return v.strip()
        for k in ("plain_text", "text", "raw_message", "content"):
            v = kwargs.get(k)
            if isinstance(v, str) and v.strip():
                return v.strip()
        return ""

    async def _check_command_access(self, kwargs: dict[str, Any]) -> tuple[bool, str, str, str]:
        """统一校验直达前缀命令的权限（支持群聊白名单门禁与管理员身份校验）"""
        self._ensure_components_synced()
        user_id, group_id, stream_id = self._extract_caller_info(kwargs)

        if group_id:
            if not self._cfg.security.allow_in_groups or not self._is_group_allowed(group_id):
                if self._is_admin(user_id) and self._cfg.security.unauthorized_group_message:
                    await self.ctx.send.text(self._cfg.security.unauthorized_group_message, stream_id)
                return False, user_id, group_id, stream_id

        if not self._is_admin(user_id):
            if self._cfg.security.unauthorized_message:
                await self.ctx.send.text(self._cfg.security.unauthorized_message, stream_id)
            return False, user_id, group_id, stream_id

        return True, user_id, group_id, stream_id

    def _save_security_config(
        self,
        allow_in_groups: bool | None = None,
        allowed_groups: list[str] | None = None,
    ) -> bool:
        """持久化保存群聊安全配置到 config.toml，并同步内存配置"""
        cfg_path = Path(__file__).parent / "config.toml"
        if not cfg_path.exists():
            return False

        try:
            content = cfg_path.read_text(encoding="utf-8")

            if allow_in_groups is not None:
                self._cfg.security.allow_in_groups = allow_in_groups
                bool_str = "true" if allow_in_groups else "false"
                if re.search(r"^allow_in_groups\s*=.*$", content, flags=re.MULTILINE):
                    content = re.sub(
                        r"^allow_in_groups\s*=.*$",
                        f"allow_in_groups = {bool_str}",
                        content,
                        flags=re.MULTILINE,
                    )
                else:
                    content = content.replace("[security]", f"[security]\nallow_in_groups = {bool_str}")

            if allowed_groups is not None:
                seen = set()
                dedup_groups = []
                for g in allowed_groups:
                    clean_g = str(g).strip()
                    if clean_g and clean_g not in seen:
                        seen.add(clean_g)
                        dedup_groups.append(clean_g)
                self._cfg.security.allowed_groups = dedup_groups
                groups_repr = "[" + ", ".join(f'"{g}"' for g in dedup_groups) + "]"
                if re.search(r"^allowed_groups\s*=\s*\[[\s\S]*?\]", content, flags=re.MULTILINE):
                    content = re.sub(
                        r"^allowed_groups\s*=\s*\[[\s\S]*?\]",
                        f"allowed_groups = {groups_repr}",
                        content,
                        flags=re.MULTILINE,
                    )
                else:
                    content = content.replace("[security]", f"[security]\nallowed_groups = {groups_repr}")

            cfg_path.write_text(content, encoding="utf-8")
            return True
        except Exception as exc:
            self._log("error", "保存群聊配置到 config.toml 失败: %s", exc)
            return False

    async def _resolve_caller_identity_from_recent(self, stream_id: str) -> tuple[str, str]:
        try:
            message_cap = getattr(self.ctx, "message", None)
            if not message_cap:
                return "", ""
            recent = await message_cap.get_recent(chat_id=stream_id, limit=8)
            if isinstance(recent, dict):
                recent = recent.get("messages") or recent.get("data") or []
            if not isinstance(recent, list):
                return "", ""
            for item in reversed(recent):
                if not isinstance(item, dict):
                    continue
                msg_info = item.get("message_info") or {}
                if not isinstance(msg_info, dict):
                    msg_info = item

                u_info = msg_info.get("user_info") or item.get("sender") or {}
                uid = ""
                if isinstance(u_info, dict):
                    uid = str(u_info.get("user_id") or u_info.get("id") or "").strip()
                if not uid:
                    continue

                gid = ""
                g_info = msg_info.get("group_info") or item.get("group_info") or item.get("group") or {}
                if isinstance(g_info, dict):
                    gid = str(g_info.get("group_id") or g_info.get("id") or "").strip()
                elif "group_id" in item:
                    gid = str(item.get("group_id") or "").strip()
                elif isinstance(item.get("group"), (str, int)):
                    gid = str(item["group"]).strip()

                return uid, gid
        except Exception as exc:
            self._log("debug", "反查最近消息身份失败: %s", exc)
        return "", ""

    async def _verify_tool_caller_detail(self, kwargs: dict[str, Any]) -> tuple[bool, str, str, str, str]:
        """严格核验大模型工具调用 (@Tool) 上下文并返回 (ok, err, stream_id, user_id, group_id)。"""
        self._ensure_components_synced()
        if not self._cfg.security.enable_llm_tools:
            return False, "大模型自然语言系统控制工具已被配置禁用，请直接发送 /cmd、/截图 等直达指令。", "", "", ""

        stream_id = str(kwargs.get("stream_id", "") or "").strip()
        if not stream_id:
            return False, "缺少有效的会话标识，无法确认调用环境。", "", "", ""

        platform = str(kwargs.get("platform", "") or "qq").strip()
        admin_list = self._cfg.security.admin_users

        is_private_admin = False
        matched_admin_uid = ""
        try:
            streams = await self.ctx.chat.get_private_streams(platform)
            for s in streams or []:
                if isinstance(s, dict):
                    sid = str(s.get("session_id", "") or s.get("stream_id", "")).strip()
                    uid = str(s.get("user_id", "")).strip()
                    if sid == stream_id and self._is_admin(uid):
                        is_private_admin = True
                        matched_admin_uid = uid
                        break
        except Exception as exc:
            self._log("debug", "通过 get_private_streams 验证会话失败: %s", exc)

        if not is_private_admin:
            try:
                for admin_raw in admin_list:
                    admin_bare = str(admin_raw).split(":")[-1].strip()
                    if not admin_bare:
                        continue
                    admin_stream = await self.ctx.chat.get_stream_by_user_id(admin_bare, platform=platform)
                    if isinstance(admin_stream, dict):
                        admin_sid = str(admin_stream.get("session_id", "") or admin_stream.get("stream_id", "")).strip()
                        if admin_sid and admin_sid == stream_id:
                            is_private_admin = True
                            matched_admin_uid = admin_bare
                            break
            except Exception as exc:
                self._log("debug", "通过 get_stream_by_user_id 验证管理员流失败: %s", exc)

        if is_private_admin:
            return True, "", stream_id, matched_admin_uid, ""

        real_uid, real_gid = await self._resolve_caller_identity_from_recent(stream_id)
        if real_gid:
            if not self._cfg.security.allow_in_groups:
                return (
                    False,
                    "安全防御策略：当前系统未开启群聊执行命令功能（allow_in_groups=false）。管理员若需在群内操作，请发送 /cmd_group on 开启群聊控制开关，或在私聊中直接用自然语言交流。",
                    stream_id,
                    real_uid,
                    real_gid,
                )

            if not self._is_group_allowed(real_gid):
                return (
                    False,
                    f"安全拦截：当前群聊（{real_gid}）未被列入管理员授权的系统命令白名单。仅授权群聊或私聊中允许调用系统工具。管理员可发送 /cmd_group add 将当前群加入白名单。",
                    stream_id,
                    real_uid,
                    real_gid,
                )

            if not real_uid or not self._is_admin(real_uid):
                return (
                    False,
                    "权限不足：当前群聊已开启系统工具支持，但系统控制与截图工具仅限管理员（admin_user）通过自然语言唤起使用，非管理员无权触发。",
                    stream_id,
                    real_uid,
                    real_gid,
                )

            return True, "", stream_id, real_uid, real_gid

        return False, "权限受限：该操作仅允许管理员在私聊或已授权的群聊会话中通过自然语言驱动。", stream_id, real_uid, ""

    async def _verify_tool_caller(self, kwargs: dict[str, Any]) -> tuple[bool, str, str]:
        ok, err, stream_id, _, _ = await self._verify_tool_caller_detail(kwargs)
        return ok, err, stream_id

    # ------------------------------------------------------------------
    # 路径与沙盒文件管控辅助（委托至 core.file_ops）
    # ------------------------------------------------------------------

    def _get_workspace_path(self) -> Path:
        ws_str = self._cfg.sandbox.workspace_dir or "D:\\Agentworkspace"
        path = Path(ws_str).resolve()
        try:
            path.mkdir(parents=True, exist_ok=True)
            return path
        except Exception as exc:
            for candidate in (
                (Path.home() / "Agentworkspace").resolve(),
                (Path(tempfile.gettempdir()) / "maibot_agent_workspace").resolve(),
            ):
                try:
                    candidate.mkdir(parents=True, exist_ok=True)
                    self._log("warning", "创建沙盒目录 %s 失败，已安全回退至 %s: %s", path, candidate, exc)
                    return candidate
                except Exception:
                    continue
            raise RuntimeError(f"无法创建默认或回退沙盒目录 ({path}): {exc}") from exc

    def _is_path_in_sandbox(self, target_path: Path) -> bool:
        return is_path_in_sandbox(target_path, self._get_workspace_path())

    def _resolve_friendly_path(self, path_str: str) -> Path:
        return resolve_safe_path(path_str, self._get_workspace_path())

    # ------------------------------------------------------------------
    # Win32 桌面控制与多粒度截图委托包装
    # ------------------------------------------------------------------

    def _detect_screen_lock_state(self) -> tuple[bool, str]:
        return self._desktop.detect_screen_lock_state()

    def _get_monitors_info(self) -> tuple[dict[str, int] | None, list[dict[str, Any]]]:
        return self._desktop.get_monitors_info()

    def _enumerate_windows(self, query: str = "") -> list[dict[str, Any]]:
        return self._desktop.enumerate_windows(query=query)

    def _resolve_target_window(self, window_spec: str) -> tuple[dict[str, Any] | None, str]:
        return self._desktop.resolve_target_window(window_spec)

    @staticmethod
    def _is_image_all_black(img: Any) -> bool:
        return Win32DesktopController.is_image_all_black(img)

    @staticmethod
    def _parse_region(region_str: str) -> tuple[tuple[int, int, int, int] | None, str]:
        return Win32DesktopController.parse_region(region_str)

    def _capture_window_image(self, win_info: dict[str, Any]) -> tuple[bool, Any, str, dict[str, Any]]:
        return self._desktop.capture_window_image(win_info)

    def _capture_desktop_image(
        self,
        screen: str = "primary",
        window: str = "",
        region: str = "",
    ) -> tuple[bool, Any, str, dict[str, Any]]:
        return self._desktop.capture_desktop_image(screen=screen, window=window, region=region)

    def _capture_and_encode(
        self,
        screen: str = "primary",
        save_path: Path | None = None,
        window: str = "",
        region: str = "",
    ) -> tuple[bool, str, str, dict[str, Any]]:
        return self._desktop.capture_and_encode(screen=screen, save_path=save_path, window=window, region=region)

    def _capture_screen_base64(
        self,
        screen: str = "primary",
        save_path: Path | None = None,
        window: str = "",
        region: str = "",
    ) -> tuple[bool, str, str]:
        ok, b64, msg, _ = self._desktop.capture_and_encode(
            screen=screen,
            save_path=save_path,
            window=window,
            region=region,
        )
        return ok, b64, msg

    # ------------------------------------------------------------------
    # 终端、后台任务、硬件状态、二次确认与看门狗辅助
    # ------------------------------------------------------------------

    async def _execute_powershell(
        self,
        command: str,
        cwd_override: str | None = None,
    ) -> tuple[int, str]:
        """执行 PowerShell 终端命令，支持指定工作目录，超时强杀派生进程树"""
        if cwd_override and Path(cwd_override).is_dir():
            cwd = str(Path(cwd_override).resolve())
        else:
            cwd = str(self._get_workspace_path())

        timeout = self._cfg.sandbox.timeout_seconds
        shell_exe = "powershell.exe" if os.name == "nt" else "/bin/bash"
        args = (
            [
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                command,
            ]
            if os.name == "nt"
            else ["-c", command]
        )

        async def _kill_proc_tree() -> None:
            if process is None or process.returncode is not None:
                return
            try:
                if os.name == "nt":
                    await asyncio.to_thread(
                        subprocess.run,
                        ["taskkill", "/F", "/T", "/PID", str(process.pid)],
                        capture_output=True,
                        check=False,
                        timeout=10,
                    )
                else:
                    process.kill()
                await process.wait()
            except Exception as clean_err:
                self._log("error", "清理子进程异常: %s", clean_err)

        process = None
        try:
            process = await asyncio.create_subprocess_exec(
                shell_exe,
                *args,
                cwd=cwd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stdout_bytes, stderr_bytes = await asyncio.wait_for(process.communicate(), timeout=timeout)
            returncode = process.returncode or 0

            output = ""
            for raw in (stdout_bytes, stderr_bytes):
                if not raw:
                    continue
                try:
                    text = raw.decode("utf-8")
                except UnicodeDecodeError:
                    text = raw.decode("gbk", errors="replace")
                output += text

            if not output.strip():
                output = f"(命令已完成，无控制台输出，退出码: {returncode})"

            max_chars = self._cfg.sandbox.max_output_chars
            if len(output) > max_chars:
                output = output[:max_chars] + f"\n... [已截断，超出 {max_chars} 字符限制]"

            return returncode, output.strip()

        except asyncio.TimeoutError:
            await _kill_proc_tree()
            return -1, f"命令执行超时（超过 {timeout} 秒限制），已强制终止子进程树。"
        except asyncio.CancelledError:
            await _kill_proc_tree()
            raise
        except Exception as exc:
            return -1, f"命令启动执行失败: {exc}"

    def _get_hardware_status_summary(self, port_query: str = "") -> dict[str, Any]:
        return get_hardware_status_summary(
            workspace_path=self._get_workspace_path(),
            port_query=port_query,
            desktop_ctrl=self._desktop,
        )

    async def _handle_power_action(self, action: str, delay: int) -> tuple[bool, str]:
        if not self._cfg.sandbox.allow_system_control:
            return False, "系统电源控制功能当前已被配置禁用。"

        action_clean = action.lower().strip()
        delay_clamped = max(0, min(delay, 86400))

        def _run_cmd(cmd_args: list[str]) -> subprocess.CompletedProcess[str]:
            return subprocess.run(cmd_args, capture_output=True, text=True, check=False)

        if action_clean in ("shutdown", "关机"):
            args = ["shutdown.exe", "/s", "/t", str(delay_clamped), "/c", "MaiBot Administrator Shutdown Requested"]
            res = await asyncio.to_thread(_run_cmd, args)
            if res.returncode == 0:
                return True, f"已成功设定计算机在 {delay_clamped} 秒后关机。若需中止可执行 /取消关机。"
            return False, f"关机指令执行失败: {res.stderr.strip() or '权限不足'}"

        if action_clean in ("restart", "reboot", "重启"):
            args = ["shutdown.exe", "/r", "/t", str(delay_clamped), "/c", "MaiBot Administrator Restart Requested"]
            res = await asyncio.to_thread(_run_cmd, args)
            if res.returncode == 0:
                return True, f"已成功设定计算机在 {delay_clamped} 秒后重启。若需中止可执行 /取消关机。"
            return False, f"重启指令执行失败: {res.stderr.strip() or '权限不足'}"

        if action_clean in ("abort", "cancel", "取消", "取消关机"):
            args = ["shutdown.exe", "/a"]
            res = await asyncio.to_thread(_run_cmd, args)
            if res.returncode == 0:
                return True, "已成功取消计划中的关机或重启任务。"
            return False, f"取消计划失败（可能当前并没有激活的倒计时）: {res.stderr.strip()}"

        return False, f"未知的电源控制动作: {action}。支持的动作包括: 关机、重启、取消关机。"

    async def _on_job_finished(self, summary: dict[str, Any]) -> None:
        """后台长任务结束通知回调。"""
        stream_id = str(summary.get("stream_id") or "").strip()
        self._audit.log(
            source="BackgroundJob",
            action="job_finish",
            user_id="",
            stream_id=stream_id,
            group_id="",
            params={"job_id": summary.get("job_id"), "status": summary.get("status")},
            risk_level="low",
            success=summary.get("status") == "completed",
            detail=f"returncode={summary.get('returncode')} elapsed={summary.get('elapsed_seconds')}s",
        )
        if not stream_id:
            return
        tail = summary.get("tail_output") or "(无输出)"
        if len(tail) > 1200:
            tail = "...[已截断]\n" + tail[-1200:]
        msg = (
            f"【后台任务结束通知】\n"
            f"任务 ID: {summary.get('job_id')}\n"
            f"状态: {summary.get('status')} (退出码: {summary.get('returncode')})\n"
            f"耗时: {summary.get('elapsed_seconds')} 秒\n"
            f"日志文件: {summary.get('log_path')}\n"
            f"末尾输出:\n{tail}"
        )
        try:
            await self.ctx.send.text(msg, stream_id)
        except Exception as exc:
            self._log("debug", "发送后台任务通知失败: %s", exc)

    async def _send_watchdog_alert(self, text: str, target_stream_id: str) -> None:
        """看门狗主动告警推送（优先指定 stream_id，否则自动查找首位管理员私聊流）。"""
        sid = str(target_stream_id or "").strip()
        if not sid:
            try:
                for admin_raw in self._cfg.security.admin_users:
                    admin_bare = str(admin_raw).split(":")[-1].strip()
                    if not admin_bare:
                        continue
                    admin_stream = await self.ctx.chat.get_stream_by_user_id(admin_bare, platform="qq")
                    if isinstance(admin_stream, dict):
                        sid = str(admin_stream.get("session_id", "") or admin_stream.get("stream_id", "")).strip()
                        if sid:
                            break
            except Exception:
                sid = ""
        if sid:
            try:
                await self.ctx.send.text(text, sid)
            except Exception as exc:
                self._log("debug", "发送看门狗告警失败: %s", exc)

    async def _queue_confirmation(
        self,
        kind: str,
        payload: dict[str, Any],
        user_id: str,
        stream_id: str,
        title: str,
        detail_lines: list[str],
        reasons: list[str] | None = None,
    ) -> dict[str, Any]:
        """挂起高危操作或沙盒外写入请求并向会话发送统一确认提示。"""
        ticket = self._confirm_store.add(
            kind=kind,
            payload=payload,
            requester_user_id=user_id,
            stream_id=stream_id,
            summary=title,
        )
        req_id = ticket["req_id"]
        confirm_cmd = "/确认写入" if kind == "file_write" else "/确认执行"
        body = [f"【安全警告 - {title}】"] + detail_lines
        if reasons:
            body.append("风险依据: " + "；".join(reasons))
        body.append(
            f"\n请在 60 秒内由原发起管理员在当前会话发送「{confirm_cmd}」或「{confirm_cmd} {req_id}」以授权执行；若非您本人意图请忽略此消息。"
        )
        if stream_id:
            await self.ctx.send.text("\n".join(body), stream_id)
        return {
            "success": False,
            "status": "pending_admin_confirmation",
            "req_id": req_id,
            "error": f"安全拦截（{title}）：已向当前会话发送二次确认提示（ID: {req_id}）。在管理员发送 {confirm_cmd} 授权前，操作未执行。",
        }

    async def _execute_pending_ticket(self, ticket: dict[str, Any]) -> tuple[bool, str]:
        """核销票据后执行对应已授权操作。"""
        kind = ticket["kind"]
        payload = ticket["payload"]

        if kind == "file_write":
            req_path = Path(payload["path"])
            content = str(payload.get("content") or "")
            act = str(payload.get("action") or "write")
            mode = "a" if act == "append" else "w"
            try:
                req_path.parent.mkdir(parents=True, exist_ok=True)
                with open(req_path, mode, encoding="utf-8") as fh:
                    fh.write(content)
                return (
                    True,
                    f"管理员已完成双重确认授权：\n成功向沙盒外部文件写入数据！\n路径: {req_path}\n模式: {act}\n大小: {len(content.encode('utf-8'))} 字节",
                )
            except Exception as exc:
                return False, f"写入外部文件时发生系统错误: {exc}"

        if kind == "terminal_cmd":
            cmd = str(payload["command"])
            cwd_override = payload.get("cwd_override")
            returncode, output = await self._execute_powershell(cmd, cwd_override=cwd_override)
            status_text = "成功" if returncode == 0 else f"异常退出(状态码: {returncode})"
            return returncode == 0, f"【已授权高危命令执行结果: {status_text}】\n{output}"

        if kind == "bg_job":
            cmd = str(payload["command"])
            cwd = str(payload["cwd"])
            timeout_sec = payload.get("timeout_seconds")
            ok, res = await self._job_manager.start_job(
                command=cmd,
                cwd=cwd,
                stream_id=ticket["stream_id"],
                user_id=ticket["requester_user_id"],
                timeout_seconds=timeout_sec,
                notify_callback=self._on_job_finished,
            )
            if not ok:
                return False, str(res)
            assert isinstance(res, dict)
            return True, (
                f"【已授权启动高危后台任务】\n"
                f"任务 ID: {res['job_id']} | PID: {res['pid']}\n"
                f"日志: {res['log_path']}\n"
                f"可使用 /job logs {res['job_id']} 查看输出。"
            )

        if kind == "process_kill":
            q = str(payload["query"])

            def _kill_sync() -> tuple[bool, str]:
                if q.isdigit():
                    cmd_args = ["taskkill", "/F", "/PID", q]
                else:
                    img_name = q if q.lower().endswith(".exe") else f"{q}.exe"
                    cmd_args = ["taskkill", "/F", "/IM", img_name]
                res = subprocess.run(cmd_args, capture_output=True, text=True, check=False)
                if res.returncode == 0:
                    return True, f"已按管理员授权强杀进程: {q}"
                return False, f"终止进程失败: {res.stderr.strip() or '未找到匹配进程或权限不足'}"

            return await asyncio.to_thread(_kill_sync)

        if kind == "gui_input":
            args = dict(payload["args"])
            ok, msg, _ = await asyncio.to_thread(
                self._desktop.send_gui_input,
                action=args.get("action", ""),
                x=args.get("x"),
                y=args.get("y"),
                text=args.get("text", ""),
                keys=args.get("keys", ""),
                delta=args.get("delta", 0),
                window=args.get("window", ""),
                self_pid=os.getpid(),
                parent_pid=os.getppid(),
            )
            return ok, msg

        return False, f"未知的待确认票据类型: {kind}"

    # ------------------------------------------------------------------
    # 直达前缀指令 (@Command)
    # ------------------------------------------------------------------

    @Command("cmd_group_cmd", aliases=["/群聊控制", "/cmd_group", "/允许群聊", "/禁用群聊"], description="管理允许执行系统命令的群聊白名单及开关（仅限管理员）")
    async def cmd_group_cmd(self, **kwargs: Any) -> None:
        user_id, group_id, stream_id = self._extract_caller_info(kwargs)
        self._ensure_components_synced()
        if not self._is_admin(user_id):
            if self._cfg.security.unauthorized_message:
                await self.ctx.send.text(self._cfg.security.unauthorized_message, stream_id)
            return

        raw_text = self._extract_command_text(kwargs)
        parts = raw_text.split()
        first_word = parts[0].lower() if parts else ""
        subcmd = parts[1].lower() if len(parts) > 1 else ""

        if "/允许群聊" in first_word and not subcmd:
            subcmd = "add"
        elif "/禁用群聊" in first_word and not subcmd:
            subcmd = "del"

        curr_groups = list(self._cfg.security.allowed_groups)

        if subcmd in ("on", "enable", "开启", "开"):
            self._save_security_config(allow_in_groups=True)
            self._audit.log("Command", "cmd_group_on", user_id, stream_id, group_id, {}, "low", True)
            await self.ctx.send.text(
                f"【群聊系统控制设置】\n群聊系统命令总开关已开启 (allow_in_groups = true)。\n当前白名单群列表: {curr_groups or '无（请使用 /cmd_group add 添加群聊）'}",
                stream_id,
            )
            return

        if subcmd in ("off", "disable", "关闭", "关"):
            self._save_security_config(allow_in_groups=False)
            self._audit.log("Command", "cmd_group_off", user_id, stream_id, group_id, {}, "low", True)
            await self.ctx.send.text(
                "【群聊系统控制设置】\n群聊系统命令总开关已关闭 (allow_in_groups = false)。\n所有群聊中的系统命令与大模型自然语言系统工具均已锁定（仅私聊可用）。",
                stream_id,
            )
            return

        if subcmd in ("add", "allow", "添加", "+"):
            target_gid = parts[2].strip() if len(parts) > 2 else group_id
            if not target_gid:
                await self.ctx.send.text("请指定要加入白名单的群号，例如: /cmd_group add 12345678", stream_id)
                return
            if not re.fullmatch(r"^[a-zA-Z0-9_\-:]+$", target_gid):
                await self.ctx.send.text(f"群号格式不合法: [{target_gid}]，仅允许字母、数字、下划线、短横线与平台冒号前缀。", stream_id)
                return
            if target_gid in curr_groups:
                await self.ctx.send.text(f"群号 {target_gid} 已经在白名单中，无需重复添加。", stream_id)
                return
            curr_groups.append(target_gid)
            self._save_security_config(allow_in_groups=True, allowed_groups=curr_groups)
            self._audit.log("Command", "cmd_group_add", user_id, stream_id, group_id, {"target_gid": target_gid}, "low", True)
            await self.ctx.send.text(
                f"【群聊白名单更新成功】\n已将群聊 [{target_gid}] 加入系统命令授权白名单。\n群聊总开关已同步开启。",
                stream_id,
            )
            return

        if subcmd in ("del", "remove", "delete", "移除", "删除", "-"):
            target_gid = parts[2].strip() if len(parts) > 2 else group_id
            if not target_gid:
                await self.ctx.send.text("请指定要从白名单移除的群号，例如: /cmd_group del 12345678", stream_id)
                return
            if target_gid not in curr_groups:
                matched = [g for g in curr_groups if g == target_gid or g.split(":")[-1] == target_gid.split(":")[-1]]
                if not matched:
                    await self.ctx.send.text(f"群号 {target_gid} 不在白名单列表中。", stream_id)
                    return
                for m in matched:
                    curr_groups.remove(m)
            else:
                curr_groups.remove(target_gid)

            self._save_security_config(allowed_groups=curr_groups)
            self._audit.log("Command", "cmd_group_del", user_id, stream_id, group_id, {"target_gid": target_gid}, "low", True)
            await self.ctx.send.text(
                f"【群聊白名单更新成功】\n已将群聊 [{target_gid}] 从系统命令白名单中移除。\n剩余白名单群: {curr_groups or '无'}",
                stream_id,
            )
            return

        status_text = "已开启 (ON)" if self._cfg.security.allow_in_groups else "已关闭 (OFF)"
        group_list_text = "\n".join(f"- {g}" for g in self._cfg.security.allowed_groups) if self._cfg.security.allowed_groups else "（暂无授权群聊）"
        help_msg = (
            f"【群聊系统命令控制面板】\n"
            f"总开关状态: {status_text}\n"
            f"当前授权群聊白名单:\n{group_list_text}\n\n"
            f"常用管理指令:\n"
            f"- /cmd_group on : 开启群聊系统命令总开关\n"
            f"- /cmd_group off : 关闭群聊系统命令总开关\n"
            f"- /cmd_group add [群号] : 将当前群或指定群加入白名单\n"
            f"- /cmd_group del [群号] : 将当前群或指定群移出白名单\n"
            f"- /cmd_group list : 查看白名单与开关状态"
        )
        await self.ctx.send.text(help_msg, stream_id)

    @Command(
        "screenshot_cmd",
        aliases=["/截图", "/screen"],
        description="截取电脑桌面、指定窗口或局部区域（支持 list / win <窗口> / rect x,y,w,h / all / primary / 1 / 2）",
    )
    async def screenshot_cmd(self, **kwargs: Any) -> None:
        allowed, user_id, group_id, stream_id = await self._check_command_access(kwargs)
        if not allowed:
            return

        raw_text = self._extract_command_text(kwargs)
        parts = raw_text.split()
        sub = parts[1].lower() if len(parts) > 1 else ""

        if sub in ("list", "ls", "windows", "列表", "窗口列表") or (sub == "窗口" and len(parts) <= 2):
            query = raw_text.split(None, 2)[2].strip() if len(parts) > 2 else ""

            def _inspect() -> tuple[bool, str, dict[str, int] | None, list[dict[str, Any]], list[dict[str, Any]]]:
                locked, reason = self._detect_screen_lock_state()
                virt, mons = self._get_monitors_info()
                wins = self._enumerate_windows(query=query)
                return locked, reason, virt, mons, wins

            is_locked, lock_reason, virtual, monitors, windows = await asyncio.to_thread(_inspect)
            lines = ["【桌面环境与窗口列表】"]
            lines.append(f"锁屏状态: {'已锁屏 (' + lock_reason + ')' if is_locked else '已解锁（可正常截图）'}")
            if virtual:
                lines.append(f"虚拟桌面总范围: left={virtual['left']}, top={virtual['top']}, {virtual['width']}x{virtual['height']}")
            for m in monitors:
                tag = " [主屏]" if m["is_primary"] else ""
                lines.append(f"- 显示器 {m['index']}{tag}: left={m['left']}, top={m['top']}, {m['width']}x{m['height']}")
            lines.append(f"可见窗口数量: {len(windows)}")
            for w in windows[:20]:
                flags = []
                if w["foreground"]:
                    flags.append("前台")
                if w["minimized"]:
                    flags.append("最小化")
                elif w["maximized"]:
                    flags.append("最大化")
                flag_str = f" [{'/'.join(flags)}]" if flags else ""
                lines.append(
                    f"- [{w['hwnd']}] {w['process']} | {w['title'][:45]} "
                    f"({w['left']},{w['top']} {w['width']}x{w['height']}){flag_str}"
                )
            if len(windows) > 20:
                lines.append(f"... 仅展示前 20 个窗口（共 {len(windows)} 个）")
            self._audit.log("Command", "screenshot_list", user_id, stream_id, group_id, {"query": query}, "low", True)
            await self.ctx.send.text("\n".join(lines), stream_id)
            return

        screen_arg = "primary"
        window_arg = ""
        region_arg = ""

        if sub in ("win", "window", "窗口"):
            if len(parts) <= 2:
                await self.ctx.send.text("请指定要截图的窗口标题、进程名或 HWND，例如: /截图 win Code.exe", stream_id)
                return
            window_arg = raw_text.split(None, 2)[2].strip()
        elif sub in ("rect", "region", "area", "区域"):
            if len(parts) <= 2:
                await self.ctx.send.text("请指定区域坐标 (x,y,width,height)，例如: /截图 rect 100,200,800,600", stream_id)
                return
            region_arg = raw_text.split(None, 2)[2].strip()
        elif len(parts) > 1:
            if "," in parts[1]:
                region_arg = raw_text.split(None, 1)[1].strip()
            else:
                screen_arg = parts[1]
                if len(parts) > 2:
                    region_arg = raw_text.split(None, 2)[2].strip()

        save_file = self._get_workspace_path() / "captures" / f"screen_{int(time.time())}.png"
        success, b64_data, msg = await asyncio.to_thread(
            self._capture_screen_base64,
            screen_arg,
            save_file,
            window_arg,
            region_arg,
        )
        self._audit.log(
            "Command",
            "screenshot",
            user_id,
            stream_id,
            group_id,
            {"screen": screen_arg, "window": window_arg, "region": region_arg},
            "low",
            success,
            msg,
        )
        if not success:
            await self.ctx.send.text(msg, stream_id)
            return

        await self.ctx.send.image(b64_data, stream_id)
        await self.ctx.send.text(f"{msg}\n本地存档: {save_file}", stream_id)

    @Command(
        "confirm_write_cmd",
        aliases=["/确认写入", "/confirm_write", "/确认执行", "/confirm_exec"],
        description="授权执行待管理员二次确认的操作请求（沙盒外写入/高危命令/进程/GUI输入）",
    )
    async def confirm_write_cmd(self, **kwargs: Any) -> None:
        allowed, user_id, group_id, stream_id = await self._check_command_access(kwargs)
        if not allowed:
            return

        raw_text = self._extract_command_text(kwargs)
        parts = raw_text.split()
        cmd_word = parts[0].lower() if parts else ""
        req_id = parts[1].strip() if len(parts) > 1 else ""
        allowed_kinds: tuple[str, ...] | None = None
        if not req_id and ("确认写入" in cmd_word or "confirm_write" in cmd_word):
            allowed_kinds = ("file_write",)

        ticket, err = self._confirm_store.consume(
            req_id=req_id,
            caller_user_id=user_id,
            stream_id=stream_id,
            allowed_kinds=allowed_kinds,
        )
        if ticket is None:
            self._audit.log("Command", "confirm_action", user_id, stream_id, group_id, {"req_id": req_id}, "high", False, err)
            await self.ctx.send.text(err, stream_id)
            return

        ok, msg = await self._execute_pending_ticket(ticket)
        self._audit.log(
            "Command",
            f"confirm_{ticket['kind']}",
            user_id,
            stream_id,
            group_id,
            {"req_id": ticket["req_id"], "kind": ticket["kind"]},
            "high",
            ok,
            msg,
        )
        await self.ctx.send.text(msg, stream_id)

    @Command("terminal_cmd", aliases=["/cmd", "/terminal"], description="在电脑中执行终端命令（仅限管理员，高危命令需二次确认）")
    async def terminal_cmd(self, **kwargs: Any) -> None:
        allowed, user_id, group_id, stream_id = await self._check_command_access(kwargs)
        if not allowed:
            return

        raw_text = self._extract_command_text(kwargs)
        command = re.sub(r"^/(?:cmd|terminal)\s*", "", raw_text, flags=re.IGNORECASE).strip()
        if not command:
            await self.ctx.send.text("使用方法: /cmd <要执行的终端命令>\n例如: /cmd dir 或 /cmd tasklist", stream_id)
            return

        risk_level, reasons = assess_command_risk(
            command,
            workspace_dir=self._get_workspace_path(),
            sandbox_only_write=self._cfg.sandbox.sandbox_only_write,
        )
        if risk_level == "high" and self._cfg.sandbox.confirm_high_risk_commands:
            await self._queue_confirmation(
                kind="terminal_cmd",
                payload={"command": command, "cwd_override": None},
                user_id=user_id,
                stream_id=stream_id,
                title="高危终端命令二次确认",
                detail_lines=[f"待执行命令: {command[:300]}"],
                reasons=reasons,
            )
            self._audit.log("Command", "terminal_cmd_pending", user_id, stream_id, group_id, {"command": command}, "high", False, "; ".join(reasons))
            return

        returncode, output = await self._execute_powershell(command)
        self._audit.log("Command", "terminal_cmd", user_id, stream_id, group_id, {"command": command}, risk_level, returncode == 0, f"rc={returncode}")
        status_text = "成功" if returncode == 0 else f"异常退出(状态码: {returncode})"
        await self.ctx.send.text(f"【命令执行结果: {status_text}】\n{output}", stream_id)

    @Command("job_cmd", aliases=["/job", "/后台任务"], description="管理后台长耗时任务（list / status <id> / logs <id> / kill <id> / run <命令>）")
    async def job_cmd(self, **kwargs: Any) -> None:
        allowed, user_id, group_id, stream_id = await self._check_command_access(kwargs)
        if not allowed:
            return

        raw_text = self._extract_command_text(kwargs)
        parts = raw_text.split()
        sub = parts[1].lower() if len(parts) > 1 else "list"

        if sub in ("list", "ls", "列表"):
            jobs = self._job_manager.list_jobs()
            if not jobs:
                await self.ctx.send.text("当前没有任何后台任务记录。", stream_id)
                return
            lines = ["【后台长任务列表】"]
            for j in jobs[:15]:
                lines.append(
                    f"- [{j['job_id']}] {j['status']} | PID: {j['pid']} | {j['elapsed_seconds']}s | {j['command'][:45]}"
                )
            await self.ctx.send.text("\n".join(lines), stream_id)
            return

        if sub in ("status", "info", "状态") and len(parts) > 2:
            st = self._job_manager.get_job_status(parts[2])
            if not st:
                await self.ctx.send.text(f"未找到任务 ID: {parts[2]}", stream_id)
                return
            await self.ctx.send.text(
                f"【任务状态】ID: {st['job_id']}\n状态: {st['status']} | PID: {st['pid']} | 退出码: {st['returncode']}\n"
                f"耗时: {st['elapsed_seconds']}s\n目录: {st['cwd']}\n日志: {st['log_path']}",
                stream_id,
            )
            return

        if sub in ("logs", "log", "日志") and len(parts) > 2:
            tail_n = int(parts[3]) if len(parts) > 3 and parts[3].isdigit() else 40
            ok, res = self._job_manager.get_job_logs(parts[2], tail_lines=tail_n, max_chars=self._cfg.sandbox.max_output_chars)
            if not ok:
                await self.ctx.send.text(str(res), stream_id)
                return
            assert isinstance(res, dict)
            await self.ctx.send.text(f"【任务 {res['job_id']} ({res['status']}) 尾部日志】\n{res['logs']}", stream_id)
            return

        if sub in ("kill", "stop", "终止") and len(parts) > 2:
            ok, msg = await self._job_manager.kill_job(parts[2])
            self._audit.log("Command", "job_kill", user_id, stream_id, group_id, {"job_id": parts[2]}, "medium", ok, msg)
            await self.ctx.send.text(msg, stream_id)
            return

        if sub in ("run", "start", "启动") and len(parts) > 2:
            cmd = raw_text.split(None, 2)[2].strip()
            cwd = str(self._get_workspace_path())
            risk_level, reasons = assess_command_risk(cmd, self._get_workspace_path(), self._cfg.sandbox.sandbox_only_write)
            if risk_level == "high" and self._cfg.sandbox.confirm_high_risk_commands:
                await self._queue_confirmation(
                    kind="bg_job",
                    payload={"command": cmd, "cwd": cwd, "timeout_seconds": None},
                    user_id=user_id,
                    stream_id=stream_id,
                    title="高危后台任务二次确认",
                    detail_lines=[f"待启动命令: {cmd[:300]}", f"工作目录: {cwd}"],
                    reasons=reasons,
                )
                return
            ok, res = await self._job_manager.start_job(
                command=cmd,
                cwd=cwd,
                stream_id=stream_id,
                user_id=user_id,
                notify_callback=self._on_job_finished,
            )
            self._audit.log("Command", "job_start", user_id, stream_id, group_id, {"command": cmd}, risk_level, ok, str(res))
            if not ok:
                await self.ctx.send.text(str(res), stream_id)
                return
            assert isinstance(res, dict)
            await self.ctx.send.text(
                f"已启动后台任务 [{res['job_id']}] (PID: {res['pid']})\n日志: {res['log_path']}\n任务完成后会自动推送通知。",
                stream_id,
            )
            return

        await self.ctx.send.text(
            "使用方法:\n"
            "- /job list : 查看全部后台任务\n"
            "- /job run <命令> : 后台启动长任务\n"
            "- /job status <ID> : 查看任务状态\n"
            "- /job logs <ID> [行数] : 查看尾部日志\n"
            "- /job kill <ID> : 强杀任务进程树",
            stream_id,
        )

    @Command("watchdog_cmd", aliases=["/watchdog", "/监控"], description="管理后台运维看门狗（status / on / off / disk <GB> / add_proc <名> / del_proc <名> / lock on|off）")
    async def watchdog_cmd(self, **kwargs: Any) -> None:
        allowed, user_id, group_id, stream_id = await self._check_command_access(kwargs)
        if not allowed:
            return

        raw_text = self._extract_command_text(kwargs)
        parts = raw_text.split()
        sub = parts[1].lower() if len(parts) > 1 else "status"

        if sub in ("on", "enable", "开启"):
            self._watchdog.configure(notify_stream_id=self._watchdog.notify_stream_id or stream_id)
            await self._watchdog.start()
            self._audit.log("Command", "watchdog_on", user_id, stream_id, group_id, {}, "low", True)
            await self.ctx.send.text(f"后台看门狗已启动（轮询间隔 {self._watchdog.interval_seconds} 秒，推送会话: {self._watchdog.notify_stream_id or '自动'}）。", stream_id)
            return

        if sub in ("off", "disable", "关闭"):
            await self._watchdog.stop()
            self._audit.log("Command", "watchdog_off", user_id, stream_id, group_id, {}, "low", True)
            await self.ctx.send.text("后台看门狗已停止。", stream_id)
            return

        if sub == "disk" and len(parts) > 2:
            try:
                val = float(parts[2])
                if not math.isfinite(val):
                    raise ValueError("non-finite")
                self._watchdog.configure(disk_min_free_gb=val)
                await self.ctx.send.text(f"已更新磁盘剩余空间告警阈值为: {self._watchdog.disk_min_free_gb} GB（0 表示关闭）。", stream_id)
            except ValueError:
                await self.ctx.send.text("请输入有效的数字，例如: /watchdog disk 15", stream_id)
            return

        if sub == "add_proc" and len(parts) > 2:
            cur = list(self._watchdog.watched_processes)
            cur.append(parts[2])
            self._watchdog.configure(watched_processes=cur)
            await self.ctx.send.text(f"当前监控进程列表: {self._watchdog.watched_processes}", stream_id)
            return

        if sub == "del_proc" and len(parts) > 2:
            tgt = parts[2].strip().lower()
            tgt_exe = tgt if tgt.endswith(".exe") else f"{tgt}.exe"
            cur = [p for p in self._watchdog.watched_processes if p not in (tgt, tgt_exe)]
            self._watchdog.configure(watched_processes=cur)
            await self.ctx.send.text(f"当前监控进程列表: {self._watchdog.watched_processes or '无'}", stream_id)
            return

        if sub == "lock" and len(parts) > 2:
            flag = parts[2].lower() in ("on", "true", "1", "开启")
            self._watchdog.configure(watch_lock_state=flag)
            await self.ctx.send.text(f"锁屏状态变更提醒已{'开启' if flag else '关闭'}。", stream_id)
            return

        st = self._watchdog.get_status()
        await self.ctx.send.text(
            f"【系统看门狗状态】\n"
            f"运行中: {st['running']} | 轮询间隔: {st['interval_seconds']}s | 冷却: {st['cooldown_seconds']}s\n"
            f"磁盘阈值: {st['disk_min_free_gb']} GB | 锁屏提醒: {st['watch_lock_state']}\n"
            f"监控进程: {st['watched_processes'] or '无'}\n"
            f"推送会话: {st['notify_stream_id'] or '自动匹配管理员私聊'}",
            stream_id,
        )

    @Command("audit_cmd", aliases=["/audit", "/审计"], description="查看最近的操作审计日志摘要")
    async def audit_cmd(self, **kwargs: Any) -> None:
        allowed, _, _, stream_id = await self._check_command_access(kwargs)
        if not allowed:
            return

        raw_text = self._extract_command_text(kwargs)
        parts = raw_text.split()
        limit = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 10
        limit = max(1, min(limit, 30))

        entries = await asyncio.to_thread(self._audit.read_recent, limit)
        if not entries:
            await self.ctx.send.text("暂无审计日志记录。", stream_id)
            return

        lines = [f"【最近 {len(entries)} 条操作审计日志】"]
        for item in entries:
            ok_tag = "成功" if item.get("success") else "拦截/失败"
            lines.append(
                f"- {item.get('timestamp')} | {item.get('source')}:{item.get('action')} "
                f"| 风险:{item.get('risk_level')} | {ok_tag} | {str(item.get('detail') or '')[:60]}"
            )
        await self.ctx.send.text("\n".join(lines), stream_id)

    @Command("power_cmd", aliases=["/关机", "/重启", "/取消关机"], description="控制计算机电源关机、重启或取消倒计时")
    async def power_cmd(self, **kwargs: Any) -> None:
        allowed, user_id, group_id, stream_id = await self._check_command_access(kwargs)
        if not allowed:
            return

        raw_text = self._extract_command_text(kwargs)
        parts = raw_text.split()
        first_word = parts[0].lower() if parts else ""

        delay = self._cfg.sandbox.shutdown_delay_seconds
        if len(parts) > 1 and parts[1].isdigit():
            delay = int(parts[1])

        if "/关机" in first_word:
            action = "关机"
        elif "/重启" in first_word:
            action = "重启"
        else:
            action = "取消关机"

        ok, msg = await self._handle_power_action(action, delay)
        self._audit.log("Command", "power", user_id, stream_id, group_id, {"action": action, "delay": delay}, "high", ok, msg)
        await self.ctx.send.text(msg, stream_id)

    # ------------------------------------------------------------------
    # 大模型专属系统工具集 (@Tool) - 仅限管理员在私聊或授权群聊中自然语言调用
    # ------------------------------------------------------------------

    @Tool(
        "list_desktop_windows",
        description=(
            "探测当前电脑是否处于锁屏状态、所有显示器的分辨率与坐标布局，以及当前桌面可见应用窗口列表（含 HWND、进程名、标题、坐标宽高、前台与最小化状态）。"
            "当管理员询问电脑打开了什么、需要查看特定程序、或你想自主选择截取哪个窗口/哪块区域时，优先调用此工具获取目标信息。"
        ),
        parameters=[
            ToolParameterInfo(
                name="query",
                param_type=ToolParamType.STRING,
                description="可选过滤关键字（按窗口标题、进程名或 HWND 过滤，留空返回全部可见窗口）",
                required=False,
            ),
        ],
    )
    async def handle_tool_list_windows(self, query: str = "", **kwargs: Any) -> dict[str, Any]:
        verified, err, stream_id, user_id, group_id = await self._verify_tool_caller_detail(kwargs)
        if not verified:
            return {"success": False, "error": err}

        def _inspect() -> tuple[bool, str, dict[str, int] | None, list[dict[str, Any]], list[dict[str, Any]]]:
            locked, reason = self._detect_screen_lock_state()
            virt, mons = self._get_monitors_info()
            wins = self._enumerate_windows(query=query)
            return locked, reason, virt, mons, wins

        is_locked, lock_reason, virtual, monitors, windows = await asyncio.to_thread(_inspect)
        self._audit.log("Tool", "list_desktop_windows", user_id, stream_id, group_id, {"query": query}, "low", True, f"locked={is_locked}, count={len(windows)}")
        return {
            "success": True,
            "locked": is_locked,
            "lock_reason": lock_reason,
            "note": (
                "当前电脑已锁屏，无法获取桌面实时图像，请直接告知管理员电脑处于锁屏状态。"
                if is_locked
                else "桌面已解锁，可调用 desktop_screenshot 自主指定 screen、window 或 region 截取目标画面。"
            ),
            "virtual_screen": virtual,
            "monitors": monitors,
            "window_count": len(windows),
            "windows": windows[:40],
            "truncated": len(windows) > 40,
        }

    @Tool(
        "desktop_screenshot",
        description=(
            "截取电脑桌面、指定应用窗口或局部矩形区域，并将图片自动发送到当前聊天会话中。"
            "内置锁屏检测：若电脑处于锁屏状态将直接返回锁屏提示，不会发送锁屏壁纸图片。"
            "支持三种自主截图模式：1) 屏幕级截图（主屏/全屏全景/指定显示器）；"
            "2) 窗口级穿透截图（通过 window 参数指定进程名、标题或 HWND，即使窗口被其他程序遮挡也能精准抓取窗口自身内容）；"
            "3) 局部区域裁剪（通过 region 参数传入 'x,y,width,height' 放大查看界面局部细节）。"
        ),
        parameters=[
            ToolParameterInfo(
                name="screen",
                param_type=ToolParamType.STRING,
                description="屏幕目标（未传 window 时生效）：'primary'（默认，主显示器）、'all'（全部显示器拼接全景）、或指定屏幕序号（如 '1', '2', '3'）",
                required=False,
            ),
            ToolParameterInfo(
                name="window",
                param_type=ToolParamType.STRING,
                description="可选，指定要独立截取的窗口（支持 HWND 数字、进程名如 'Code.exe'/'WeChat.exe'、或窗口标题关键字）。传入此参数时将穿透遮挡单独截取该窗口",
                required=False,
            ),
            ToolParameterInfo(
                name="region",
                param_type=ToolParamType.STRING,
                description="可选，局部区域裁剪坐标，格式为 'x,y,width,height'（相对本次截取的屏幕或窗口图像左上角，如 '100,200,800,600'），用于局部放大查看细节",
                required=False,
            ),
        ],
    )
    async def handle_tool_screenshot(
        self,
        screen: str = "primary",
        window: str = "",
        region: str = "",
        **kwargs: Any,
    ) -> dict[str, Any]:
        verified, err, stream_id, user_id, group_id = await self._verify_tool_caller_detail(kwargs)
        if not verified:
            return {"success": False, "error": err}

        save_file = self._get_workspace_path() / "captures" / f"screen_{int(time.time())}.png"
        success, b64_data, msg, meta = await asyncio.to_thread(
            self._capture_and_encode,
            screen,
            save_file,
            window,
            region,
        )
        self._audit.log(
            "Tool",
            "desktop_screenshot",
            user_id,
            stream_id,
            group_id,
            {"screen": screen, "window": window, "region": region},
            "low",
            success,
            msg,
        )

        if not success:
            resp: dict[str, Any] = {"success": False, "error": msg}
            if meta.get("locked"):
                resp["locked"] = True
                resp["lock_reason"] = meta.get("lock_reason", "")
            return resp

        if stream_id:
            await self.ctx.send.image(b64_data, stream_id)

        result: dict[str, Any] = {
            "success": True,
            "message": f"{msg}。图片已直接发送到当前聊天中，你可以在对话中提示用户查看图片。",
            "saved_local_path": str(save_file),
        }
        for key in ("image_size", "bounds", "crop_region"):
            if meta.get(key):
                result[key] = meta[key]
        return result

    @Tool(
        "control_window",
        description=(
            "控制桌面指定窗口的显示状态或位置尺寸。支持恢复最小化窗口（便于后续截图）、最小化、最大化、激活置前、置顶切换、移动调整大小以及温和关闭 (WM_CLOSE)。"
            "锁屏状态下自动拒绝；受保护的系统关键窗口禁止操作。"
        ),
        parameters=[
            ToolParameterInfo(
                name="window",
                param_type=ToolParamType.STRING,
                description="目标窗口标识：支持 HWND 数字、进程名（如 'Code.exe'）或窗口标题关键字",
                required=True,
            ),
            ToolParameterInfo(
                name="action",
                param_type=ToolParamType.STRING,
                description="窗口操作动作：'restore'（恢复）、'minimize'（最小化）、'maximize'（最大化）、'focus'（激活置前）、'topmost'（切换置顶）、'topmost_on'、'topmost_off'、'move_resize'（移动缩放）、'close'（温和关闭）",
                required=True,
            ),
            ToolParameterInfo(
                name="x",
                param_type=ToolParamType.INTEGER,
                description="仅 move_resize 时可选：目标左上角 X 坐标",
                required=False,
            ),
            ToolParameterInfo(
                name="y",
                param_type=ToolParamType.INTEGER,
                description="仅 move_resize 时可选：目标左上角 Y 坐标",
                required=False,
            ),
            ToolParameterInfo(
                name="width",
                param_type=ToolParamType.INTEGER,
                description="仅 move_resize 时可选：目标宽度（像素）",
                required=False,
            ),
            ToolParameterInfo(
                name="height",
                param_type=ToolParamType.INTEGER,
                description="仅 move_resize 时可选：目标高度（像素）",
                required=False,
            ),
        ],
    )
    async def handle_tool_control_window(
        self,
        window: str = "",
        action: str = "restore",
        x: int | None = None,
        y: int | None = None,
        width: int | None = None,
        height: int | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        verified, err, stream_id, user_id, group_id = await self._verify_tool_caller_detail(kwargs)
        if not verified:
            return {"success": False, "error": err}

        if not self._cfg.sandbox.allow_window_control:
            return {"success": False, "error": "窗口控制功能当前已被配置禁用 (allow_window_control=false)。"}

        ok, msg, meta = await asyncio.to_thread(
            self._desktop.control_window,
            window,
            action,
            x,
            y,
            width,
            height,
            os.getpid(),
            os.getppid(),
        )
        self._audit.log(
            "Tool",
            "control_window",
            user_id,
            stream_id,
            group_id,
            {"window": window, "action": action, "x": x, "y": y, "width": width, "height": height},
            "medium" if str(action or "").strip().lower() in ("close", "关闭") else "low",
            ok,
            msg,
        )
        if not ok:
            return {"success": False, "error": msg, **({"locked": True} if meta.get("locked") else {})}
        return {"success": True, "message": msg, "window": meta}

    @Tool(
        "gui_input",
        description=(
            "受控 GUI 键鼠交互工具（基于 Win32 SendInput）。支持鼠标点击/双击/右击/移动/滚轮、Unicode 文本输入与快捷键（如 ctrl+s、media_play_pause）。"
            "仅当配置显式开启 allow_gui_input=true 时可用；锁屏状态及系统安全界面下强制禁止。"
        ),
        parameters=[
            ToolParameterInfo(
                name="action",
                param_type=ToolParamType.STRING,
                description="键鼠动作：'click'、'double_click'、'right_click'、'middle_click'、'move'、'scroll'、'type_text'、'hotkey'",
                required=True,
            ),
            ToolParameterInfo(
                name="x",
                param_type=ToolParamType.INTEGER,
                description="鼠标操作 X 坐标（若同时传入 window，则为相对该窗口左上角的坐标）",
                required=False,
            ),
            ToolParameterInfo(
                name="y",
                param_type=ToolParamType.INTEGER,
                description="鼠标操作 Y 坐标（若同时传入 window，则为相对该窗口左上角的坐标）",
                required=False,
            ),
            ToolParameterInfo(
                name="text",
                param_type=ToolParamType.STRING,
                description="action='type_text' 时要输入的文本（最多 500 字符）",
                required=False,
            ),
            ToolParameterInfo(
                name="keys",
                param_type=ToolParamType.STRING,
                description="action='hotkey' 时的快捷键组合（如 'ctrl+s'、'alt+tab'、'enter'、'volume_up'、'media_play_pause'）",
                required=False,
            ),
            ToolParameterInfo(
                name="delta",
                param_type=ToolParamType.INTEGER,
                description="action='scroll' 时的滚轮步数（正数向上，负数向下）",
                required=False,
            ),
            ToolParameterInfo(
                name="window",
                param_type=ToolParamType.STRING,
                description="可选，目标窗口（HWND/进程名/标题）；传入时先安全聚焦该窗口再相对窗口坐标执行操作",
                required=False,
            ),
        ],
    )
    async def handle_tool_gui_input(
        self,
        action: str = "click",
        x: int | None = None,
        y: int | None = None,
        text: str = "",
        keys: str = "",
        delta: int = 0,
        window: str = "",
        **kwargs: Any,
    ) -> dict[str, Any]:
        verified, err, stream_id, user_id, group_id = await self._verify_tool_caller_detail(kwargs)
        if not verified:
            return {"success": False, "error": err}

        if not self._cfg.sandbox.allow_gui_input:
            return {
                "success": False,
                "error": "安全策略拦截：GUI 键鼠交互功能当前默认禁用 (allow_gui_input=false)。如需启用请在 config.toml 的 [sandbox] 中设置 allow_gui_input = true。",
            }

        is_locked, lock_reason = await asyncio.to_thread(self._desktop.detect_screen_lock_state)
        if is_locked:
            return {"success": False, "locked": True, "error": f"安全拦截：{lock_reason}，锁屏状态下严禁注入键鼠操作。"}

        args_dict = {
            "action": action,
            "x": x,
            "y": y,
            "text": text,
            "keys": keys,
            "delta": delta,
            "window": window,
        }
        audit_args = {
            "action": action,
            "x": x,
            "y": y,
            "text_len": len(text or ""),
            "keys": keys,
            "delta": delta,
            "window": window,
        }
        if self._cfg.sandbox.require_confirm_gui_input:
            self._audit.log("Tool", "gui_input_pending", user_id, stream_id, group_id, audit_args, "high", False, "等待二次确认")
            return await self._queue_confirmation(
                kind="gui_input",
                payload={"args": args_dict},
                user_id=user_id,
                stream_id=stream_id,
                title="GUI 键鼠操作二次确认",
                detail_lines=[
                    f"动作: {action}",
                    f"目标窗口: {window or '当前焦点/全屏坐标'}",
                    f"参数: x={x}, y={y}, keys={keys or '-'}, delta={delta}, text_len={len(text or '')}",
                ],
                reasons=["当前开启了 require_confirm_gui_input 安全门禁"],
            )

        ok, msg, meta = await asyncio.to_thread(
            self._desktop.send_gui_input,
            action=action,
            x=x,
            y=y,
            text=text,
            keys=keys,
            delta=delta,
            window=window,
            self_pid=os.getpid(),
            parent_pid=os.getppid(),
        )
        self._audit.log("Tool", "gui_input", user_id, stream_id, group_id, audit_args, "high", ok, msg)
        if not ok:
            return {"success": False, "error": msg}
        return {"success": True, "message": msg, "detail": meta}

    @Tool(
        "get_system_status",
        description="获取电脑实时系统资源与硬件/网络状态，包括 CPU 使用率、物理内存、磁盘剩余空间、电池/供电、NVIDIA GPU（如有）、局域网 IP、开机时长，以及可选的端口占用排查。",
        parameters=[
            ToolParameterInfo(
                name="port_query",
                param_type=ToolParamType.STRING,
                description="可选，传入端口号或关键字（如 '8080'、'LISTENING'、'all'）以排查端口占用与对应进程",
                required=False,
            ),
        ],
    )
    async def handle_tool_system_status(self, port_query: str = "", **kwargs: Any) -> dict[str, Any]:
        verified, err, stream_id, user_id, group_id = await self._verify_tool_caller_detail(kwargs)
        if not verified:
            return {"success": False, "error": err}

        data = await asyncio.to_thread(self._get_hardware_status_summary, port_query)
        self._audit.log("Tool", "get_system_status", user_id, stream_id, group_id, {"port_query": port_query}, "low", True)
        return {"success": True, "status": data}

    @Tool(
        "manage_file",
        description=(
            "安全管理电脑中的文件与目录。支持在沙盒工作区内读写、按行分片读取大日志（支持负数查看末尾行）、关键字/正则搜索文本、递归查找文件与查看目录/属性。"
            "沙盒外写入受管理员双重确认门禁保护。支持路径别名：'Workspace'、'Desktop'、'Downloads'、'Documents'。"
        ),
        parameters=[
            ToolParameterInfo(
                name="action",
                param_type=ToolParamType.STRING,
                description="文件动作：'read'（整文件读取）、'read_lines'（按行区间或末尾行读取）、'search'（搜索关键字或正则）、'find'（查找文件名）、'write'（写入/覆盖）、'append'（追加）、'list'（列目录）、'info'（属性）",
                required=True,
            ),
            ToolParameterInfo(
                name="path",
                param_type=ToolParamType.STRING,
                description="目标文件或目录路径。支持绝对路径、相对沙盒路径、或别名（如 'Desktop/notes.txt'、'Workspace/my_script.py'）",
                required=True,
            ),
            ToolParameterInfo(
                name="content",
                param_type=ToolParamType.STRING,
                description="action 为 'write' 或 'append' 时要写入的文本内容",
                required=False,
            ),
            ToolParameterInfo(
                name="start_line",
                param_type=ToolParamType.INTEGER,
                description="action='read_lines' 时的起始行号（1-based；传负数如 -100 表示读取文件最后 100 行）",
                required=False,
            ),
            ToolParameterInfo(
                name="end_line",
                param_type=ToolParamType.INTEGER,
                description="action='read_lines' 时的结束行号（正数区间时生效，0 表示自动向后读 200 行）",
                required=False,
            ),
            ToolParameterInfo(
                name="pattern",
                param_type=ToolParamType.STRING,
                description="action='search' 时的文本或正则关键字；action='find' 时的文件名通配符/关键字（如 '*.log'）",
                required=False,
            ),
            ToolParameterInfo(
                name="use_regex",
                param_type=ToolParamType.BOOLEAN,
                description="action='search' 时是否按正则表达式匹配（默认 false）",
                required=False,
            ),
        ],
    )
    async def handle_tool_file(
        self,
        action: str = "read",
        path: str = "",
        content: str = "",
        start_line: int = 1,
        end_line: int = 0,
        pattern: str = "",
        use_regex: bool = False,
        **kwargs: Any,
    ) -> dict[str, Any]:
        verified, err, stream_id, user_id, group_id = await self._verify_tool_caller_detail(kwargs)
        if not verified:
            return {"success": False, "error": err}

        act = str(action or "read").lower().strip()
        raw_target = self._resolve_friendly_path(path)
        target_path = raw_target.resolve()
        is_in_sandbox = self._is_path_in_sandbox(raw_target) and self._is_path_in_sandbox(target_path)

        if act == "read":
            if not target_path.exists():
                return {"success": False, "error": f"目标文件不存在: {target_path}"}
            if not target_path.is_file():
                return {"success": False, "error": f"目标路径不是一个普通文件: {target_path}"}
            try:
                size = target_path.stat().st_size
                if size > 100 * 1024:
                    with open(target_path, "r", encoding="utf-8", errors="replace") as f:
                        text = f.read(50000)
                    res = {
                        "success": True,
                        "path": str(target_path),
                        "truncated": True,
                        "content": text + "\n... [已截断，文件超出 100KB 大小限制，建议使用 read_lines 或 search]",
                    }
                else:
                    with open(target_path, "r", encoding="utf-8", errors="replace") as f:
                        text = f.read()
                    res = {"success": True, "path": str(target_path), "content": text}
                self._audit.log("Tool", "file_read", user_id, stream_id, group_id, {"path": str(target_path), "in_sandbox": is_in_sandbox}, "low", True)
                return res
            except Exception as exc:
                return {"success": False, "error": f"读取文件失败: {exc}"}

        if act == "read_lines":
            res = await asyncio.to_thread(read_file_lines, target_path, start_line, end_line)
            self._audit.log("Tool", "file_read_lines", user_id, stream_id, group_id, {"path": str(target_path), "start_line": start_line, "end_line": end_line}, "low", bool(res.get("success")))
            return res

        if act == "search":
            res = await asyncio.to_thread(search_text_in_path, target_path, pattern, bool(use_regex))
            self._audit.log("Tool", "file_search", user_id, stream_id, group_id, {"path": str(target_path), "pattern": pattern, "use_regex": bool(use_regex)}, "low", bool(res.get("success")))
            return res

        if act == "find":
            res = await asyncio.to_thread(find_files, target_path, pattern or "*")
            self._audit.log("Tool", "file_find", user_id, stream_id, group_id, {"path": str(target_path), "pattern": pattern}, "low", bool(res.get("success")))
            return res

        if act == "list":
            if not target_path.exists():
                return {"success": False, "error": f"目标目录不存在: {target_path}"}
            if not target_path.is_dir():
                return {"success": False, "error": f"目标路径不是目录: {target_path}"}
            try:
                entries = []
                for item in list(target_path.iterdir())[:100]:
                    try:
                        is_dir = item.is_dir()
                        size_bytes = item.stat().st_size if item.is_file() else 0
                    except OSError:
                        is_dir = False
                        size_bytes = 0
                    entries.append(
                        {
                            "name": item.name,
                            "is_dir": is_dir,
                            "size_bytes": size_bytes,
                        }
                    )
                self._audit.log("Tool", "file_list", user_id, stream_id, group_id, {"path": str(target_path)}, "low", True)
                return {"success": True, "path": str(target_path), "entries": entries}
            except Exception as exc:
                return {"success": False, "error": f"遍历目录失败: {exc}"}

        if act == "info":
            if not target_path.exists():
                return {"success": False, "error": f"目标不存在: {target_path}"}
            st = target_path.stat()
            return {
                "success": True,
                "path": str(target_path),
                "is_file": target_path.is_file(),
                "is_dir": target_path.is_dir(),
                "size_bytes": st.st_size,
                "in_sandbox": is_in_sandbox,
            }

        if act in ("write", "append"):
            if is_in_sandbox:
                try:
                    target_path.parent.mkdir(parents=True, exist_ok=True)
                    mode = "a" if act == "append" else "w"
                    with open(target_path, mode, encoding="utf-8") as f:
                        f.write(content or "")
                    self._audit.log("Tool", f"file_{act}", user_id, stream_id, group_id, {"path": str(target_path), "in_sandbox": True, "bytes": len((content or "").encode("utf-8"))}, "low", True)
                    return {
                        "success": True,
                        "message": f"成功在沙盒工作区内写入文件: {target_path} (模式: {act}, 大小: {len((content or '').encode('utf-8'))} 字节)",
                        "path": str(target_path),
                        "in_sandbox": True,
                    }
                except Exception as exc:
                    return {"success": False, "error": f"写入沙盒文件失败: {exc}"}

            if self._cfg.sandbox.sandbox_only_write and not self._cfg.sandbox.allow_write_outside_with_confirm:
                self._audit.log("Tool", f"file_{act}_blocked", user_id, stream_id, group_id, {"path": str(target_path)}, "high", False, "禁止沙盒外写入")
                return {
                    "success": False,
                    "error": f"安全拦截：系统已启用纯沙盒写入限制（sandbox_only_write=true），严禁在沙盒工作区（{self._get_workspace_path()}）外部创建或修改文件。",
                }

            if self._cfg.sandbox.allow_write_outside_with_confirm:
                self._audit.log("Tool", f"file_{act}_pending", user_id, stream_id, group_id, {"path": str(target_path)}, "high", False, "等待双重确认")
                return await self._queue_confirmation(
                    kind="file_write",
                    payload={"path": str(target_path), "content": content or "", "action": act},
                    user_id=user_id,
                    stream_id=stream_id,
                    title="沙盒外写入双重确认",
                    detail_lines=[
                        f"目标路径: {target_path}",
                        f"操作模式: {act}",
                        f"写入大小: {len((content or '').encode('utf-8'))} 字节",
                    ],
                )

            return {"success": False, "error": "系统未授权对沙盒外部路径进行写操作。"}

        return {"success": False, "error": f"不支持的文件操作动作: {act}"}

    @Tool(
        "send_local_image",
        description=(
            "将电脑本地已生成或保存的图片文件（如 Python 绘制的数据图表）直接发送到当前聊天会话中。"
            "默认开启严格沙盒限制，仅允许发送沙盒工作区（Workspace）内部且经过格式完整性校验的图片文件。"
        ),
        parameters=[
            ToolParameterInfo(
                name="path",
                param_type=ToolParamType.STRING,
                description="图片文件路径（支持相对沙盒路径或 'Workspace/chart.png' 别名）",
                required=True,
            ),
            ToolParameterInfo(
                name="caption",
                param_type=ToolParamType.STRING,
                description="可选的图片附带文字说明",
                required=False,
            ),
        ],
    )
    async def handle_tool_send_image(
        self,
        path: str = "",
        caption: str = "",
        **kwargs: Any,
    ) -> dict[str, Any]:
        verified, err, stream_id, user_id, group_id = await self._verify_tool_caller_detail(kwargs)
        if not verified:
            return {"success": False, "error": err}

        target_path = self._resolve_friendly_path(path)
        ok, b64_data, msg, meta = await asyncio.to_thread(
            load_local_image_base64,
            target_path,
            self._get_workspace_path(),
            self._cfg.sandbox.allow_send_image_outside_sandbox,
            self._cfg.sandbox.max_send_image_mb,
        )
        self._audit.log("Tool", "send_local_image", user_id, stream_id, group_id, {"path": str(target_path)}, "low", ok, msg)
        if not ok:
            return {"success": False, "error": msg}

        if stream_id:
            await self.ctx.send.image(b64_data, stream_id)
            if str(caption or "").strip():
                await self.ctx.send.text(str(caption).strip(), stream_id)

        return {"success": True, "message": msg, "image": meta}

    @Tool(
        "open_application_or_url",
        description="在电脑上启动应用程序、打开指定路径的文件或在默认浏览器中打开指定网址。支持常见应用简称（如 'wechat', 'vscode', 'notepad', 'calc', 'taskmgr' 等）。当管理员要求打开网页或启动电脑软件时调用此工具。",
        parameters=[
            ToolParameterInfo(
                name="target",
                param_type=ToolParamType.STRING,
                description="要打开的目标：可以是网址链接（如 https://www.bing.com）、程序名称（如 'notepad'）、或文件的完整路径",
                required=True,
            ),
        ],
    )
    async def handle_tool_open(self, target: str = "", **kwargs: Any) -> dict[str, Any]:
        verified, err, stream_id, user_id, group_id = await self._verify_tool_caller_detail(kwargs)
        if not verified:
            return {"success": False, "error": err}

        tgt = str(target or "").strip()
        if not tgt:
            return {"success": False, "error": "目标参数不能为空。"}

        alias_map = {
            "notepad": "notepad.exe",
            "记事本": "notepad.exe",
            "calc": "calc.exe",
            "计算器": "calc.exe",
            "taskmgr": "taskmgr.exe",
            "任务管理器": "taskmgr.exe",
            "explorer": "explorer.exe",
            "资源管理器": "explorer.exe",
            "cmd": "cmd.exe",
            "powershell": "powershell.exe",
            "wechat": "WeChat.exe",
            "微信": "WeChat.exe",
        }
        exec_target = alias_map.get(tgt.lower(), tgt)

        def _do_open() -> tuple[bool, str]:
            try:
                if hasattr(os, "startfile"):
                    os.startfile(exec_target)
                else:
                    subprocess.Popen([exec_target], shell=False)
                return True, f"已向操作系统发出启动程序或打开目标指令: {exec_target}"
            except Exception as exc:
                try:
                    env = os.environ.copy()
                    env["MAIBOT_OPEN_TARGET"] = exec_target
                    subprocess.Popen(
                        [
                            "powershell.exe",
                            "-NoProfile",
                            "-NonInteractive",
                            "-Command",
                            "Start-Process -FilePath $env:MAIBOT_OPEN_TARGET",
                        ],
                        env=env,
                        shell=False,
                    )
                    return True, f"已通过系统进程管理器启动目标: {exec_target}"
                except Exception as p_exc:
                    return False, f"启动程序失败: {exc} (回退启动亦失败: {p_exc})"

        ok, msg = await asyncio.to_thread(_do_open)
        self._audit.log("Tool", "open_application_or_url", user_id, stream_id, group_id, {"target": exec_target}, "low", ok, msg)
        return {"success": ok, "message": msg}

    @Tool(
        "manage_process",
        description="排查或结束电脑中运行的进程。支持根据关键字搜索活跃进程（查看 PID 和名称），或根据进程名/PID 强制结束卡死无响应的程序。内置关键系统进程保护与二次确认机制。",
        parameters=[
            ToolParameterInfo(
                name="action",
                param_type=ToolParamType.STRING,
                description="进程操作：'list'（搜索并列出当前匹配的进程）、'kill'（强制结束进程）",
                required=True,
            ),
            ToolParameterInfo(
                name="query",
                param_type=ToolParamType.STRING,
                description="action 为 'list' 时为过滤关键字（留空列出常见进程）；action 为 'kill' 时为要结束的进程名称（如 'notepad.exe'）或纯数字 PID",
                required=False,
            ),
        ],
    )
    async def handle_tool_process(
        self,
        action: str = "list",
        query: str = "",
        **kwargs: Any,
    ) -> dict[str, Any]:
        verified, err, stream_id, user_id, group_id = await self._verify_tool_caller_detail(kwargs)
        if not verified:
            return {"success": False, "error": err}

        act = str(action or "list").lower().strip()
        q = str(query or "").strip()

        if act == "list":
            def _list_proc() -> list[str]:
                res = subprocess.run(["tasklist", "/FO", "CSV", "/NH"], capture_output=True, text=True, check=False)
                matched = []
                for line in res.stdout.strip().splitlines():
                    parts = line.split('","')
                    if len(parts) >= 2:
                        name = parts[0].replace('"', "")
                        pid = parts[1].replace('"', "")
                        mem = parts[4].replace('"', "") if len(parts) >= 5 else ""
                        item_str = f"PID: {pid} | 名称: {name} | 内存: {mem}"
                        if not q or q.lower() in name.lower() or q == pid:
                            matched.append(item_str)
                            if len(matched) >= 30:
                                break
                return matched

            procs = await asyncio.to_thread(_list_proc)
            return {"success": True, "count": len(procs), "processes": procs}

        if act == "kill":
            if not q:
                return {"success": False, "error": "结束进程必须提供进程名称或 PID。"}

            resolved_name = ""
            if q.isdigit():
                resolved_name = await asyncio.to_thread(self._desktop.get_process_name_by_pid, int(q))

            self_proc_name = await asyncio.to_thread(self._desktop.get_process_name_by_pid, os.getpid())
            parent_proc_name = await asyncio.to_thread(self._desktop.get_process_name_by_pid, os.getppid())

            risk_level, reasons = assess_process_kill_risk(
                q,
                self_pid=os.getpid(),
                parent_pid=os.getppid(),
                resolved_process_name=resolved_name,
                self_proc_name=self_proc_name,
                parent_proc_name=parent_proc_name,
            )
            if risk_level == "blocked":
                msg = "；".join(reasons)
                self._audit.log("Tool", "process_kill_blocked", user_id, stream_id, group_id, {"query": q}, "blocked", False, msg)
                return {"success": False, "error": f"安全拦截：{msg}"}

            if risk_level == "high" and self._cfg.sandbox.confirm_high_risk_commands:
                self._audit.log("Tool", "process_kill_pending", user_id, stream_id, group_id, {"query": q}, "high", False, "; ".join(reasons))
                return await self._queue_confirmation(
                    kind="process_kill",
                    payload={"query": q},
                    user_id=user_id,
                    stream_id=stream_id,
                    title="关键进程终止二次确认",
                    detail_lines=[f"目标进程: {q} ({resolved_name or '按名称匹配'})"],
                    reasons=reasons,
                )

            def _kill_proc() -> tuple[bool, str]:
                if q.isdigit():
                    cmd = ["taskkill", "/F", "/PID", q]
                else:
                    img_name = q if q.lower().endswith(".exe") else f"{q}.exe"
                    cmd = ["taskkill", "/F", "/IM", img_name]
                res = subprocess.run(cmd, capture_output=True, text=True, check=False)
                if res.returncode == 0:
                    return True, f"已成功强制终止进程: {q}"
                return False, f"终止进程失败: {res.stderr.strip() or '未找到匹配的进程或权限不足'}"

            ok, msg = await asyncio.to_thread(_kill_proc)
            self._audit.log("Tool", "process_kill", user_id, stream_id, group_id, {"query": q}, risk_level, ok, msg)
            return {"success": ok, "message": msg}

        return {"success": False, "error": f"不支持的进程操作: {act}"}

    @Tool(
        "execute_terminal_command",
        description="在电脑中执行原生的 PowerShell/CMD 命令（默认超时 30 秒；长耗时任务请使用 manage_job）。命中高危操作特征时将挂起等待管理员二次确认。",
        parameters=[
            ToolParameterInfo(
                name="command",
                param_type=ToolParamType.STRING,
                description="要执行的终端命令（如：python xxx.py, ping, dir, git status 等）",
                required=True,
            ),
            ToolParameterInfo(
                name="working_dir",
                param_type=ToolParamType.STRING,
                description="命令执行的工作目录。留空则默认在沙盒工作区（D:\\Agentworkspace）中运行",
                required=False,
            ),
        ],
    )
    async def handle_tool_terminal(
        self,
        command: str = "",
        working_dir: str = "",
        **kwargs: Any,
    ) -> dict[str, Any]:
        verified, err, stream_id, user_id, group_id = await self._verify_tool_caller_detail(kwargs)
        if not verified:
            return {"success": False, "error": err}

        cmd_clean = str(command or "").strip()
        if not cmd_clean:
            return {"success": False, "error": "执行命令不能为空。"}

        target_dir: str | None = None
        if str(working_dir or "").strip():
            resolved = self._resolve_friendly_path(working_dir)
            if not resolved.is_dir():
                return {"success": False, "error": f"指定的工作目录不存在或不是文件夹: {resolved}"}
            target_dir = str(resolved)

        risk_level, reasons = assess_command_risk(
            cmd_clean,
            workspace_dir=self._get_workspace_path(),
            sandbox_only_write=self._cfg.sandbox.sandbox_only_write,
            working_dir=Path(target_dir) if target_dir else None,
        )
        if risk_level == "high" and self._cfg.sandbox.confirm_high_risk_commands:
            self._audit.log("Tool", "terminal_pending", user_id, stream_id, group_id, {"command": cmd_clean, "working_dir": target_dir}, "high", False, "; ".join(reasons))
            return await self._queue_confirmation(
                kind="terminal_cmd",
                payload={"command": cmd_clean, "cwd_override": target_dir},
                user_id=user_id,
                stream_id=stream_id,
                title="高危终端命令二次确认",
                detail_lines=[f"待执行命令: {cmd_clean[:300]}", f"工作目录: {target_dir or str(self._get_workspace_path())}"],
                reasons=reasons,
            )

        returncode, output = await self._execute_powershell(cmd_clean, cwd_override=target_dir)
        self._audit.log("Tool", "terminal", user_id, stream_id, group_id, {"command": cmd_clean, "working_dir": target_dir}, risk_level, returncode == 0, f"rc={returncode}")
        return {
            "success": returncode == 0,
            "returncode": returncode,
            "output": output,
            "workspace": target_dir or str(self._get_workspace_path()),
        }

    @Tool(
        "manage_job",
        description=(
            "托管长耗时后台命令（突破 30 秒终端超时限制）。支持启动后台任务（立即返回 job_id，结束后自动通知）、查询状态、读取尾部实时日志、列出任务与强杀进程树。"
        ),
        parameters=[
            ToolParameterInfo(
                name="action",
                param_type=ToolParamType.STRING,
                description="任务动作：'start'（启动后台任务）、'status'（查状态）、'logs'（读尾部日志）、'list'（列出全部任务）、'kill'（终止进程树）",
                required=True,
            ),
            ToolParameterInfo(
                name="command",
                param_type=ToolParamType.STRING,
                description="action='start' 时要运行的 PowerShell/CMD 命令",
                required=False,
            ),
            ToolParameterInfo(
                name="job_id",
                param_type=ToolParamType.STRING,
                description="action 为 'status' / 'logs' / 'kill' 时的 8 位任务 ID",
                required=False,
            ),
            ToolParameterInfo(
                name="working_dir",
                param_type=ToolParamType.STRING,
                description="action='start' 时可选的工作目录（默认沙盒工作区）",
                required=False,
            ),
            ToolParameterInfo(
                name="tail_lines",
                param_type=ToolParamType.INTEGER,
                description="action='logs' 时读取的末尾行数（默认 50，最大 300）",
                required=False,
            ),
            ToolParameterInfo(
                name="timeout_seconds",
                param_type=ToolParamType.INTEGER,
                description="action='start' 时可选最长运行超时秒数（不超过配置上限）",
                required=False,
            ),
        ],
    )
    async def handle_tool_job(
        self,
        action: str = "list",
        command: str = "",
        job_id: str = "",
        working_dir: str = "",
        tail_lines: int = 50,
        timeout_seconds: int | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        verified, err, stream_id, user_id, group_id = await self._verify_tool_caller_detail(kwargs)
        if not verified:
            return {"success": False, "error": err}

        act = str(action or "list").lower().strip()

        if act == "list":
            jobs = self._job_manager.list_jobs()
            return {"success": True, "count": len(jobs), "jobs": jobs}

        if act == "status":
            st = self._job_manager.get_job_status(job_id)
            if not st:
                return {"success": False, "error": f"未找到任务 ID: {job_id}"}
            return {"success": True, "job": st}

        if act == "logs":
            ok, res = self._job_manager.get_job_logs(job_id, tail_lines=tail_lines, max_chars=self._cfg.sandbox.max_output_chars)
            if not ok:
                return {"success": False, "error": str(res)}
            return {"success": True, "job": res}

        if act == "kill":
            ok, msg = await self._job_manager.kill_job(job_id)
            self._audit.log("Tool", "job_kill", user_id, stream_id, group_id, {"job_id": job_id}, "medium", ok, msg)
            return {"success": ok, "message": msg}

        if act == "start":
            cmd_clean = str(command or "").strip()
            if not cmd_clean:
                return {"success": False, "error": "启动后台任务必须提供 command 参数。"}
            cwd = str(self._get_workspace_path())
            if str(working_dir or "").strip():
                resolved = self._resolve_friendly_path(working_dir)
                if not resolved.is_dir():
                    return {"success": False, "error": f"指定的工作目录不存在或不是文件夹: {resolved}"}
                cwd = str(resolved)

            risk_level, reasons = assess_command_risk(
                cmd_clean,
                workspace_dir=self._get_workspace_path(),
                sandbox_only_write=self._cfg.sandbox.sandbox_only_write,
                working_dir=Path(cwd),
            )
            if risk_level == "high" and self._cfg.sandbox.confirm_high_risk_commands:
                self._audit.log("Tool", "job_start_pending", user_id, stream_id, group_id, {"command": cmd_clean, "cwd": cwd}, "high", False, "; ".join(reasons))
                return await self._queue_confirmation(
                    kind="bg_job",
                    payload={"command": cmd_clean, "cwd": cwd, "timeout_seconds": timeout_seconds},
                    user_id=user_id,
                    stream_id=stream_id,
                    title="高危后台任务二次确认",
                    detail_lines=[f"待启动命令: {cmd_clean[:300]}", f"工作目录: {cwd}"],
                    reasons=reasons,
                )

            ok, res = await self._job_manager.start_job(
                command=cmd_clean,
                cwd=cwd,
                stream_id=stream_id,
                user_id=user_id,
                timeout_seconds=timeout_seconds,
                notify_callback=self._on_job_finished,
            )
            self._audit.log("Tool", "job_start", user_id, stream_id, group_id, {"command": cmd_clean, "cwd": cwd}, risk_level, ok, str(res))
            if not ok:
                return {"success": False, "error": str(res)}
            return {"success": True, "job": res, "message": f"后台任务已启动，任务结束时将自动通知当前会话。"}

        return {"success": False, "error": f"不支持的后台任务动作: {act}"}

    @Tool(
        "manage_watchdog",
        description="管理后台运维看门狗：查询状态、启停监控、配置磁盘剩余空间告警阈值、受监控关键进程列表及锁屏状态变化提醒。",
        parameters=[
            ToolParameterInfo(
                name="action",
                param_type=ToolParamType.STRING,
                description="看门狗动作：'status'（查看配置与状态）、'enable'（开启）、'disable'（关闭）、'configure'（更新阈值与监控项）",
                required=True,
            ),
            ToolParameterInfo(
                name="disk_min_free_gb",
                param_type=ToolParamType.NUMBER,
                description="磁盘剩余空间低于此 GB 时触发告警（0 表示关闭）",
                required=False,
            ),
            ToolParameterInfo(
                name="watched_processes",
                param_type=ToolParamType.STRING,
                description="受监控进程列表（逗号分隔，如 'python.exe,QQ.exe'）",
                required=False,
            ),
            ToolParameterInfo(
                name="watch_lock_state",
                param_type=ToolParamType.BOOLEAN,
                description="是否开启锁屏与解锁状态变更通知",
                required=False,
            ),
            ToolParameterInfo(
                name="interval_seconds",
                param_type=ToolParamType.INTEGER,
                description="轮询检查间隔秒数（最小 10 秒）",
                required=False,
            ),
        ],
    )
    async def handle_tool_watchdog(
        self,
        action: str = "status",
        disk_min_free_gb: float | None = None,
        watched_processes: str | None = None,
        watch_lock_state: bool | None = None,
        interval_seconds: int | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        verified, err, stream_id, user_id, group_id = await self._verify_tool_caller_detail(kwargs)
        if not verified:
            return {"success": False, "error": err}

        act = str(action or "status").lower().strip()
        proc_list: list[str] | None = None
        if watched_processes is not None:
            proc_list = [p.strip() for p in str(watched_processes).split(",") if p.strip()]

        if act in ("configure", "enable", "on"):
            self._watchdog.configure(
                interval_seconds=interval_seconds,
                disk_min_free_gb=disk_min_free_gb,
                watched_processes=proc_list,
                watch_lock_state=watch_lock_state,
                notify_stream_id=self._watchdog.notify_stream_id or stream_id,
            )
            if act in ("enable", "on"):
                await self._watchdog.start()
            self._audit.log("Tool", f"watchdog_{act}", user_id, stream_id, group_id, {"disk_min_free_gb": disk_min_free_gb, "watched_processes": proc_list, "watch_lock_state": watch_lock_state}, "low", True)
            return {"success": True, "status": self._watchdog.get_status()}

        if act in ("disable", "off"):
            await self._watchdog.stop()
            self._audit.log("Tool", "watchdog_disable", user_id, stream_id, group_id, {}, "low", True)
            return {"success": True, "status": self._watchdog.get_status()}

        if act == "status":
            return {"success": True, "status": self._watchdog.get_status()}

        return {"success": False, "error": f"不支持的看门狗动作: {act}"}

    @Tool(
        "computer_power_control",
        description="执行电脑关机、重启或取消关机倒计时。当管理员在私聊或授权群聊对话中要求关机、重启或取消时调用此工具。",
        parameters=[
            ToolParameterInfo(
                name="action",
                param_type=ToolParamType.STRING,
                description="要执行的动作：'关机' (shutdown)、'重启' (restart)、或 '取消关机' (abort)",
                required=True,
            ),
            ToolParameterInfo(
                name="delay_seconds",
                param_type=ToolParamType.INTEGER,
                description="倒计时延时秒数（默认 60 秒，留出反悔缓冲时间）",
                required=False,
            ),
        ],
    )
    async def handle_tool_power(
        self,
        action: str = "关机",
        delay_seconds: int = 60,
        **kwargs: Any,
    ) -> dict[str, Any]:
        verified, err, stream_id, user_id, group_id = await self._verify_tool_caller_detail(kwargs)
        if not verified:
            return {"success": False, "error": err}

        delay = int(delay_seconds or self._cfg.sandbox.shutdown_delay_seconds)
        success, msg = await self._handle_power_action(action, delay)
        self._audit.log("Tool", "power", user_id, stream_id, group_id, {"action": action, "delay": delay}, "high", success, msg)
        return {"success": success, "message": msg}


def create_plugin() -> SandboxCommandPlugin:
    """Runner 插件工厂函数"""
    return SandboxCommandPlugin()
