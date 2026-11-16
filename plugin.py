# -*- coding: utf-8 -*-
import asyncio
import base64
import ctypes
import io
import os
import re
import shutil
import string
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Any

from maibot_sdk import Command, Field, MaiBotPlugin, PluginConfigBase, Tool
from maibot_sdk.types import ToolParamType, ToolParameterInfo


# ----------------------------------------------------------------------
# 配置结构定义
# ----------------------------------------------------------------------

class PluginSection(PluginConfigBase):
    enabled: bool = Field(default=True, description="是否启用插件")
    config_version: str = Field(default="1.4.0", description="配置文件版本")


class SecuritySection(PluginConfigBase):
    admin_users: list[str] = Field(
        default_factory=list,
        description="管理员账号列表，仅允许管理员执行系统控制与终端命令",
    )
    unauthorized_message: str = Field(
        default="权限不足：该系统控制与截图命令仅允许管理员执行。",
        description="非管理员触发命令时的拦截回复",
    )
    enable_llm_tools: bool = Field(
        default=True,
        description="是否允许大模型通过自然语言调用系统控制与终端工具",
    )
    allow_in_groups: bool = Field(
        default=False,
        description="是否允许在指定的群聊中执行系统控制与终端命令（总开关）",
    )
    allowed_groups: list[str] = Field(
        default_factory=list,
        description="允许执行系统控制与终端命令的群聊白名单列表（支持纯群号或如 qq:12345678）",
    )
    unauthorized_group_message: str = Field(
        default="未授权群聊：当前群未开启系统命令执行权限，仅在管理员授权的指定群聊或私聊中可用。",
        description="未授权群聊触发命令时的提示回复（留空则静默不回复）",
    )


class SandboxSection(PluginConfigBase):
    workspace_dir: str = Field(
        default="D:\\Agentworkspace",
        description="默认沙盒工作区目录，Agent 在此路径下编写脚本、搭建工具套件与执行命令",
    )
    sandbox_only_write: bool = Field(
        default=True,
        description="写入权限约束：是否默认仅允许在沙盒工作区内进行文件写入",
    )
    allow_write_outside_with_confirm: bool = Field(
        default=True,
        description="沙盒外写入双重确认门禁：在沙盒外写入时，是否必须经管理员显式双重确认才允许写入",
    )
    timeout_seconds: int = Field(
        default=30,
        description="终端命令单次执行超时秒数",
    )
    max_output_chars: int = Field(
        default=2000,
        description="命令输出最大截断字符数",
    )
    allow_system_control: bool = Field(
        default=True,
        description="是否允许执行系统电源控制（关机/重启）",
    )
    shutdown_delay_seconds: int = Field(
        default=60,
        description="关机/重启默认延时秒数",
    )


class SandboxPluginConfig(PluginConfigBase):
    plugin: PluginSection = Field(default_factory=PluginSection)
    security: SecuritySection = Field(default_factory=SecuritySection)
    sandbox: SandboxSection = Field(default_factory=SandboxSection)


# Windows 内存状态结构体（免第三方库秒级读取物理内存）
class MEMORYSTATUSEX(ctypes.Structure):
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


# ----------------------------------------------------------------------
# 核心插件类实现
# ----------------------------------------------------------------------

class SandboxCommandPlugin(MaiBotPlugin):
    """为麦麦提供多屏幕桌面截图、沙盒文件管控与脚本套件编写、终端命令执行、进程管理与系统控制"""

    config_model = SandboxPluginConfig

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._custom_config: SandboxPluginConfig | None = None
        # 待管理员双重确认的沙盒外部写入请求票据表: {req_id: req_dict}
        self._pending_outside_writes: dict[str, dict[str, Any]] = {}

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
        # 尝试直接从本地 config.toml 自动加载
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
        self._log("info", 
            "沙盒终端与全能系统控制插件(v%s)已成功加载，沙盒工作区: %s",
            self._cfg.plugin.config_version,
            ws,
        )

    async def on_unload(self) -> None:
        self._pending_outside_writes.clear()
        self._log("info", "沙盒终端与全能系统控制插件已安全卸载。")

    async def on_config_update(self, scope: str, config_data: dict[str, Any], version: str) -> None:
        try:
            self._custom_config = SandboxPluginConfig.model_validate(config_data)
            self._plugin_config_instance = self._custom_config
            self._get_workspace_path()
            self._log("info", "沙盒控制插件配置已动态更新至版本 %s", version)
        except Exception as exc:
            self._log("error", "沙盒控制插件配置更新校验失败: %s", exc)

    # ------------------------------------------------------------------
    # 鉴权与身份核验辅助
    # ------------------------------------------------------------------

    def _is_admin(self, user_id: str | None) -> bool:
        if not user_id:
            return False
        raw_id = str(user_id).strip()
        bare_id = raw_id.split(":")[-1].strip() if ":" in raw_id else raw_id
        for admin_raw in self._cfg.security.admin_users:
            if not admin_raw:
                continue
            admin_bare = str(admin_raw).split(":")[-1].strip() if ":" in str(admin_raw) else str(admin_raw).strip()
            if raw_id == str(admin_raw).strip() or bare_id == admin_bare:
                return True
        return False

    def _is_group_allowed(self, group_id: str | None) -> bool:
        """检查群聊是否被允许执行系统控制与终端命令（总开关开启且在白名单中）"""
        if not self._cfg.security.allow_in_groups:
            return False
        if not group_id:
            return False
        raw_id = str(group_id).strip()
        bare_id = raw_id.split(":")[-1].strip() if ":" in raw_id else raw_id
        for group_raw in self._cfg.security.allowed_groups:
            if not group_raw:
                continue
            group_bare = str(group_raw).split(":")[-1].strip() if ":" in str(group_raw) else str(group_raw).strip()
            if raw_id == str(group_raw).strip() or bare_id == group_bare:
                return True
        return False

    def _extract_caller_info(self, kwargs: dict[str, Any]) -> tuple[str, str, str]:
        """从宿主指令事件中提取可靠的 (user_id, group_id, stream_id)"""
        stream_id = str(kwargs.get("stream_id", "") or "").strip()
        user_id = ""
        group_id = ""

        # 仅信任宿主传递的真实事件消息体 (message dict)
        msg = kwargs.get("message")
        if isinstance(msg, dict):
            msg_info = msg.get("message_info") or {}
            if isinstance(msg_info, dict):
                # 提取 group_info
                g_info = msg_info.get("group_info") or {}
                if isinstance(g_info, dict):
                    gid = g_info.get("group_id") or g_info.get("id")
                    if gid and not isinstance(gid, (dict, list, set)):
                        group_id = str(gid).strip()

                # 提取 user_info
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

        # 宿主事件直接参数兼容（如未包装在 message 中时）
        if not user_id and "from_user_id" in kwargs:
            user_id = str(kwargs.get("from_user_id") or "").strip()

        return user_id, group_id, stream_id

    def _extract_command_context(self, kwargs: dict[str, Any]) -> tuple[str, str]:
        """向下兼容从直达前缀指令中提取可靠的 (user_id, stream_id)"""
        user_id, _, stream_id = self._extract_caller_info(kwargs)
        return user_id, stream_id

    def _extract_command_text(self, kwargs: dict[str, Any]) -> str:
        """从直达指令事件中兼容提取消息文本（支持 plain_text, text, raw_message, content）"""
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
        """统一校验直达前缀命令的权限（支持群聊白名单门禁与管理员身份校验）
        返回: (allowed, user_id, group_id, stream_id)
        """
        user_id, group_id, stream_id = self._extract_caller_info(kwargs)

        # 1. 若来自群聊，先核验群聊权限
        if group_id:
            if not self._cfg.security.allow_in_groups or not self._is_group_allowed(group_id):
                if self._is_admin(user_id) and self._cfg.security.unauthorized_group_message:
                    await self.ctx.send.text(self._cfg.security.unauthorized_group_message, stream_id)
                return False, user_id, group_id, stream_id

        # 2. 核验管理员身份
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
                    content = content.replace(
                        "[security]",
                        f"[security]\nallow_in_groups = {bool_str}",
                    )

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
                # 兼容单行与跨行数组格式的匹配替换，防止破坏 TOML 结构
                if re.search(r"^allowed_groups\s*=\s*\[[\s\S]*?\]", content, flags=re.MULTILINE):
                    content = re.sub(
                        r"^allowed_groups\s*=\s*\[[\s\S]*?\]",
                        f"allowed_groups = {groups_repr}",
                        content,
                        flags=re.MULTILINE,
                    )
                else:
                    content = content.replace(
                        "[security]",
                        f"[security]\nallowed_groups = {groups_repr}",
                    )

            cfg_path.write_text(content, encoding="utf-8")
            return True
        except Exception as exc:
            self._log("error", "保存群聊配置到 config.toml 失败: %s", exc)
            return False

    async def _resolve_caller_identity_from_recent(
        self,
        stream_id: str,
    ) -> tuple[str, str]:
        """通过宿主权威消息存储层反查当前流中最新触发消息的 (user_id, group_id)"""
        try:
            message_cap = getattr(self.ctx, "message", None)
            if not message_cap:
                return "", ""
            recent = await message_cap.get_recent(chat_id=stream_id, limit=8)
            if isinstance(recent, dict):
                recent = recent.get("messages") or recent.get("data") or []
            if not isinstance(recent, list):
                return "", ""
            # 从最新消息向前查找首条包含真实 user_id 的消息
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
                # 多层级完整兜底提取 group_id
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

    async def _verify_tool_caller(self, kwargs: dict[str, Any]) -> tuple[bool, str, str]:
        """严格核验大模型工具调用 (@Tool) 上下文，彻底防御提示词注入伪造与越权"""
        if not self._cfg.security.enable_llm_tools:
            return False, "大模型自然语言系统控制工具已被配置禁用，请直接发送 /cmd、/截图 等直达指令。", ""

        # 仅取宿主上下文注入的 stream_id，绝不读取模型 arguments 中可能被注入的 user_id/group_id
        stream_id = str(kwargs.get("stream_id", "") or "").strip()
        if not stream_id:
            return False, "缺少有效的会话标识，无法确认调用环境。", ""

        platform = str(kwargs.get("platform", "") or "qq").strip()
        admin_list = self._cfg.security.admin_users

        # -------------------------------------------------------------
        # 1. 优先通过宿主 chat 能力比对权威私聊流
        # -------------------------------------------------------------
        is_private_admin = False
        try:
            streams = await self.ctx.chat.get_private_streams(platform)
            for s in streams or []:
                if isinstance(s, dict):
                    sid = str(s.get("session_id", "") or s.get("stream_id", "")).strip()
                    uid = str(s.get("user_id", "")).strip()
                    if sid == stream_id and self._is_admin(uid):
                        is_private_admin = True
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
                            break
            except Exception as exc:
                self._log("debug", "通过 get_stream_by_user_id 验证管理员流失败: %s", exc)

        if is_private_admin:
            return True, "", stream_id

        # -------------------------------------------------------------
        # 2. 非权威私聊流：通过宿主数据层反查当前群聊真实触发者
        # -------------------------------------------------------------
        real_uid, real_gid = await self._resolve_caller_identity_from_recent(stream_id)

        # 若从数据层确认是群聊环境
        if real_gid:
            if not self._cfg.security.allow_in_groups:
                return (
                    False,
                    "安全防御策略：当前系统未开启群聊执行命令功能（allow_in_groups=false）。管理员若需在群内操作，请发送 /cmd_group on 开启群聊控制开关，或在私聊中直接用自然语言交流。",
                    stream_id,
                )

            if not self._is_group_allowed(real_gid):
                return (
                    False,
                    f"安全拦截：当前群聊（{real_gid}）未被列入管理员授权的系统命令白名单。仅授权群聊或私聊中允许调用系统工具。管理员可发送 /cmd_group add 将当前群加入白名单。",
                    stream_id,
                )

            # 在白名单群聊中，严格校验真实发言者是否为管理员
            if not real_uid or not self._is_admin(real_uid):
                return (
                    False,
                    "权限不足：当前群聊已开启系统工具支持，但系统控制与截图工具仅限管理员（admin_user）通过自然语言唤起使用，非管理员无权触发。",
                    stream_id,
                )

            # 授权群聊且真实发送者为管理员：安全放行！
            return True, "", stream_id

        # 非私聊流且未命中合法授权群聊，坚决阻断，杜绝任何未授权群聊门禁穿透
        return False, "权限受限：该操作仅允许管理员在私聊或已授权的群聊会话中通过自然语言驱动。", stream_id

    # ------------------------------------------------------------------
    # 路径与沙盒文件管控辅助
    # ------------------------------------------------------------------

    def _get_workspace_path(self) -> Path:
        """获取并自动初始化沙盒工作区路径"""
        ws_str = self._cfg.sandbox.workspace_dir or "D:\\Agentworkspace"
        path = Path(ws_str).resolve()
        try:
            path.mkdir(parents=True, exist_ok=True)
        except Exception as exc:
            self._log("warning", "创建沙盒目录失败，回退至当前路径: %s", exc)
            path = Path.cwd()
        return path

    def _is_path_in_sandbox(self, target_path: Path) -> bool:
        """判断目标路径是否位于沙盒工作区目录内部"""
        ws = self._get_workspace_path().resolve()
        try:
            target_path.resolve().relative_to(ws)
            return True
        except ValueError:
            return False

    def _resolve_friendly_path(self, path_str: str) -> Path:
        """解析路径别名（支持 Desktop、Downloads、Workspace、沙盒、桌面等）"""
        clean_str = str(path_str or "").strip()
        if not clean_str:
            return self._get_workspace_path()

        user_home = Path.home()
        lower_str = clean_str.lower().replace("/", "\\")

        if lower_str in ("workspace", "sandbox", "沙盒", "工作区", "."):
            return self._get_workspace_path()
        if lower_str in ("desktop", "桌面"):
            return user_home / "Desktop"
        if lower_str in ("downloads", "download", "下载"):
            return user_home / "Downloads"
        if lower_str in ("documents", "document", "文档"):
            return user_home / "Documents"

        # 处理类似 "Desktop\test.txt" 或 "沙盒\my_tool.py"
        for prefix, base in [
            ("desktop\\", user_home / "Desktop"),
            ("桌面\\", user_home / "Desktop"),
            ("downloads\\", user_home / "Downloads"),
            ("下载\\", user_home / "Downloads"),
            ("workspace\\", self._get_workspace_path()),
            ("沙盒\\", self._get_workspace_path()),
        ]:
            if lower_str.startswith(prefix):
                rel_part = clean_str[len(prefix):]
                return base / rel_part

        p = Path(clean_str)
        if not p.is_absolute():
            # 相对路径默认以沙盒工作区为基准
            return self._get_workspace_path() / p
        return p

    # ------------------------------------------------------------------
    # 多显示器智能截图
    # ------------------------------------------------------------------

    def _capture_screen_base64(
        self,
        screen: str = "primary",
        save_path: Path | None = None,
    ) -> tuple[bool, str, str]:
        """抓取 Windows 屏幕画面。
        screen 可选:
          - 'primary' (默认): 自动抓取标记为 is_primary 的主屏幕（如4K主屏）
          - 'all': 截取所有显示器拼接构成的完整虚拟桌面全景
          - '1', '2', '3': 截取指定编号的显示器画面
        """
        img = None
        screen_desc = ""

        try:
            from mss import MSS
            with MSS() as sct:
                monitors = sct.monitors
                target_monitor = None

                screen_lower = str(screen or "primary").lower().strip()

                if screen_lower in ("all", "0", "全屏", "全部", "全景"):
                    target_monitor = monitors[0]
                    screen_desc = f"全部屏幕全景 (合并分辨率: {target_monitor['width']}x{target_monitor['height']})"
                elif screen_lower in ("primary", "main", "主屏", "主屏幕"):
                    # 遍历寻找标记为 is_primary 的物理屏幕
                    for idx, m in enumerate(monitors[1:], start=1):
                        if m.get("is_primary"):
                            target_monitor = m
                            screen_desc = f"主显示器 (屏幕 {idx}, 分辨率: {m['width']}x{m['height']})"
                            break
                    if not target_monitor:
                        # 若无显式标记，优先取最大分辨率显示器或第1个物理屏
                        target_monitor = monitors[1] if len(monitors) > 1 else monitors[0]
                        screen_desc = f"主显示器 (默认屏幕, 分辨率: {target_monitor['width']}x{target_monitor['height']})"
                else:
                    # 尝试按数字序号选择
                    try:
                        idx = int(screen_lower)
                        if 0 <= idx < len(monitors):
                            target_monitor = monitors[idx]
                            screen_desc = f"显示器 {idx} (分辨率: {target_monitor['width']}x{target_monitor['height']})"
                    except ValueError:
                        pass

                if not target_monitor:
                    target_monitor = monitors[1] if len(monitors) > 1 else monitors[0]
                    screen_desc = f"默认显示器 (分辨率: {target_monitor['width']}x{target_monitor['height']})"

                sct_img = sct.grab(target_monitor)
                from PIL import Image
                img = Image.frombytes("RGB", sct_img.size, sct_img.bgra, "raw", "BGRX")

        except Exception as exc:
            self._log("warning", "使用 mss 多屏抓取失败，尝试回退: %s", exc)

        # 回退策略: PIL.ImageGrab
        if img is None:
            try:
                from PIL import ImageGrab
                all_scr = str(screen or "").lower().strip() in ("all", "0", "全屏", "全部", "全景")
                img = ImageGrab.grab(all_screens=all_scr)
                screen_desc = "屏幕截图 (回退模式)"
            except Exception:
                pass

        if img is None:
            return (
                False,
                "",
                "截图失败：当前 Windows 桌面可能处于锁屏、息屏或会话保护状态（系统 GDI 接口受限），请在电脑屏幕处于解锁与点亮状态下重试。",
            )

        try:
            if save_path:
                save_path.parent.mkdir(parents=True, exist_ok=True)
                img.save(str(save_path), format="PNG")

            buf = io.BytesIO()
            img.save(buf, format="PNG")
            b64 = base64.b64encode(buf.getvalue()).decode("ascii")
            return True, b64, f"截图成功：{screen_desc}"
        except Exception as exc:
            return False, "", f"图像处理编码失败: {exc}"

    # ------------------------------------------------------------------
    # 终端与系统管理辅助
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
        args = [
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            command,
        ] if os.name == "nt" else ["-c", command]

        process = None
        try:
            process = await asyncio.create_subprocess_exec(
                shell_exe,
                *args,
                cwd=cwd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout,
            )
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
            if process is not None:
                try:
                    if os.name == "nt":
                        subprocess.run(
                            ["taskkill", "/F", "/T", "/PID", str(process.pid)],
                            capture_output=True,
                            check=False,
                        )
                    else:
                        process.kill()
                    await process.wait()
                except Exception as clean_err:
                    self._log("error", "清理超时子进程异常: %s", clean_err)
            return -1, f"命令执行超时（超过 {timeout} 秒限制），已强制终止子进程树。"
        except Exception as exc:
            return -1, f"命令启动执行失败: {exc}"

    def _get_hardware_status_summary(self) -> dict[str, Any]:
        """获取 Windows 系统的实时硬件与资源状态概览"""
        summary: dict[str, Any] = {}

        # 1. 物理内存与使用率
        try:
            stat = MEMORYSTATUSEX()
            stat.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
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

        # 2. 系统开机时长与平台
        try:
            uptime_ms = ctypes.windll.kernel32.GetTickCount64()
            uptime_sec = uptime_ms // 1000
            hours = uptime_sec // 3600
            mins = (uptime_sec % 3600) // 60
            summary["system"] = {
                "os": sys.platform,
                "uptime": f"{hours} 小时 {mins} 分钟",
            }
        except Exception as exc:
            summary["system_error"] = str(exc)

        # 3. 本地磁盘分区使用情况
        drives_info = []
        for letter in string.ascii_uppercase:
            drive_path = f"{letter}:\\"
            if os.path.exists(drive_path):
                try:
                    total, used, free = shutil.disk_usage(drive_path)
                    total_gb = total / (1024**3)
                    free_gb = free / (1024**3)
                    used_pct = round((used / total) * 100, 1)
                    drives_info.append({
                        "drive": f"{letter}:",
                        "total_gb": round(total_gb, 1),
                        "free_gb": round(free_gb, 1),
                        "used_percent": f"{used_pct}%",
                    })
                except Exception:
                    pass
        summary["disks"] = drives_info
        summary["sandbox_workspace"] = str(self._get_workspace_path())

        return summary

    async def _handle_power_action(self, action: str, delay: int) -> tuple[bool, str]:
        """执行系统电源操作（关机/重启/取消关机）"""
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

    # ------------------------------------------------------------------
    # 直达前缀指令 (@Command)
    # ------------------------------------------------------------------

    @Command("cmd_group_cmd", aliases=["/群聊控制", "/cmd_group", "/允许群聊", "/禁用群聊"], description="管理允许执行系统命令的群聊白名单及开关（仅限管理员）")
    async def cmd_group_cmd(self, **kwargs: Any) -> None:
        user_id, group_id, stream_id = self._extract_caller_info(kwargs)
        # 该配置管理命令仅允许管理员使用
        if not self._is_admin(user_id):
            if self._cfg.security.unauthorized_message:
                await self.ctx.send.text(self._cfg.security.unauthorized_message, stream_id)
            return

        raw_text = self._extract_command_text(kwargs)
        parts = raw_text.split()
        first_word = parts[0].lower() if parts else ""
        subcmd = parts[1].lower() if len(parts) > 1 else ""

        # 快捷别名处理
        if "/允许群聊" in first_word and not subcmd:
            subcmd = "add"
        elif "/禁用群聊" in first_word and not subcmd:
            subcmd = "del"

        curr_groups = list(self._cfg.security.allowed_groups)

        # 1. 开启总开关
        if subcmd in ("on", "enable", "开启", "开"):
            self._save_security_config(allow_in_groups=True)
            msg = (
                "【群聊系统控制设置】\n"
                "群聊系统命令总开关已开启 (allow_in_groups = true)。\n"
                f"当前白名单群列表: {curr_groups or '无（请使用 /cmd_group add 添加群聊）'}"
            )
            await self.ctx.send.text(msg, stream_id)
            return

        # 2. 关闭总开关
        if subcmd in ("off", "disable", "关闭", "关"):
            self._save_security_config(allow_in_groups=False)
            msg = (
                "【群聊系统控制设置】\n"
                "群聊系统命令总开关已关闭 (allow_in_groups = false)。\n"
                "所有群聊中的系统命令与大模型自然语言系统工具均已锁定（仅私聊可用）。"
            )
            await self.ctx.send.text(msg, stream_id)
            return

        # 3. 添加群聊到白名单
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
            await self.ctx.send.text(
                f"【群聊白名单更新成功】\n"
                f"已将群聊 [{target_gid}] 加入系统命令授权白名单。\n"
                f"群聊总开关已同步开启。\n"
                f"管理员（admin_user）现可在此群聊中使用前缀命令（如 /cmd、/截图）及自然语言驱动麦麦操作电脑！",
                stream_id,
            )
            return

        # 4. 从白名单移除群聊
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
            await self.ctx.send.text(
                f"【群聊白名单更新成功】\n"
                f"已将群聊 [{target_gid}] 从系统命令白名单中移除。\n"
                f"剩余白名单群: {curr_groups or '无'}",
                stream_id,
            )
            return

        # 5. 查看列表或默认帮助
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

    @Command("screenshot_cmd", aliases=["/截图", "/screen"], description="截取当前电脑屏幕画面（可选 all/primary/1/2/3）")
    async def screenshot_cmd(self, **kwargs: Any) -> None:
        allowed, _, _, stream_id = await self._check_command_access(kwargs)
        if not allowed:
            return

        # 解析屏幕参数
        raw_text = self._extract_command_text(kwargs)
        parts = raw_text.split()
        screen_arg = parts[1] if len(parts) > 1 else "primary"

        save_file = self._get_workspace_path() / "captures" / f"screen_{int(time.time())}.png"
        success, b64_data, msg = self._capture_screen_base64(screen=screen_arg, save_path=save_file)
        if not success:
            await self.ctx.send.text(msg, stream_id)
            return

        await self.ctx.send.image(b64_data, stream_id)
        await self.ctx.send.text(f"{msg}\n本地存档: {save_file}", stream_id)

    @Command("confirm_write_cmd", aliases=["/确认写入", "/confirm_write"], description="授权 Agent 在沙盒外部写入文件的待处理请求")
    async def confirm_write_cmd(self, **kwargs: Any) -> None:
        allowed, _, _, stream_id = await self._check_command_access(kwargs)
        if not allowed:
            return

        now = time.time()
        # 清理 60 秒以上过期的请求
        expired_keys = [k for k, v in self._pending_outside_writes.items() if now - v["timestamp"] > 60]
        for k in expired_keys:
            self._pending_outside_writes.pop(k, None)

        if not self._pending_outside_writes:
            await self.ctx.send.text("当前没有任何等待授权的沙盒外写入请求，或请求已超过 60 秒超时失效。", stream_id)
            return

        # 获取请求 ID 参数（若无则取最新一个）
        raw_text = self._extract_command_text(kwargs)
        parts = raw_text.split()
        target_req = None
        if len(parts) > 1 and parts[1] in self._pending_outside_writes:
            target_req = self._pending_outside_writes.pop(parts[1])
        else:
            # 取时间最近的一个
            latest_key = max(self._pending_outside_writes.keys(), key=lambda k: self._pending_outside_writes[k]["timestamp"])
            target_req = self._pending_outside_writes.pop(latest_key)

        req_path = target_req["path"]
        content = target_req["content"]
        mode = "a" if target_req["action"] == "append" else "w"

        try:
            req_path.parent.mkdir(parents=True, exist_ok=True)
            with open(req_path, mode, encoding="utf-8") as f:
                f.write(content)
            await self.ctx.send.text(
                f"管理员已完成双重确认授权：\n"
                f"成功向沙盒外部文件写入数据！\n"
                f"路径: {req_path}\n"
                f"模式: {target_req['action']}\n"
                f"大小: {len(content.encode('utf-8'))} 字节",
                stream_id,
            )
        except Exception as exc:
            await self.ctx.send.text(f"写入外部文件时发生系统错误: {exc}", stream_id)

    @Command("terminal_cmd", aliases=["/cmd", "/terminal"], description="在电脑中执行终端命令（仅限管理员）")
    async def terminal_cmd(self, **kwargs: Any) -> None:
        allowed, _, _, stream_id = await self._check_command_access(kwargs)
        if not allowed:
            return

        raw_text = self._extract_command_text(kwargs)
        command = re.sub(r"^/(?:cmd|terminal)\s*", "", raw_text, flags=re.IGNORECASE).strip()
        if not command:
            await self.ctx.send.text("使用方法: /cmd <要执行的终端命令>\n例如: /cmd dir 或 /cmd tasklist", stream_id)
            return

        returncode, output = await self._execute_powershell(command)
        status_text = "成功" if returncode == 0 else f"异常退出(状态码: {returncode})"
        reply = f"【命令执行结果: {status_text}】\n{output}"
        await self.ctx.send.text(reply, stream_id)

    @Command("power_cmd", aliases=["/关机", "/重启", "/取消关机"], description="控制计算机电源关机、重启或取消倒计时")
    async def power_cmd(self, **kwargs: Any) -> None:
        allowed, _, _, stream_id = await self._check_command_access(kwargs)
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

        _, msg = await self._handle_power_action(action, delay)
        await self.ctx.send.text(msg, stream_id)

    # ------------------------------------------------------------------
    # 大模型专属系统工具集 (@Tool) - 仅限管理员在私聊或授权群聊中自然语言调用
    # ------------------------------------------------------------------

    @Tool(
        "desktop_screenshot",
        description="截取电脑桌面屏幕画面并将图片自动发送到当前聊天会话中。支持智能识别主屏幕（4K）、全屏全景合并或指定显示器。当管理员要求看屏幕、截桌面或检查程序界面时调用此工具。",
        parameters=[
            ToolParameterInfo(
                name="screen",
                param_type=ToolParamType.STRING,
                description="要截取的屏幕目标：'primary'（默认，主显示器）、'all'（截取所有显示器合并的全景）、或指定屏幕序号（如 '1', '2', '3'）",
                required=False,
            ),
        ],
    )
    async def handle_tool_screenshot(self, screen: str = "primary", **kwargs: Any) -> dict[str, Any]:
        verified, err, stream_id = await self._verify_tool_caller(kwargs)
        if not verified:
            return {"success": False, "error": err}

        save_file = self._get_workspace_path() / "captures" / f"screen_{int(time.time())}.png"
        success, b64_data, msg = self._capture_screen_base64(screen=screen, save_path=save_file)
        if not success:
            return {"success": False, "error": msg}

        if stream_id:
            await self.ctx.send.image(b64_data, stream_id)

        return {
            "success": True,
            "message": f"{msg}。图片已直接发送到当前聊天中，你可以在对话中提示用户查看图片。",
            "saved_local_path": str(save_file),
        }

    @Tool(
        "get_system_status",
        description="一键获取电脑当前的系统资源占用与硬件状态概览，包括物理内存容量与使用率、所有磁盘驱动器（C盘、D盘等）剩余空间与总容量、系统开机运行时间及沙盒工作区路径。当管理员询问电脑状态、内存余量或磁盘空间时调用此工具。",
        parameters=[],
    )
    async def handle_tool_system_status(self, **kwargs: Any) -> dict[str, Any]:
        verified, err, _ = await self._verify_tool_caller(kwargs)
        if not verified:
            return {"success": False, "error": err}

        data = await asyncio.to_thread(self._get_hardware_status_summary)
        return {"success": True, "status": data}

    @Tool(
        "manage_file",
        description="安全管理电脑中的文件与目录。支持在沙盒工作区自由创建与编写 Python 脚本、工具套件、读取文本文件、列出目录内容。对于沙盒外部路径的写入受管理员双重确认保护。支持使用常见路径别名：'Desktop'（桌面）、'Downloads'（下载）、'Workspace'（沙盒工作区）。",
        parameters=[
            ToolParameterInfo(
                name="action",
                param_type=ToolParamType.STRING,
                description="文件操作动作：'read'（读取文本文件）、'write'（创建或覆盖文件）、'append'（追加文本）、'list'（列出目录下的文件和文件夹）、'info'（查看文件属性）",
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
                description="当 action 为 'write' 或 'append' 时要写入的文本内容；读取或列出目录时可留空",
                required=False,
            ),
        ],
    )
    async def handle_tool_file(
        self,
        action: str = "read",
        path: str = "",
        content: str = "",
        **kwargs: Any,
    ) -> dict[str, Any]:
        verified, err, stream_id = await self._verify_tool_caller(kwargs)
        if not verified:
            return {"success": False, "error": err}

        act = str(action or "read").lower().strip()
        target_path = self._resolve_friendly_path(path).resolve()
        is_in_sandbox = self._is_path_in_sandbox(target_path)

        # 1. 读操作
        if act == "read":
            if not target_path.exists():
                return {"success": False, "error": f"目标文件不存在: {target_path}"}
            if not target_path.is_file():
                return {"success": False, "error": f"目标路径不是一个普通文件: {target_path}"}
            try:
                # 限制最大读取 100KB 防止上下文爆满
                size = target_path.stat().st_size
                if size > 100 * 1024:
                    with open(target_path, "r", encoding="utf-8", errors="replace") as f:
                        text = f.read(50000)
                    return {
                        "success": True,
                        "path": str(target_path),
                        "truncated": True,
                        "content": text + "\n... [已截断，文件超出 100KB 大小限制]",
                    }
                with open(target_path, "r", encoding="utf-8", errors="replace") as f:
                    text = f.read()
                return {"success": True, "path": str(target_path), "content": text}
            except Exception as exc:
                return {"success": False, "error": f"读取文件失败: {exc}"}

        # 2. 列出目录
        if act == "list":
            if not target_path.exists():
                return {"success": False, "error": f"目标目录不存在: {target_path}"}
            if not target_path.is_dir():
                return {"success": False, "error": f"目标路径不是目录: {target_path}"}
            try:
                entries = []
                for item in list(target_path.iterdir())[:100]:
                    entries.append({
                        "name": item.name,
                        "is_dir": item.is_dir(),
                        "size_bytes": item.stat().st_size if item.is_file() else 0,
                    })
                return {"success": True, "path": str(target_path), "entries": entries}
            except Exception as exc:
                return {"success": False, "error": f"遍历目录失败: {exc}"}

        # 3. 文件属性信息
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

        # 4. 写操作（write / append） - 执行权限约束门禁
        if act in ("write", "append"):
            if is_in_sandbox:
                # 在沙盒内部：完全放行，允许 Agent 自由编写脚本与工具套件
                try:
                    target_path.parent.mkdir(parents=True, exist_ok=True)
                    mode = "a" if act == "append" else "w"
                    with open(target_path, mode, encoding="utf-8") as f:
                        f.write(content or "")
                    return {
                        "success": True,
                        "message": f"成功在沙盒工作区内写入文件: {target_path} (模式: {act}, 大小: {len((content or '').encode('utf-8'))} 字节)",
                        "path": str(target_path),
                        "in_sandbox": True,
                    }
                except Exception as exc:
                    return {"success": False, "error": f"写入沙盒文件失败: {exc}"}

            # 试图在沙盒外部写入：触发严格安全保护
            if self._cfg.sandbox.sandbox_only_write and not self._cfg.sandbox.allow_write_outside_with_confirm:
                return {
                    "success": False,
                    "error": f"安全拦截：系统已启用纯沙盒写入限制（sandbox_only_write=true），严禁在沙盒工作区（{self._get_workspace_path()}）外部创建或修改文件。如需编写脚本或生成工具，请保存在沙盒工作区中。",
                }

            if self._cfg.sandbox.allow_write_outside_with_confirm:
                # 挂起请求，发起管理员双重确认流程
                req_id = str(uuid.uuid4())[:8]
                now = time.time()
                self._pending_outside_writes[req_id] = {
                    "req_id": req_id,
                    "path": target_path,
                    "content": content or "",
                    "action": act,
                    "timestamp": now,
                    "stream_id": stream_id,
                }
                if stream_id:
                    await self.ctx.send.text(
                        f"【安全警告 - 沙盒外写入双重确认】\n"
                        f"Agent 正在尝试在沙盒外部写入文件：\n"
                        f"目标路径: {target_path}\n"
                        f"操作模式: {act}\n"
                        f"写入大小: {len((content or '').encode('utf-8'))} 字节\n\n"
                        f"请在 60 秒内发送「/确认写入」或「/确认写入 {req_id}」以授权执行；若非您本人意图请忽略此消息。",
                        stream_id,
                    )
                return {
                    "success": False,
                    "status": "pending_admin_confirmation",
                    "error": f"安全拦截：目标路径 [{target_path}] 位于沙盒外部。已向当前会话发送双重确认提示（ID: {req_id}）。在管理员确认授权前，该文件未被写入。请在聊天中告知用户，若同意请发送 /确认写入 予以授权。",
                }

            return {"success": False, "error": "系统未授权对沙盒外部路径进行写操作。"}

        return {"success": False, "error": f"不支持的文件操作动作: {act}"}

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
        verified, err, _ = await self._verify_tool_caller(kwargs)
        if not verified:
            return {"success": False, "error": err}

        tgt = str(target or "").strip()
        if not tgt:
            return {"success": False, "error": "目标参数不能为空。"}

        # 映射常见软件快捷名称
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
                # Windows ShellExecute 原生调起（支持网址、本地应用、带空格或单引号路径）
                if hasattr(os, "startfile"):
                    os.startfile(exec_target)
                else:
                    subprocess.Popen([exec_target], shell=False)
                return True, f"已向操作系统发出启动程序或打开目标指令: {exec_target}"
            except Exception as exc:
                # 回退方案: 通过环境变量安全传递目标，彻底隔绝 -Command 字符串拼接解析与代码注入
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
        return {"success": ok, "message": msg}

    @Tool(
        "manage_process",
        description="排查或结束电脑中运行的进程。支持根据关键字搜索活跃进程（查看 PID 和名称），或根据进程名/PID 强制结束卡死无响应的程序。当管理员询问什么程序在运行或要求关闭某个程序时调用此工具。",
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
                description="当 action 为 'list' 时为过滤关键字（留空列出常见进程）；当 action 为 'kill' 时为要结束的进程名称（如 'notepad.exe'）或纯数字 PID",
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
        verified, err, _ = await self._verify_tool_caller(kwargs)
        if not verified:
            return {"success": False, "error": err}

        act = str(action or "list").lower().strip()
        q = str(query or "").strip()

        if act == "list":
            def _list_proc() -> list[str]:
                # 使用 tasklist 快速列出
                res = subprocess.run(["tasklist", "/FO", "CSV", "/NH"], capture_output=True, text=True, check=False)
                lines = res.stdout.strip().splitlines()
                matched = []
                for line in lines:
                    parts = line.split('","')
                    if len(parts) >= 2:
                        name = parts[0].replace('"', '')
                        pid = parts[1].replace('"', '')
                        mem = parts[4].replace('"', '') if len(parts) >= 5 else ""
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
            return {"success": ok, "message": msg}

        return {"success": False, "error": f"不支持的进程操作: {act}"}

    @Tool(
        "execute_terminal_command",
        description="在电脑中执行原生的 PowerShell/CMD 命令。无命令白名单限制。支持在沙盒工作区执行自定义 Python 脚本、构建工具链、运行批处理或检查网络状态。可通过 working_dir 指定运行目录。",
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
        verified, err, _ = await self._verify_tool_caller(kwargs)
        if not verified:
            return {"success": False, "error": err}

        cmd_clean = str(command or "").strip()
        if not cmd_clean:
            return {"success": False, "error": "执行命令不能为空。"}

        # 确定工作目录
        target_dir = None
        if working_dir:
            resolved = self._resolve_friendly_path(working_dir)
            if resolved.is_dir():
                target_dir = str(resolved)

        returncode, output = await self._execute_powershell(cmd_clean, cwd_override=target_dir)
        return {
            "success": returncode == 0,
            "returncode": returncode,
            "output": output,
            "workspace": target_dir or str(self._get_workspace_path()),
        }

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
        verified, err, _ = await self._verify_tool_caller(kwargs)
        if not verified:
            return {"success": False, "error": err}

        delay = int(delay_seconds or self._cfg.sandbox.shutdown_delay_seconds)
        success, msg = await self._handle_power_action(action, delay)
        return {"success": success, "message": msg}


def create_plugin() -> SandboxCommandPlugin:
    """Runner 插件工厂函数"""
    return SandboxCommandPlugin()

