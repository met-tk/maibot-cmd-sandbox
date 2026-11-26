# -*- coding: utf-8 -*-
"""沙盒路径安全校验、大文件分片与搜索、本地图片校验编码模块。"""

from __future__ import annotations

import base64
import fnmatch
import io
import os
import re
from collections import deque
from pathlib import Path
from typing import Any


SKIP_SEARCH_DIRS: frozenset[str] = frozenset(
    {
        ".git",
        "node_modules",
        "__pycache__",
        ".venv",
        "venv",
        "$recycle.bin",
        "system volume information",
    }
)

ALLOWED_IMAGE_FORMATS: frozenset[str] = frozenset({"PNG", "JPEG", "WEBP", "BMP", "GIF"})
MAX_IMAGE_PIXELS = 40_000_000


def resolve_safe_path(path_str: str, workspace_dir: Path) -> Path:
    """解析路径别名与相对路径（相对路径基准始终为沙盒工作区）。"""
    clean_str = str(path_str or "").strip()
    if not clean_str:
        return workspace_dir

    user_home = Path.home()
    lower_str = clean_str.lower().replace("/", "\\")

    if lower_str in ("workspace", "sandbox", "沙盒", "工作区", "."):
        return workspace_dir
    if lower_str in ("desktop", "桌面"):
        return user_home / "Desktop"
    if lower_str in ("downloads", "download", "下载"):
        return user_home / "Downloads"
    if lower_str in ("documents", "document", "文档"):
        return user_home / "Documents"

    for prefix, base in (
        ("desktop\\", user_home / "Desktop"),
        ("桌面\\", user_home / "Desktop"),
        ("downloads\\", user_home / "Downloads"),
        ("下载\\", user_home / "Downloads"),
        ("documents\\", user_home / "Documents"),
        ("文档\\", user_home / "Documents"),
        ("workspace\\", workspace_dir),
        ("沙盒\\", workspace_dir),
    ):
        if lower_str.startswith(prefix):
            rel_part = clean_str[len(prefix) :]
            return base / rel_part

    p = Path(clean_str)
    if not p.is_absolute():
        return workspace_dir / p
    return p


def _resolve_real_with_missing_tail(target_path: Path) -> Path | None:
    """解析包含尚未创建后缀的路径真实物理位置，防御悬空符号链接、Junction 与 '..' 逃逸。"""
    probe = target_path
    missing_parts: list[str] = []
    # 使用 lexists 避免悬空符号链接/Junction 返回 False 被当成普通未创建子段剥离
    while not os.path.lexists(str(probe)):
        parent = probe.parent
        if parent == probe:
            break
        missing_parts.append(probe.name)
        probe = parent

    if any(part == ".." for part in missing_parts):
        return None

    probe_str = str(probe)
    # 若该节点是悬空重解析点（lexists=True 但目标不存在），按 fail-closed 视作沙盒外拒绝
    if (os.path.islink(probe_str) or (hasattr(probe, "is_junction") and probe.is_junction())) and not os.path.exists(probe_str):
        return None

    base_real = Path(os.path.realpath(probe_str))
    if os.path.islink(probe_str) and Path(os.path.abspath(probe_str)) == base_real:
        return None

    resolved = base_real
    for part in reversed(missing_parts):
        resolved = resolved / part
    return resolved


def is_path_in_sandbox(target_path: Path, workspace_dir: Path) -> bool:
    """校验目标路径在解析所有符号链接/Junction 后是否仍位于沙盒目录内。"""
    try:
        ws_real = Path(os.path.realpath(str(workspace_dir)))
        resolved = _resolve_real_with_missing_tail(target_path)
        if resolved is None:
            return False
        resolved.relative_to(ws_real)
        return True
    except Exception:
        return False


def read_file_lines(
    target_path: Path,
    start_line: int = 1,
    end_line: int = 0,
    max_chars: int = 30000,
) -> dict[str, Any]:
    """按行号范围或负数尾部行号流式读取文本文件（大文件不爆内存）。"""
    if not target_path.exists():
        return {"success": False, "error": f"目标文件不存在: {target_path}"}
    if not target_path.is_file():
        return {"success": False, "error": f"目标路径不是普通文件: {target_path}"}

    try:
        s_line = int(start_line)
        e_line = int(end_line)
    except (TypeError, ValueError):
        return {"success": False, "error": "start_line 与 end_line 必须为整数。"}

    try:
        collected: list[tuple[int, str]] = []
        total_lines = 0

        if s_line < 0:
            tail_count = min(abs(s_line), 2000)
            dq: deque[tuple[int, str]] = deque(maxlen=tail_count)
            with open(target_path, "r", encoding="utf-8", errors="replace") as fh:
                for idx, raw in enumerate(fh, start=1):
                    total_lines = idx
                    dq.append((idx, raw.rstrip("\r\n")))
            collected = list(dq)
        else:
            start_pos = max(1, s_line)
            end_pos = e_line if e_line >= start_pos else start_pos + 199
            with open(target_path, "r", encoding="utf-8", errors="replace") as fh:
                for idx, raw in enumerate(fh, start=1):
                    total_lines = idx
                    if start_pos <= idx <= end_pos:
                        collected.append((idx, raw.rstrip("\r\n")))

        lines_out: list[str] = []
        char_acc = 0
        truncated = False
        for lno, text in collected:
            formatted = f"{lno}: {text}"
            if char_acc + len(formatted) + 1 > max_chars:
                truncated = True
                break
            lines_out.append(formatted)
            char_acc += len(formatted) + 1

        actual_start = collected[0][0] if collected else 0
        actual_end = (
            int(lines_out[-1].split(":", 1)[0])
            if lines_out
            else (collected[-1][0] if collected else 0)
        )
        return {
            "success": True,
            "path": str(target_path),
            "total_lines": total_lines,
            "start_line": actual_start,
            "end_line": actual_end,
            "truncated": truncated,
            "content": "\n".join(lines_out),
        }
    except Exception as exc:
        return {"success": False, "error": f"按行读取文件失败: {exc}"}


def _iter_safe_files(root_dir: Path, max_depth: int, max_files: int):
    """受深度与噪声目录约束的文件迭代器（不跟随目录符号链接防止死循环）。"""
    scanned = 0
    stack: list[tuple[Path, int]] = [(root_dir, 0)]
    while stack:
        current, depth = stack.pop()
        if depth > max_depth:
            continue
        try:
            with os.scandir(current) as it:
                entries = list(it)
        except Exception:
            continue

        for entry in entries:
            name_low = entry.name.lower()
            try:
                is_dir = entry.is_dir(follow_symlinks=False)
            except Exception:
                continue
            if is_dir:
                if name_low in SKIP_SEARCH_DIRS:
                    continue
                if depth + 1 <= max_depth:
                    stack.append((Path(entry.path), depth + 1))
            else:
                try:
                    if entry.is_file(follow_symlinks=False):
                        scanned += 1
                        yield Path(entry.path), scanned
                        if scanned >= max_files:
                            return
                except Exception:
                    continue


def search_text_in_path(
    target_path: Path,
    pattern: str,
    use_regex: bool = False,
    case_sensitive: bool = False,
    max_results: int = 50,
    max_files: int = 500,
    max_file_bytes: int = 2 * 1024 * 1024,
) -> dict[str, Any]:
    """在指定文件或目录中检索关键字或正则表达式匹配行。"""
    pat_str = str(pattern or "")
    if not pat_str:
        return {"success": False, "error": "搜索关键字 pattern 不能为空。"}
    if len(pat_str) > 200:
        return {"success": False, "error": "搜索关键字过长（最大允许 200 字符）。"}
    if not target_path.exists():
        return {"success": False, "error": f"搜索目标不存在: {target_path}"}

    compiled: re.Pattern[str] | None = None
    if use_regex:
        flags = 0 if case_sensitive else re.IGNORECASE
        try:
            compiled = re.compile(pat_str, flags)
        except re.error as exc:
            return {"success": False, "error": f"正则表达式语法错误: {exc}"}

    needle = pat_str if case_sensitive else pat_str.lower()
    matches: list[dict[str, Any]] = []
    scanned_files = 0
    truncated = False

    def _scan_one(fpath: Path) -> bool:
        try:
            if fpath.stat().st_size > max_file_bytes:
                return False
            with open(fpath, "rb") as probe_fh:
                head = probe_fh.read(2048)
                if b"\x00" in head:
                    return False
            with open(fpath, "r", encoding="utf-8", errors="replace") as fh:
                for idx, line in enumerate(fh, start=1):
                    line_clean = line.rstrip("\r\n")
                    hit = bool(compiled.search(line_clean)) if compiled else (
                        needle in (line_clean if case_sensitive else line_clean.lower())
                    )
                    if hit:
                        matches.append(
                            {
                                "file": str(fpath),
                                "line": idx,
                                "text": line_clean[:300],
                            }
                        )
                        if len(matches) >= max_results:
                            return True
        except Exception:
            pass
        return False

    if target_path.is_file():
        scanned_files = 1
        truncated = _scan_one(target_path)
    elif target_path.is_dir():
        for fpath, count in _iter_safe_files(target_path, max_depth=8, max_files=max_files):
            scanned_files = count
            if _scan_one(fpath):
                truncated = True
                break
        if scanned_files >= max_files:
            truncated = True
    else:
        return {"success": False, "error": f"目标既不是普通文件也不是目录: {target_path}"}

    return {
        "success": True,
        "path": str(target_path),
        "scanned_files": scanned_files,
        "match_count": len(matches),
        "truncated": truncated,
        "matches": matches,
    }


def find_files(
    target_path: Path,
    pattern: str = "*",
    max_results: int = 80,
    max_depth: int = 8,
) -> dict[str, Any]:
    """在指定目录下按通配符或名称子串递归查找文件与目录。"""
    if not target_path.exists():
        return {"success": False, "error": f"查找目录不存在: {target_path}"}
    if not target_path.is_dir():
        return {"success": False, "error": f"查找目标不是目录: {target_path}"}

    pat_clean = str(pattern or "*").strip() or "*"
    has_glob = any(ch in pat_clean for ch in ("*", "?", "["))
    pat_lower = pat_clean.lower()

    entries_out: list[dict[str, Any]] = []
    truncated = False
    stack: list[tuple[Path, int]] = [(target_path, 0)]

    while stack and not truncated:
        current, depth = stack.pop()
        if depth > max_depth:
            continue
        try:
            with os.scandir(current) as it:
                items = list(it)
        except Exception:
            continue

        for entry in items:
            name_low = entry.name.lower()
            try:
                is_dir = entry.is_dir(follow_symlinks=False)
            except Exception:
                continue

            if is_dir and name_low in SKIP_SEARCH_DIRS:
                continue

            matched = fnmatch.fnmatch(name_low, pat_lower) if has_glob else (pat_lower in name_low)
            if matched:
                size_bytes = 0
                if not is_dir:
                    try:
                        size_bytes = entry.stat(follow_symlinks=False).st_size
                    except Exception:
                        size_bytes = 0
                entries_out.append(
                    {
                        "path": entry.path,
                        "name": entry.name,
                        "is_dir": is_dir,
                        "size_bytes": size_bytes,
                    }
                )
                if len(entries_out) >= max_results:
                    truncated = True
                    break

            if is_dir and depth + 1 <= max_depth:
                stack.append((Path(entry.path), depth + 1))

    return {
        "success": True,
        "root": str(target_path),
        "pattern": pat_clean,
        "count": len(entries_out),
        "truncated": truncated,
        "entries": entries_out,
    }


def load_local_image_base64(
    target_path: Path,
    workspace_dir: Path,
    allow_outside_sandbox: bool = False,
    max_mb: int = 15,
) -> tuple[bool, str, str, dict[str, Any]]:
    """安全校验并重编码本地图片文件为 Base64 PNG（默认严格限定在沙盒目录内）。"""
    if not allow_outside_sandbox and not is_path_in_sandbox(target_path, workspace_dir):
        return (
            False,
            "",
            f"安全拦截：目标图片 [{target_path}] 位于沙盒工作区外部（allow_send_image_outside_sandbox=false），已拒绝发送。",
            {},
        )

    if not target_path.exists():
        return False, "", f"图片文件不存在: {target_path}", {}
    if not target_path.is_file():
        return False, "", f"目标路径不是普通文件: {target_path}", {}

    max_bytes = max(1, int(max_mb)) * 1024 * 1024
    try:
        file_size = target_path.stat().st_size
    except Exception as exc:
        return False, "", f"读取图片属性失败: {exc}", {}

    if file_size <= 0:
        return False, "", f"图片文件为空: {target_path}", {}
    if file_size > max_bytes:
        return (
            False,
            "",
            f"图片文件过大（{round(file_size / (1024 * 1024), 2)} MB），超出上限 {max_mb} MB。",
            {},
        )

    try:
        from PIL import Image

        with Image.open(target_path) as probe_img:
            fmt = (probe_img.format or "").upper()
            if fmt not in ALLOWED_IMAGE_FORMATS:
                return False, "", f"不支持的图像格式 [{fmt or '未知'}]，仅允许 PNG/JPEG/WEBP/BMP/GIF。", {}
            probe_img.verify()

        with Image.open(target_path) as img:
            w, h = img.size
            if w <= 0 or h <= 0:
                return False, "", "图像尺寸无效。", {}
            if w * h > MAX_IMAGE_PIXELS:
                scale = (MAX_IMAGE_PIXELS / float(w * h)) ** 0.5
                new_size = (max(1, int(w * scale)), max(1, int(h * scale)))
                img = img.resize(new_size, Image.Resampling.LANCZOS)
            mode = "RGBA" if "A" in img.getbands() else "RGB"
            cleaned = img.convert(mode)
            buf = io.BytesIO()
            cleaned.save(buf, format="PNG")
            b64 = base64.b64encode(buf.getvalue()).decode("ascii")
            meta = {
                "path": str(target_path),
                "source_format": fmt,
                "width": cleaned.width,
                "height": cleaned.height,
                "size_bytes": file_size,
            }
            return True, b64, f"图片读取与校验成功 ({cleaned.width}x{cleaned.height}, {fmt})", meta
    except Exception as exc:
        return False, "", f"图片文件校验或编码失败（可能已损坏或非真实图像）: {exc}", {}
