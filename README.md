# 沙盒终端与全能系统控制插件 (maibot-cmd-sandbox)

> 为 MaiBot（麦麦）打造的 Windows 原生沙盒终端执行、多粒度桌面与窗口截图、异步后台长任务、文件检索、系统运维监控与桌面控制插件。支持管理员通过私聊或授权群聊，以**前缀指令**或**自然语言（LLM Tool Calling）**安全操控宿主机。

---

## 核心特性

1. **智能感知与多粒度桌面截图**
   - **锁屏状态精准拦截**：自动探测 Windows 会话锁定、`Winlogon` 安全桌面、屏保及 `LockApp.exe` / `LogonUI.exe` 前台遮罩；锁屏状态下直接提示电脑已锁屏，不再误发送锁屏壁纸图片。
   - **多显示器自适应截图**：自动识别并优先截取主显示器（含高分屏/4K 适配），支持全屏幕拼接全景（`all`）以及指定显示器序号（`1`、`2`、`3` 等）。
   - **窗口级穿透遮挡抓取**：支持枚举可见应用窗口并按 `HWND`、进程名或标题独立捕获指定窗口内容（基于 `PrintWindow` + `PW_RENDERFULLCONTENT`），被其他窗口遮挡时仍可抓取目标画面。
   - **任意矩形区域裁剪**：支持指定 `x,y,width,height` 对屏幕或窗口进行局部区域放大裁剪。

2. **窗口状态控制与受控 GUI 键鼠交互**
   - **窗口控制（默认开启）**：支持恢复最小化窗口、最小化、最大化、激活置前、切换置顶、移动调整尺寸及温和关闭窗口（`WM_CLOSE`），内置系统核心与宿主进程保护。
   - **受控键鼠交互（默认关闭 `allow_gui_input = false`）**：基于纯 Win32 `SendInput`，支持坐标点击/右击/双击/移动/滚轮、Unicode 文本输入及组合快捷键；强制前置锁屏检测、系统管理窗口隔离与危险热键拦截，并可要求每次二次确认。

3. **异步后台长任务池（突破 30 秒超时限制）**
   - 支持后台启动长耗时 PowerShell/CMD 任务并立即返回 8 位 `job_id`，支持查询状态、分页读取尾部实时日志、强杀整个子进程树，并在任务完成或异常退出时主动推送结果通知；插件卸载时自动清理全部子进程。

4. **沙盒文件检索、双重确认与本地图片直发**
   - **大日志分片与全文检索**：在原有读写与列目录基础上，新增 `read_lines`（支持负数查看末尾行）、`search`（关键字/正则跨文件检索）与 `find`（文件名通配符递归查找）。
   - **防符号链接逃逸校验**：通过逐级 `realpath` 解析防御符号链接/目录穿越绕过沙盒边界。
   - **本地图片校验直发**：支持将沙盒内生成的数据图表直接校验格式并发送到会话（默认严禁发送沙盒外部图片）。

5. **扩展硬件状态直查与后台轻量看门狗**
   - 秒级读取 CPU 利用率、物理内存、磁盘剩余空间、电池供电状态、NVIDIA GPU（如有 `nvidia-smi`）、局域网 IP、开机时长及端口占用排查。
   - 可选开启后台看门狗，监控磁盘剩余空间过低、受监控关键进程意外退出及锁屏状态变更，内置冷却防刷屏。

6. **高危操作二次确认门禁与脱敏审计日志**
   - 对高危终端命令、后台任务、关键进程强杀及沙盒外文件写入实施 60 秒超时且绑定发起人与会话 ID 的 `/确认执行`（`/确认写入`）双重确认机制。
   - 按天自动记录脱敏后的结构化 JSONL 审计日志至沙盒 `audit_logs/` 目录，支持 `/audit` 快速回溯。

---

## 环境要求与安装

### 1. 环境要求
- **操作系统**：Windows（推荐 Windows 10 / Windows 11）
- **宿主框架**：MaiBot（`host_application` 1.0.0 ~ 1.9.99，`maibot_sdk` 1.0.0 ~ 2.9.99）
- **Python 依赖**：
  - `pillow>=9.0.0`
  - `mss>=9.0.0`

### 2. 安装步骤
1. 将本仓库克隆或下载至 MaiBot 的 `plugins` 目录：
   ```bash
   git clone https://github.com/met-tk/maibot-cmd-sandbox.git
   ```
2. 在 MaiBot 所使用的 Python 环境中安装依赖（如尚未安装）：
   ```bash
   pip install "pillow>=9.0.0" "mss>=9.0.0"
   ```
3. 复制示例配置文件并按需修改：
   ```bash
   copy config.example.toml config.toml
   ```
4. 在 `config.toml` 的 `[security]` 节点中填入你的管理员账号（如 `admin_users = ["123456789"]`），保存后重启或重载 MaiBot 插件即可生效。

---

## 配置说明 (`config.toml`)

### `[plugin]`
| 配置项 | 类型 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `enabled` | `bool` | `true` | 是否启用本插件 |
| `config_version` | `str` | `"1.5.0"` | 配置文件版本号 |

### `[security]`
| 配置项 | 类型 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `admin_users` | `list[str]` | `[]` | 管理员账号列表，支持纯数字账号或带平台前缀（如 `"qq:123456789"`） |
| `unauthorized_message` | `str` | `"权限不足：该系统控制与截图命令仅允许管理员执行。"` | 非管理员触发命令时的拦截回复（留空则静默忽略） |
| `enable_llm_tools` | `bool` | `true` | 是否允许大模型通过自然语言调用系统控制与终端工具 |
| `allow_in_groups` | `bool` | `false` | 是否允许在白名单群聊中执行系统控制与终端命令（总开关） |
| `allowed_groups` | `list[str]` | `[]` | 允许执行命令的群聊白名单（支持纯群号或 `"qq:12345678"`） |
| `unauthorized_group_message` | `str` | `"未授权群聊：..."` | 未授权群聊触发命令时的拦截回复（留空则静默忽略） |

### `[sandbox]`
| 配置项 | 类型 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `workspace_dir` | `str` | `"D:\\Agentworkspace"` | 默认沙盒工作区目录 |
| `sandbox_only_write` | `bool` | `true` | 是否默认仅允许在沙盒工作区内进行文件写入 |
| `allow_write_outside_with_confirm` | `bool` | `true` | 沙盒外写入是否开启管理员双重确认门禁（60 秒有效） |
| `timeout_seconds` | `int` | `30` | 单次同步终端命令执行的超时时间（秒） |
| `max_output_chars` | `int` | `2000` | 命令返回结果的最大字符数 |
| `allow_system_control` | `bool` | `true` | 是否允许执行系统电源控制（关机 / 重启） |
| `shutdown_delay_seconds` | `int` | `60` | 关机或重启的默认倒计时缓冲秒数 |
| `allow_window_control` | `bool` | `true` | 是否允许控制桌面窗口显示状态、尺寸与关闭 |
| `allow_gui_input` | `bool` | `false` | 是否允许受控 GUI 键鼠交互（高敏感开关，默认关闭） |
| `require_confirm_gui_input` | `bool` | `true` | GUI 键鼠交互每次操作是否要求管理员二次确认 |
| `confirm_high_risk_commands` | `bool` | `true` | 高危终端命令、后台任务与关键进程终止是否需要二次确认 |
| `allow_send_image_outside_sandbox` | `bool` | `false` | 是否允许发送沙盒外部的本地图片 |
| `max_send_image_mb` | `int` | `15` | 本地直发图片允许的最大体积（MB） |
| `max_concurrent_jobs` | `int` | `5` | 后台长任务最大同时运行数 |
| `max_job_runtime_seconds` | `int` | `3600` | 单个后台长任务最长运行时长（秒） |
| `enable_audit_log` | `bool` | `true` | 是否启用本地操作审计日志 |
| `audit_retention_days` | `int` | `30` | 审计日志自动保留天数 |
| `watchdog_enabled` | `bool` | `false` | 是否默认启动后台运维看门狗 |
| `watchdog_interval_seconds` | `int` | `60` | 看门狗轮询间隔（最小 10 秒） |
| `watchdog_cooldown_seconds` | `int` | `300` | 看门狗同类型告警冷却时间（秒） |
| `watchdog_disk_min_free_gb` | `float` | `10.0` | 磁盘剩余空间告警阈值（GB，0 表示关闭） |
| `watchdog_processes` | `list[str]` | `[]` | 看门狗监控的进程名列表 |
| `watchdog_lock_state` | `bool` | `false` | 是否监听锁屏/解锁变更通知 |
| `watchdog_notify_stream_id` | `str` | `""` | 看门狗主动告警默认推送会话 ID |

---

## 使用指南

### 1. 直达前缀指令（仅限管理员）

| 指令 | 别名 | 说明 | 示例 |
| --- | --- | --- | --- |
| `/screen [目标]` | `/截图` | 截取桌面、窗口或局部区域（支持 `primary`、`all`、屏幕序号 `1`/`2`、`list`、`win <窗口>`、`rect x,y,w,h`；锁屏时自动拦截） | `/截图`、`/截图 list`、`/截图 win Code`、`/截图 rect 100,200,800,600` |
| `/confirm_exec` | `/确认执行`、`/确认写入`、`/confirm_write` | 授权执行待管理员二次确认的操作请求（60 秒内有效，绑定原发起人及会话） | `/确认执行`、`/确认写入` |
| `/cmd <命令>` | `/terminal` | 在终端中执行同步 PowerShell / CMD 命令（命中高危特征时触发二次确认） | `/cmd dir`、`/cmd ipconfig` |
| `/job <子命令>` | `/后台任务` | 管理后台长耗时任务（`list`、`run <命令>`、`status <id>`、`logs <id>`、`kill <id>`） | `/job list`、`/job run python train.py` |
| `/watchdog <子命令>` | `/监控` | 管理后台看门狗（`status`、`on`、`off`、`disk <GB>`、`add_proc <名>`、`del_proc <名>`、`lock on\|off`） | `/watchdog status`、`/watchdog disk 20` |
| `/audit [条数]` | `/审计` | 查看最近 N 条本地操作审计日志摘要 | `/audit 15` |
| `/关机 [秒数]` | - | 设置定时关机（默认按配置的 `shutdown_delay_seconds` 延时） | `/关机`、`/关机 120` |
| `/重启 [秒数]` | - | 设置定时重启 | `/重启 30` |
| `/取消关机` | - | 取消已计划的关机或重启倒计时 | `/取消关机` |
| `/cmd_group <子命令>` | `/群聊控制`、`/允许群聊`、`/禁用群聊` | 动态管理群聊总开关与白名单（支持 `on`、`off`、`add [群号]`、`del [群号]`、`list`） | `/cmd_group list`、`/cmd_group add` |

### 2. 自然语言交互（私聊或已授权群聊）

开启 `enable_llm_tools = true` 后，插件会向大模型注册以下 13 个系统工具：

1. **`list_desktop_windows`**：检测锁屏状态、多显示器布局与当前桌面可见窗口列表。
2. **`desktop_screenshot`**：支持屏幕、`window` 穿透抓取、`region` 局部裁剪，并在锁屏时自动拦截。
3. **`control_window`**：恢复最小化窗口、最小化、最大化、激活置前、切换置顶、移动缩放及温和关闭。
4. **`gui_input`**：受控 Win32 键鼠交互（默认禁用，支持二次确认与锁屏/安全桌面隔离）。
5. **`get_system_status`**：查询 CPU、内存、磁盘、电池、NVIDIA GPU、局域网 IP、开机时长及可选端口占用排查（`port_query`）。
6. **`manage_file`**：支持 `read`、`read_lines`（按行或负数查末尾）、`search`（关键字/正则）、`find`（通配符查找）、`write`、`append`、`list`、`info`。
7. **`send_local_image`**：校验格式并直接发送沙盒工作区内的本地图片文件到聊天中。
8. **`open_application_or_url`**：打开本地程序、文件或网址链接。
9. **`manage_process`**：列出进程或按名称/PID 终止进程（内置系统核心进程硬阻断与关键进程二次确认）。
10. **`execute_terminal_command`**：执行同步 PowerShell / CMD 命令（高危命令触发二次确认）。
11. **`manage_job`**：启动后台长任务、查看状态、读取尾部实时日志与强杀任务进程树。
12. **`manage_watchdog`**：动态启停看门狗及调整磁盘/进程/锁屏告警规则。
13. **`computer_power_control`**：设置定时关机、重启或取消倒计时。

---

## 安全机制说明

1. **身份与会话双重鉴权**：所有前缀指令与大模型工具调用均从宿主上下文及消息存储层核验真实发起者身份与群白名单，防范提示词注入伪造（若开启 `allow_in_groups = true`，建议仅在受信任小群中使用）。
2. **防逃逸沙盒隔离与绑定式二次确认**：路径校验使用逐级 `realpath` 防御符号链接与 `..` 穿越；高危命令、沙盒外写入、关键进程终止与 GUI 输入的待确认票据严格绑定原发起管理员与所属 `stream_id`，杜绝跨会话或他人抢先核销。
3. **锁屏隔离与敏感窗屏蔽**：锁屏时阻断屏幕抓取及一切窗口/键鼠操控；严禁操作或终止系统核心进程及宿主自身进程。
4. **全链路审计与脱敏**：每次关键操作均自动脱敏凭据后写入按天轮转的 JSONL 审计日志，插件卸载时自动停用看门狗并清理所有托管后台子进程树。

---

## 开源协议

本项目基于 [MIT License](https://opensource.org/licenses/MIT) 开源。
