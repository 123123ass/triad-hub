"""services/runtime_worker.py —— 常驻运行时循环（Step 11 / Gate 1）。

职责（严格按 Codex Step 11 裁决）：
- run_agent_loop：常驻循环调用 services.call_worker.run_call_once，把"能调用"变成"在调用"。
- run_outbox_loop：常驻循环调用 services.feishu_outbox.run_outbox_once，把"能发送"变成"在发送"。
- recover_runtime_state：进程启动时一次性崩溃恢复，只恢复协议允许恢复的状态。

安全红线（不可协商）：
- 本模块不新增任何业务语义：状态机、幂等键、游标全部由 repository / call_worker / feishu_outbox 决定。
- result_unknown（调用结果未知）与 delivery_unknown（投递结果未知）一律保持人工复核，
  worker 绝不自动重试、绝不自动重发。
- 日志只落白名单字段（agent/status/reason/count/error_code），
  绝不落 prompt、回复正文、stdout/stderr、命令行、凭据、完整 URL。
- 任何"无进展"状态（idle / lease_conflict / paused / retry）都必须等待 idle_wait_sec 后再取下一条，
  禁止忙等（CPU 热循环）。
- 收到 stop_event 后：当前这一次调用跑完即退出，绝不中途打断已发出的外部调用。
"""
from __future__ import annotations

import json
import os
import re
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Dict, Optional

from config import config
from logging_config import get_logger

log = get_logger("runtime_worker")

AGENTS = ("workbuddy", "hermes", "codex")

# 运行时状态目录（只放脱敏的 PID / 心跳 / 锁，绝不放凭据或业务内容）
HUB_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_RUNTIME_DIR = HUB_ROOT / "runtime"
GATE4_ISO_ROOT = HUB_ROOT / ".gate4_iso"
ENV_RUNTIME_DIR = "TRIAD_RUNTIME_DIR"
# 隔离路径禁止指向的目录名（规则 6）
_FORBIDDEN_RUNTIME_PARTS = frozenset({".git", "backups", "evidence", "archive"})

# ---------------------------------------------------------------------------
# R2-FIX.2 受控隔离 live 验证（Codex 2026-08-26 裁决，窄例外）
#
# 背景：Gate4 规则 2 铁律 = live 模式（BRIDGE_DRY_RUN=false）显式设置
# TRIAD_RUNTIME_DIR 一律 RuntimeDirError。该铁律**不放宽**。
# 但 SR-2 R2 受控验收必须在 live 桥语义下跑八角色，且绝不能把栅栏写进生产
# runtime/（#537 根因之一）。故新增唯一窄例外："受控隔离 live 验证"——
# 仅当下列条件**全部**成立才放行，任一不满足即 RuntimeDirError，
# 且**绝不降级回生产 runtime**（fail-closed）：
#   a) TRIAD_TEST_MODE=true；
#   b) TRIAD_ALLOW_ISOLATED_LIVE_RUNTIME=true（本次新增的显式许可开关）；
#   c) TRIAD_RUNTIME_DIR == HUB_ROOT/.gate4_iso/r2fix2/<run_id>/runtime（层级严格两段）；
#   d) TRIAD_DB_PATH 与 TRIAD_EVIDENCE_ROOT 均为同一 <run_id> 的受控隔离路径；
#   e) 三者互不重叠，且路径链无 symlink/junction/reparse、无 `..` 逃逸。
# 说明：本段常量必须定义在模块顶部——RUNTIME_DIR 在 import 期即解析（见下方
# `RUNTIME_DIR = get_runtime_dir()`），而 ENV_RUN_ID / is_identity_token /
# _IDENTITY_TOKEN_RE 都定义在其**之后**，窄例外内引用它们会在 import 期
# NameError。且 _IDENTITY_TOKEN_RE 是纯 hex，匹配不了 R2 的 run_id
# （形如 20260825_155417_q505r2_5f1892），故此处单独定义判据。
# ---------------------------------------------------------------------------
ENV_TEST_MODE = "TRIAD_TEST_MODE"
ENV_ALLOW_ISOLATED_LIVE_RUNTIME = "TRIAD_ALLOW_ISOLATED_LIVE_RUNTIME"
ENV_DB_PATH = "TRIAD_DB_PATH"
ENV_EVIDENCE_ROOT = "TRIAD_EVIDENCE_ROOT"
# 与 ENV_RUN_ID（定义于本模块 710 行）同值；此处提前定义仅为规避 import 期顺序问题
_ENV_RUN_ID_EARLY = "TRIAD_RUN_ID"
# R2 代次显式绑定（Phase2/Phase4 注入本轮 R2 run_id）。注意：TRIAD_RUN_ID 在
# supervisor 启动链里是 run_triad_runtime.new_identity_token() 产生的 32 位 hex
# 启动身份令牌，与 R2 run_id 不同源，两者不可混用（历史坑：混用会让八角色子进程
# 在 import 期被误判 run_id 不一致而全部启动失败）。
ENV_R2_RUN_ID = "TRIAD_R2_RUN_ID"
# 32 位纯 hex = supervisor 启动身份令牌，不是 R2 run_id（提前定义，规避顺序问题）
_IDENTITY_TOKEN_RE_EARLY = re.compile(r"^[0-9a-f]{32}$")
# 唯一允许承载 live 隔离 runtime 的子树名（.gate4_iso 下）
R2FIX2_ISO_SUBDIR = "r2fix2"
# 允许承载同代次隔离 DB / evidence 的受控根（相对 HUB_ROOT）；
# .gate4_iso/r2fix2/<run_id>/ 亦同时被允许（见 _isolated_run_roots）
_R2FIX2_DATA_ROOTS = ("_sr2_qualify",)
# run_id 目录段判据：contract.new_run_id() = %Y%m%d_%H%M%S_<tag>_<6hex>
_R2FIX2_RUN_SEG_RE = re.compile(r"^[0-9A-Za-z_]{8,64}$")


class RuntimeDirError(ValueError):
    """TRIAD_RUNTIME_DIR 校验失败（fail-closed）。消息即稳定错误码。"""

# 无进展状态：必须退避等待，避免热循环
_NO_PROGRESS_STATUSES = frozenset({"idle", "lease_conflict", "paused", "retry"})
# 结果未知状态：仅记录，绝不自动重试 / 重发
_MANUAL_REVIEW_STATUSES = frozenset({"result_unknown", "delivery_unknown"})
# 连续异常退避上限（秒）
_MAX_ERROR_BACKOFF_SEC = 5.0


# =====================================================================
# 进程身份工具（PID 存活 + 二次核验）
#
# 【重要】Windows 上禁止用 os.kill(pid, 0) 做存活探测。准确机理（CPython Modules/posixmodule.c
# os_kill_impl，已核对 3.13 分支源码 + 本机 3.13.14/3.14.3 实测）：
#   1) sig == CTRL_C_EVENT(0) 或 CTRL_BREAK_EVENT(1) 时走 GenerateConsoleCtrlEvent(sig, pid)，
#      这是向**进程组**广播控制台控制事件，不是"探测进程是否存在"；
#      其成功/失败与目标进程是否存活并不对应，可能误判存活，也可能真的中断同控制台会话的进程。
#   2) 该分支仅在编译期定义 HAVE_WINDOWS_CONSOLE_IO 时存在；未定义时 sig=0 会落到
#      OpenProcess(PROCESS_ALL_ACCESS) + TerminateProcess(handle, 0)，即**直接杀死目标进程**。
#   3) 历史 CPython（bpo-42962 修复前）缺少 return，GenerateConsoleCtrlEvent 失败会继续
#      TerminateProcess，同样会杀进程。
#   4) 回退路径要求 PROCESS_ALL_ACCESS，对他人/提权进程会 AccessDenied → 误判为已死。
# 因此统一改用 OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION) +
# GetExitCodeProcess() == STILL_ACTIVE(259) 做只读探测。
# =====================================================================
_WIN = os.name == "nt"
_PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
_STILL_ACTIVE = 259


def _k32():
    """返回已声明原型的 kernel32（默认 restype=c_int 会截断 64 位句柄）。"""
    import ctypes
    from ctypes import wintypes

    k = ctypes.WinDLL("kernel32", use_last_error=True)
    k.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    k.OpenProcess.restype = wintypes.HANDLE
    k.CloseHandle.argtypes = [wintypes.HANDLE]
    k.CloseHandle.restype = wintypes.BOOL
    k.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    k.GetExitCodeProcess.restype = wintypes.BOOL
    k.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4
    k.GetProcessTimes.restype = wintypes.BOOL
    k.QueryFullProcessImageNameW.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.LPWSTR,
        ctypes.POINTER(wintypes.DWORD),
    ]
    k.QueryFullProcessImageNameW.restype = wintypes.BOOL
    return k


def _win_open_process(pid: int, k=None):
    k = k or _k32()
    handle = k.OpenProcess(_PROCESS_QUERY_LIMITED_INFORMATION, False, int(pid))
    return (handle or None), k


def pid_alive(pid: int) -> bool:
    """只读判断 PID 是否存活。绝不对目标进程产生任何副作用。"""
    try:
        pid = int(pid)
    except Exception:
        return False
    if pid <= 0:
        return False
    if _WIN:
        import ctypes
        from ctypes import wintypes

        handle, k = _win_open_process(pid)
        if handle is None:
            return False
        try:
            code = wintypes.DWORD()
            if not k.GetExitCodeProcess(handle, ctypes.byref(code)):
                return False
            return code.value == _STILL_ACTIVE
        finally:
            k.CloseHandle(handle)
    try:
        os.kill(pid, 0)
    except (OSError, ProcessLookupError):
        return False
    return True


def process_start_time(pid: int) -> Optional[float]:
    """进程创建时间（Unix 秒）。用于 PID 复用二次核验；取不到返回 None。"""
    try:
        pid = int(pid)
    except Exception:
        return None
    if pid <= 0:
        return None
    if _WIN:
        import ctypes
        from ctypes import wintypes

        handle, k = _win_open_process(pid)
        if handle is None:
            return None
        try:
            creation = wintypes.FILETIME()
            exit_t = wintypes.FILETIME()
            kernel_t = wintypes.FILETIME()
            user_t = wintypes.FILETIME()
            ok = k.GetProcessTimes(
                handle,
                ctypes.byref(creation),
                ctypes.byref(exit_t),
                ctypes.byref(kernel_t),
                ctypes.byref(user_t),
            )
            if not ok:
                return None
            ticks = (creation.dwHighDateTime << 32) | creation.dwLowDateTime
            # FILETIME 起点 1601-01-01，换算到 Unix 纪元
            return ticks / 10_000_000.0 - 11644473600.0
        finally:
            k.CloseHandle(handle)
    try:
        with open(f"/proc/{pid}/stat", "r", encoding="utf-8") as f:
            fields = f.read().rsplit(")", 1)[1].split()
        clk = os.sysconf("SC_CLK_TCK")
        boot = 0.0
        with open("/proc/stat", "r", encoding="utf-8") as f:
            for line in f:
                if line.startswith("btime"):
                    boot = float(line.split()[1])
                    break
        return boot + float(fields[19]) / clk
    except Exception:
        return None


def process_image_name(pid: int) -> Optional[str]:
    """进程可执行文件名（不含路径，避免把完整路径写进日志）。取不到返回 None。"""
    if not _WIN:
        try:
            return os.path.basename(os.readlink(f"/proc/{int(pid)}/exe"))
        except Exception:
            return None
    import ctypes
    from ctypes import wintypes

    handle, k = _win_open_process(pid)
    if handle is None:
        return None
    try:
        size = wintypes.DWORD(1024)
        buf = ctypes.create_unicode_buffer(size.value)
        ok = k.QueryFullProcessImageNameW(handle, 0, buf, ctypes.byref(size))
        if not ok:
            return None
        return os.path.basename(buf.value)
    except Exception:
        return None
    finally:
        k.CloseHandle(handle)


def verify_pid_identity(
    pid: int,
    expected_start_time: Optional[float] = None,
    expected_image: Optional[str] = None,
    tolerance_sec: float = 2.0,
) -> Dict[str, Any]:
    """PID 二次核验：存活 + 创建时间匹配 + 镜像名匹配，防 PID 复用误判。

    P0-3（Codex 2026-08-19）：两个期望身份都为空（无可比信息）时，不得退化为
    仅判断 PID 存活——`verified` 必须为 False（fail-closed），由调用方决定阻断。
    """
    alive = pid_alive(pid)
    result: Dict[str, Any] = {
        "pid": int(pid) if str(pid).lstrip("-").isdigit() else 0,
        "alive": alive,
        "start_time_match": None,
        "image_match": None,
        "verified": False,
    }
    if not alive:
        return result
    if expected_start_time is not None:
        actual = process_start_time(pid)
        result["start_time_match"] = (
            actual is not None and abs(actual - expected_start_time) <= tolerance_sec
        )
    if expected_image is not None:
        actual_img = process_image_name(pid)
        result["image_match"] = (
            actual_img is not None and actual_img.lower() == expected_image.lower()
        )
    checks = [v for v in (result["start_time_match"], result["image_match"]) if v is not None]
    # P0-3：期望身份为空 → fail-closed，绝不按 alive 放行
    result["verified"] = alive and bool(checks) and all(checks)
    return result


# =====================================================================
# 控制文件删除：safe-delete 护栏受控 fallback（Gate4 B 分支）
#
# 【背景】执行环境（WB 沙箱）存在外部 safe-delete 护栏：任何进程的 unlink() 都会
# fail-closed 抛 OSError("[safe-delete][SAFE_DELETE_FAIL_CLOSED] ...")。该护栏不是本项目
# 代码（全仓源码零命中），无法从项目内关闭。后果：release_role_lock() / clear_stop_request()
# 原本 `except OSError: pass`，静默吞掉异常 → .role_lock_* 与 *.stop 残留 → Gate4 #244
# 第 13/14 项不达标。已实测 os.rename 不受该护栏管辖（rename 探针 = RENAME_ALLOWED）。
#
# 【授权】Codex 2026-08-11 裁决：授权受控 fallback，仅适用于运行控制文件，且必须满足 9 条规则：
#   1) 正常 unlink 成功则结束；
#   2) 只有捕获明确的 SAFE_DELETE_FAIL_CLOSED 才允许 fallback；
#   3) fallback 原子移动到 runtime/.retired_control/<run_id>/；
#   4) 移动前验证：路径在 runtime 根内 / 非链接或 reparse / 文件名符合控制文件白名单 /
#      role 属角色白名单 / 锁内 PID 已死或 stop marker 属已结束本轮 run；
#   5) 不得移动活动锁；
#   6) 目标文件名含 role + 类型 + 唯一后缀，禁止覆盖；
#   7) fallback 成功后活动 runtime 目录不得残留对应锁或 stop marker；
#   8) 日志只记相对路径和稳定状态码，不记 nonce；
#   9) .retired_control 不参与运行时锁或 stop 判断。
#
# 【规则 4/5 的解释点，已报 Codex 复核】owner_verified=True 表示调用方（release_role_lock）
# 已核验锁内 PID == os.getpid()，即"释放本进程自己的锁"。原 unlink 路径本就允许这样做，
# fallback 与之等价，不得更弱也不得更强。规则 5 保护的是"别人的活动锁"：默认
# owner_verified=False 时，锁内 PID 存活一律拒绝移动。
# =====================================================================
RETIRED_CONTROL_DIRNAME = ".retired_control"

# 允许走受控 fallback 的角色：supervisor 管的八角色 + supervisor 自身
# （残留实测含 .role_lock_supervisor，故纳入；已报 Codex 复核是否收窄为纯八角色）
CONTROL_ROLE_WHITELIST = frozenset(
    {
        "hub",
        "outbox",
        "agent-workbuddy",
        "agent-hermes",
        "agent-codex",
        "bridge-workbuddy",
        "bridge-hermes",
        "bridge-codex",
        "supervisor",
    }
)

# 护栏错误的唯一识别标记（规则 2：其它 OSError 一律不 fallback）
_SAFE_DELETE_MARKER = "SAFE_DELETE_FAIL_CLOSED"
_FILE_ATTRIBUTE_REPARSE_POINT = 0x400
_RETIRE_NO_RUN_DIR = "norun"

# 心跳新鲜度上限（与 run_triad_runtime.HEARTBEAT_FRESH_SEC 同口径；#404 heartbeat
# 受控归档用它拒绝"最近更新过"的心跳——fresh 心跳一律不得归档）
HEARTBEAT_FRESH_SEC = 90.0


def _is_reparse_point(path: Path) -> bool:
    """只读判断是否为 symlink / junction / 其它 reparse point（不跟随目标）。"""
    try:
        st = os.lstat(path)
    except OSError:
        return False
    if getattr(st, "st_file_attributes", 0) & _FILE_ATTRIBUTE_REPARSE_POINT:
        return True
    import stat as _stat

    return _stat.S_ISLNK(st.st_mode)


def _no_reparse_chain(leaf: Path, stop: Path) -> bool:
    """leaf 及其父级（至 stop 止，含 stop）均非 reparse point。

    stop 必须是 leaf 的祖先；若不是，向上遍历到根即止（返回时已覆盖全链）。
    """
    cur = leaf
    while True:
        if _is_reparse_point(cur):
            return False
        if cur == stop or cur == cur.parent:
            return True
        cur = cur.parent


def _isolated_run_roots(run_seg: str) -> tuple:
    """同一代次允许承载隔离 DB / evidence 的受控根（已 resolve）。"""
    roots = [(HUB_ROOT / ".gate4_iso" / R2FIX2_ISO_SUBDIR / run_seg)]
    for name in _R2FIX2_DATA_ROOTS:
        roots.append(HUB_ROOT / name / run_seg)
    out = []
    for r in roots:
        try:
            out.append(r.resolve())
        except OSError:
            continue
    return tuple(out)


def _verify_isolated_data_path(
    raw: Optional[str], run_seg: str, error_code: str
) -> Path:
    """校验 TRIAD_DB_PATH / TRIAD_EVIDENCE_ROOT 属于本代次受控隔离根。

    未设置 / 相对路径 / UNC / 越出受控根 / reparse 链 → RuntimeDirError(error_code)。
    """
    if not raw or not raw.strip():
        raise RuntimeDirError(error_code)
    value = raw.strip()
    if not os.path.isabs(value) or value.startswith(("//", "\\\\")):
        raise RuntimeDirError(error_code)
    try:
        resolved = Path(value).resolve()
    except OSError:
        raise RuntimeDirError(error_code)
    # 直接对原始叶子做 lstat：resolve() 会吞掉叶子上的 symlink
    if _is_reparse_point(Path(value)):
        raise RuntimeDirError("isolated_live_reparse_rejected")
    for root in _isolated_run_roots(run_seg):
        if resolved == root or root in resolved.parents:
            if not _no_reparse_chain(resolved, root):
                raise RuntimeDirError("isolated_live_reparse_rejected")
            return resolved
    raise RuntimeDirError(error_code)


def _verify_isolated_live_runtime(resolved: Path) -> None:
    """R2-FIX.2 受控隔离 live 验证（窄例外的追加校验，见模块顶部说明）。

    调用前提：调用方已确认 TRIAD_TEST_MODE=true 且
    TRIAD_ALLOW_ISOLATED_LIVE_RUNTIME=true，且 resolved 已通过 Gate4
    规则 3~7 全部默认校验。本函数只做**更严格**的追加约束，任一不满足
    即 RuntimeDirError（fail-closed，绝不降级回生产 runtime）。
    """
    try:
        r2_root = (HUB_ROOT / ".gate4_iso" / R2FIX2_ISO_SUBDIR).resolve()
    except OSError:
        raise RuntimeDirError("isolated_live_outside_r2fix2")

    # 条件 c：必须严格是 .gate4_iso/r2fix2/<run_id>/runtime（两段，不多不少）
    try:
        rel = resolved.relative_to(r2_root)
    except ValueError:
        raise RuntimeDirError("isolated_live_outside_r2fix2")
    if len(rel.parts) != 2 or rel.parts[1] != "runtime":
        raise RuntimeDirError("isolated_live_bad_layout")
    run_seg = rel.parts[0]
    if not _R2FIX2_RUN_SEG_RE.match(run_seg):
        raise RuntimeDirError("isolated_live_bad_run_id")

    # 代次一致性（两条独立判据，任一冲突即拒绝）：
    #   ① TRIAD_R2_RUN_ID：Phase2/Phase4 显式注入的本轮 R2 代次，必须与目录段完全一致；
    #   ② TRIAD_RUN_ID：supervisor 启动链注入的 32 位 hex 启动身份令牌（与 R2 run_id
    #      不同源），故仅当它明显不是身份令牌（即被当作 R2 风格 run_id 传入）时才要求一致，
    #      否则八角色子进程会在 import 期被误拒。
    r2_run_id = (os.environ.get(ENV_R2_RUN_ID) or "").strip()
    if r2_run_id and r2_run_id != run_seg:
        raise RuntimeDirError("isolated_live_run_id_mismatch")
    env_run_id = (os.environ.get(_ENV_RUN_ID_EARLY) or "").strip()
    if (
        env_run_id
        and not _IDENTITY_TOKEN_RE_EARLY.match(env_run_id)
        and env_run_id != run_seg
    ):
        raise RuntimeDirError("isolated_live_run_id_mismatch")

    # 条件 d：DB 与 evidence 必须同为本代次受控隔离路径
    db_path = _verify_isolated_data_path(
        os.environ.get(ENV_DB_PATH), run_seg, "isolated_live_db_not_isolated"
    )
    ev_root = _verify_isolated_data_path(
        os.environ.get(ENV_EVIDENCE_ROOT), run_seg,
        "isolated_live_evidence_not_isolated",
    )

    # 条件 e：三者互不重叠（含相等与父子包含）
    for a, b in ((resolved, db_path), (resolved, ev_root), (db_path, ev_root)):
        if a == b or a in b.parents or b in a.parents:
            raise RuntimeDirError("isolated_live_paths_overlap")


def get_runtime_dir() -> Path:
    """解析运行时控制目录（全仓唯一入口，禁止各模块自行解析环境变量）。

    Codex 2026-08-11 裁决（Gate4 完全隔离控制面）11 条规则：
      1) 未设置 TRIAD_RUNTIME_DIR -> 默认 HUB_ROOT/runtime；
      2) 仅 BRIDGE_DRY_RUN=true 下生效（live 模式显式设置 -> RuntimeDirError）；
         【R2-FIX.2 窄例外 / Codex 2026-08-26】live 模式下唯一放行条件为
         TRIAD_TEST_MODE=true + TRIAD_ALLOW_ISOLATED_LIVE_RUNTIME=true，
         且须再通过 _verify_isolated_live_runtime 的追加约束
         （.gate4_iso/r2fix2/<run_id>/runtime + 同代次隔离 DB/evidence +
         三者互不重叠 + 无 reparse）；任一不满足即 RuntimeDirError，
         绝不降级回生产 runtime。规则 2 的默认拒绝语义不变。
      3) 必须是绝对路径；
      4) resolve 后必须位于 HUB_ROOT/.gate4_iso/ 内；
      5) 目标及其父级（至 .gate4_iso 止）不得是 symlink/junction/reparse point；
      6) 禁止指向仓库根 / 默认 runtime / .git / backups / evidence / archive；
      7) 禁止空值 / 相对路径 / `..` 逃逸 / UNC；
      8) 只允许唯一叶子目录（调用方负责 mkdir，本函数不创建、不清理、不覆盖）；
      9) supervisor 经环境变量把同一已验证路径显式传给子进程（run_triad_runtime._spawn）；
      10) 八角色 + supervisor 全部使用该目录的 registry/heartbeat/lock/stop/retired；
      11) 日志只记相对路径或哈希（本函数不落任何日志）。
    """
    raw = os.environ.get(ENV_RUNTIME_DIR)
    if raw is None:
        return HUB_ROOT / "runtime"  # 规则 1

    value = raw.strip()
    if not value:
        raise RuntimeDirError("empty")  # 规则 7 禁空值
    from config import config

    live_isolated = False
    if not config.BRIDGE_DRY_RUN:
        # 规则 2 铁律保持不变：live 模式显式设置默认一律拒绝。
        # 唯一窄例外（R2-FIX.2 / Codex 2026-08-26）：TRIAD_TEST_MODE=true 且
        # TRIAD_ALLOW_ISOLATED_LIVE_RUNTIME=true 时进入"受控隔离 live 验证"，
        # 由 _verify_isolated_live_runtime 在规则 3~7 之后追加更严格约束。
        # 两个开关缺任一 → 沿用原稳定错误码 live_mode_override_rejected。
        if (
            os.environ.get(ENV_TEST_MODE) != "true"
            or os.environ.get(ENV_ALLOW_ISOLATED_LIVE_RUNTIME) != "true"
        ):
            raise RuntimeDirError("live_mode_override_rejected")  # 规则 2
        live_isolated = True
    if not os.path.isabs(value):
        raise RuntimeDirError("not_absolute")  # 规则 3
    if value.startswith(("//", "\\\\")):
        raise RuntimeDirError("unc_rejected")  # 规则 7 禁 UNC

    try:
        resolved = Path(value).resolve()
    except OSError:
        raise RuntimeDirError("resolve_failed")
    hub_resolved = HUB_ROOT.resolve()
    default_resolved = (HUB_ROOT / "runtime").resolve()
    iso_resolved = (HUB_ROOT / ".gate4_iso").resolve()

    # 规则 6：禁止指向仓库根 / 默认 runtime（含其内部）
    if resolved == hub_resolved:
        raise RuntimeDirError("repo_root_rejected")
    if resolved == default_resolved or default_resolved in resolved.parents:
        raise RuntimeDirError("default_runtime_rejected")

    # 规则 4 + 规则 7（`..` 逃逸）：resolve 后必须位于 .gate4_iso/ 内
    try:
        rel = resolved.relative_to(iso_resolved)
    except ValueError:
        raise RuntimeDirError("outside_gate4_iso")

    # 规则 6：隔离目录内不得包含黑名单目录段
    for part in rel.parts:
        if part in _FORBIDDEN_RUNTIME_PARTS:
            raise RuntimeDirError("forbidden_path_rejected")

    # 规则 5：目标及其父级（至 .gate4_iso 止）不得为 reparse point
    cur = resolved
    while True:
        if _is_reparse_point(cur):
            raise RuntimeDirError("reparse_rejected")
        if cur == iso_resolved or cur == cur.parent:
            break
        cur = cur.parent

    # 窄例外追加校验（只在受控隔离 live 验证下执行；dry-run 路径完全不变）
    if live_isolated:
        _verify_isolated_live_runtime(resolved)
    return resolved


# 模块加载时解析一次；env 非法即 import 失败（fail-closed）
RUNTIME_DIR = get_runtime_dir()


def _control_file_name(role: str, kind: str) -> Optional[str]:
    """控制文件名白名单：锁 / 停机标记 / 心跳（Codex #404 新增 heartbeat 分支）。

    文件名必须与 role 严格对应；heartbeat 是 #404 受控归档白名单的一部分，
    但仅命中白名单不足以归档——归档必须经 delete_or_retire_control_file 的
    heartbeat 专用身份核验（fresh/trusted/活 PID 一律拒绝，未验证即拒绝）。
    """
    if kind == "lock":
        return f".role_lock_{role}"
    if kind == "stop":
        return f"{role}.stop"
    if kind == "heartbeat":
        return f"{role}.heartbeat.json"
    return None


def _retire_run_dirname() -> str:
    value = os.environ.get(ENV_RUN_ID)
    return value if is_identity_token(value) else _RETIRE_NO_RUN_DIR


def delete_or_retire_control_file(
    path: Any, role: str, kind: str, *, owner_verified: bool = False,
    heartbeat_verified: Optional[Dict[str, Any]] = None,
) -> str:
    """删除运行控制文件；被 safe-delete 护栏 fail-closed 拦截时走受控归档 fallback。

    返回稳定状态码：
      deleted / retired / missing / delete_failed
      retire_rejected_outside_runtime / retire_rejected_reparse
      retire_rejected_not_control_file / retire_rejected_role
      retire_rejected_active_lock / retire_failed_mkdir / retire_failed_rename
      retire_rejected_unverified_heartbeat / retire_rejected_fresh_heartbeat
      retire_rejected_alive_heartbeat / retire_rejected_heartbeat_refreshed

    kind == "heartbeat" 时（Codex #404 受控归档白名单，P0-1 修正）：
      - 在任何 unlink() 之前进入专属核验路径；绝不走普通"先删、失败再归档"路径，
        普通环境下未验证 / fresh / 活 PID / 刚刷新的 heartbeat 不得被直接删除；
      - 调用方必须先完成身份核验并显式传入 heartbeat_verified（未传一律拒绝，
        绝不静默降级为普通控制文件归档）；
      - 未验证 / fresh / trusted / PID 仍存活 / 角色不符 / 文件被刷新 → 一律拒绝
        且保留原文件；
      - 只有验证通过的陈旧 heartbeat 才能归档（os.rename 原子移动，绝不覆盖）。
    """
    path = Path(path)
    if not path.exists():
        return "missing"

    def _reject(code: str) -> str:
        log.warn("control_file_retire_rejected", agent=role, status=code, reason=kind)
        return code

    # ---- 规则 4a：路径必须直接位于 runtime 根内（用 parent 解析，避免跟随文件自身链接）----
    try:
        parent_resolved = path.parent.resolve()
        root_resolved = Path(RUNTIME_DIR).resolve()
    except OSError:
        return _reject("retire_rejected_outside_runtime")
    if os.path.normcase(str(parent_resolved)) != os.path.normcase(str(root_resolved)):
        return _reject("retire_rejected_outside_runtime")

    # ---- 规则 4b：不是链接 / reparse point ----
    if _is_reparse_point(path):
        return _reject("retire_rejected_reparse")

    # ---- 规则 4c：文件名必须命中控制文件白名单，且与 role 严格对应 ----
    expected_name = _control_file_name(role, kind)
    if expected_name is None or path.name != expected_name:
        return _reject("retire_rejected_not_control_file")

    # ---- 规则 4d：role 必须在角色白名单内 ----
    if role not in CONTROL_ROLE_WHITELIST:
        return _reject("retire_rejected_role")

    # ---- 规则 0（Codex P0-1）：heartbeat 专属路径，任何 unlink() 之前完成核验 ----
    if kind == "heartbeat":
        return _retire_heartbeat_guarded(path, role, heartbeat_verified, _reject)

    # ---- 规则 1：正常删除优先（仅 lock/stop 等非 heartbeat 控制文件）----
    try:
        path.unlink()
        return "deleted"
    except OSError as exc:
        message = str(exc)

    # ---- 规则 2：只有护栏 fail-closed 才允许 fallback ----
    if _SAFE_DELETE_MARKER not in message:
        log.warn(
            "control_file_delete_failed",
            agent=role,
            status="delete_failed",
            reason=kind,
            error_code="oserror_not_safe_delete",
        )
        return "delete_failed"

    # ---- 规则 4e + 5：不得移动别人的活动锁 ----
    if kind == "lock" and not owner_verified:
        try:
            holder = int((path.read_text(encoding="utf-8").strip() or "0"))
        except Exception:
            holder = 0
        if holder and pid_alive(holder):
            return _reject("retire_rejected_active_lock")

    # ---- 规则 3：归档到 runtime/.retired_control/<run_id 或 norun>/ ----
    run_dirname = _retire_run_dirname()
    run_dir = Path(RUNTIME_DIR) / RETIRED_CONTROL_DIRNAME / run_dirname
    try:
        run_dir.mkdir(parents=True, exist_ok=True)
    except OSError:
        return _reject("retire_failed_mkdir")

    # ---- 规则 6：目标名含 role + 类型 + 唯一后缀，且绝不覆盖已有文件 ----
    import uuid

    stamp = time.strftime("%Y%m%dT%H%M%S", time.gmtime())
    for _ in range(8):
        target = run_dir / f"{role}.{kind}.{stamp}-{uuid.uuid4().hex[:8]}"
        if target.exists():
            continue
        try:
            os.rename(path, target)  # 原子移动；不删除、不重试、不碰其它文件
        except OSError:
            return _reject("retire_failed_rename")
        # ---- 规则 8：只记相对路径与稳定状态码，绝不记 nonce / 绝对路径 ----
        log.info(
            "control_file_retired",
            agent=role,
            status="retired",
            reason=kind,
            state=f"{RETIRED_CONTROL_DIRNAME}/{run_dirname}",
            error_code="safe_delete_fail_closed",
        )
        return "retired"
    return _reject("retire_failed_rename")


def _retire_heartbeat_guarded(
    path: Path, role: str,
    heartbeat_verified: Optional[Dict[str, Any]],
    _reject,
) -> str:
    """heartbeat 受控归档核验（Codex #404）：fresh/trusted/活 PID/未验证/刷新一律拒绝。

    归档必须由调用方先完成身份核验并显式传入 heartbeat_verified（字典）：
      - pid_dead: bool           心跳内 runtime_pid 已确认死亡
      - frozen_updated_ts: float  双次采样确认未刷新的 updated_ts
      - no_live_process: bool    无同角色活进程
    未显式传入已验证状态 → retire_rejected_unverified_heartbeat（绝不静默降级）。
    文件被刷新（updated_ts 与验证时不一致）或角色不符 → 拒绝。
    归档目标遵循规则 3/6：.retired_control/<run_id|norun>/ + role.heartbeat.<stamp>-<uuid>，
    绝不覆盖同名文件。
    """
    import uuid

    # ---- #404 强制：未显式传入已验证状态一律拒绝 ----
    if not isinstance(heartbeat_verified, dict) or not heartbeat_verified:
        return _reject("retire_rejected_unverified_heartbeat")

    # ---- 解析心跳内容（解析失败/无 updated_ts → 无法验证 → 拒绝）----
    try:
        hb = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return _reject("retire_rejected_unverified_heartbeat")
    if not isinstance(hb, dict):
        return _reject("retire_rejected_unverified_heartbeat")

    try:
        file_ts = float(hb.get("updated_ts"))
    except (TypeError, ValueError):
        file_ts = None
    if file_ts is None:
        return _reject("retire_rejected_unverified_heartbeat")

    # ---- 角色必须与文件内 role 严格一致（防错位归档）----
    if str(hb.get("role", "")) != role:
        return _reject("retire_rejected_not_control_file")

    # ---- 文件刷新检查：updated_ts 与调用方验证时不一致 = 身份变化 → 拒绝 ----
    try:
        verified_ts = float(heartbeat_verified.get("frozen_updated_ts"))
    except (TypeError, ValueError):
        verified_ts = None
    if verified_ts is not None and abs(file_ts - verified_ts) > 0.001:
        return _reject("retire_rejected_heartbeat_refreshed")

    # ---- fresh 检查：最近更新过的一律不得归档 ----
    fresh_sec = HEARTBEAT_FRESH_SEC if HEARTBEAT_FRESH_SEC > 0 else 90.0
    if (time.time() - file_ts) < fresh_sec:
        return _reject("retire_rejected_fresh_heartbeat")

    # ---- 活 PID 检查：心跳内 runtime_pid 仍存活 → 拒绝 ----
    try:
        hb_pid = int(hb.get("runtime_pid") or hb.get("pid") or 0)
    except (TypeError, ValueError):
        hb_pid = 0
    if hb_pid > 0 and pid_alive(hb_pid):
        return _reject("retire_rejected_alive_heartbeat")

    # ---- 调用方核验事实复核：pid_dead / no_live_process 必须为真 ----
    if not heartbeat_verified.get("pid_dead"):
        return _reject("retire_rejected_unverified_heartbeat")
    if not heartbeat_verified.get("no_live_process"):
        return _reject("retire_rejected_unverified_heartbeat")

    # ---- 归档（规则 3/6）：绝不覆盖同名文件 ----
    run_dirname = _retire_run_dirname()
    run_dir = Path(RUNTIME_DIR) / RETIRED_CONTROL_DIRNAME / run_dirname
    try:
        run_dir.mkdir(parents=True, exist_ok=True)
    except OSError:
        return _reject("retire_failed_mkdir")

    stamp = time.strftime("%Y%m%dT%H%M%S", time.gmtime())
    for _ in range(8):
        target = run_dir / f"{role}.heartbeat.{stamp}-{uuid.uuid4().hex[:8]}"
        if target.exists():
            continue
        try:
            os.rename(path, target)
        except OSError:
            return _reject("retire_failed_rename")
        log.info(
            "control_file_retired",
            agent=role,
            status="retired",
            reason="heartbeat",
            state=f"{RETIRED_CONTROL_DIRNAME}/{run_dirname}",
            error_code="safe_delete_fail_closed",
        )
        return "retired"
    return _reject("retire_failed_rename")


# =====================================================================
# 角色锁 + 心跳（脱敏，仅角色/PID/时间/状态）
#
# 规则 9：锁与 stop 判断只看 RUNTIME_DIR 根下的固定文件名，不递归扫描，
# 因此 .retired_control/ 归档区天然不参与任何运行时判定。
# =====================================================================
def _role_lock_path(role: str) -> Path:
    return RUNTIME_DIR / f".role_lock_{role}"


def _heartbeat_path(role: str) -> Path:
    return RUNTIME_DIR / f"{role}.heartbeat.json"


def acquire_role_lock(role: str) -> bool:
    """单实例角色锁。锁内只写 PID；持有者已死则允许接管。"""
    RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
    path = _role_lock_path(role)
    if path.exists():
        try:
            holder = int((path.read_text(encoding="utf-8").strip() or "0"))
        except Exception:
            holder = 0
        if holder and holder != os.getpid() and pid_alive(holder):
            return False
    path.write_text(str(os.getpid()), encoding="utf-8")
    return True


def release_role_lock(role: str) -> None:
    """只删除本进程持有的锁，绝不动别的活跃进程的锁。"""
    path = _role_lock_path(role)
    if not path.exists():
        return
    try:
        holder = int((path.read_text(encoding="utf-8").strip() or "0"))
    except Exception:
        return
    if holder == os.getpid():
        # 已核验"锁内 PID == 本进程"，即释放自己的锁；护栏拦截时走受控归档 fallback。
        delete_or_retire_control_file(path, role, "lock", owner_verified=True)


# ---- 跨进程优雅停机信号（Windows 无法向别的进程发 SIGTERM，用停机标记文件） ----
def stop_file_path(role: str) -> Path:
    return RUNTIME_DIR / f"{role}.stop"


def request_stop(role: str) -> None:
    """请求某角色优雅停机：写标记文件，由该角色自己在当前任务完成后退出。"""
    RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
    stop_file_path(role).write_text(
        time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()), encoding="utf-8"
    )


def clear_stop_request(role: str) -> None:
    path = stop_file_path(role)
    if path.exists():
        # stop marker 属于已结束的本轮 run；护栏拦截时走受控归档 fallback。
        delete_or_retire_control_file(path, role, "stop")


def start_stop_file_watcher(
    role: str, stop_event: Any, poll_sec: float = 0.25
) -> threading.Thread:
    """后台线程轮询停机标记文件，命中即置位 stop_event（当前任务完成后退出）。"""

    def _watch() -> None:
        path = stop_file_path(role)
        while not stop_event.is_set():
            if path.exists():
                log.info("stop_request_detected", status="stopping", reason="stop_file")
                stop_event.set()
                return
            _wait(stop_event, poll_sec)

    t = threading.Thread(target=_watch, name=f"stopwatch-{role}", daemon=True)
    t.start()
    return t


# ---- 运行时身份（Gate4 F-3 修复） ----
# 背景：Windows DETACHED_PROCESS 启动 venv python 时存在瞬退壳进程，supervisor 拿到的
# Popen().pid 只是壳 PID，秒退后就不再对应任何真实 worker。
# 结论（Codex 裁决）：spawn_pid 仅作启动过程审计证据，永不参与就绪/终止决策；
# 进程自身 os.getpid() 写进心跳的 runtime_pid 才是唯一身份来源。
# run_id：本次 --start 全局唯一；launch_nonce：本次 spawn 单角色唯一。二者由 supervisor
# 经环境变量注入子进程，用于识别"本轮"心跳，杜绝陈旧心跳/跨轮串台被误判为就绪。
ENV_RUN_ID = "TRIAD_RUN_ID"
ENV_LAUNCH_NONCE = "TRIAD_LAUNCH_NONCE"

# 身份令牌格式：仅小写十六进制、8~64 位。限格式限长，防脏值/超长字段夹带信息落盘。
_IDENTITY_TOKEN_RE = re.compile(r"[0-9a-f]{8,64}")


def is_identity_token(value: Any) -> bool:
    """校验运行时身份令牌（run_id / launch_nonce）格式。"""
    return isinstance(value, str) and _IDENTITY_TOKEN_RE.fullmatch(value) is not None


def _resolve_identity(fields: Dict[str, Any]) -> Dict[str, str]:
    """取本进程的身份令牌：显式传参优先，其次环境变量；格式非法一律丢弃。"""
    out: Dict[str, str] = {}
    for key, env_name in (("run_id", ENV_RUN_ID), ("launch_nonce", ENV_LAUNCH_NONCE)):
        value = fields.pop(key, None)
        if value is None:
            value = os.environ.get(env_name)
        if is_identity_token(value):
            out[key] = value
    return out


# =====================================================================
# 启动代次取消栅栏（SR-2 P0 #402，Codex 裁决）
#
# 【根因】孤儿 37460：上一轮代次被取消/重启后，旧 spawn 仍作为 live 桥起来并
# 维持 ESTABLISHED 外发连接（live_confirmed）。本栅栏在 supervisor _spawn() 前
# 建立"本轮代次 active"证据，桥在入口/建飞书连接前/写心跳前三次校验：cancelled/
# 缺失/损坏/不匹配即非零退出，从根上阻止陈旧/孤儿代次冒充就绪。
#
# 【权威实现集中】Codex #402.2：栅栏全部 API 落地本模块（runtime_worker.py），
# 禁止在 supervisor / hub_bridge 各自造副本。复用现有 launch_nonce，不造第三套令牌。
#
# 【fail-closed】损坏/缺失（当调用方预期代次）/代次不匹配/cancelled 一律非 active，
# 不得降级放行。
# 【cancelled 保留】取消后保留 ≥300s（长于 启动 ~20s + 连接 ≤60s + #401 复核 ≥180s），
# 仅过期后受控归档，绝不立即删除——否则回滚窗口内取消证据丢失，孤儿可趁虚而入。
# 【落盘】同目录临时文件 + flush/fsync + 原子 replace；截断/半写不得生效。
# =====================================================================
LAUNCH_FENCE_SCHEMA = "triad.launch_fence.v1"
LAUNCH_FENCE_VERSION = 1
# cancelled 栅栏最短保留时长：> 启动+连接+#401 复核窗口上界，留余量
LAUNCH_FENCE_CANCELLED_RETENTION_SEC = 300.0
# active 栅栏软过期（兜底；正常由代次取消驱动，verify 不依赖墙上时间）
LAUNCH_FENCE_ACTIVE_EXPIRES_SEC = 3600.0


def _launch_fence_path(role: str) -> Path:
    return RUNTIME_DIR / f"{role}.launch_fence.json"


def _cancel_fence_path(role: str) -> Path:
    """不可变取消 sidecar 文件（R2-FIX #519）：active 栅栏只创建、不覆盖；取消
    状态写入本文件，绝不回写 active 文件。active 与 sidecar 双文件构成完整代次状态。
    """
    return RUNTIME_DIR / f"{role}.launch_fence.cancel.json"


def _read_cancel_sidecar(role: str) -> "tuple[str, Optional[Dict[str, Any]]]":
    """读取不可变取消 sidecar，返回显式三态（R2-FIX.1 #1，Codex 裁决）：
      ("missing", None)  文件不存在（干净、无取消证据）；
      ("valid",   rec)   文件存在且 schema/version/role/state 全部合法；
      ("invalid", None)  文件存在但解析失败 / 非 dict / schema 或 version 不符 /
                         role 不符 / state 非 cancelled。

    调用方对 "invalid" 必须 fail-closed：绝不当作"未取消"放行 active，也绝不覆盖
    损坏件。旧版把 missing 与 invalid 一并折叠成 None，导致 verify 遇损坏 sidecar
    误判为 active 放行——本次显式三态即为堵这个逃逸。
    """
    p = _cancel_fence_path(role)
    if not p.exists():
        return ("missing", None)
    try:
        rec = json.loads(p.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return ("invalid", None)
    if not isinstance(rec, dict):
        return ("invalid", None)
    if rec.get("schema") != LAUNCH_FENCE_SCHEMA or rec.get("version") != LAUNCH_FENCE_VERSION:
        return ("invalid", None)
    if rec.get("role") != role:
        return ("invalid", None)
    if rec.get("state") != "cancelled":
        return ("invalid", None)
    return ("valid", rec)


def _sidecar_matches(sidecar: Dict[str, Any], active_rec: Dict[str, Any]) -> bool:
    """sidecar 必须与 active 栅栏同代次（role/run_id/launch_nonce 精确一致），否则视为
    陈旧/错代次，不采信（fail-closed：绝不拿旧代次取消当新代次凭证）。"""
    return (
        sidecar.get("role") == active_rec.get("role")
        and sidecar.get("run_id") == active_rec.get("run_id")
        and sidecar.get("launch_nonce") == active_rec.get("launch_nonce")
    )


def _fence_role_lock_fd(role: str) -> int:
    """每角色跨进程互斥锁文件 fd（RUNTIME_DIR 下 <role>.launch_fence.lock）。"""
    lock_path = RUNTIME_DIR / f"{role}.launch_fence.lock"
    RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
    return os.open(str(lock_path), os.O_CREAT | os.O_RDWR, 0o644)


@contextmanager
def _fence_role_lock(role: str):
    """SR-2 P0 #402.7 Gap2：每角色跨进程短锁，保证 create/cancel/retire 的
    读-校验-写回为原子（真 CAS），杜绝代次取消与新建栅栏之间的竞态丢失。

    Windows 用 msvcrt.locking（非阻塞轮询、有界重试 ≤30s），POSIX 用 fcntl.flock（阻塞）。
    获取失败（超时/系统错误）按 fail-closed 抛出，绝不静默幽灵锁。
    #402.8（Codex 裁决）：最内层角色白名单保护——即使调用方漏了前置校验，
    也绝不创建锁文件/栅栏/归档目录；非法角色 fail-closed 抛 ValueError。
    """
    if role not in CONTROL_ROLE_WHITELIST:
        raise ValueError(f"invalid_fence_role: {role}")
    fd = _fence_role_lock_fd(role)
    _locked = False
    try:
        try:
            import fcntl  # type: ignore  # POSIX
        except ImportError:
            import msvcrt  # type: ignore  # Windows
            _deadline = time.time() + 30.0
            while True:
                try:
                    msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                    break
                except OSError:
                    if time.time() >= _deadline:
                        raise
                    time.sleep(0.02)
        else:
            fcntl.flock(fd, fcntl.LOCK_EX)
        _locked = True
        yield
    finally:
        if _locked:
            try:
                try:
                    import fcntl  # type: ignore
                except ImportError:
                    import msvcrt  # type: ignore
                    try:
                        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
                    except OSError:
                        pass
                else:
                    fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)
        else:
            os.close(fd)



_FENCE_PUBLISH_LOCKS = tuple(threading.Lock() for _ in range(64))


def _write_fence_atomic(path: Path, record: Dict[str, Any]) -> None:
    # Serialize in-process writers to the same normalized destination. The
    # existing role lock remains responsible for cross-process generations.
    # Fixed stripes bound memory; unrelated collisions only serialize writes.
    identity = os.path.normcase(os.path.abspath(path))
    with _FENCE_PUBLISH_LOCKS[hash(identity) % len(_FENCE_PUBLISH_LOCKS)]:
        _write_fence_atomic_locked(path, record)


def _write_fence_atomic_locked(path: Path, record: Dict[str, Any]) -> None:
    """同目录临时文件 + flush/fsync + 原子 replace；截断/半写不得落盘。

    #402.6-remediation 竞态修复（race item ⑪）：临时名带 8 字节随机后缀，保证并发写同一
    栅栏路径时各自使用唯一临时文件，杜绝 Windows 上「固定 .tmp 被另一线程 replace 后
    os.open 报 PermissionError」的并发冲突；原子 replace 仍保证最终文件完整不损坏。
    """
    RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
    tmp = path.parent / f"{path.name}.{os.urandom(8).hex()}.tmp"
    data = json.dumps(record, ensure_ascii=False, sort_keys=True).encode("utf-8")
    tmp.write_bytes(data)
    # fsync 数据文件（写句柄，Windows 要求可写句柄才能 FlushFileBuffers），确保原子
    # replace 前已落盘（防崩溃留半截栅栏）
    fd = os.open(tmp, os.O_WRONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    # fsync 目录项（Windows 未必支持目录 fsync，失败忽略）
    try:
        dirfd = os.open(str(RUNTIME_DIR), os.O_RDONLY)
        try:
            os.fsync(dirfd)
        finally:
            os.close(dirfd)
    except OSError:
        pass
    # 原子 replace：Windows 下并发写同一目标路径时，目标文件可能在极短窗口内被锁定，
    # 导致 MoveFileEx 报 ERROR_SHARING_VIOLATION / ACCESS_DENIED（WinError 5）。做有界重试
    # 吸收瞬态冲突，最终仍保证"要么旧版、要么新版、绝不半截"的原子语义。
    _last_err: OSError | None = None
    for _attempt in range(5):
        try:
            tmp.replace(path)
            return
        except OSError as _err:  # noqa: BLE001
            _last_err = _err
            time.sleep(0.001)
    if _last_err is not None:
        raise _last_err


def _write_active_fence_record(role: str, run_id: str, launch_nonce: str) -> None:
    """写不可变 active 栅栏记录（只创建、不覆盖；R2-FIX #519）。"""
    now_ts = time.time()
    now = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(now_ts))
    record = {
        "schema": LAUNCH_FENCE_SCHEMA,
        "version": LAUNCH_FENCE_VERSION,
        "role": role,
        "run_id": run_id,
        "launch_nonce": launch_nonce,
        "state": "active",
        "created_at": now,
        "created_ts": round(now_ts, 3),
        "cancelled_at": None,
        "cancelled_ts": None,
        "expires_at": time.strftime(
            "%Y-%m-%dT%H:%M:%S", time.gmtime(now_ts + LAUNCH_FENCE_ACTIVE_EXPIRES_SEC)
        ),
    }
    _write_fence_atomic(_launch_fence_path(role), record)


def _archive_fence_files(role: str, old_run_id: Optional[str]) -> str:
    """把旧代次 active + 取消 sidecar 受控归档到 .retired_control/<old_run>/。

    R2-FIX.1 #1（Codex 裁决）：双文件归档必须可恢复——两文件任一移动失败都必须
    能回滚已完成的移动，禁止留"半归档"中间态导致证据丢失或建新代次时撞车。
    返回稳定结果码（调用方据此 fail-closed）：
      "archived"            两文件全部成功移动；
      "archive_partial"     仅完成部分移动（第一步成功、第二步失败）且回滚成功；
      "rollback_failed"     部分移动后回滚也失败（磁盘/权限异常）——调用方 MUST
                            禁止建新代次、禁止删证据，交由人工介入；
      "archive_failed"      第一步移动即失败（目录不可建/active 不可 rename）。
    绝不删除审计证据（R2-FIX #519）：只原子移动，不 unlink。
    """
    run_dirname = old_run_id if is_identity_token(old_run_id) else _RETIRE_NO_RUN_DIR
    run_dir = Path(RUNTIME_DIR) / RETIRED_CONTROL_DIRNAME / run_dirname
    try:
        run_dir.mkdir(parents=True, exist_ok=True)
    except OSError:
        return "archive_failed"
    stamp = time.strftime("%Y%m%dT%H%M%S", time.gmtime())
    suffix = os.urandom(4).hex()
    active_src = _launch_fence_path(role)
    active_target: Optional[Path] = None
    if active_src.exists():
        active_target = run_dir / f"{role}.launch_fence.{stamp}-{suffix}.active.retired"
        try:
            os.rename(active_src, active_target)  # 原子移动；RENAME_ALLOWED
        except OSError:
            return "archive_failed"
    sidecar_src = _cancel_fence_path(role)
    if sidecar_src.exists():
        sidecar_target = run_dir / f"{role}.launch_fence.cancel.{stamp}-{suffix}.cancelled"
        try:
            os.rename(sidecar_src, sidecar_target)
        except OSError:
            # 第二步失败 -> 回滚第一步（把已移动的 active 移回原处）
            if active_target is not None and active_target.exists():
                try:
                    os.rename(active_target, active_src)
                    return "archive_partial"
                except OSError:
                    return "rollback_failed"
            return "archive_partial"
    return "archived"


def _has_partial_retire_evidence(role: str) -> bool:
    """探测 .retired_control 下是否残留本角色的半归档件（R2-FIX.1 #1）。

    场景：归档第二步（sidecar 移动）失败并回滚第一步（archive_partial），或回滚也
    失败（rollback_failed）——此时 .retired_control/<run>/ 下可能留 active.retired
    孤儿（无配对 cancel sidecar）。create 时若发现此类证据，禁止直接建新 active，
    须先 resolve。仅探测、不改动任何文件。

    #537 回归修复（2026-08-25，Codex #537 诊断分支）：
    - 只认 `{role}.launch_fence.<stamp>.active.retired` 且同 stamp **无配对**
      `.cancel.<stamp>.cancelled`（孤儿 active 归档 = 归档未干净收口）；
    - 正常收口的 `.cancelled`（cancel sidecar 归档）不构成半归档证据——
      R2-FIX.1 #1 的 `{prefix}.*` 宽匹配会把历史正常归档永久误判为半归档，
      导致生产 runtime 该角色 create 永远 blocked（真实 R2 无法启动）。
    """
    base = Path(RUNTIME_DIR) / RETIRED_CONTROL_DIRNAME
    if not base.exists():
        return False
    prefix = f"{role}.launch_fence"
    try:
        retired = [e for e in base.rglob(f"{prefix}.*.active.retired") if e.is_file()]
        for e in retired:
            # name 形如 "{prefix}.<stamp>-<suffix>.active.retired"
            stamp = e.name[len(prefix) + 1:-len(".active.retired")]
            pairs = list(base.rglob(f"{prefix}.cancel.{stamp}.cancelled"))
            if not pairs:
                return True  # 孤儿 active 归档（半归档证据）
        return False
    except OSError:
        return False


def create_active_launch_fence(role: str, run_id: str, launch_nonce: str) -> str:
    """建 active 代次栅栏（两文件模型，R2-FIX #519；R2-FIX.1 #1 严整）。

    返回稳定状态码：created / blocked / invalid_role / invalid_identity /
    archive_partial / rollback_failed / archive_failed。

    语义（R2-FIX.1 #1，Codex 裁决）：
    - active 文件只创建、不覆盖（不可变）；首次发布不覆盖语义——若目标 active 已存在
      且为本代次，幂等返回 created（不重写、不触碰既有文件）；
    - active 文件已存在但无法识别（损坏/非法 schema/role 不符）-> 不得覆盖，fail-closed
      返回 blocked，绝不"修复"式重写；
    - active 缺失但有 sidecar 或半归档证据（.retired_control 下残留本角色文件）-> 禁止
      直接建新 active，fail-closed 返回 blocked（旧代次取消/归档流程未干净收口，须先
      显式 retire 或人工清理，避免孤儿代次冒充就绪）；
    - 不同代次且存在有效取消 sidecar -> 角色锁内把旧 active+sidecar 一起归档（可恢复，
      见 _archive_fence_files）；归档结果 archived 才建新 active -> created；
      归档 partial/rollback_failed/archive_failed -> 禁止建新代次，返回对应码（fail-closed）；
    - 不同代次且无有效取消 sidecar（旧代次仍在运行/未授权作废）-> 禁止新一代接管，
      返回 blocked（绝不覆盖活动栅栏）。
    """
    if role not in CONTROL_ROLE_WHITELIST:
        return "invalid_role"
    if not (is_identity_token(run_id) and is_identity_token(launch_nonce)):
        return "invalid_identity"
    with _fence_role_lock(role):
        # R2-FIX.1 #1：半归档证据（.retired_control 残留本角色件）无论 active 是否存在
        # 都先拦——旧代次取消/归档流程未干净收口，禁止直接建新 active，须先显式 resolve。
        if _has_partial_retire_evidence(role):
            return "blocked"
        # #402.7 Gap2：建栅栏纳入每角色互斥，避免与并发 cancel 交错丢失更新
        path = _launch_fence_path(role)
        if path.exists():
            try:
                rec = json.loads(path.read_text(encoding="utf-8"))
            except Exception:  # noqa: BLE001
                rec = None
            if (not isinstance(rec, dict)
                    or rec.get("schema") != LAUNCH_FENCE_SCHEMA
                    or rec.get("version") != LAUNCH_FENCE_VERSION
                    or rec.get("role") != role):
                # active 文件无法识别 -> 不得覆盖，fail-closed 禁止接管
                return "blocked"
            if rec.get("run_id") == run_id and rec.get("launch_nonce") == launch_nonce:
                # 同代次：幂等，active 已存在且不可变，不重写
                return "created"
            # 不同代次：必须旧代次已被有效取消方可接管
            sidecar_state, sidecar = _read_cancel_sidecar(role)
            if sidecar_state != "valid" or not _sidecar_matches(sidecar, rec):
                # 旧代次未授权作废（missing/invalid/不匹配）-> 禁止接管（fail-closed）
                return "blocked"
            # 旧代次有效取消 -> 归档旧 active+sidecar（可恢复），再建新 active
            arc = _archive_fence_files(role, rec.get("run_id"))
            if arc != "archived":
                # 归档未干净完成：禁止建新代次，保留证据，交由人工介入
                return arc  # archive_partial / rollback_failed / archive_failed
        else:
            # active 缺失：检查是否残留取消 sidecar（旧代次取消但未归档）或半归档证据
            sidecar_state, _ = _read_cancel_sidecar(role)
            if sidecar_state != "missing":
                # 有取消 sidecar 但无 active -> 取消流程未收口（须先 retire），禁止建新
                return "blocked"
            if _has_partial_retire_evidence(role):
                # .retired_control 残留本角色半归档件 -> 禁止直接建新 active
                return "blocked"
        _write_active_fence_record(role, run_id, launch_nonce)
    return "created"


def verify_launch_fence(role: str, run_id: str, launch_nonce: str) -> Dict[str, Any]:
    """校验代次栅栏。返回 {verdict, state, reason}。

    verdict ∈ active / cancelled / missing / corrupt / mismatch / invalid。
    active 才放行；其余一律 fail-closed（非 active）。R2-FIX #519 两文件模型：
    active 文件 state 恒为 active（不可变），取消态以独立 sidecar 为准。
    """
    if not (is_identity_token(run_id) and is_identity_token(launch_nonce)):
        return {"verdict": "invalid", "state": None, "reason": "bad_identity"}
    path = _launch_fence_path(role)
    if not path.exists():
        return {"verdict": "missing", "state": None, "reason": "no_fence_file"}
    try:
        rec = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {"verdict": "corrupt", "state": None, "reason": "json_parse_error"}
    if not isinstance(rec, dict):
        return {"verdict": "corrupt", "state": None, "reason": "not_object"}
    if rec.get("schema") != LAUNCH_FENCE_SCHEMA or rec.get("version") != LAUNCH_FENCE_VERSION:
        return {"verdict": "corrupt", "state": None, "reason": "schema_mismatch"}
    if rec.get("role") != role:
        return {"verdict": "corrupt", "state": None, "reason": "role_mismatch"}
    # 两文件模型：active state 恒为 active；兼容历史单文件遗留（state 直接标 cancelled）
    state = rec.get("state")
    if state is not None and state != "active":
        return {"verdict": "corrupt", "state": None, "reason": "bad_state"}
    if rec.get("run_id") != run_id or rec.get("launch_nonce") != launch_nonce:
        return {"verdict": "mismatch", "state": "active", "reason": "generation_mismatch"}
    # active 代次匹配 -> 检查不可变取消 sidecar 是否存在且有效（R2-FIX.1 #1：三态）
    sidecar_state, sidecar = _read_cancel_sidecar(role)
    if sidecar_state == "valid" and _sidecar_matches(sidecar, rec):
        return {"verdict": "cancelled", "state": "cancelled", "reason": "fence_cancelled"}
    if sidecar_state == "invalid":
        # 损坏 sidecar 不得误判为"未取消"放行 active；fail-closed 报 corrupt
        return {"verdict": "corrupt", "state": None, "reason": "invalid_cancel_sidecar"}
    return {"verdict": "active", "state": "active", "reason": "ok"}


def _cancel_fence_locked(
    role: str,
    path: Path,
    expected_run_id: Optional[str],
    expected_launch_nonce: Optional[str],
    reason: str = "",
) -> str:
    """锁内读-校验-写回（#402.8 提取；调用方必须已持有 _fence_role_lock(role)）。

    R2-FIX #519 两文件模型：active 文件只创建、不覆盖；取消状态写入独立的不可变
    sidecar（新文件，绝不回写 active）。返回同 cancel_launch_fence 的稳定码：
    cancelled / already_cancelled / missing / corrupt / generation_mismatch。
    """
    if not path.exists():
        return "missing"
    try:
        rec = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        # 损坏：绝不覆盖原件（防止不同代次借"修复"之名改写栅栏）
        return "corrupt"
    if not isinstance(rec, dict):
        return "corrupt"
    if rec.get("schema") != LAUNCH_FENCE_SCHEMA or rec.get("version") != LAUNCH_FENCE_VERSION:
        return "corrupt"
    if rec.get("role") != role:
        return "corrupt"
    # 代次校验：必须精确匹配本调用方声明的 run_id / launch_nonce，否则拒绝取消
    if rec.get("run_id") != expected_run_id or rec.get("launch_nonce") != expected_launch_nonce:
        return "generation_mismatch"
    # 两文件模型：取消状态写入独立 sidecar，绝不回写 active 文件。
    # 先检查既有 sidecar 是否已是本代次的有效取消（重复取消 -> already_cancelled）。
    # R2-FIX.1 #1：三态——invalid sidecar 不得覆盖（防不同代次借"修复"改写），
    # 仅 valid 且同代次才认 already_cancelled；missing 才允许新建。
    existing_state, existing = _read_cancel_sidecar(role)
    if existing_state == "valid" and _sidecar_matches(existing, rec):
        return "already_cancelled"
    if existing_state == "invalid":
        # 损坏 sidecar 绝不覆盖原件——fail-closed 阻断取消写回，交由人工 resolve
        return "corrupt"
    now_ts = time.time()
    sidecar = {
        "schema": LAUNCH_FENCE_SCHEMA,
        "version": LAUNCH_FENCE_VERSION,
        "role": role,
        "run_id": expected_run_id,
        "launch_nonce": expected_launch_nonce,
        "state": "cancelled",
        "created_at": rec.get("created_at"),
        "created_ts": rec.get("created_ts"),
        "cancelled_at": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(now_ts)),
        "cancelled_ts": round(now_ts, 3),
        "cancelled_reason": reason[:128] if reason else "",
        "expires_at": time.strftime(
            "%Y-%m-%dT%H:%M:%S",
            time.gmtime(now_ts + LAUNCH_FENCE_CANCELLED_RETENTION_SEC),
        ),
    }
    # 写新文件（sidecar），不触碰 active 文件；强制 unlink/覆盖式 replace 失败将由
    # 调用方（_stop_role）以 stop_incomplete fail-closed 处理。
    _write_fence_atomic(_cancel_fence_path(role), sidecar)
    # #547 Step3：写后复读校验（仍在角色锁内）——落盘件必须可解析、schema/version/
    # role/state 全合法，且与本代次 active 记录精确同代次。sidecar 是停机闭环的唯一
    # 权威凭证，"写了但没落成有效件"等于没取消，绝不返回 cancelled 让调用方误判已停。
    readback_state, readback = _read_cancel_sidecar(role)
    if readback_state != "valid" or not _sidecar_matches(readback, rec):
        return "readback_failed"
    return "cancelled"


def cancel_launch_fence(
    role: str,
    expected_run_id: Optional[str],
    expected_launch_nonce: Optional[str],
    reason: str = "",
) -> str:
    """原子标 cancelled（保留文件 ≥300s），但先校验代次身份（P0-1, #402.6-remediation）。

    返回稳定状态码：
      cancelled / already_cancelled / missing / corrupt / generation_mismatch /
      invalid_role / invalid_identity / readback_failed。

    fail-closed（绝不覆盖原件、绝不写 stopped 之外的状态）：
    - role 不在白名单 → invalid_role；
    - 声明的 expected_* 非合法身份令牌 → invalid_identity（无法校验代次）；
    - 文件缺失 → missing；
    - 损坏（解析失败 / schema 不符 / 不属于本 role）→ corrupt，绝不覆盖原件；
    - 代次不匹配（run_id 或 launch_nonce 与文件不一致）→ generation_mismatch，不改文件；
    - 仅当 run_id+launch_nonce 完全匹配且 state==active 才 atomic 转 cancelled；
      state 已 cancelled → 同代次先验后返回 already_cancelled；
      state 非 active 非 cancelled（异常态）→ corrupt 不改件。
    - #547 Step3：sidecar 写入后锁内复读校验，落盘件不合法/非同代次 → readback_failed
      （持久化未成功，调用方必须按 fail-closed 处理，不得记 role_stopped）。
    """
    if role not in CONTROL_ROLE_WHITELIST:
        return "invalid_role"
    if not (is_identity_token(expected_run_id) and is_identity_token(expected_launch_nonce)):
        return "invalid_identity"
    with _fence_role_lock(role):
        # #402.7 Gap2 真 CAS / #402.8 提取：锁内重新读取并校验，再写回——杜绝代次
        # 取消与新建栅栏之间的读-校验→写回竞态。跨进程测试复用 _cancel_fence_locked
        # 以复现"持锁写回阶段受控暂停"（A 持锁期间 B 的 create 不得完成）。
        return _cancel_fence_locked(
            role, _launch_fence_path(role),
            expected_run_id, expected_launch_nonce, reason,
        )


def retire_expired_launch_fence(role: str) -> str:
    """仅归档已取消且超保留时长的栅栏（受控归档，不立即删除）。

    返回 retired / not_expired / missing / invalid_role / failed。
    R2-FIX #519 两文件模型：取消态在 sidecar，active 文件 state 恒为 active，故改由
    sidecar 判定是否已取消及取消时间戳。
    #402.8（Codex 裁决）：非法角色返回 invalid_role，且不创建锁文件/栅栏/归档目录
    （与 create/cancel 的防护一致；_fence_role_lock 最内层亦兜底白名单保护）。
    """
    if role not in CONTROL_ROLE_WHITELIST:
        return "invalid_role"
    with _fence_role_lock(role):
        # #402.7 Gap2：归档同样纳入每角色互斥——锁内重读并判定，避免读取"已过期"
        # 与 rename 之间被并发新建栅栏插入，导致陈旧状态被误归档。
        path = _launch_fence_path(role)
        if not path.exists():
            return "missing"
        try:
            rec = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return "failed"
        if not isinstance(rec, dict) or rec.get("role") != role:
            return "failed"
        # 两文件模型：取消态在 sidecar，active 文件 state 恒为 active。
        sidecar_state, sidecar = _read_cancel_sidecar(role)
        if sidecar_state != "valid" or not _sidecar_matches(sidecar, rec):
            return "not_expired"  # 无有效取消（含 missing/invalid）-> active 栅栏不得归档
        ca_ts = sidecar.get("cancelled_ts")
        try:
            age = time.time() - float(ca_ts)
        except (TypeError, ValueError):
            return "not_expired"
        if age < LAUNCH_FENCE_CANCELLED_RETENTION_SEC:
            return "not_expired"
        # 受控归档 active + sidecar 到 .retired_control/<run_id 或 norun>/
        # R2-FIX.1 #1：复用可恢复双文件归档（archive_partial/rollback_failed 必须
        # fail-closed 拒绝本次 retire，避免留半归档证据）
        arc = _archive_fence_files(role, rec.get("run_id"))
        if arc == "archived":
            return "retired"
        return "failed"


# 心跳文件字段白名单：白名单之外一律丢弃（防止 prompt/凭据从这里漏出去）
HEARTBEAT_ALLOWED_FIELDS = frozenset(
    {"state", "last_status", "agent", "run_id", "launch_nonce", "error_code"}
)


def write_heartbeat(role: str, *, runtime_pid: Optional[int] = None,
                    **fields: Any) -> None:
    """写脱敏心跳文件。只允许角色/PID/时间/状态类字段，其余一律丢弃。

    runtime_pid 默认取本进程 os.getpid()——进程自己写心跳时，这是该角色唯一可信身份；
    pid 作为兼容别名保留。

    Gate4 B-3：bridge / hub 没有停机钩子，被 TerminateProcess 强杀后来不及自己写
    stopped，心跳会永远卡在 running。supervisor 需要在**可信终止完成后**代写这条
    stopped，此时若仍写 os.getpid() 就会把 supervisor 自己的 PID 冒充成被终止角色的
    身份，属于伪造。故允许显式传入被终止角色的真实 runtime PID。

    该参数是具名参数、不走 **fields，因此不受 HEARTBEAT_ALLOWED_FIELDS 白名单影响，
    也不会被记进 dropped_fields。传入非正整数一律抛 ValueError：宁可写失败，
    也绝不静默回退成 supervisor 自身 PID。
    """
    if runtime_pid is None:
        effective_pid = os.getpid()
    elif isinstance(runtime_pid, bool) or not isinstance(runtime_pid, int) or runtime_pid <= 0:
        raise ValueError("runtime_pid must be a positive int")
    else:
        effective_pid = runtime_pid
    RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
    identity = _resolve_identity(fields)
    record = {
        "role": role,
        "pid": effective_pid,
        "runtime_pid": effective_pid,
        "updated_at": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()),
        "updated_ts": round(time.time(), 3),
    }
    record.update(identity)
    dropped = []
    for k, v in fields.items():
        if k not in HEARTBEAT_ALLOWED_FIELDS:
            dropped.append(k)
            continue
        if isinstance(v, (str, int, float, bool)) or v is None:
            record[k] = v if not isinstance(v, str) else v[:64]
        else:
            dropped.append(k)
    if dropped:
        record["dropped_fields"] = sorted(set(dropped))
    tmp = _heartbeat_path(role).with_suffix(".tmp")
    try:
        tmp.write_text(json.dumps(record, ensure_ascii=False), encoding="utf-8")
        tmp.replace(_heartbeat_path(role))
    except OSError:
        pass


def read_heartbeat(role: str) -> Optional[Dict[str, Any]]:
    path = _heartbeat_path(role)
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


class _NeverSet:
    """stop_event 缺省实现：永不置位（仅用于测试便利，正式入口必须显式传入）。"""

    def is_set(self) -> bool:  # pragma: no cover - 简单委托
        return False

    def wait(self, timeout: Optional[float] = None) -> bool:  # pragma: no cover
        if timeout:
            threading.Event().wait(timeout)
        return False


def _normalize_stop_event(stop_event: Any) -> Any:
    return _NeverSet() if stop_event is None else stop_event


def _wait(stop_event: Any, seconds: float) -> None:
    """可被 stop_event 立刻打断的等待，避免停机时白等。"""
    if seconds <= 0:
        return
    try:
        stop_event.wait(seconds)
    except Exception:  # pragma: no cover - 兜底：非标准 event 退化为普通 sleep
        threading.Event().wait(seconds)


def _tick(callback: Optional[Callable[[Dict[str, Any]], None]], payload: Dict[str, Any]) -> None:
    """心跳回调：失败绝不影响主循环。"""
    if callback is None:
        return
    try:
        callback(payload)
    except Exception:  # pragma: no cover - 心跳失败不得中断运行时
        pass


# ---------------- Agent 常驻循环 ----------------
def run_agent_loop(
    agent: str,
    worker_id: str,
    stop_event: Any,
    idle_wait_sec: float = 0.25,
    *,
    adapter: Optional[Any] = None,
    heartbeat: Optional[Callable[[Dict[str, Any]], None]] = None,
    max_consecutive_errors: int = 20,
) -> None:
    """常驻循环执行某个 Agent 的调用队列。

    - 无任务（idle）等待 idle_wait_sec，不忙等。
    - 单次调用超时或 result_unknown 不自动重试（由 call_worker 落 result_unknown 状态，
      该状态不会被 claim_next_delivery 重新领取）。
    - blocked / failed 只记录稳定错误码，不落原始错误文本。
    - stop_event 置位后，当前调用完成即退出。
    """
    if agent not in AGENTS:
        raise ValueError(f"unknown agent: {agent}")
    stop_event = _normalize_stop_event(stop_event)

    # 延迟导入，避免 services 包循环依赖
    from services.call_worker import run_call_once

    log.info("agent_loop_started", agent=agent, status="running")
    consecutive_errors = 0
    lock_degraded_since = None  # Gate5-B2-WB：锁故障降级起点（time.time）
    try:
        while not stop_event.is_set():
            try:
                result = run_call_once(agent=agent, worker_id=worker_id, adapter=adapter)
                consecutive_errors = 0
                if lock_degraded_since is not None:
                    log.info(
                        "agent_loop_recovered",
                        agent=agent,
                        status="running",
                        degraded_sec=int(time.time() - lock_degraded_since),
                    )
                    lock_degraded_since = None
            except Exception as exc:
                is_lock = "locked" in str(exc).lower()
                if is_lock:
                    # 锁故障：降级不退出（Gate5-B2-WB），指数退避，上限 5s
                    if lock_degraded_since is None:
                        lock_degraded_since = time.time()
                        log.warn(
                            "agent_loop_degraded",
                            agent=agent,
                            status="degraded",
                            error_code="db_locked",
                        )
                    else:
                        dur = int(time.time() - lock_degraded_since)
                        if dur >= 60 and dur % 30 < 3:
                            log.error(
                                "db_lock_persistent",
                                agent=agent,
                                status="degraded",
                                error_code="db_lock_persistent",
                                duration_sec=dur,
                            )
                    _wait(stop_event, min(idle_wait_sec * (consecutive_errors + 1), _MAX_ERROR_BACKOFF_SEC))
                    continue
                consecutive_errors += 1
                log.exception(
                    "agent_loop_iteration_error",
                    exc,
                    agent=agent,
                    status="error",
                    count=consecutive_errors,
                )
                if consecutive_errors >= max_consecutive_errors:
                    log.error(
                        "agent_loop_aborted",
                        agent=agent,
                        status="aborted",
                        error_code="too_many_consecutive_errors",
                        count=consecutive_errors,
                    )
                    return
                _wait(stop_event, min(idle_wait_sec * consecutive_errors, _MAX_ERROR_BACKOFF_SEC))
                continue

            status = str(result.get("status", "unknown"))
            _tick(heartbeat, {"role": f"agent-{agent}", "last_status": status})

            if config.FEISHU_TASKS_ENABLED:
                # Same worker owns the session; this controller step only creates
                # a bounded next delivery after verified evidence and Feishu send.
                from services.auto_handoff import advance_for_agent
                advance_for_agent(agent)

            if status != "idle":
                # idle 不写日志（避免日志淹没）；其余状态只落白名单字段
                log.info(
                    "agent_loop_iteration",
                    agent=agent,
                    status=status,
                    reason=str(result.get("reason") or ""),
                    call_id=str(result.get("call_id") or ""),
                )
            if status in _MANUAL_REVIEW_STATUSES:
                log.warn(
                    "manual_review_required",
                    agent=agent,
                    status=status,
                    error_code=str(result.get("reason") or "result_unknown"),
                )

            if status in _NO_PROGRESS_STATUSES:
                _wait(stop_event, idle_wait_sec)
    finally:
        log.info("agent_loop_stopped", agent=agent, status="stopped")


# ---------------- Outbox 常驻循环 ----------------
def run_outbox_loop(
    worker_id: str,
    stop_event: Any,
    idle_wait_sec: float = 0.25,
    *,
    heartbeat: Optional[Callable[[Dict[str, Any]], None]] = None,
    max_consecutive_errors: int = 20,
) -> None:
    """常驻循环把 outbox 里 pending 的回复真正发到飞书群。

    - 严格沿用 outbox 幂等键（outbox_id），本循环不生成任何新幂等键。
    - delivery_unknown 只记录不重发。
    - retry 由 feishu_outbox.schedule_retry 写 next_attempt_at 控制退避，本循环不加速。
    """
    stop_event = _normalize_stop_event(stop_event)

    from services.feishu_outbox import run_outbox_once

    log.info("outbox_loop_started", status="running")
    consecutive_errors = 0
    lock_degraded_since = None  # Gate5-B2-WB：锁故障降级起点
    try:
        while not stop_event.is_set():
            try:
                result = run_outbox_once(worker_id)
                consecutive_errors = 0
                if lock_degraded_since is not None:
                    log.info(
                        "outbox_loop_recovered",
                        status="running",
                        degraded_sec=int(time.time() - lock_degraded_since),
                    )
                    lock_degraded_since = None
            except Exception as exc:
                is_lock = "locked" in str(exc).lower()
                if is_lock:
                    if lock_degraded_since is None:
                        lock_degraded_since = time.time()
                        log.warn(
                            "outbox_loop_degraded",
                            status="degraded",
                            error_code="db_locked",
                        )
                    else:
                        dur = int(time.time() - lock_degraded_since)
                        if dur >= 60 and dur % 30 < 3:
                            log.error(
                                "db_lock_persistent",
                                status="degraded",
                                error_code="db_lock_persistent",
                                duration_sec=dur,
                            )
                    _wait(stop_event, min(idle_wait_sec * (consecutive_errors + 1), _MAX_ERROR_BACKOFF_SEC))
                    continue
                consecutive_errors += 1
                log.exception(
                    "outbox_loop_iteration_error",
                    exc,
                    status="error",
                    count=consecutive_errors,
                )
                if consecutive_errors >= max_consecutive_errors:
                    log.error(
                        "outbox_loop_aborted",
                        status="aborted",
                        error_code="too_many_consecutive_errors",
                        count=consecutive_errors,
                    )
                    return
                _wait(stop_event, min(idle_wait_sec * consecutive_errors, _MAX_ERROR_BACKOFF_SEC))
                continue

            status = str(result.get("status", "unknown"))
            _tick(heartbeat, {"role": "outbox", "last_status": status})

            if status != "idle":
                log.info(
                    "outbox_loop_iteration",
                    status=status,
                    outbox_id=str(result.get("outbox_id") or ""),
                )
            if status in _MANUAL_REVIEW_STATUSES:
                log.warn(
                    "manual_review_required",
                    status=status,
                    outbox_id=str(result.get("outbox_id") or ""),
                    error_code="delivery_unknown",
                )

            # idle / retry 都必须退避：retry 的实际可发时间由 next_attempt_at 决定
            if status in ("idle", "retry"):
                _wait(stop_event, idle_wait_sec)
    finally:
        log.info("outbox_loop_stopped", status="stopped")


# ---------------- 启动时崩溃恢复 ----------------
def recover_runtime_state() -> Dict[str, int]:
    """进程启动时执行一次崩溃恢复。

    只恢复协议允许恢复的状态：
    - claimed 但未 running 且 claim 过期 -> retry（可安全重领）
    - running 且 lease 过期 -> result_unknown（人工复核，不自动重试）
    - outbox 残留 sending -> delivery_unknown（人工复核，不自动重发）

    返回脱敏计数字典，绝不返回任何业务内容。
    """
    from services.call_worker import recover_stuck_calls
    from services.feishu_outbox import recover_stuck_sending

    summary: Dict[str, int] = {
        "calls_reset_to_retry": 0,
        "calls_result_unknown": 0,
        "calls_unchanged": 0,
        "outbox_delivery_unknown": 0,
    }

    calls = recover_stuck_calls()
    if isinstance(calls, dict):
        summary["calls_reset_to_retry"] = int(calls.get("retry", 0) or 0)
        summary["calls_result_unknown"] = int(calls.get("result_unknown", 0) or 0)
        summary["calls_unchanged"] = int(calls.get("unchanged", 0) or 0)
    summary["outbox_delivery_unknown"] = int(recover_stuck_sending() or 0)

    recovered = (
        summary["calls_reset_to_retry"]
        + summary["calls_result_unknown"]
        + summary["outbox_delivery_unknown"]
    )
    log.info(
        "runtime_recovery_done",
        status="recovered",
        count=recovered,
    )
    if summary["calls_result_unknown"] or summary["outbox_delivery_unknown"]:
        log.warn(
            "manual_review_required",
            status="unknown_after_recovery",
            error_code="unknown_requires_human_review",
            count=summary["calls_result_unknown"] + summary["outbox_delivery_unknown"],
        )
    return summary
