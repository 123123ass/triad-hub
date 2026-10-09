"""hub_bridge.py —— 飞书入口桥（纯入口，唯一职责是把标准化事件签名后 POST 给本机 Hub）。

严格限制：
1. 启动指定 Bot 飞书长连接（仅 dry_run=False，Step 11 灰度前不得使用）。
2. 接收标准化飞书事件。
3. 对请求体做稳定 JSON 编码。
4. 计算内部 HMAC。
5. POST 给本机 Hub。
6. 记录脱敏状态。
7. 不调用任何 Agent。
8. 不直接发送飞书消息。
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Optional

import security
from config import config
from logging_config import get_logger
from redaction import error_code as redacted_error_code
from redaction import install_stream_redactor

# 【P0 安全】进程存活探测统一复用 services.runtime_worker.pid_alive，禁止本模块自建第二套实现。
# 原因（准确机理，CPython Modules/posixmodule.c os_kill_impl 已核对 3.13 分支源码 + 本机
# 3.13.14/3.14.3 实测）：Windows 上 os.kill(pid, 0) 的 sig==CTRL_C_EVENT(0) 走
# GenerateConsoleCtrlEvent(sig, pid)——这是向**进程组**广播控制台控制事件，不是"探测进程是否存在"；
# 其成功/失败与目标进程是否存活并不对应，可能误判存活，也可能真把同控制台会话的进程打断；该分支仅在
# 编译期定义 HAVE_WINDOWS_CONSOLE_IO 时存在，未定义时 sig=0 才落到 OpenProcess(PROCESS_ALL_ACCESS)
# + TerminateProcess 直接杀进程；历史 bpo-42962 修复前缺 return 也会穿透到 TerminateProcess；
# 回退路径要求 PROCESS_ALL_ACCESS，对他人/提权进程会 AccessDenied 误判为已死。
# 旧 _pid_alive 用 os.kill(pid,0) 既可能误判存活又不安全，故统一复用只读的 pid_alive
# （OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)+GetExitCodeProcess==STILL_ACTIVE）。
from services.runtime_worker import (
    clear_stop_request,
    DEFAULT_RUNTIME_DIR,
    ENV_LAUNCH_NONCE,
    ENV_RUN_ID,
    is_identity_token,
    pid_alive,
    process_start_time,
    RUNTIME_DIR,
    RETIRED_CONTROL_DIRNAME,
    read_heartbeat,
    start_stop_file_watcher,
    verify_launch_fence,
    write_heartbeat,
)

BOT_NAMES = ("workbuddy", "codex", "hermes")
INGRESS_PATH = "/internal/feishu/events"
# SR-1 #5 P0-A：桥单实例锁必须与心跳/stop 同落 RUNTIME_DIR（受 TRIAD_RUNTIME_DIR 隔离
# override 控制），禁止写 HUB 根。原 LOCK_DIR = HUB 根会无视隔离、跨运行残留，是
# Aug-16 bridge_process_start_timeout 的根因（lock_held 自强化环）。
LOCK_DIR = RUNTIME_DIR

log = get_logger("hub_bridge")


# ---------------- 5.5.1 稳定JSON编码 ----------------
def canonical_json_bytes(
    payload: dict[str, Any],
) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


_HTTP_STATUS_MAP = {
    202: "accepted",
    200: "duplicate",
    401: "rejected",
    403: "rejected",
    409: "paused",
    422: "rejected",
    503: "rejected",
}


def _shape_response(status_code: int, raw: bytes) -> dict[str, Any]:
    """只接受约定的三字段结构，其余一律丢弃，绝不回显响应全文。"""
    body: dict[str, Any] = {}
    try:
        parsed = json.loads(raw or b"{}")
        if isinstance(parsed, dict):
            body = parsed
    except Exception:  # noqa: BLE001
        body = {}
    status = body.get("status")
    if status not in ("accepted", "duplicate", "rejected", "paused"):
        status = _HTTP_STATUS_MAP.get(status_code, "rejected")
    event_seq = body.get("event_seq")
    if not isinstance(event_seq, int):
        event_seq = None
    err = body.get("error_code")
    if err is not None and not isinstance(err, str):
        err = None
    if status == "paused" and err is None:
        err = "paused"
    return {"status": status, "event_seq": event_seq, "error_code": err}


# ---------------- 5.5.2 POST到Hub ----------------
def post_to_hub(
    payload: dict[str, Any],
    timeout: float = 10.0,
) -> dict[str, Any]:
    body = canonical_json_bytes(payload)
    try:
        timestamp, signature = security.build_signature(body)
    except security.SecurityError as e:
        return {"status": "rejected", "event_seq": None, "error_code": e.code}

    req = urllib.request.Request(
        config.HUB_URL.rstrip("/") + INGRESS_PATH,
        data=body,
        headers={
            "Content-Type": "application/json",
            "X-Triad-Timestamp": timestamp,
            "X-Triad-Signature": signature,
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return _shape_response(resp.status, resp.read())
    except urllib.error.HTTPError as e:
        try:
            raw = e.read()
        except Exception:  # noqa: BLE001
            raw = b""
        return _shape_response(getattr(e, "code", 0), raw)
    except Exception as e:  # noqa: BLE001
        return {
            "status": "rejected",
            "event_seq": None,
            "error_code": redacted_error_code(e),
        }


# ---------------- 5.5.3 飞书事件回调 ----------------
def on_feishu_event(
    bot_name: str,
    normalized_event: dict[str, Any],
) -> None:
    started = time.time()
    if bot_name not in BOT_NAMES:
        log.info(
            "bridge_event",
            agent=bot_name,
            status="rejected",
            error_code="bot_unknown",
            duration_ms=int((time.time() - started) * 1000),
        )
        return
    if normalized_event.get("receiving_bot") != bot_name:
        log.info(
            "bridge_event",
            agent=bot_name,
            event_id=normalized_event.get("event_id"),
            status="rejected",
            error_code="receiving_bot_mismatch",
            duration_ms=int((time.time() - started) * 1000),
        )
        return

    result = post_to_hub(
        {
            "bot_identity": bot_name,
            "raw_event": normalized_event,
            "received_at": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()),
        }
    )
    log.info(
        "bridge_event",
        agent=bot_name,
        event_id=normalized_event.get("event_id"),
        status=result.get("status"),
        error_code=result.get("error_code"),
        duration_ms=int((time.time() - started) * 1000),
    )


# ---------------- 5.5.4 单实例锁 ----------------
def _lock_path(bot_name: str) -> Path:
    return LOCK_DIR / f".bridge_lock_{bot_name}"


def _read_lock_token(path: Path) -> tuple[int, Optional[float]]:
    """返回 (pid, born)。兼容旧裸整数格式（born=None）。无法解析返回 (0, None)。"""
    if not path.exists():
        return (0, None)
    try:
        raw = path.read_text(encoding="utf-8").strip()
    except Exception:  # noqa: BLE001
        return (0, None)
    try:
        return (int(raw), None)
    except Exception:  # noqa: BLE001
        pass
    try:
        d = json.loads(raw)
        born = d.get("born")
        return (int(d.get("pid", 0) or 0), float(born) if born is not None else None)
    except Exception:  # noqa: BLE001
        return (0, None)


def _write_lock_token(path: Path, pid: int, born: Optional[float]) -> None:
    path.write_text(json.dumps({"pid": pid, "born": born}), encoding="utf-8")


def acquire_bridge_lock(
    bot_name: str,
) -> bool:
    """获取桥单实例锁。

    身份稳健规则（SR-1 #5 P0-B）：仅当锁中 PID 仍存活【且】其进程创建时间与
    锁记录的 born 一致（确为同一进程）时，才视为真正持锁并拒绝；
    否则视为 PID 回收/陈旧锁，安全接管（覆盖写入自身 token）。
    """
    path = _lock_path(bot_name)
    pid, born = _read_lock_token(path)
    self_born = process_start_time(os.getpid())
    if pid and pid != os.getpid() and pid_alive(pid):
        live_born = process_start_time(pid)
        if born is not None and live_born is not None:
            if abs(live_born - born) < 2.0:
                return False  # 同一进程仍持锁
            # 创建时间不同 -> PID 已回收给无关进程 -> 陈旧锁，接管
        elif born is None and live_born is None:
            return False  # 双方创建时间均不可判定，保守拒绝（保持旧行为）
        # 其余（born 不可比 / 一方缺失）-> 视为陈旧，接管
    _write_lock_token(path, os.getpid(), self_born)
    return True


# ---------------- 5.5.4 单实例锁：受控删除 / 安全归档 fallback ----------------
# safe-delete 护栏标记：只有 unlink 抛此标记才允许 fallback（规则 2）
_BRIDGE_SAFE_DELETE_MARKER = "SAFE_DELETE_FAIL_CLOSED"
_BRIDGE_FILE_ATTR_REPARSE = 0x400

# bridge bot 白名单：仅 workbuddy / hermes / codex（与 BOT_NAMES 一致）
_BRIDGE_BOT_WHITELIST = frozenset(BOT_NAMES)


def _bridge_is_reparse_point(path: Path) -> bool:
    """只读判断是否为 symlink / junction / 其它 reparse point（不跟随目标）。"""
    try:
        st = os.lstat(path)
    except OSError:
        return False
    if getattr(st, "st_file_attributes", 0) & _BRIDGE_FILE_ATTR_REPARSE:
        return True
    import stat as _stat

    return _stat.S_ISLNK(st.st_mode)


def _bridge_retire_run_dirname() -> str:
    value = os.environ.get(ENV_RUN_ID)
    return value if is_identity_token(value) else "norun"


def _retire_bridge_lock(bot_name: str, path: Path, *, owner_verified: bool) -> str:
    """受控归档：把 bridge 锁原子移动到 RUNTIME_DIR/.retired_control/<run_id|norun>/。

    仅在 unlink 被 safe-delete 护栏 fail-closed 拦截时调用；绝不动活锁。
    返回稳定状态码（与 runtime_worker.delete_or_retire_control_file 同构）：
      retired / retire_rejected_outside_root / retire_rejected_reparse /
      retire_rejected_bot / retire_rejected_active_lock /
      retire_failed_mkdir / retire_failed_rename
    """
    # 路径必须直接位于 LOCK_DIR 根内（bridge 锁实际落点；非子目录、非越界）
    try:
        parent_resolved = path.parent.resolve()
        root_resolved = LOCK_DIR.resolve()
    except OSError:
        return "retire_rejected_outside_root"
    if os.path.normcase(str(parent_resolved)) != os.path.normcase(str(root_resolved)):
        return "retire_rejected_outside_root"
    # 非 reparse point
    if _bridge_is_reparse_point(path):
        return "retire_rejected_reparse"
    # 仅本 bot 的锁
    if bot_name not in _BRIDGE_BOT_WHITELIST:
        return "retire_rejected_bot"
    # 活的其他进程锁禁移动（防御：本函数仅在 owner_verified 或陈旧死 PID 时调用）
    if not owner_verified:
        try:
            holder, _ = _read_lock_token(path)
        except Exception:  # noqa: BLE001
            return "retire_rejected_parse"
        if holder and pid_alive(holder):
            return "retire_rejected_active_lock"
    # 归档到 RUNTIME_DIR/.retired_control/<run_id 或 norun>/
    run_dirname = _bridge_retire_run_dirname()
    run_dir = RUNTIME_DIR / RETIRED_CONTROL_DIRNAME / run_dirname
    try:
        run_dir.mkdir(parents=True, exist_ok=True)
    except OSError:
        return "retire_failed_mkdir"
    import uuid

    stamp = time.strftime("%Y%m%dT%H%M%S", time.gmtime())
    for _ in range(8):
        target = run_dir / f"bridge.{bot_name}.{stamp}-{uuid.uuid4().hex[:8]}"
        if target.exists():
            continue
        try:
            os.rename(path, target)  # 原子移动；不删除、不重试、不碰其它文件
        except OSError:
            return "retire_failed_rename"
        # 只记相对路径与稳定状态码，绝不记 nonce / 绝对路径 / 锁原文
        log.info(
            "bridge_lock_retired",
            agent=bot_name,
            status="retired",
            reason="lock",
            state=f"{RETIRED_CONTROL_DIRNAME}/{run_dirname}",
            error_code="safe_delete_fail_closed",
        )
        return "retired"
    return "retire_failed_rename"


def release_or_retire_bridge_lock(bot_name: str) -> str:
    """释放或受控归档 bridge 单实例锁。

    返回稳定状态：missing / deleted / retired / delete_failed /
    retire_rejected_bot / release_failed_parse / retire_rejected_active_lock /
    retire_rejected_outside_root / retire_rejected_reparse /
    retire_failed_mkdir / retire_failed_rename

    规则（Codex 2026-08-11 裁决，与 runtime 同构受控 fallback）：
    - 仅认本 bot 的锁，bot 白名单 = {workbuddy, hermes, codex}。
    - 正常 unlink 优先；仅当 safe-delete 护栏 fail-closed 才受控归档。
    - 释放自己锁前验 PID（owner_verified=True）；
    - 接管陈旧锁须 PID 已死；活的其他进程锁绝不移动。
    - 不含 except OSError: pass / except Exception: pass 宽吞。
    """
    if bot_name not in _BRIDGE_BOT_WHITELIST:
        return "retire_rejected_bot"
    path = _lock_path(bot_name)
    if not path.exists():
        return "missing"
    try:
        holder, _ = _read_lock_token(path)
    except Exception:  # noqa: BLE001
        return "release_failed_parse"
    owner_verified = holder == os.getpid()
    # 活的其他进程锁：绝不移动（也不尝试 unlink）
    if not owner_verified and pid_alive(holder):
        return "retire_rejected_active_lock"
    try:
        path.unlink()
        return "deleted"
    except OSError as exc:
        message = str(exc)
    if _BRIDGE_SAFE_DELETE_MARKER not in message:
        log.warn(
            "bridge_lock_delete_failed",
            agent=bot_name,
            status="delete_failed",
            reason="lock",
            error_code="oserror_not_safe_delete",
        )
        return "delete_failed"
    return _retire_bridge_lock(bot_name, path, owner_verified=owner_verified)


def release_bridge_lock(bot_name: str) -> None:
    """兼容旧调用方：忽略返回状态，只执行释放/受控归档。"""
    release_or_retire_bridge_lock(bot_name)


# ---------------- 5.5.5 启动桥 ----------------
def bridge_role(bot_name: str) -> str:
    """桥角色名，与 supervisor ROLE_SPECS / 心跳文件名保持一致。"""
    return f"bridge-{bot_name}"


# =====================================================================
# 启动代次取消栅栏校验（SR-2 P0 #402，Codex 裁决三处校验点）
#
# 仅在「受监管代次」下生效：env 含合法 run_id + launch_nonce（supervisor 经
# _spawn 注入）。此时栅栏必须由 supervisor 建好且 active；cancelled/缺失/损坏/
# 不匹配一律非零退出（fail-closed），从根阻止陈旧/孤儿代次冒充就绪（孤儿 37460 根因）。
#
# 直调/测试无代次 env（不设置 TRIAD_RUN_ID/TRIAD_LAUNCH_NONCE）时放行并 warn——
# 既满足 Codex fail-closed（防御受监管代次的陈旧 spawn），又不破坏既有直调测试路径。
# =====================================================================
def _fence_test_bypass_ok() -> bool:
    """P0-5(#402.6-remediation) 显式测试放行：四条件全满足才允许 dry-run 无代次运行。

    仅 TRIAD_TEST_MODE=true + TRIAD_FENCE_TEST_BYPASS=true + 隔离（非默认）RUNTIME_DIR
    同时成立时放行；生产等价 dry-run 若非 supervisor 拉起必被拦。
    """
    if os.environ.get("TRIAD_TEST_MODE") != "true":
        return False
    if os.environ.get("TRIAD_FENCE_TEST_BYPASS") != "true":
        return False
    return _runtime_dir_is_isolated_tmp()


def _runtime_dir_is_isolated_tmp() -> bool:
    """RUNTIME_DIR 必须显式重定向到系统临时目录之下（非默认运行时目录）。"""
    try:
        real = os.path.realpath(str(RUNTIME_DIR))
    except Exception:  # noqa: BLE001
        return False
    default_real = os.path.realpath(str(DEFAULT_RUNTIME_DIR))
    if real == default_real or real.startswith(default_real + os.sep):
        return False
    tmp = os.path.realpath(tempfile.gettempdir())
    return real == tmp or real.startswith(tmp + os.sep)


def _launch_fence_active(role: str) -> bool:
    """P0-3(#402.6-remediation)：基于本进程 env 代次身份重验栅栏是否仍 active。

    不抛异常，仅返回布尔；无代次 env 一律视为不 active（fail-closed，交由调用方处置）。
    """
    run_id = os.environ.get(ENV_RUN_ID)
    nonce = os.environ.get(ENV_LAUNCH_NONCE)
    if not (is_identity_token(run_id) and is_identity_token(nonce)):
        return False
    return verify_launch_fence(role, run_id, nonce)["verdict"] == "active"


def _enforce_launch_fence(role: str, *, dry_run: bool = False) -> None:
    """SR-2 P0 #402 / #402.6-remediation 校验点：cancelled/缺失/损坏/不匹配 → SystemExit(1)。

    P0-5：生产 live（dry_run=False）缺合法代次身份（run_id+launch_nonce）→ fail-closed，
    绝不导入 adapters.feishu、绝不连飞书。dry_run 缺代次仅在满足全部放行条件
    （TRIAD_TEST_MODE=true + TRIAD_FENCE_TEST_BYPASS=true + 隔离 RUNTIME_DIR）时才 warn 放行，
    否则同样 fail-closed（生产等价 dry-run 不被 supervisor 拉起必须被拦）。
    """
    run_id = os.environ.get(ENV_RUN_ID)
    nonce = os.environ.get(ENV_LAUNCH_NONCE)
    if not (is_identity_token(run_id) and is_identity_token(nonce)):
        if dry_run and _fence_test_bypass_ok():
            log.warn("launch_fence_unsupervised_test_bypass", agent=role, status="warn")
            return
        log.error("launch_fence_no_generation", agent=role, status="rejected",
                  error_code="no_generation", reason="unsupervised")
        raise SystemExit(1)
    res = verify_launch_fence(role, run_id, nonce)
    if res["verdict"] != "active":
        log.error("launch_fence_rejected", agent=role, status="rejected",
                  error_code=res["verdict"], reason=str(res.get("reason") or ""))
        raise SystemExit(1)


def _attempt_close_client(client: Any) -> None:
    """受控停机时尽量断开底层飞书连接，使阻塞的 client.start() 能返回。best-effort。"""
    for meth in ("close", "disconnect", "stop", "shutdown"):
        fn = getattr(client, meth, None)
        if callable(fn):
            try:
                fn()
            except Exception:  # noqa: BLE001
                pass


def _run_dry_run_stub(
    bot_name: str,
    stop_event: Optional[Any] = None,
    poll_sec: float = 0.25,
) -> None:
    """dry-run 常驻 stub（Gate4 F-1 修复，Codex 批准方案 A）。

    行为：持桥锁 + 周期写 state=running 心跳 + 挂停机标记 watcher + 循环等停机。

    安全硬约束（本函数内绝不违反）：
    1. 绝不 import adapters.feishu；
    2. 绝不读取任何飞书凭据（app_id / app_secret / token）；
    3. 绝不建立任何网络连接（无 socket、无 HTTP、无长连接）。
    存在的唯一目的：让 supervisor 在受控灰度下拿到一个可校验身份的常驻角色，
    从而验证"八角色全 running"，而不真连飞书。
    """
    role = bridge_role(bot_name)
    event = threading.Event() if stop_event is None else stop_event
    fence_invalidated = threading.Event()  # #402.7 Gap3：栅栏失效标志，区别于正常 stop 文件
    # 清掉上一轮遗留的停机标记，否则本轮一启动就会被误停
    clear_stop_request(role)
    # SR-2 P0 #402 校验点3（dry-run 路径）：写心跳前校验代次栅栏
    _enforce_launch_fence(role, dry_run=True)
    start_stop_file_watcher(role, event, poll_sec=poll_sec)
    write_heartbeat(role, state="running", last_status="dry_run", agent=bot_name)
    log.info("bridge_start", agent=bot_name, status="ok", state="dry_run")
    try:
        while not event.is_set():
            event.wait(poll_sec)
            if event.is_set():
                break
            # P0-3(#402.6-remediation)：每次写心跳前重验代次栅栏；被取消则立即停写
            # 并受控退出，绝不继续冒充 running（supervisor 已原子标 cancelled）。
            if not _launch_fence_active(role):
                # #402.7 Gap3：栅栏失效——停止冒充 running，交由 finally 写稳定失败心跳
                # 并主路径 SystemExit(1)；绝不写 stopped（否则与正常 stop 文件无法区分）。
                log.error("launch_fence_dropped_dryrun", agent=bot_name, status="rejected",
                          error_code="fence_not_active")
                fence_invalidated.set()
                break
            write_heartbeat(role, state="running", last_status="dry_run", agent=bot_name)
    finally:
        if fence_invalidated.is_set():
            # #402.7 Gap3：栅栏失效主路径——稳定失败心跳 + 非零退出，禁止写 stopped
            write_heartbeat(role, state="failed", last_status="launch_fence_invalidated", agent=bot_name)
            clear_stop_request(role)
            log.error("bridge_stopped", agent=bot_name, status="failed", state="dry_run",
                       error_code="launch_fence_invalidated")
            raise SystemExit(1)
        write_heartbeat(role, state="stopped", last_status="dry_run", agent=bot_name)
        clear_stop_request(role)
        log.info("bridge_stopped", agent=bot_name, status="stopped", state="dry_run")


# ---------------- Gate5-B1 连接状态机（Codex 2026-08-12 裁决 v2） ----------------
# 语义：starting(连接前) → connected(SDK 真实连接成功，仅晋升一次) → failed(异常)
#      / reconnecting(断连降级) → 重新 connected → stopped(supervisor 强杀后代写，B-3)。
# supervisor 只认 state=running 且 last_status=connected 为真实 bridge ready；
# connecting/reconnecting 一律不算 ready。
CONNECT_WAIT_SEC = 20.0       # 等待真实 WS 连接成功单轮上限
CONNECT_POLL_SEC = 0.2
HEARTBEAT_REFRESH_SEC = 20.0  # connected 后周期刷新，防 90s 陈旧


def _ws_is_open(client: Any) -> bool:
    """真实 WebSocket 连接状态统一判断（Codex v2 P0-1）。

    - _conn 非 None（websockets.connect 成功赋值）；
    - 且连接未关闭：websockets 15.x ClientConnection.state == State.OPEN（int 1），
      拒绝 CLOSING/CLOSED/CONNECTING；不得只靠对象存在。
    """
    conn = getattr(client, "_conn", None)
    if conn is None:
        return False
    try:
        state = getattr(conn, "state", None)
        if state is None:
            return False
        return int(state) == 1  # websockets.connection.State.OPEN
    except Exception:  # noqa: BLE001 状态读取失败一律视为未连接（fail-closed）
        return False


def _wait_ws_connected(client: Any, timeout: float = CONNECT_WAIT_SEC) -> bool:
    """轮询真实连接状态直到 OPEN。Codex 裁决：不得用固定 sleep 假造 connected。"""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if _ws_is_open(client):
            return True
        time.sleep(CONNECT_POLL_SEC)
    return False


def _run_bridge_longconn(bot_name: str, client: Any) -> None:
    """真实飞书长连接（dry_run=False）。Codex 连接状态机 v2。

    - 启动前清上轮 stop marker，写 starting/connecting（supervisor 不认 ready）；
    - 监测线程按真实连接状态刷新心跳：OPEN→running/connected（仅首次晋升一次）；
      连接丢失→降级 starting/reconnecting（不再写 connected），重新 OPEN 才再晋升；
      每次刷新都重新检查真实连接状态（不无条件写 connected）；
    - client.start() 鉴权/网络失败→写 failed（稳定脱敏码）+SystemExit(1)，不留
      running/connected；start() 返回时 set 停止事件，监测线程随之停止（共享事件）；
    - 停止仍由 supervisor 强杀后代写 stopped（B-3），本分支不重复。
    """
    role = bridge_role(bot_name)
    clear_stop_request(role)
    # SR-2 P0 #402 校验点3（live 路径）：写心跳前校验代次栅栏
    _enforce_launch_fence(role, dry_run=False)
    write_heartbeat(role, state="starting", last_status="connecting", agent=bot_name)
    log.info("bridge_start", agent=bot_name, status="ok", state="longconn")
    install_stream_redactor()

    stop_event = threading.Event()
    promoted = threading.Event()
    hb_lock = threading.Lock()  # 心跳写入互斥：异常路径的 failed 必须是最后写
    fence_invalidated = threading.Event()  # #402.7 Gap3：栅栏失效标志，区别于正常 stop 文件
    # 发现②：live 长连接此前不装 stop 文件监听，受控 stop 对它无效只能精确 terminate。
    # 这里装上 watcher：supervisor request_stop 写 .stop 文件即置位 stop_event，监测线程
    # 据此断开底层连接（见 _monitor），让阻塞的 client.start() 返回，实现受控停机。
    start_stop_file_watcher(role, stop_event, poll_sec=0.25)

    def _monitor() -> None:
        """监测 + 心跳刷新合一：每次循环重新检查真实连接状态与代次栅栏。

        P0-4(#402.6-remediation)：停机分支置于循环顶部（while True 首行即查 stop_event），
        确保 watcher 置位后确定性可达，绝不依赖不可达的内层冗余判断。
        P0-3(#402.6-remediation)：每次刷新前重验代次栅栏；被取消立即停止写 connected，
        触发受控停机（断开底层连接 + set stop_event 使阻塞的 client.start() 返回）。
        首次连接阶段按 CONNECT_POLL_SEC 快速轮询（不能首次失败后等 20s）；
        已 connected 后按 HEARTBEAT_REFRESH_SEC 慢节奏刷新。
        """
        while True:
            if stop_event.is_set():
                # 受控停机：断开底层连接，使阻塞的 client.start() 返回（best-effort）
                _attempt_close_client(client)
                return
            # P0-3：每次刷新前重验代次栅栏；被取消立即停止写 connected，触发受控停机
            if not _launch_fence_active(role):
                # #402.7 Gap3：栅栏失效——标记失效（区别于正常 stop），关连接使阻塞的
                # client.start() 返回；主路径 finally 据 fence_invalidated 写稳定失败 + SystemExit(1)。
                log.error("launch_fence_dropped_live", agent=bot_name, status="rejected",
                          error_code="fence_not_active")
                fence_invalidated.set()
                _attempt_close_client(client)
                stop_event.set()
                return
            if _ws_is_open(client):
                if not promoted.is_set():
                    promoted.set()
                with hb_lock:
                    # 持锁后再确认一次停机标记：避免与 except 分支的 failed 写入竞态
                    # （P0-4 确定性停机：failed 必须是最后写，绝不回退成 starting）
                    if stop_event.is_set():
                        return
                    write_heartbeat(
                        role, state="running", last_status="connected", agent=bot_name
                    )
                stop_event.wait(HEARTBEAT_REFRESH_SEC)
            else:
                # 连接未建立或已丢失：绝不写 connected；降级为 reconnecting
                promoted.clear()
                with hb_lock:
                    # 持锁后再确认一次停机标记：与 except 分支的 failed 写入互斥，
                    # 防止监测循环在 stop_event 置位后（已绕过顶部检查）仍覆盖 failed。
                    if stop_event.is_set():
                        return
                    write_heartbeat(
                        role, state="starting", last_status="reconnecting", agent=bot_name
                    )
                stop_event.wait(CONNECT_POLL_SEC)  # 未连接：快速轮询

    monitor_thread = threading.Thread(target=_monitor, name=f"conn-{role}", daemon=True)
    monitor_thread.start()

    try:
        try:
            client.start()  # 阻塞：鉴权 / 网络不可达会抛异常
        except SystemExit:
            raise
        except Exception as exc:  # noqa: BLE001 SDK 异常（鉴权 ClientException / 网络不可达等）
            code = redacted_error_code(exc) or "connect_failed"
            # 先停监测线程（其不再写心跳），再锁内写 failed——保证 failed 是最后写
            stop_event.set()
            with hb_lock:
                write_heartbeat(role, state="failed", last_status=code[:32], agent=bot_name)
            log.error("bridge_start_failed", agent=bot_name, status="failed", error_code=code)
            raise SystemExit(1) from exc
    finally:
        stop_event.set()  # start() 返回后停止监测/心跳线程
        monitor_thread.join(timeout=HEARTBEAT_REFRESH_SEC + 1.0)  # 有界 join
        # Gate5-B1（Codex v6）：join 超时仍存活 = 失败可传播，不得当作完整成功。
        # 若已有原始异常在传播（鉴权/网络失败），保留原始失败为主错误、join 超时仅
        # 记录清理失败字段（不掩盖）；否则主动写 failed 心跳 + 非零退出。
        if monitor_thread.is_alive():
            with hb_lock:
                write_heartbeat(role, state="failed",
                                last_status="bridge_monitor_join_timeout", agent=bot_name)
            log.error("bridge_monitor_join_timeout", agent=bot_name, status="failed",
                      error_code="bridge_monitor_join_timeout")
            if not sys.exc_info()[0]:
                raise SystemExit(1)
        # #402.7 Gap3：栅栏失效主路径——区别于正常 stop（.stop 文件触发 stop_event）。
        # 栅栏被取消=代次权威判定本角色不应存活；写稳定失败心跳并 SystemExit(1)。
        # 已有异常在传播（鉴权/网络失败/ join 超时）时不覆盖原始失败。
        if fence_invalidated.is_set() and not sys.exc_info()[0]:
            with hb_lock:
                write_heartbeat(role, state="failed",
                                last_status="launch_fence_invalidated", agent=bot_name)
            log.error("bridge_fence_invalidated", agent=bot_name, status="failed",
                      error_code="launch_fence_invalidated")
            raise SystemExit(1)


def run_bridge(
    bot_name: str,
    dry_run: bool = False,
    stop_event: Optional[Any] = None,
    poll_sec: float = 0.25,
) -> None:
    if bot_name not in BOT_NAMES:
        raise ValueError(f"unknown bot_name: {bot_name}")
    role = bridge_role(bot_name)
    if not acquire_bridge_lock(bot_name):
        log.info("bridge_start", agent=bot_name, status="rejected", error_code="lock_held")
        return
    try:
        # SR-2 P0 #402 校验点1（入口）：受监管代次下栅栏必须 active，否则非零退出
        _enforce_launch_fence(role, dry_run=dry_run)
        if dry_run:
            _run_dry_run_stub(bot_name, stop_event=stop_event, poll_sec=poll_sec)
            return
        # SR-2 P0 #402 校验点2（建飞书连接前）：再校验一次，防代次在入口后被取消。
        # 首个可信心跳必须位于 SDK 导入/客户端构建之前：supervisor 的阶段一窗口
        # 只判断本轮桥进程是否真正启动，SDK 冷导入和建连耗时应计入阶段二连接窗口。
        # 若把首个心跳留到 _run_bridge_longconn，慢导入会被误报为
        # bridge_process_start_timeout，且回滚拿不到 runtime_pid。
        _enforce_launch_fence(role, dry_run=dry_run)
        clear_stop_request(role)
        write_heartbeat(role, state="starting", last_status="initializing", agent=bot_name)
        import adapters.feishu as feishu

        app_id, app_secret = feishu.BOTS[bot_name]
        client = feishu._build_client(bot_name, app_id, app_secret, on_feishu_event)
        _run_bridge_longconn(bot_name, client)
    finally:
        release_bridge_lock(bot_name)


def main() -> None:
    install_stream_redactor()
    parser = argparse.ArgumentParser(description="Triad Hub 飞书入口桥")
    parser.add_argument("bot", choices=list(BOT_NAMES))
    parser.add_argument("--dry-run", action="store_true", default=False)
    args = parser.parse_args()
    dry_run = args.dry_run or config.BRIDGE_DRY_RUN
    run_bridge(args.bot, dry_run=dry_run)


if __name__ == "__main__":
    main()
