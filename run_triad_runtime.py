"""run_triad_runtime.py —— Triad 统一运行时 supervisor（Step 11 / Gate 1）。

受管 8 个角色（缺一不可，多一个都不允许）：
    hub               1  FastAPI/uvicorn，127.0.0.1:<PORT>
    outbox            1  飞书出站 worker
    agent-workbuddy   1  WB 调用 worker
    agent-hermes      1  Hermes 调用 worker
    agent-codex       1  Codex 调用 worker
    bridge-workbuddy  1  飞书入口桥
    bridge-hermes     1  飞书入口桥
    bridge-codex      1  飞书入口桥

子命令：
    --preflight   只读体检，不启动任何进程、不建长连接、不调 Agent
    --start       按固定顺序启动全部角色；任一角色失败 -> 受控回滚
    --status      读注册表 + PID 二次核验 + 心跳，输出脱敏 JSON
    --stop        按固定顺序优雅停机

启动顺序：hub -> outbox -> agent(wb, hermes, codex) -> bridge(wb, hermes, codex)
停机顺序：bridge×3 -> agent worker×3（等当前调用完成） -> outbox -> hub

安全红线：
- 全部用 argv 列表 spawn，禁止任何 shell 字符串拼接。
- 子进程 stdout/stderr 一律丢弃：进程自身已写脱敏结构化日志 logs/hub.jsonl，
  避免 uvicorn / SDK 原始输出（含 URL、query）落盘。
- 注册表只写角色/PID/启动时间/状态/脱敏日志路径，绝不写命令行、环境变量、凭据。
- PID 一律二次核验（存活 + 创建时间 + 镜像名），防 PID 复用误杀。
- supervisor 自身单实例。

运行时身份模型（Gate 4 / F-3 修复，Codex 裁决）：
- spawn_pid = Popen().pid。Windows DETACHED_PROCESS 启动 venv python 存在瞬退壳进程，
  这个 PID 秒退后不再对应任何真实角色进程，因此它**只作启动过程审计证据，
  永不参与就绪判定，也永不参与终止决策**。
- runtime_pid = 角色进程自身 os.getpid()，由该进程写进心跳文件上报，是唯一可信身份。
- run_id（本轮 --start 唯一）+ launch_nonce（本轮单角色唯一）经环境变量注入子进程，
  再由子进程回写心跳；supervisor 只认令牌匹配的心跳，杜绝陈旧心跳/跨轮串台被误判为就绪。
- 停机时身份来源优先取注册表已接管的 runtime_pid，其次回退实时心跳（须同轮且非陈旧，
  创建时间与镜像名一律从 OS 重查）；两者都拿不到就上报人工清理，绝不盲杀、绝不按进程名批量杀。
"""
from __future__ import annotations

import argparse
import errno
import hashlib
import json
import os
import secrets
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional

HUB_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(HUB_ROOT))

from config import config  # noqa: E402
from logging_config import get_logger  # noqa: E402
from redaction import install_stream_redactor  # noqa: E402
from services.runtime_worker import (  # noqa: E402
    DEFAULT_RUNTIME_DIR,
    ENV_LAUNCH_NONCE,
    ENV_RUN_ID,
    ENV_RUNTIME_DIR,
    RUNTIME_DIR,
    acquire_role_lock,
    cancel_launch_fence,
    clear_stop_request,
    create_active_launch_fence,
    is_identity_token,
    pid_alive,
    process_image_name,
    process_start_time,
    read_heartbeat,
    recover_runtime_state,
    release_role_lock,
    request_stop,
    retire_expired_launch_fence,
    verify_launch_fence,
    verify_pid_identity,
    write_heartbeat,
)

log = get_logger("triad_runtime")

SHARED_LOG_PATH = "logs/hub.jsonl"
SUPERVISOR_ROLE = "supervisor"


def registry_path() -> Path:
    """运行时注册表路径：隔离模式落隔离 runtime 目录，默认模式保持 docs/ 兼容。

    Codex 2026-08-11 裁决规则 10：八角色 + supervisor 全部使用隔离目录的
    registry/heartbeat/lock/stop/retired。无 override 时（默认模式）不改变
    现有 docs/runtime_registry.json 行为。
    """
    if RUNTIME_DIR != DEFAULT_RUNTIME_DIR:
        return RUNTIME_DIR / "runtime_registry.json"
    return HUB_ROOT / "docs" / "runtime_registry.json"

PY = sys.executable

# 角色定义：argv 一律列表，禁 shell 拼接
ROLE_SPECS: Dict[str, Dict[str, Any]] = {
    "hub": {
        "argv": [PY, "main.py"],
        "kind": "hub",
        "graceful": False,  # uvicorn 无停机标记钩子
    },
    "outbox": {
        "argv": [PY, "tools/run_outbox_worker.py", "--worker-id", "triad-outbox-1"],
        "kind": "worker",
        "graceful": True,
    },
    "agent-workbuddy": {
        "argv": [
            PY, "tools/run_agent_worker.py",
            "--agent", "workbuddy", "--worker-id", "triad-wb-worker-1",
        ],
        "kind": "worker",
        "graceful": True,
    },
    "agent-hermes": {
        "argv": [
            PY, "tools/run_agent_worker.py",
            "--agent", "hermes", "--worker-id", "triad-hermes-worker-1",
        ],
        "kind": "worker",
        "graceful": True,
    },
    "agent-codex": {
        "argv": [
            PY, "tools/run_agent_worker.py",
            "--agent", "codex", "--worker-id", "triad-codex-worker-1",
        ],
        "kind": "worker",
        "graceful": True,
    },
    "bridge-workbuddy": {
        "argv": [PY, "hub_bridge.py", "workbuddy"],
        "kind": "bridge",
        "graceful": False,  # lark SDK client.start() 阻塞，无停机标记钩子
    },
    "bridge-hermes": {
        "argv": [PY, "hub_bridge.py", "hermes"],
        "kind": "bridge",
        "graceful": False,
    },
    "bridge-codex": {
        "argv": [PY, "hub_bridge.py", "codex"],
        "kind": "bridge",
        "graceful": False,
    },
}

START_ORDER: List[str] = [
    "hub",
    "outbox",
    "agent-workbuddy",
    "agent-hermes",
    "agent-codex",
    "bridge-workbuddy",
    "bridge-hermes",
    "bridge-codex",
]
# 停机顺序：先切断入口，再等 worker 把手上的活干完，最后停 outbox 和 Hub
STOP_ORDER: List[str] = [
    "bridge-workbuddy",
    "bridge-hermes",
    "bridge-codex",
    "agent-workbuddy",
    "agent-hermes",
    "agent-codex",
    "outbox",
    "hub",
]

# Gate5-B1（Codex 2026-08-12 v3）：bridge ready timeout 必须大于连接观察上限
# （CONNECT_WAIT_SEC=20s）并留余量，否则真实连接尚未建立就超时误判。
READY_TIMEOUT = {"hub": 25.0, "worker": 15.0, "bridge": 30.0}
STOP_TIMEOUT = {"worker": 30.0, "bridge": 10.0, "hub": 10.0}

# 心跳新鲜度上限：超过它的心跳一律视为陈旧，不得用于就绪判定，更不得用于终止决策
HEARTBEAT_FRESH_SEC = 90.0


# ---------------------------------------------------------------- 运行时身份
def new_identity_token() -> str:
    """生成身份令牌：32 位小写十六进制随机串。

    用于 run_id（本轮 --start 唯一）与 launch_nonce（本轮单角色唯一）。
    令牌不是凭据，但仍**禁止写入任何日志**，只经环境变量注入子进程 + 落脱敏注册表。
    """
    return secrets.token_hex(16)


def _heartbeat_identity(
    role: str,
    run_id: str,
    launch_nonce: str,
    *,
    require_running: bool = True,
    max_age: float = HEARTBEAT_FRESH_SEC,
) -> Optional[int]:
    """读心跳并做本轮身份校验，返回可信 runtime_pid；任一项不满足一律返回 None。

    校验项：state（可选）+ run_id + launch_nonce + 新鲜度 + runtime_pid 合法。
    这是 supervisor 唯一承认的身份来源，spawn_pid 永不参与。
    """
    hb = read_heartbeat(role)
    if not hb:
        return None
    if require_running and hb.get("state") != "running":
        return None
    hb_run_id = hb.get("run_id")
    hb_nonce = hb.get("launch_nonce")
    if not is_identity_token(hb_run_id) or hb_run_id != run_id:
        return None
    if not is_identity_token(hb_nonce) or hb_nonce != launch_nonce:
        return None
    try:
        updated_ts = float(hb.get("updated_ts"))
    except (TypeError, ValueError):
        return None
    if (time.time() - updated_ts) > max_age:
        return None
    try:
        runtime_pid = int(hb.get("runtime_pid") or 0)
    except (TypeError, ValueError):
        return None
    return runtime_pid if runtime_pid > 0 else None


# ---------------------------------------------------------------- 注册表
def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime())


class RegistryCorruptError(Exception):
    """registry 文件存在但已损坏 / schema 错误 / roles 类型错误。

    P0-1（DGN-4.3）：绝不允许静默恢复成空 registry（旧行为会让 preflight 放行、
    start_all 派生进程、stop_all 误判无角色）。一律 fail-closed：调用方捕获后
    必须禁止启动 / 禁止终止任何进程。
    """


def load_registry() -> Dict[str, Any]:
    if not registry_path().exists():
        # 文件不存在 = 首次运行 / 已清理，返回空 registry（合法，非损坏）
        return {"version": 1, "updated_at": None, "roles": {}}
    try:
        raw = registry_path().read_text(encoding="utf-8")
        data = json.loads(raw)
    except Exception as exc:
        raise RegistryCorruptError(
            f"registry_json_unparseable:{type(exc).__name__}") from exc
    if not isinstance(data, dict):
        raise RegistryCorruptError("registry_schema_not_object")
    if "roles" not in data:
        # schema 缺 roles 键 = 损坏 / 旧版不兼容结构 → fail-closed（不再静默重建）
        raise RegistryCorruptError("registry_schema_missing_roles")
    roles = data.get("roles")
    if not isinstance(roles, dict):
        raise RegistryCorruptError("registry_roles_not_object")
    # JSON 序列化会把进程树 dict 的 int 键变成 str；反向加载时还原为 int，
    # 否则 _terminate_registered_runtime_tree 的 `pid not in tree` 因 int/str 键
    # 不匹配永远为真 → 误判未登记后代 → 拒绝终止（生产环境真实停机会失败）。
    # 同时逐条校验树结构（[ppid:int, start_ts, image:str]），任一不合法即视为损坏快照
    # → 作废整棵 + snapshot_complete=False（fail-closed：普通停机将拒停该角色，
    # 绝不拿脏快照去误判后代或按脏值误杀其它 PID）。角色条目本身非 dict（结构损坏）
    # → 直接剔除，避免下游 stop_all 对其误用非 dict 条目而崩溃。
    for role, entry in list(roles.items()):
        if not isinstance(entry, dict):
            roles.pop(role, None)
            continue
        tree = entry.get("process_tree")
        if isinstance(tree, dict) and tree:
            coerced = {}
            corrupt = False
            for k, v in tree.items():
                try:
                    pk = int(k)
                except (TypeError, ValueError):
                    corrupt = True
                    break
                if not (isinstance(v, (list, tuple)) and len(v) >= 3
                        and isinstance(v[0], int) and isinstance(v[2], str)):
                    corrupt = True
                    break
                coerced[pk] = list(v)
            if corrupt:
                entry["process_tree"] = None
                entry["snapshot_complete"] = False
            else:
                entry["process_tree"] = coerced
    return data


def save_registry(registry: Dict[str, Any]) -> None:
    registry["updated_at"] = _now_iso()
    registry.setdefault("version", 1)
    registry["note"] = "脱敏运行时注册表：只含角色/PID/启动时间/状态/共享脱敏日志路径。"
    rp = registry_path()
    rp.parent.mkdir(parents=True, exist_ok=True)
    tmp = rp.with_suffix(".tmp")
    tmp.write_text(json.dumps(registry, ensure_ascii=False, indent=2), encoding="utf-8")
    # #495：Hub 退出 / 自身写盘瞬间可能短暂持有 registry 文件句柄，Windows 下
    # os.replace 会抛 ERROR_SHARING_VIOLATION(32)/ERROR_ACCESS_DENIED(5)。正常 stop
    # 必须自行等到句柄释放，不依赖第二条 recover 命令——故对锁类错误做有界重试。
    _replace_with_lock_retry(tmp, rp)


def _is_transient_lock_error(exc: OSError) -> bool:
    """判定是否为文件锁 / 共享冲突类瞬时错误（应重试而非直接失败）。"""
    win = getattr(exc, "winerror", None)
    if win in (5, 32, 33):  # Windows: ACCESS_DENIED / SHARING_VIOLATION / LOCK_VIOLATION
        return True
    e = getattr(exc, "errno", None)
    return e in (errno.EACCES, errno.EPERM, errno.EBUSY)


def _replace_with_lock_retry(tmp: Path, rp: Path, *, budget: float = 2.0,
                             interval: float = 0.1) -> None:
    """原子替换 registry，遇锁类错误有界重试，直到句柄释放。

    budget 默认 2.0s：Hub 被终止后 OS 释放句柄为毫秒级，2s 绰绰有余；若超时仍锁
    （异常态，如被杀僵尸 / 杀软长占），上浮异常交由调用方 fail-closed。非锁类
    OSError（权限、路径不存在等）立即上浮，不重试。
    """
    deadline = time.monotonic() + budget
    last_exc: Optional[OSError] = None
    while True:
        try:
            tmp.replace(rp)
            return
        except OSError as exc:
            if not _is_transient_lock_error(exc):
                raise
            last_exc = exc
            if time.monotonic() >= deadline:
                raise
            time.sleep(interval)


def _registry_entry(
    role: str,
    spawn_pid: int,
    status: str,
    runtime_pid: Optional[int] = None,
    run_id: Optional[str] = None,
    launch_nonce: Optional[str] = None,
) -> Dict[str, Any]:
    """构造脱敏注册表条目。

    - spawn_pid：Popen().pid，只作启动过程审计证据，永不参与就绪/终止决策。
    - runtime_pid：角色进程自身 os.getpid()（经心跳上报），唯一可信身份。
    - pid：兼容字段，始终指向"当前可信身份"（已接管时=runtime_pid，未接管时回退 spawn_pid）。
    - start_ts / image 一律按当前可信身份 PID 从 OS 查询。
    """
    spawn_pid = int(spawn_pid)
    try:
        rt = int(runtime_pid) if runtime_pid else None
    except (TypeError, ValueError):
        rt = None
    identity_pid = rt if rt and rt > 0 else spawn_pid
    # #401.1 根身份持久化（Codex 验收红线）：spawn_pid 仅存在于字段、未进
    # process_tree，必须持久保存其创建时间/映像，复核时才能验证 OS 是否复用该 PID。
    # 这些字段在 adopt_runtime_pid 接管 runtime_pid 时绝不覆盖（仅作启动审计证据）。
    try:
        spawn_ppid = _get_ppid(spawn_pid)
        spawn_start_ts = process_start_time(spawn_pid)
        spawn_image = process_image_name(spawn_pid)
    except Exception:  # noqa: BLE001 注册时刻 OS 查询失败 → 留 None，复核时 fail-closed
        spawn_ppid = None
        spawn_start_ts = None
        spawn_image = None
    return {
        "role": role,
        "pid": identity_pid,
        "spawn_pid": spawn_pid,
        "runtime_pid": rt if rt and rt > 0 else None,
        "spawn_ppid": spawn_ppid,
        "spawn_start_ts": spawn_start_ts,
        "spawn_image": spawn_image,
        "kind": ROLE_SPECS[role]["kind"],
        "started_at": _now_iso(),
        "start_ts": process_start_time(identity_pid),
        "image": process_image_name(identity_pid),
        "status": status,
        "run_id": run_id if is_identity_token(run_id) else None,
        "launch_nonce": launch_nonce if is_identity_token(launch_nonce) else None,
        "log_path": SHARED_LOG_PATH,
    }


def adopt_runtime_pid(
    registry: Dict[str, Any],
    role: str,
    runtime_pid: int,
    run_id: str,
    launch_nonce: str,
) -> Dict[str, Any]:
    """把心跳上报的 runtime_pid 接管进注册表（原子替换整条 entry）。

    安全约束：
    - 令牌不匹配 -> runtime_identity_mismatch，绝不写入。
    - 同角色同 run_id 已接管过且 PID 不同 -> runtime_identity_conflict，阻塞且不覆盖。
    - 接管时 start_ts / image 必须按 runtime_pid 重新从 OS 查询，不沿用壳进程旧值。
    - spawn_pid 必须原样保留，作为启动过程审计证据。
    """
    roles = registry.setdefault("roles", {})
    entry = roles.get(role)
    if not entry:
        return {"ok": False, "error_code": "role_not_registered"}

    try:
        rt = int(runtime_pid or 0)
    except (TypeError, ValueError):
        rt = 0
    if rt <= 0:
        return {"ok": False, "error_code": "runtime_pid_invalid"}

    if entry.get("run_id") != run_id or entry.get("launch_nonce") != launch_nonce:
        log.error("runtime_pid_adopt_rejected", status="rejected", reason=role,
                  error_code="runtime_identity_mismatch")
        return {"ok": False, "error_code": "runtime_identity_mismatch"}

    existing = entry.get("runtime_pid")
    if existing:
        if int(existing) == rt:
            return {"ok": True, "error_code": "", "runtime_pid": rt, "idempotent": True}
        log.error("runtime_pid_adopt_conflict", status="rejected", reason=role,
                  error_code="runtime_identity_conflict")
        return {"ok": False, "error_code": "runtime_identity_conflict"}

    updated = dict(entry)
    updated["runtime_pid"] = rt
    updated["pid"] = rt
    updated["start_ts"] = process_start_time(rt)
    updated["image"] = process_image_name(rt)
    roles[role] = updated  # 原子替换，避免半更新条目
    return {"ok": True, "error_code": "", "runtime_pid": rt}


# ---------------------------------------------------------------- Preflight
def _port_in_use(host: str, port: int) -> bool:
    import socket

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        return s.connect_ex((host, int(port))) == 0


def _http_get(path: str, timeout: float = 2.0) -> Optional[int]:
    url = f"http://{config.HOST}:{config.PORT}{path}"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:  # noqa: S310 回环自有服务
            return resp.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:
        return None


def preflight() -> Dict[str, Any]:
    """只读体检。绝不启动进程、绝不建长连接、绝不调用任何 Agent。"""
    import db as hubdb
    import main as hubmain

    checks: List[Dict[str, Any]] = []

    def add(name: str, ok: bool, detail: str = "") -> None:
        checks.append({"check": name, "ok": bool(ok), "detail": detail})

    # 1 supervisor 单实例（探测式：不真正长期占锁）
    lock_free = acquire_role_lock(SUPERVISOR_ROLE)
    if lock_free:
        release_role_lock(SUPERVISOR_ROLE)
    add("supervisor_single_instance", lock_free, "" if lock_free else "lock_held")

    # 2 DB 可连接 + integrity ok
    db_ok = False
    try:
        conn = hubdb.connect()
        try:
            db_ok = hubdb.integrity_check(conn) == [("ok",)]
        finally:
            conn.close()
    except Exception:
        db_ok = False
    add("db_integrity", db_ok, "" if db_ok else "db_unavailable")

    # 3 迁移注册表完整应用
    expected = hubmain.expected_migrations()
    mig_ok = False
    missing_count = 0
    try:
        conn = hubdb.connect()
        try:
            applied = {r["version"] for r in conn.execute("SELECT version FROM schema_migrations")}
        finally:
            conn.close()
        missing = [v for v in expected if v not in applied]
        missing_count = len(missing)
        mig_ok = bool(expected) and not missing
    except Exception:
        mig_ok = False
    add("migrations_complete", mig_ok, f"expected={len(expected)},missing={missing_count}")

    # 4 必填安全配置
    missing_cfg = config.missing_required()
    add("required_config", not missing_cfg, f"missing={len(missing_cfg)}")
    add("hmac_configured", bool(config.HUB_INTERNAL_HMAC_SECRET))
    open_ids = config.bot_open_ids()
    add("bot_open_ids", all(open_ids.values()), f"configured={sum(1 for v in open_ids.values() if v)}/3")

    # 5 回环绑定
    add("loopback_only", bool(config.LOOPBACK_ONLY))

    # 6 端口空闲（Hub 未在跑）
    port_busy = _port_in_use(config.HOST, config.PORT)
    add("hub_port_free", not port_busy, "in_use" if port_busy else "")

    # 7 无活跃残留角色锁
    stale: List[str] = []
    for role in ROLE_SPECS:
        lock = RUNTIME_DIR / f".role_lock_{role}"
        if lock.exists():
            try:
                holder = int(lock.read_text(encoding="utf-8").strip() or "0")
            except Exception:
                holder = 0
            if holder and pid_alive(holder):
                stale.append(role)
    for bot in ("workbuddy", "hermes", "codex"):
        # SR-1 #5 P0-A：桥锁已迁至 RUNTIME_DIR（与心跳/stop 同目录），此处随之对齐；
        # 解析兼容裸整数（旧格式）与 JSON token {pid,born}（新格式）。
        blk = RUNTIME_DIR / f".bridge_lock_{bot}"
        if blk.exists():
            try:
                raw = blk.read_text(encoding="utf-8").strip()
                try:
                    holder = int(raw)
                except Exception:
                    holder = int((json.loads(raw)).get("pid", 0) or 0)
            except Exception:
                holder = 0
            if holder and pid_alive(holder):
                stale.append(f"bridge-{bot}")
    add("no_active_locks", not stale, f"held={len(stale)}")

    # 8 无前轮幸存进程（Gate5-B2-WB DGN-4.1 P0-2：registry PID 存活即阻断，含身份不明）
    survivor_roles: List[str] = []
    unverified: List[str] = []
    check_error: str | None = None
    last_status = ""
    # P0-1（DGN-4.3）：registry 损坏 → fail-closed，绝不静默恢复；preflight 直接判失败。
    try:
        reg = load_registry()
    except RegistryCorruptError as exc:
        # P0-1：registry 损坏 → fail-closed，禁止启动，绝不静默恢复
        check_error = f"prior_runtime_check_failed:registry_corrupt:{exc}"
        reg = None
    if reg is not None:
        last_status = reg.get("last_status") or ""
        try:
            for role in ROLE_SPECS:
                entry = reg.get("roles", {}).get(role)
                if not entry:
                    continue
                # 同时读 runtime_pid（终止身份）与 spawn_pid（仅启动审计证据，但用于保守阻断）
                try:
                    cand_pid = int(entry.get("runtime_pid") or 0)
                    spawn_pid = int(entry.get("spawn_pid") or 0)
                except (TypeError, ValueError):
                    # registry 结构损坏 / PID 不可读 → fail-closed
                    check_error = "prior_runtime_check_failed:pid_unreadable"
                    break
                if cand_pid < 0 or spawn_pid < 0:
                    check_error = "prior_runtime_check_failed:pid_invalid"
                    break
                resolved = _resolve_stop_identity(role, entry)
                alive_runtime = cand_pid > 0 and pid_alive(cand_pid)
                alive_spawn = spawn_pid > 0 and pid_alive(spawn_pid)

                # 1) 身份可解析且 PID 存活 → 幸存
                if resolved is not None and pid_alive(resolved["pid"]):
                    survivor_roles.append(role)
                    continue
                # 2) 候选 runtime_pid 存活但身份无法验证 → 身份不明
                if alive_runtime and resolved is None:
                    unverified.append(role)
                    continue
                # 3) 仅 spawn_pid 存活（未接管 runtime_pid）→ 保守阻断（派生进程数为 0）
                if alive_spawn and not alive_runtime:
                    survivor_roles.append(role)
                    continue
                # 4) 状态为 starting/running/stop_failed 但无法证明相关进程已退出
                #    （无存活 PID 且身份不可解析；PID 可读且已死则视为已退出，放行）
                st = entry.get("status")
                if st in ("starting", "running", "stop_failed"):
                    proven_exit = (cand_pid > 0 and not alive_runtime) or (
                        spawn_pid > 0 and not alive_spawn)
                    if not proven_exit:
                        unverified.append(role)
                        continue
        except Exception as exc:  # 记录稳定错误码，不吞（P0-2：fail-closed）
            check_error = check_error or f"prior_runtime_check_failed:{type(exc).__name__}"
    if check_error:
        add("no_prior_runtime_survivors", False, check_error)
    elif last_status in ("stop_incomplete", "stop_failed"):
        # 上次未完整停止：任何存活角色或未知状态都阻断
        add("no_prior_runtime_survivors", False,
            f"last_status={last_status},survivors={len(survivor_roles)}")
    elif survivor_roles:
        add("no_prior_runtime_survivors", False,
            f"prior_runtime_survivors={','.join(survivor_roles[:5])}")
    elif unverified:
        add("no_prior_runtime_survivors", False,
            f"prior_runtime_identity_unverified={','.join(unverified[:5])}")
    else:
        add("no_prior_runtime_survivors", True, "")

    # 9 stdout 证据审计（Gate5-B2 v4：纯只读 audit，发现 pending / verified 不一致
    # 即阻止启动；显式恢复由 --recover-evidence 或受控恢复阶段调用，绝不在 preflight 内写库/改文件）
    audit = {}
    audit_ok = False
    try:
        from adapters.extract import stdout_evidence_audit
        audit = stdout_evidence_audit()
        audit_ok = True
    except Exception:  # noqa: BLE001
        audit_ok = False
    if audit_ok and audit.get("ok"):
        counts = audit.get("counts", {})
        add("stdout_evidence_audit", True,
            (f"pending={counts.get('pending', 0)},verified={counts.get('verified', 0)},"
             f"failed={counts.get('failed', 0)},quarantined={counts.get('quarantined', 0)}"))
    else:
        issues = audit.get("issues", ["audit_error"]) if audit else ["audit_error"]
        add("stdout_evidence_audit", False, f"issues={len(issues)}")

    # 9 WB Gateway 就绪（Gate5-B2-WB R2：仅 live 时强制；dry-run 零网络探测）
    if bool(config.BRIDGE_DRY_RUN):
        add("wb_gateway_ready", True, "dry_run_skip")
    else:
        try:
            from services.wb_gateway_health import probe_wb_gateway
            gw = probe_wb_gateway()
        except Exception:  # noqa: BLE001
            gw = {"ready": False, "error_code": "wb_gateway_probe_error"}
        add(
            "wb_gateway_ready",
            bool(gw.get("ready")),
            gw.get("error_code") or "ready",
        )

    # 10 数据库写锁健康（Gate5-B2-WB：启动前 BEGIN IMMEDIATE;ROLLBACK 探测，不修改业务行）
    try:
        lock = hubdb.probe_db_write_lock(timeout_ms=1000)
        add(
            "db_write_ready",
            bool(lock.get("ready")),
            "" if lock.get("ready") else (lock.get("error_code") or "db_write_locked"),
        )
    except Exception:  # noqa: BLE001
        add("db_write_ready", False, "db_write_probe_error")

    # 11 G9：未登记活进程/陈旧心跳扫描（Codex #404 唯一只读检测，preflight 复用）
    g9 = g9_scan_unregistered_live_runtime()
    add(
        "g9_unregistered_live_runtime",
        bool(g9.get("ok")),
        "" if g9.get("ok") else f"findings={len(g9.get('findings') or [])}",
    )

    result = {
        "ok": all(c["ok"] for c in checks),
        "checked_at": _now_iso(),
        "bridge_dry_run": bool(config.BRIDGE_DRY_RUN),
        "hub_endpoint": f"{config.HOST}:{config.PORT}",
        "roles_managed": len(ROLE_SPECS),
        "checks": checks,
    }
    log.info(
        "preflight_done",
        status="ok" if result["ok"] else "failed",
        count=sum(1 for c in checks if not c["ok"]),
    )
    return result


# ---------------------------------------------------------------- 启动
def _spawn(role: str, run_id: str, launch_nonce: str) -> int:
    """启动角色进程，并把本轮身份令牌经环境变量注入子进程。

    返回 spawn_pid（Popen().pid）。Windows DETACHED_PROCESS 下它可能只是瞬退壳进程，
    因此**只作启动过程审计证据**，绝不参与就绪判定与终止决策。
    """
    spec = ROLE_SPECS[role]
    creationflags = 0
    if os.name == "nt":
        creationflags = (
            getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
            | getattr(subprocess, "DETACHED_PROCESS", 0)
        )
    env = os.environ.copy()  # 必须继承父环境，否则子进程连 PATH / venv 都没有
    env[ENV_RUN_ID] = run_id
    env[ENV_LAUNCH_NONCE] = launch_nonce
    # Gate5-B2-WB DGN-4：agent/outbox worker 注入短 DB busy timeout（1000ms），
    # 使 worker 在锁下能及时返回循环检查停止标记，不拖死停机。
    if ROLE_SPECS[role]["kind"] in ("worker",):
        env["TRIAD_RUNTIME_DB_BUSY_TIMEOUT_MS"] = "1000"
    # 规则 9：supervisor 显式把已验证的隔离 runtime 路径传给子进程，保证八角色
    # 与 supervisor 解析同一目录（默认模式不注入，子进程自然回落默认 runtime）。
    if RUNTIME_DIR != DEFAULT_RUNTIME_DIR:
        env[ENV_RUNTIME_DIR] = str(RUNTIME_DIR)
    proc = subprocess.Popen(  # noqa: S603 argv 列表，无 shell
        spec["argv"],
        cwd=str(HUB_ROOT),
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        close_fds=True,
        creationflags=creationflags,
    )
    return proc.pid


def _wait_ready(role: str, spawn_pid: int, run_id: str, launch_nonce: str) -> Dict[str, Any]:
    """等待角色就绪。返回 {ok, reason, runtime_pid, spawn_pid}。

    统一判据（Codex 裁决，8 角色一致）：
      心跳 state=="running" 且 run_id/launch_nonce 与本轮一致 且 心跳未陈旧
      且 pid_alive(runtime_pid)；hub 另需 /health/live == 200。
    桥不再依赖锁文件内容，spawn_pid 不参与任何判定。

    Gate5-B2（Codex 2026-08-12）：live bridge（BRIDGE_DRY_RUN=false）走两阶段
    _wait_bridge_live_ready（进程启动窗口 + 连接窗口，自 spawn 起算扣除启动开销）；
    dry-run 桥维持原语义（last_status=dry_run 即可），其他角色不变。
    """
    kind = ROLE_SPECS[role]["kind"]
    if kind == "bridge" and not config.BRIDGE_DRY_RUN:
        return _wait_bridge_live_ready(role, spawn_pid, run_id, launch_nonce)
    deadline = time.time() + READY_TIMEOUT[kind]
    # R2-FIX.1 #3：agent-workbuddy 首次 ready 必须本轮可信心跳 + last_status 经网关验证。
    # 错密码 / 网关不可达时 worker 不会写 wb_gateway_verified，故绝不会被认作 ready。
    require_gw_verified = (kind == "worker" and role == "agent-workbuddy")
    wb_ready_status = ('wb_cli_binding_verified' if config.WB_TRANSPORT == 'cli_fixed_session'
                       else 'wb_gateway_verified')
    while True:
        # Gate5-B1（Codex v2）P0：就绪等待期间持续刷新受控进程树身份快照
        _record_process_tree(role, spawn_pid)
        runtime_pid = _heartbeat_identity(role, run_id, launch_nonce)
        if runtime_pid and pid_alive(runtime_pid):
            hb = read_heartbeat(role)
            gw_ok = (not require_gw_verified) or (
                hb is not None and hb.get("last_status") == wb_ready_status
            )
            if gw_ok and (kind != "hub" or _http_get("/health/live") == 200):
                return {
                    "ok": True,
                    "reason": (wb_ready_status if require_gw_verified else "heartbeat"),
                    "runtime_pid": runtime_pid,
                    "spawn_pid": int(spawn_pid),
                }
        if time.time() >= deadline:
            break
        time.sleep(0.3)
    return {
        "ok": False,
        "reason": "ready_timeout",
        "runtime_pid": None,
        "spawn_pid": int(spawn_pid),
    }


# ---------------- live bridge 两阶段 ready（Codex 2026-08-12 裁决） ----------------
# 背景：30s 单窗口自 spawn 起算，但进程启动开销（venv 导入 lark SDK ~12s）压缩了
# 连接有效时间，导致 codex 偶发慢连接超时。拆两阶段以准确区分失败原因：
#   阶段一 进程启动窗口（≤20s）：spawn 起等待本轮可信 starting/running 心跳；
#   阶段二 连接窗口（≤30s）：自首个可信心跳单调时刻起等待 connected；
# 最坏总 ~50s，但两阶段错误码可区分。全部用 time.monotonic()，不依赖日志/墙上时间。
BRIDGE_PROCESS_START_TIMEOUT = 20.0
# Codex 2026-08-12（最后一次单纯延长）：连接窗口 30s→60s 容忍飞书连接延迟；
# 不自动重试连接或整轮启动；窗口内 PID 死亡/failed/身份冲突/鉴权错误仍立即失败。
# 阶段二覆盖 SDK 冷导入、client 构建及 WebSocket 建连。Windows 上冷启动/安全
# 扫描曾使 Hermes 在 initializing 超过 60 秒；120 秒仍有界，同时避免把初始化慢
# 误判成网络或鉴权失败。
BRIDGE_CONNECT_TIMEOUT = 120.0


def _read_bridge_hb_verified(
    role: str, run_id: str, launch_nonce: str,
) -> Optional[tuple]:
    """读 bridge 心跳并验证本轮身份（starting/running 均可）。返回 (hb, runtime_pid) 或 None。"""
    hb = read_heartbeat(role)
    if not hb:
        return None
    if not is_identity_token(hb.get("run_id")) or hb.get("run_id") != run_id:
        return None
    if not is_identity_token(hb.get("launch_nonce")) or hb.get("launch_nonce") != launch_nonce:
        return None
    try:
        rpid = int(hb.get("runtime_pid") or 0)
    except (TypeError, ValueError):
        return None
    if rpid <= 0:
        return None
    return hb, rpid


def _wait_bridge_live_ready(
    role: str, spawn_pid: int, run_id: str, launch_nonce: str,
) -> Dict[str, Any]:
    """live bridge 两阶段 ready。返回 {ok, reason, runtime_pid, spawn_pid}。

    阶段一：spawn 起 ≤20s 等待本轮可信 starting/running 心跳（PID 存活）；
    超时 bridge_process_start_timeout。stale/前轮心跳（错 run_id/nonce）不得采信。
    阶段二：自首个可信心跳单调时刻起 ≤120s 等待 state=running + last_status=connected；
    超时 bridge_connect_timeout。任一阶段 runtime PID 死亡立即失败；心跳 failed 立即
    失败。阶段二冻结 initial_runtime_pid：每次心跳 runtime_pid 必须一致，不一致立即
    bridge_runtime_identity_conflict（不得接管新 PID、不得继续等待）。
    两阶段每轮持续刷新本轮受控进程树快照（回滚依据不缺真实进程）。
    """
    t0 = time.monotonic()
    initial_runtime_pid: Optional[int] = None
    # ---- 阶段一：进程启动窗口 ----
    while True:
        _record_process_tree(role, spawn_pid)
        ok = _read_bridge_hb_verified(role, run_id, launch_nonce)
        if ok:
            hb, rpid = ok
            if hb.get("state") == "failed":
                return {"ok": False, "reason": "bridge_heartbeat_failed",
                        "runtime_pid": rpid, "spawn_pid": int(spawn_pid)}
            if hb.get("state") in ("starting", "running"):
                if pid_alive(rpid):
                    initial_runtime_pid = rpid
                    break
                return {"ok": False, "reason": "bridge_runtime_died",
                        "runtime_pid": rpid, "spawn_pid": int(spawn_pid)}
        if time.monotonic() - t0 >= BRIDGE_PROCESS_START_TIMEOUT:
            return {"ok": False, "reason": "bridge_process_start_timeout",
                    "runtime_pid": None, "spawn_pid": int(spawn_pid)}
        time.sleep(0.3)
    # ---- 阶段二：连接窗口（自首个可信心跳单调时刻起） ----
    t_conn = time.monotonic()
    while True:
        _record_process_tree(role, spawn_pid)
        if not pid_alive(initial_runtime_pid):
            return {"ok": False, "reason": "bridge_runtime_died",
                    "runtime_pid": initial_runtime_pid, "spawn_pid": int(spawn_pid)}
        ok = _read_bridge_hb_verified(role, run_id, launch_nonce)
        if ok:
            hb, rpid = ok
            # 身份一致性：同 run_id/nonce 下 runtime_pid 必须保持阶段一冻结值
            if rpid != initial_runtime_pid:
                return {"ok": False, "reason": "bridge_runtime_identity_conflict",
                        "runtime_pid": None, "spawn_pid": int(spawn_pid)}
            if hb.get("state") == "failed":
                return {"ok": False, "reason": "bridge_heartbeat_failed",
                        "runtime_pid": initial_runtime_pid, "spawn_pid": int(spawn_pid)}
            if hb.get("state") == "running" and hb.get("last_status") == "connected":
                return {"ok": True, "reason": "connected",
                        "runtime_pid": initial_runtime_pid, "spawn_pid": int(spawn_pid)}
        if time.monotonic() - t_conn >= BRIDGE_CONNECT_TIMEOUT:
            return {"ok": False, "reason": "bridge_connect_timeout",
                    "runtime_pid": initial_runtime_pid, "spawn_pid": int(spawn_pid)}
        time.sleep(0.3)


def start_all(dry_run_ok: bool = True) -> Dict[str, Any]:
    """按顺序启动 8 个角色。任一失败 -> 受控回滚。"""
    # Gate5-B1（Codex v2）P0：清掉上轮受控进程树快照，杜绝跨轮误用
    _TREE_RECORDS.clear()
    if not acquire_role_lock(SUPERVISOR_ROLE):
        log.error("supervisor_start_rejected", status="rejected", error_code="lock_held")
        return {"ok": False, "error_code": "supervisor_lock_held", "started": []}

    try:
        pre = preflight()
        if not pre["ok"]:
            failed = [c["check"] for c in pre["checks"] if not c["ok"]]
            log.error("start_aborted", status="aborted", error_code="preflight_failed",
                      count=len(failed))
            return {"ok": False, "error_code": "preflight_failed", "failed_checks": failed,
                    "started": []}
        if not dry_run_ok and config.BRIDGE_DRY_RUN:
            return {"ok": False, "error_code": "bridge_dry_run_enabled", "started": []}

        recovery = recover_runtime_state()
        log.info("start_recovery", status="recovered",
                 count=sum(int(v) for v in recovery.values()))

        try:
            registry = load_registry()
        except RegistryCorruptError as exc:
            # P0-1（DGN-4.3）：registry 损坏 → fail-closed，禁止启动、派生进程数 0
            log.error("start_aborted", status="aborted", error_code="registry_corrupt",
                      detail=str(exc))
            return {"ok": False, "error_code": "registry_corrupt", "started": []}
        # Gate5-B2-WB DGN-4：仅清理已确认死亡的记录；stop_incomplete 时 roles 保留
        # （preflight 的 no_prior_runtime_survivors 已确保无存活角色才走到这里）。
        old_roles = registry.get("roles") or {}
        kept = {}
        for role, entry in old_roles.items():
            resolved = None
            try:
                resolved = _resolve_stop_identity(role, entry)
            except Exception:  # noqa: BLE001
                pass
            alive = bool(resolved and pid_alive(resolved["pid"]))
            if alive:
                kept[role] = entry  # 理论上 preflight 已拦截，防御保留
        registry["roles"] = kept
        run_id = new_identity_token()  # 本轮唯一，用于杜绝上一轮陈旧心跳被误判为就绪
        registry["run_id"] = run_id
        started: List[str] = []

        for role in START_ORDER:
            clear_stop_request(role)
            # SR-2 P0 #402：先归档上一轮已取消且过保留期的栅栏（受控清理，不删活动栅栏）
            try:
                retire_expired_launch_fence(role)
            except Exception:  # noqa: BLE001 归档失败不阻断启动
                pass
            launch_nonce = new_identity_token()  # 本轮单角色唯一
            # SR-2 P0 #402：_spawn() 前建 active 代次栅栏；建不成则回滚，绝不带着缺失
            # 栅栏去 spawn（fail-closed：栅栏缺失会让桥在入口非零退出，但这里先拦截更稳）。
            fence_rc = create_active_launch_fence(role, run_id, launch_nonce)
            if fence_rc != "created":
                log.error("role_fence_create_failed", status="failed", reason=role,
                          error_code=fence_rc)
                try:
                    cancel_launch_fence(role, run_id, launch_nonce, "fence_create_failed")
                except Exception as exc:  # noqa: BLE001 清理失败不阻断回滚返回
                    log.exception("role_fence_cancel_error", exc, reason=role)
                roll_res = _rollback(started, registry)
                return {"ok": False, "error_code": "launch_fence_create_failed",
                        "failed_role": role, "started": started,
                        "rolled_back": roll_res.get("rolled_back", []),
                        "rollback_status": roll_res.get("status"),
                        "rollback_error_code": roll_res.get("error_code", ""),
                        "survivor_roles": roll_res.get("survivor_roles", [])}
            try:
                spawn_pid = _spawn(role, run_id, launch_nonce)
            except Exception as exc:  # noqa: BLE001
                log.exception("role_spawn_failed", exc, status="failed", reason=role)
                # spawn 失败：先取消已建栅栏（本代次未起），再回滚已起角色
                try:
                    cancel_launch_fence(role, run_id, launch_nonce, "spawn_failed")
                except Exception as exc2:  # noqa: BLE001 清理失败不阻断回滚返回
                    log.exception("role_fence_cancel_error", exc2, reason=role)
                roll_res = _rollback(started, registry)
                return {"ok": False, "error_code": "spawn_failed", "failed_role": role,
                        "started": started,
                        "rolled_back": roll_res.get("rolled_back", []),
                        "rollback_status": roll_res.get("status"),
                        "rollback_error_code": roll_res.get("error_code", ""),
                        "survivor_roles": roll_res.get("survivor_roles", [])}
            # Gate5-B1（Codex v2）P0：spawn 后尽早记录受控进程树身份快照（回滚清理依据）
            _record_process_tree(role, spawn_pid)

            # 先登记 starting（只有 spawn_pid），就绪后再接管 runtime_pid
            registry["roles"][role] = _registry_entry(
                role, spawn_pid, "starting", run_id=run_id, launch_nonce=launch_nonce
            )
            save_registry(registry)

            ready = _wait_ready(role, spawn_pid, run_id, launch_nonce)
            if not ready["ok"]:
                registry["roles"][role]["status"] = "failed"
                save_registry(registry)
                log.error("role_not_ready", status="failed", reason=role,
                          error_code=ready["reason"])
                started.append(role)  # 已 spawn，回滚时必须一并处置
                roll_res = _rollback(started, registry)
                return {"ok": False, "error_code": ready["reason"], "failed_role": role,
                        "started": started,
                        "rolled_back": roll_res.get("rolled_back", []),
                        "rollback_status": roll_res.get("status"),
                        "rollback_error_code": roll_res.get("error_code", ""),
                        "survivor_roles": roll_res.get("survivor_roles", [])}

            adopted = adopt_runtime_pid(
                registry, role, ready["runtime_pid"], run_id, launch_nonce
            )
            if not adopted["ok"]:
                registry["roles"][role]["status"] = "failed"
                save_registry(registry)
                log.error("role_adopt_failed", status="failed", reason=role,
                          error_code=adopted["error_code"])
                started.append(role)
                roll_res = _rollback(started, registry)
                return {"ok": False, "error_code": adopted["error_code"], "failed_role": role,
                        "started": started,
                        "rolled_back": roll_res.get("rolled_back", []),
                        "rollback_status": roll_res.get("status"),
                        "rollback_error_code": roll_res.get("error_code", ""),
                        "survivor_roles": roll_res.get("survivor_roles", [])}

            registry["roles"][role]["status"] = "running"
            # DGN-4.2：接管真实 runtime_pid 后，把可信进程树快照持久写入注册表，
            # 供普通停机 _terminate_registered_runtime_tree 读取（不依赖 _TREE_RECORDS 内存）。
            try:
                rpid = int(ready["runtime_pid"])
                tree = _snapshot_runtime_tree(rpid)
                entry = registry["roles"][role]
                entry["runtime_root_pid"] = rpid
                # #401.1 根身份持久化：runtime_root（=runtime_pid，唯一可信身份）的
                # 创建时间/映像/父 PID 单独登记，供 _review_role_tree 复用校验比对。
                entry["runtime_root_ppid"] = _get_ppid(rpid)
                entry["runtime_root_start_ts"] = process_start_time(rpid)
                entry["runtime_root_image"] = process_image_name(rpid)
                entry["process_tree"] = tree
                entry["snapshot_complete"] = tree is not None
                if tree is None:
                    log.warn("runtime_tree_snapshot_incomplete", status="incomplete",
                             reason=role, error_code="runtime_tree_snapshot_incomplete")
            except Exception:  # noqa: BLE001 —— 快照失败不阻断启动，但标记不完整
                registry["roles"][role]["snapshot_complete"] = False
                registry["roles"][role]["process_tree"] = None
            save_registry(registry)
            started.append(role)
            log.info("role_started", status="running", reason=role)

        # Hub 就绪深检（live 之后再看 ready）
        ready_code = _http_get("/health/ready")
        registry["hub_ready_http"] = ready_code
        save_registry(registry)
        if ready_code != 200:
            log.error("hub_not_ready", status="failed", error_code="hub_ready_not_200")
            roll_res = _rollback(started, registry)
            return {"ok": False, "error_code": "hub_ready_not_200",
                    "hub_ready_http": ready_code, "started": started,
                    "rolled_back": roll_res.get("rolled_back", []),
                    "rollback_status": roll_res.get("status"),
                    "rollback_error_code": roll_res.get("error_code", ""),
                    "survivor_roles": roll_res.get("survivor_roles", [])}

        log.info("runtime_started", status="running", count=len(started))
        return {
            "ok": True,
            "started": started,
            "bridge_dry_run": bool(config.BRIDGE_DRY_RUN),
            "hub_ready_http": ready_code,
        }
    finally:
        release_role_lock(SUPERVISOR_ROLE)


# ---------------------------------------------------------------------------
# #401 有界回滚后复核窗口（Codex 2026-08-18 裁决；仅启动失败 _rollback 路径接入）
# ---------------------------------------------------------------------------
POST_ROLLBACK_REVIEW_WINDOW_SEC = 180.0
POST_ROLLBACK_REVIEW_SCAN_SEC = 1.0
_POST_ROLLBACK_TERMINATE_CONFIRM_SEC = 15.0


def _safe_int(v: Any) -> Optional[int]:
    """安全转 int（JSON round-trip 后 process_tree 键/值可能是字符串）；失败返回 None。"""
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _read_identity(pid: int) -> Optional[tuple]:
    """现场读取 (ppid, ts, img)；任一不可读/异常返回 None。"""
    try:
        ppid = _get_ppid(pid)
        ts = process_start_time(pid)
        img = process_image_name(pid)
    except Exception:  # noqa: BLE001 身份读取异常视为不可读
        return None
    if ppid is None or ts is None or img is None:
        return None
    return (int(ppid), float(ts), str(img))


def _recorded_root_identity(entry: Dict[str, Any], root: Any) -> Optional[tuple]:
    """返回登记根 (ppid, ts, img)；无法比对（缺字段）→ None（调用方须 fail-closed）。

    #401.1 根身份复用校验（Codex 验收红线）：spawn_pid 只存在于字段、未进
    process_tree，必须靠登记身份验证 OS 是否复用该 PID；runtime_root_pid /
    runtime_pid / pid 三者指向同一可信 runtime 进程，共享 runtime_root_* 登记身份。
    """
    root = _safe_int(root)
    if root is None:
        return None
    if root == _safe_int(entry.get("spawn_pid")):
        ppid = entry.get("spawn_ppid")
        ts = entry.get("spawn_start_ts")
        img = entry.get("spawn_image")
    else:
        ppid = entry.get("runtime_root_ppid")
        ts = entry.get("runtime_root_start_ts")
        img = entry.get("runtime_root_image")
    # ppid 为可选（孤儿进程可能为 None）；Codex 验收红线要求创建时间(ts)与映像(img)
    # 必须持久化并比对；ppid 仅在其非 None 时参与复用判断（None==None 视为父一致）。
    if ts is None or img is None:
        return None
    return (_safe_int(ppid), float(ts), str(img))


def _enumerate_system_tree(
    roots: Set[int], max_depth: int = 8
) -> Optional[Dict[int, tuple]]:
    """系统 PID/PPID 快照递归枚举（#401.1：**不依赖 root 存活**）。

    从登记根出发按 Toolhelp32 父链递归：`_child_pids(root)` 在 root 已死时仍能返回
    ppid==root 的活子进程（ppid 字段按 PID 匹配，不要求父进程存活）。节点身份不可读
    则跳过该节点（其子进程仍经 ppid 链可达）；`_child_pids` 返回 None（系统枚举失败/
    不完整）→ 整体返回 None（不可信，黏性 stop_incomplete）。深度/节点上限与
    MAX_TREE_DEPTH=8 / MAX_TREE_NODES=64 对齐。
    """
    records: Dict[int, tuple] = {}
    seen: Set[int] = set()
    queue: List[tuple] = [(int(r), 0) for r in roots]
    while queue:
        cur, depth = queue.pop(0)
        if cur in seen:
            continue
        if depth > max_depth:
            return None
        if len(records) >= 64:
            return None
        seen.add(cur)
        ident = _read_identity(cur)
        if ident is not None:
            records[cur] = ident
        children = _child_pids(cur)
        if children is None:
            return None
        for ch in children:
            if ch not in seen:
                queue.append((ch, depth + 1))
    return records


def _review_role_tree(
    role: str,
    entry: Dict[str, Any],
    run_id: str,
    launch_nonce: str,
    *,
    expected_run_id: Optional[str] = None,
    clock=time.monotonic,
    sleep=time.sleep,
) -> Dict[str, Any]:
    """#401.1 单角色单轮复核（dead-root 感知）：发现 + 身份核对 + 迟到后代子到根精确结束。

    #401.1 关键修复（Codex 裁决：root 死亡不得跳过枚举）：
    - 已登记 `process_tree` 成员**逐个核对**（不依赖 root 存活）：存活才核对 PPID/创建时间/
      映像；身份一致才入候选；PID 复用 / 漂移 / 不可读 → 黏性，绝不终止（测试 1/4/8）；
    - 迟到后代经**系统 PID/PPID 快照**（`_enumerate_system_tree`，按 ppid 递归，root 已死
      仍可发现其活子进程）发现，祖先链归根才入候选（测试 2/3/9）；
    - JSON round-trip 后 `process_tree` 键/值可能是字符串 → `_safe_int` 统一转换（测试 7）；
    - `entry.run_id != expected_run_id` → `review_generation_mismatch`（测试 5）；
    - root 被复用且现场身份与登记漂移 → `root_pid_reused`（测试 4）；
    - 系统枚举失败 / 不完整 → `system_enum_incomplete` 黏性（测试 8）；
    - 子到根顺序保持（高度升序=叶子先，孙→子→根），终止前复核身份与归属，终止后确认
      退出（测试 3）。
    """
    # 代次核对（#401.1 测试 5）：旧代次 entry 不得按本轮复核
    if expected_run_id is not None and entry.get("run_id") != expected_run_id:
        return {"ok": False, "survivor": True,
                "error_code": "review_generation_mismatch"}
    baseline_roots = {
        x for x in (_safe_int(entry.get("runtime_root_pid")),
                    _safe_int(entry.get("runtime_pid")),
                    _safe_int(entry.get("pid")),
                    _safe_int(entry.get("spawn_pid"))) if x
    }
    if not baseline_roots:
        # 无任何可信身份线索（仅登记 spawn PID 尚未接管时至少有一个）→ 无法归属
        return {"ok": False, "survivor": True, "error_code": "no_identity_root"}

    # #401.1 根身份复用校验（Codex 验收红线）：spawn_pid 仅存在于字段、未进
    # process_tree 时，必须能验证 OS 是否复用该 PID；一旦复用会把新进程及其后代
    # 误判为本轮候选而误杀。枚举 baseline_roots 前逐个核对现场身份：
    #   - 根已死 → 信任 _child_pids 发现迟到后代（dead-root 场景）
    #   - 根存活但身份不可读 → 排除该根（保持 system_enum_incomplete 黏性，绝不终止）
    #   - 根存活但 registry 无登记身份 → root_identity_unrecorded 黏性（无法验证复用）
    #   - 根存活且父/映像/创建时间与登记漂移（含同父同名映像但创建时间差超容差）
    #     → root_pid_reused 黏性（PID 被 OS 复用，对终止安全而言差一秒都不能信）
    #   - 根存活且父/映像/创建时间(容差内)匹配 → 可信，送 _enumerate_system_tree
    # 仅可信根 + 死根进入枚举；不可读/未登记/复用根一律排除或 fail-closed。
    trusted_roots: Set[int] = set()
    dead_roots: Set[int] = set()
    for r in baseline_roots:
        if not pid_alive(r):
            dead_roots.add(r)  # 死根：信任 _child_pids 发现迟到后代
            continue
        live_ident = _read_identity(r)
        if live_ident is None:
            # 存活但身份不可读（权限/枚举失败）→ 排除该根，避免把不可验证进程当候选
            continue
        rec = _recorded_root_identity(entry, r)
        if rec is None:
            # 根存活但 registry 未登记创建时间/映像 → 无法验证复用 → fail-closed
            return {"ok": False, "survivor": True,
                    "error_code": "root_identity_unrecorded"}
        r_ppid, r_ts, r_img = rec
        l_ppid, l_ts, l_img = live_ident
        # 根身份复用校验（Codex P0 验收红线 2026-08-18）：必须同时比对
        # ppid + image + start_ts。PID 被复用后新进程完全可能仍是同一父启动的
        # 同名映像，仅 ppid+image 相同不足以证明同代次；创建时间差 > 2s 容差
        # 即判 root_pid_reused 黏性拒停，绝不归为 identity_drift 后继续信任。
        if r_ppid is not None and l_ppid != r_ppid:
            # 父进程不同 = PID 被 OS 复用 → 绝不终止
            return {"ok": False, "survivor": True, "error_code": "root_pid_reused"}
        if l_img != r_img:
            # 映像不同 = PID 被 OS 复用 → 绝不终止
            return {"ok": False, "survivor": True, "error_code": "root_pid_reused"}
        if r_ts is not None and abs(l_ts - r_ts) > 2.0:
            # 父/映像相同但创建时间漂移超容差 = 不同代次（同一父同名映像新进程）
            # → 无法证明同代次，必须拒停（对终止安全而言，差一秒都不能信）
            return {"ok": False, "survivor": True, "error_code": "root_pid_reused"}
        # ppid（若登记）/映像/创建时间均在容差内一致 → 同一代次可信根
        trusted_roots.add(r)

    # 登记成员（JSON round-trip 兼容：键/值可能是字符串，测试 7）
    known: Dict[int, tuple] = {}
    for k, v in (entry.get("process_tree") or {}).items():
        pid = _safe_int(k)
        if pid is None:
            continue
        try:
            vals = tuple(v)
        except TypeError:
            continue
        if len(vals) < 3:
            continue
        known[pid] = (
            _safe_int(vals[0]),
            float(vals[1]) if vals[1] is not None else None,
            str(vals[2]) if vals[2] is not None else None,
        )

    # 已登记成员逐个核对（不依赖 root 存活；测试 1/4）
    candidates: Dict[int, tuple] = {}
    for pid, (k_ppid, k_ts, k_img) in known.items():
        if not pid_alive(pid):
            continue
        ident = _read_identity(pid)
        if ident is None:
            # #401.1 测试 8：身份不可读 → 黏性，绝不终止
            return {"ok": False, "survivor": True, "error_code": "identity_unreadable"}
        cur_ppid, cur_ts, cur_img = ident
        if k_ppid is not None and (cur_ppid != k_ppid or cur_img != k_img):
            # 父进程 / 映像完全不同 → 身份被替换；baseline_root 视为 PID 复用
            if pid in baseline_roots:
                return {"ok": False, "survivor": True, "error_code": "root_pid_reused"}
            # 非根成员身份被替换 → 不结束
            return {"ok": False, "survivor": True, "error_code": "identity_drift"}
        if k_ppid is not None and (k_ts is None or abs(cur_ts - k_ts) > 2.0):
            # 仅创建时间漂移（同一进程重启 / 时钟误差）→ 保守不结束，归 identity_drift，
            # 不升级为 root_pid_reused（避免把"时钟/启动慢"误判为 PID 复用而停不干净）
            return {"ok": False, "survivor": True, "error_code": "identity_drift"}
        candidates[pid] = ident

    # 系统 PID/PPID 快照发现迟到后代（root 已死仍递归；测试 2/3/8/9）
    # 仅基于可信根 + 死根枚举；复用/未登记/不可读根已排除或 fail-closed。
    enum_roots = dead_roots | trusted_roots
    if not enum_roots:
        # 所有根均存活但不可读/未登记 → 无法可靠枚举 → 黏性不终止
        return {"ok": False, "survivor": True, "error_code": "system_enum_incomplete"}
    try:
        tree = _enumerate_system_tree(enum_roots)
    except Exception:  # noqa: BLE001 枚举异常 fail-closed
        return {"ok": False, "survivor": True, "error_code": "enum_exception"}
    if tree is None:
        return {"ok": False, "survivor": True, "error_code": "system_enum_incomplete"}
    for pid, ident in tree.items():
        if pid in candidates:
            continue
        if not pid_alive(pid):
            continue
        if not any(_ancestry_to(pid, r) for r in baseline_roots):
            # 测试 9：映像相同但祖先链不归根的无关进程 → 不结束
            return {"ok": False, "survivor": True,
                    "error_code": "unrecorded_descendant"}
        candidates[pid] = ident

    if not candidates:
        # 测试 10：root 死亡且无任何登记成员/可归属迟到后代 → 干净（外层仍须满窗口）
        return {"ok": True, "survivor": False, "error_code": "", "terminated": []}

    # 子到根逐个结束（高度升序=叶子先；测试 3 孙→子），每次结束前重核身份与归属
    child_map: Dict[int, List[int]] = {}
    for c, (pp, _, _) in candidates.items():
        child_map.setdefault(pp, []).append(c)

    def _height(p: int) -> int:
        best = 0
        stack = [(p, 0)]
        while stack:
            node, d = stack.pop()
            if d > best:
                best = d
            for ch in child_map.get(node, []):
                stack.append((ch, d + 1))
        return best

    try:
        for pid in sorted(candidates.keys(), key=_height):
            if not pid_alive(pid):
                continue
            ident = _read_identity(pid)
            if ident is None:
                return {"ok": False, "survivor": True, "error_code": "reverify_failed"}
            cur_ppid, cur_ts, cur_img = ident
            if cur_ppid != candidates[pid][0] or abs(cur_ts - candidates[pid][1]) > 2.0 \
                    or cur_img != candidates[pid][2] \
                    or not any(_ancestry_to(pid, r) for r in baseline_roots):
                # 终止前复验失败（身份漂移 / 归属断裂）→ fail-closed 不结束
                return {"ok": False, "survivor": True, "error_code": "reverify_failed"}
            if not _terminate_pid(pid):
                # 终止失败 → fail-closed
                return {"ok": False, "survivor": True, "error_code": "terminate_failed"}
    except Exception:  # noqa: BLE001 终止/复验异常 fail-closed
        return {"ok": False, "survivor": True, "error_code": "terminate_exception"}

    # 退出确认（有界轮询，clock/sleep 由外层注入——FakeClock 测试无真实等待）
    deadline = clock() + _POST_ROLLBACK_TERMINATE_CONFIRM_SEC
    while clock() < deadline:
        if not any(pid_alive(p) for p in candidates):
            break
        sleep(0.2)
    survivors = [p for p in candidates if pid_alive(p)]
    if survivors:
        # 发出终止后仍存活 → stop_incomplete（绝不停在"已结束"假象）
        return {"ok": False, "survivor": True, "error_code": "survivors_after_terminate"}
    return {"ok": True, "survivor": False, "error_code": "", "terminated": list(candidates)}


def _bounded_post_rollback_review(
    attempted_roles: List[str],
    registry: Dict[str, Any],
    *,
    expected_run_id: Optional[str] = None,
    clock=time.monotonic,
    sleep=time.sleep,
    window_sec: float = POST_ROLLBACK_REVIEW_WINDOW_SEC,
) -> Dict[str, Any]:
    """#401/#401.1 有界 180 秒复核（仅启动失败 _rollback 路径接入）。

    - 覆盖本轮所有执行过 _spawn() 的角色（attempted_roles，含 ready/timeout/
      未接管/已回滚角色）——#401-1；
    - 持续复核 ≥window_sec；首次扫描为空不得提前成功；deadline 必须执行最终
      完整扫描——#401-2；
    - 每轮同时核对 role + run_id + launch_nonce + cancelled fence + PID + 创建时间
      + 映像 + PPID + 完整祖先链——#401-3；
    - 迟到进程仅当代次 / PID 身份 / 完整祖先链精确匹配本轮登记根才子到根逐个
      结束（每次结束前后重核）——#401-4；
    - fence missing/corrupt/active/mismatch、身份不可读/漂移、祖先链断裂/循环、
      未登记后代、树枚举不完整、终止失败/异常、最终扫描不干净 → 黏性
      stop_incomplete，不得结束不确定进程或恢复为成功——#401-5/6。
    - #401.1：`registry["run_id"]` 与调用方 `expected_run_id` 不一致 → 立即失败
      review_generation_mismatch；每角色 `entry.run_id != expected_run_id` →
      review_generation_mismatch（旧代次 entry 不得按本轮复核）。
    - 成功：满窗口 + 无黏性 + 最终扫描干净（无存活/无未知后代/无身份不可读/
      无树不完整/精确结束均确认退出）→ ok=stopped；
    - 失败：ok=False/status=stop_incomplete + survivor_roles（调用方写 stop_failed
      + stop_attempted_at，绝不写 stopped_at）。
    """
    t_start = clock()
    # #401.1 测试 6：registry["run_id"] 与调用方声明的 expected_run_id 不一致 → 立即失败
    if expected_run_id is not None and registry.get("run_id") != expected_run_id:
        return {"ok": False, "status": "stop_incomplete",
                "error_code": "review_generation_mismatch",
                "survivor_roles": sorted(attempted_roles),
                "review_elapsed_sec": round(clock() - t_start, 3),
                "review_completed": False}
    sticky_error: str = ""
    survivor_roles: List[str] = []
    final_scan_done = False
    while True:
        now = clock()
        final_scan = now >= t_start + window_sec
        for role in attempted_roles:
            entry = registry.get("roles", {}).get(role) or {}
            r_run = entry.get("run_id")
            r_nonce = entry.get("launch_nonce")
            if not (is_identity_token(r_run) and is_identity_token(r_nonce)):
                if not sticky_error:
                    sticky_error = "review_invalid_identity"
                if role not in survivor_roles:
                    survivor_roles.append(role)
                continue
            try:
                fv = verify_launch_fence(role, r_run, r_nonce)
            except Exception:  # noqa: BLE001 fence 校验异常 fail-closed
                fv = {"verdict": "exception"}
            if fv.get("verdict") != "cancelled":
                # #401-6：fence missing/corrupt/active/mismatch/exception → 黏性
                if not sticky_error:
                    sticky_error = f"fence_{fv.get('verdict', 'unknown')}"
                if role not in survivor_roles:
                    survivor_roles.append(role)
                continue
            rr = _review_role_tree(role, entry, r_run, r_nonce,
                                   expected_run_id=expected_run_id,
                                   clock=clock, sleep=sleep)
            if not rr["ok"]:
                if not sticky_error:
                    sticky_error = rr.get("error_code") or "review_failed"
                if role not in survivor_roles:
                    survivor_roles.append(role)
        if final_scan:
            final_scan_done = True
            break
        sleep(POST_ROLLBACK_REVIEW_SCAN_SEC)

    elapsed = round(clock() - t_start, 3)
    if sticky_error or survivor_roles:
        return {"ok": False, "status": "stop_incomplete",
                "error_code": sticky_error or "review_incomplete",
                "survivor_roles": sorted(survivor_roles),
                "review_elapsed_sec": elapsed, "review_completed": final_scan_done}
    return {"ok": True, "status": "stopped", "error_code": "",
            "survivor_roles": [],
            "review_elapsed_sec": elapsed, "review_completed": final_scan_done}


def _rollback(
    started: List[str],
    registry: Dict[str, Any],
    *,
    clock=time.monotonic,
    sleep=time.sleep,
    window_sec: float = POST_ROLLBACK_REVIEW_WINDOW_SEC,
) -> Dict[str, Any]:
    """受控回滚 + #401 有界 180 秒复核（仅启动失败路径）。

    入口顺序（Codex #401 第 8 条）：
      取消本轮 fence（_stop_role 内部先原子取消）→ 现有初始受控停机/树清理
      → 初始结果只作临时结果（不提前写最终 stopped_at）→ _bounded_post_rollback_review
      → 按复核结果最终写 registry → 保存 → 结构化结果返回 start_all()。

    返回结构化 {ok, status, rolled_back, survivor_roles, error_code}（#401 第 9 条），
    由 start_all() 原样传播回滚是否完整。
    """
    log.warn("start_rollback", status="rolling_back", count=len(started))
    rolled: List[str] = []
    for role in STOP_ORDER:
        if role not in started:
            continue
        entry = registry.get("roles", {}).get(role) or {}
        # Gate5-B1（Codex 2026-08-12）P0：回滚路径允许按本轮 spawn_pid 清理
        # ready 前未接管身份的启动进程树；普通 --stop 绝不走此路径。
        res = _stop_role(role, entry, rollback=True)
        if res.get("stopped"):
            rolled.append(role)
        # 初始清理结果只作为临时结果，不提前写最终 stopped_at
        entry["status"] = "stopped" if res.get("stopped") else "stop_failed"
        registry.setdefault("roles", {})[role] = entry

    # #401/#401.1：有界 180 秒复核（attempted = 本轮所有 _spawn 过的角色；
    # expected_run_id 取 registry["run_id"]，entry 旧代次或 registry run_id 漂移 →
    # review_generation_mismatch 立即失败）
    review = _bounded_post_rollback_review(
        started, registry, expected_run_id=registry.get("run_id"),
        clock=clock, sleep=sleep, window_sec=window_sec
    )
    survivors: List[str] = []
    for role in started:
        entry = registry.setdefault("roles", {}).get(role) or {}
        if not review["ok"] and role in review.get("survivor_roles", []):
            # #401-6：失败角色写 stop_failed + stop_attempted_at，绝不写 stopped_at；
            # 若此前已有本轮错误写入的 stopped_at，必须移除
            entry["status"] = "stop_failed"
            entry["stop_attempted_at"] = _now_iso()
            entry.pop("stopped_at", None)
            survivors.append(role)
        else:
            entry["status"] = "stopped"
            entry["stopped_at"] = _now_iso()
    registry["last_action"] = "rollback"
    save_registry(registry)
    return {
        "ok": review["ok"],
        "status": "stopped" if review["ok"] else "stop_incomplete",
        "rolled_back": rolled,
        "survivor_roles": sorted(set(survivors)),
        "error_code": review.get("error_code", ""),
    }



def _child_pids(pid: int) -> Optional[List[int]]:
    """Toolhelp32 只读枚举，返回给定 PID 的直接子进程 PID 列表；枚举失败返回 None。"""
    import ctypes
    from ctypes import wintypes

    k = ctypes.WinDLL("kernel32", use_last_error=True)
    k.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    k.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    k.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
    k.Process32FirstW.restype = wintypes.BOOL
    k.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
    k.Process32NextW.restype = wintypes.BOOL
    k.CloseHandle.argtypes = [wintypes.HANDLE]

    class _PE(ctypes.Structure):
        _fields_ = [("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD),
                    ("th32ProcessID", wintypes.DWORD),
                    ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
                    ("th32ModuleID", wintypes.DWORD), ("cntThreads", wintypes.DWORD),
                    ("th32ParentProcessID", wintypes.DWORD),
                    ("pcPriClassBase", ctypes.c_long), ("dwFlags", wintypes.DWORD),
                    ("szExeFile", ctypes.c_wchar * 260)]

    snap = k.CreateToolhelp32Snapshot(0x2, 0)
    if snap == -1:
        return None
    try:
        children: List[int] = []
        pe = _PE()
        pe.dwSize = ctypes.sizeof(_PE)
        if not k.Process32FirstW(snap, ctypes.byref(pe)):
            return None  # 首进程枚举失败
        while True:
            if pe.th32ParentProcessID == int(pid):
                children.append(int(pe.th32ProcessID))
            if not k.Process32NextW(snap, ctypes.byref(pe)):
                break
        return children
    finally:
        k.CloseHandle(snap)


def _get_ppid(pid: int) -> Optional[int]:
    """Toolhelp32 只读查询指定 PID 的父 PID；查不到返回 None。"""
    import ctypes
    from ctypes import wintypes

    k = ctypes.WinDLL("kernel32", use_last_error=True)
    k.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    k.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    k.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
    k.Process32FirstW.restype = wintypes.BOOL
    k.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
    k.Process32NextW.restype = wintypes.BOOL
    k.CloseHandle.argtypes = [wintypes.HANDLE]

    class _PE(ctypes.Structure):
        _fields_ = [("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD),
                    ("th32ProcessID", wintypes.DWORD),
                    ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
                    ("th32ModuleID", wintypes.DWORD), ("cntThreads", wintypes.DWORD),
                    ("th32ParentProcessID", wintypes.DWORD),
                    ("pcPriClassBase", ctypes.c_long), ("dwFlags", wintypes.DWORD),
                    ("szExeFile", ctypes.c_wchar * 260)]

    snap = k.CreateToolhelp32Snapshot(0x2, 0)
    if snap == -1:
        return None
    try:
        pe = _PE()
        pe.dwSize = ctypes.sizeof(_PE)
        if k.Process32FirstW(snap, ctypes.byref(pe)):
            while True:
                if pe.th32ProcessID == int(pid):
                    return int(pe.th32ParentProcessID)
                if not k.Process32NextW(snap, ctypes.byref(pe)):
                    break
    finally:
        k.CloseHandle(snap)
    return None


# Gate5-B1（Codex 2026-08-12 v3）P0：本轮受控启动进程树身份快照。
# role -> {pid: (ppid, start_ts, image)}；_spawn 后尽早记录，_wait_ready 轮询期间刷新，
# 回滚时现场递归重枚举 + 未登记后代拒绝 + 祖先链校验后才终止。
# 仅限 start_all 失败回滚路径使用。
_TREE_RECORDS: Dict[str, Dict[int, tuple]] = {}

# 进程树快照限制：防畸形进程树撑爆 / 防环路死循环
MAX_TREE_NODES = 64
MAX_TREE_DEPTH = 8


class ProcessTreeSnapshot:
    """受控进程树采集结果：记录 + 完整性标记（Codex v5）。

    records: {pid: (ppid, start_ts, image)}
    complete: False 表示采集不完整（身份不可读/枚举失败/超限/环路/根不可读），
              调用方必须拒绝基于它的任何终止决策，且不得保存为可信基线。
    error_code: 不完整时的稳定错误码（rollback_tree_snapshot_incomplete 系列原因）。
    """

    __slots__ = ("records", "complete", "error_code")

    def __init__(self, records: Optional[Dict[int, tuple]] = None,
                 complete: bool = True, error_code: str = ""):
        self.records = records or {}
        self.complete = complete
        self.error_code = error_code


def _record_process_tree(role: str, spawn_pid: int) -> ProcessTreeSnapshot:
    """递归采集完整后代树（BFS），返回记录 + 完整性（Codex v5）。

    下列任一情况 complete=False（不得保存为可信基线，回滚必须拒绝）：
      - 根进程身份不可读；
      - 任一成员 PPID/创建时间/image 不可读；
      - 子进程枚举失败（_child_pids 返回 None）；
      - 超过最大节点数；
      - 超过最大深度且该节点仍有后代；
      - 检测到环 / 重复关系异常。
    """
    records: Dict[int, tuple] = {}
    queue: List[tuple] = [(int(spawn_pid), 0)]
    seen: set = set()
    failed = ""

    def _mark(code: str) -> None:
        nonlocal failed
        if not failed:
            failed = code

    root_ppid = _get_ppid(spawn_pid)
    root_ts = process_start_time(spawn_pid)
    root_img = process_image_name(spawn_pid)
    if root_ppid is None or root_ts is None or root_img is None:
        _mark("root_identity_unreadable")

    while queue and not failed:
        pid, depth = queue.pop(0)
        if pid in seen:
            _mark("cycle_detected")  # 重复入队/环
            break
        if depth > MAX_TREE_DEPTH:
            _mark("depth_limit_exceeded")
            break
        seen.add(pid)
        ppid = _get_ppid(pid)
        ts = process_start_time(pid)
        img = process_image_name(pid)
        if ppid is None or ts is None or img is None:
            _mark("member_identity_unreadable")
            break
        records[pid] = (ppid, ts, img)
        if len(records) >= MAX_TREE_NODES:
            _mark("node_limit_exceeded")
            break
        children = _child_pids(pid)
        if children is None:
            _mark("child_enum_failed")
            break
        for child in children:
            if child not in seen:
                if depth + 1 > MAX_TREE_DEPTH:
                    _mark("depth_limit_exceeded")
                    break
                queue.append((child, depth + 1))

    snap = ProcessTreeSnapshot(
        records=records,
        complete=not bool(failed),
        error_code=failed,
    )
    # 仅完整快照保存为可信基线；不完整快照绝不覆盖
    if snap.complete:
        _TREE_RECORDS[role] = records
    return snap


def _snapshot_runtime_tree(pid: int, max_depth: int = MAX_TREE_DEPTH) -> Optional[Dict[int, tuple]]:
    """枚举 pid 及其全部后代，返回 {pid: (ppid, start_ts, image)}（DGN-4.2 持久化快照）。

    任一成员身份不可读 / 子进程枚举失败 / 超限 / 环路 → 返回 None（不可信，不得保存为基线）。
    与 _record_process_tree 同源但根节点为运行态 runtime_pid（而非启动壳 spawn_pid）。
    """
    pid = int(pid)
    records: Dict[int, tuple] = {}
    queue: List[tuple] = [(pid, 0)]
    seen: set = set()
    while queue:
        cur, depth = queue.pop(0)
        if cur in seen:
            return None
        if depth > max_depth:
            return None
        if len(records) >= MAX_TREE_NODES:
            return None
        seen.add(cur)
        ppid = _get_ppid(cur)
        ts = process_start_time(cur)
        img = process_image_name(cur)
        if ppid is None or ts is None or img is None:
            return None
        records[cur] = (ppid, ts, img)
        children = _child_pids(cur)
        if children is None:
            return None
        for child in children:
            if child not in seen:
                queue.append((child, depth + 1))
    return records


def _ancestry_to(pid: int, ancestor: int) -> bool:
    """现场沿 ppid 链上溯，确认 pid 的祖先链最终回到 ancestor（防 PID 复用误杀）。"""
    cur = int(pid)
    seen = set()
    for _ in range(32):  # 防环
        if cur == int(ancestor):
            return True
        if cur in seen:
            return False
        seen.add(cur)
        nxt = _get_ppid(cur)
        if not nxt or nxt == cur:
            return False
        cur = nxt
    return False


def _rollback_cleanup_spawn(role: str, entry: Dict[str, Any]) -> bool:
    """ready 前回滚专用：按本轮受控进程树身份快照核验后清理（Codex v5）。

    - 必须有本轮完整快照（rollback_tree_identity_unverified 否则拒绝）；
    - 现场递归采集：快照不完整 → 整体拒绝（rollback_tree_snapshot_incomplete）；
    - 现场树存在未登记后代 → 整体拒绝（rollback_tree_unrecorded_descendant）；
    - 每个存活成员现场重核 ppid/创建时间/image 与快照一致 + 祖先链回 spawn 根；
    - **终止循环：每个 PID 终止前再次重核**（存活/ppid/ts/image/祖先链），
      任一变化立即停止并返回失败；
    - **终止后：每个确认并尝试终止的成员必须验证退出**，任何子进程仍存活
      → 整体失败（不能只以根 PID 退出判成功）。
    仅限 start_all 失败回滚路径（rollback=True）；普通 --stop 绝不信任 spawn_pid。
    """
    try:
        spawn_pid = int(entry.get("spawn_pid") or 0)
    except (TypeError, ValueError):
        spawn_pid = 0
    if spawn_pid <= 0:
        return False
    prior = _TREE_RECORDS.get(role)
    if not prior or int(spawn_pid) not in prior:
        log.error("rollback_spawn_cleanup_refused", status="refused", reason=role,
                  error_code="rollback_tree_identity_unverified")
        return False

    # 现场递归采集；快照不完整 → 拒绝，不终止任何进程
    current = _record_process_tree(role, spawn_pid)
    if not current.complete:
        log.error("rollback_spawn_cleanup_refused", status="refused", reason=role,
                  error_code="rollback_tree_snapshot_incomplete",
                  error_summary=current.error_code)
        return False

    # 未登记后代 → 拒绝
    unrecorded = [pid for pid in current.records if pid not in prior]
    if unrecorded:
        log.error("rollback_spawn_cleanup_refused", status="refused", reason=role,
                  error_code="rollback_tree_unrecorded_descendant", count=unrecorded[0])
        return False

    # 先整体核验一遍（构造候选集），终止循环内再逐 PID 重核
    candidates: List[int] = []
    for pid, (rec_ppid, rec_ts, rec_img) in current.records.items():
        if not pid_alive(pid):
            continue  # 已自行退出，无需处理
        cur_ppid = _get_ppid(pid) or 0
        cur_ts = process_start_time(pid)
        cur_img = process_image_name(pid)
        if cur_ppid != rec_ppid or cur_ts is None or abs(cur_ts - rec_ts) > 2.0 \
                or cur_img != rec_img:
            log.error("rollback_spawn_cleanup_refused", status="refused", reason=role,
                      error_code="rollback_tree_identity_conflict", count=pid)
            return False
        if int(pid) != int(spawn_pid) and not _ancestry_to(pid, spawn_pid):
            log.error("rollback_spawn_cleanup_refused", status="refused", reason=role,
                      error_code="rollback_tree_ancestry_mismatch", count=pid)
            return False
        candidates.append(int(pid))
    if not candidates:
        return False

    # 先子后根：按现场 ppid 链深度降序终止（根最后）
    def _depth(p: int) -> int:
        d = 0
        cur = p
        for _ in range(16):
            if cur == int(spawn_pid):
                return d
            nxt = _get_ppid(cur)
            if not nxt or nxt == cur:
                return d + 1
            cur = nxt
            d += 1
        return d

    for pid in sorted(candidates, key=_depth, reverse=True):
        # 终止前逐 PID 重核（防核验与终止之间 PID 复用 / 父子关系变化）
        if not pid_alive(pid):
            continue
        rec_ppid, rec_ts, rec_img = prior.get(pid, (None, None, None))
        cur_ppid = _get_ppid(pid) or 0
        cur_ts = process_start_time(pid)
        cur_img = process_image_name(pid)
        if rec_ts is None or cur_ts is None or abs(cur_ts - rec_ts) > 2.0 \
                or cur_img != rec_img:
            log.error("rollback_spawn_cleanup_refused", status="refused", reason=role,
                      error_code="rollback_tree_terminate_reverify_failed", count=pid)
            return False
        if int(pid) != int(spawn_pid) and not _ancestry_to(pid, spawn_pid):
            log.error("rollback_spawn_cleanup_refused", status="refused", reason=role,
                      error_code="rollback_tree_terminate_reverify_failed", count=pid)
            return False
        _terminate_pid(pid)

    # 终止后：每个确认并尝试终止的成员必须验证退出（任何存活 → 整体失败）
    survivors = [pid for pid in candidates if pid_alive(pid)]
    if survivors:
        log.error("rollback_spawn_cleanup_failed", status="failed", reason=role,
                  error_code="rollback_tree_survivors", count=survivors[0])
        return False
    clear_stop_request(role)
    log.info("rollback_spawn_cleanup_done", status="stopped", reason=role,
             error_code="rollback_spawn_cleanup")
    return True


# ---------------------------------------------------------------- 停机
def _terminate_pid(pid: int) -> bool:
    """硬停机。仅在 PID 二次核验通过后调用。"""
    if os.name != "nt":
        import signal as _sig

        try:
            os.kill(pid, _sig.SIGTERM)
            return True
        except OSError:
            return False
    import ctypes
    from ctypes import wintypes

    PROCESS_TERMINATE = 0x0001
    k = ctypes.WinDLL("kernel32", use_last_error=True)
    k.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    k.OpenProcess.restype = wintypes.HANDLE
    k.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
    k.TerminateProcess.restype = wintypes.BOOL
    k.CloseHandle.argtypes = [wintypes.HANDLE]
    handle = k.OpenProcess(PROCESS_TERMINATE, False, int(pid))
    if not handle:
        return False
    try:
        return bool(k.TerminateProcess(handle, 0))
    finally:
        k.CloseHandle(handle)


def _resolve_stop_identity(role: str, entry: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """解析可信终止身份，拿不到就返回 None（上层必须拒停，绝不盲杀）。

    优先级：
      1) 注册表已接管的 runtime_pid（配套 start_ts / image 为接管时按 runtime_pid 查得）
      2) 回退实时心跳的 runtime_pid —— 必须本轮 run_id + launch_nonce 且未陈旧，
         且 start_ts / image 一律从 OS 重新查询，不沿用注册表旧值
    永不使用 spawn_pid，永不按进程名匹配。
    """
    try:
        runtime_pid = int(entry.get("runtime_pid") or 0)
    except (TypeError, ValueError):
        runtime_pid = 0
    if runtime_pid > 0:
        return {
            "pid": runtime_pid,
            "start_ts": entry.get("start_ts"),
            "image": entry.get("image"),
            "source": "registry",
        }

    run_id = entry.get("run_id")
    launch_nonce = entry.get("launch_nonce")
    if not (is_identity_token(run_id) and is_identity_token(launch_nonce)):
        return None
    hb_pid = _heartbeat_identity(role, run_id, launch_nonce, require_running=False)
    if not hb_pid:
        return None
    return {
        "pid": hb_pid,
        "start_ts": process_start_time(hb_pid),
        "image": process_image_name(hb_pid),
        "source": "heartbeat",
    }


def _supervisor_write_stopped(role: str, entry: Dict[str, Any], pid: int) -> None:
    """可信终止完成后，由 supervisor 代写该角色的 stopped 心跳（Gate4 B-3）。

    背景：bridge / hub 没有停机钩子，被 TerminateProcess 强杀后来不及自己写 stopped，
    心跳文件会永远卡在 running。下一轮 --status 只能靠"陈旧"去猜，既无法与"真死了"
    区分，也让"停止后八角色心跳全 stopped"这条 Gate4 验收永远过不了。

    五项全部满足才代写（Codex 冻结口径）：
      1) 该角色曾完成可信 runtime PID 接管（entry.runtime_pid 为正整数）；
      2) 停止目标就是 registry 中经核验的那个 runtime_pid；
      3) 终止后已确认该 PID 不存活；
      4) run_id / launch_nonce 与本轮 registry 一致，且现存心跳不得来自别轮；
      5) 没有发生身份冲突（心跳里的 runtime_pid 必须与已接管身份相同）。

    任一不满足直接返回，绝不代写——伪造一条 stopped 比留一条 running 危害大得多。
    """
    try:
        adopted = int(entry.get("runtime_pid") or 0)
    except (TypeError, ValueError):
        adopted = 0
    if adopted <= 0 or adopted != int(pid):
        return  # 条件 1 / 2 不满足：没接管过，或停的不是接管的那个身份

    run_id = entry.get("run_id")
    launch_nonce = entry.get("launch_nonce")
    if not (is_identity_token(run_id) and is_identity_token(launch_nonce)):
        return  # 条件 4 不满足：本轮令牌都不合法，无从证明归属

    if pid_alive(adopted):
        return  # 条件 3 不满足：进程还活着，严禁伪造 stopped

    hb = read_heartbeat(role) or {}
    if hb:
        if hb.get("run_id") != run_id or hb.get("launch_nonce") != launch_nonce:
            log.warn("supervisor_stopped_write_skipped", status="skipped", reason=role,
                     error_code="heartbeat_run_mismatch")
            return  # 跨轮心跳：不是本轮这条命，绝不覆盖别人的记录
        try:
            hb_pid = int(hb.get("runtime_pid") or 0)
        except (TypeError, ValueError):
            hb_pid = 0
        if hb_pid != adopted:
            log.warn("supervisor_stopped_write_skipped", status="skipped", reason=role,
                     error_code="heartbeat_pid_conflict")
            return  # 条件 5 不满足：身份冲突

    fields: Dict[str, Any] = {
        "state": "stopped",
        # 代写来源只用 last_status 表达。心跳 schema 白名单不含 reported_by，
        # 不为此扩大 schema（Codex 明示）。
        "last_status": "stopped_by_supervisor",
        "run_id": run_id,
        "launch_nonce": launch_nonce,
    }
    agent = hb.get("agent")
    if isinstance(agent, str) and agent:
        fields["agent"] = agent

    try:
        write_heartbeat(role, runtime_pid=adopted, **fields)
    except (OSError, ValueError):
        # 代写失败只降级记录，不改变停机结论（进程确实已经死了）
        log.warn("supervisor_stopped_write_failed", status="failed", reason=role,
                 error_code="heartbeat_write_failed")


def _terminate_registered_runtime_tree(
    role: str,
    entry: Dict[str, Any],
    deadline: float,
) -> Dict[str, Any]:
    """基于持久化 runtime_registry 树快照的子到根终止（DGN-4.2 P0-4）。

    普通停机专用，绝不依赖 _TREE_RECORDS 进程内内存（start/stop 为不同 CLI 进程）。

    - 每次枚举 / 身份复核 / 终止 / 退出轮询前先查 time.monotonic() >= deadline，
      到期立即返回 overall_deadline，不得通过外层计时掩盖内部超时。
    - 缺快照 / 快照不完整 → runtime_tree_identity_unverified，终止 0 个成员。
    - 现场出现未登记后代 / 身份漂移 → runtime_tree_unrecorded_descendant /
      runtime_tree_identity_unverified，终止 0 个成员。
    - 成功时按子到根顺序终止，每个成员终止前重新验真；所有等待受 deadline 约束。
    - 严禁回退 _terminate_pid(root_pid)。
    """
    def _deadline_hit() -> bool:
        return time.monotonic() >= deadline

    if _deadline_hit():
        return {"ok": False, "stopped": False, "reason": "overall_deadline",
                "error_code": "overall_deadline", "terminated": []}

    tree = entry.get("process_tree") or {}
    if not tree or not entry.get("snapshot_complete"):
        log.error("registered_tree_terminate_refused", status="refused", reason=role,
                  error_code="runtime_tree_identity_unverified")
        return {"ok": False, "stopped": False, "reason": "no_snapshot",
                "error_code": "runtime_tree_identity_unverified", "terminated": []}

    # 推断根：runtime_root_pid 优先；否则取"父节点不在树内"的节点
    root_pid = int(entry.get("runtime_root_pid") or 0)
    if root_pid <= 0:
        for p, (pp, _, _) in tree.items():
            if pp not in tree:
                root_pid = int(p)
                break

    # 现场重枚举（受 deadline 约束）
    if _deadline_hit():
        return {"ok": False, "stopped": False, "reason": "overall_deadline",
                "error_code": "overall_deadline", "terminated": []}
    current = _snapshot_runtime_tree(root_pid)
    if current is None:
        log.error("registered_tree_terminate_refused", status="refused", reason=role,
                  error_code="runtime_tree_identity_unverified")
        return {"ok": False, "stopped": False, "reason": "live_enum_incomplete",
                "error_code": "runtime_tree_identity_unverified", "terminated": []}

    # 校验：未登记后代 + 身份漂移 → 终止 0 个成员
    for pid, (ppid, start_ts, img) in current.items():
        if pid not in tree:
            log.error("registered_tree_terminate_refused", status="refused", reason=role,
                      error_code="runtime_tree_unrecorded_descendant", count=pid)
            return {"ok": False, "stopped": False, "reason": "unrecorded_descendant",
                    "error_code": "runtime_tree_unrecorded_descendant", "terminated": []}
        snap_ppid, snap_ts, snap_img = tree[pid]
        if ppid is None or start_ts is None or snap_ts is None or img is None \
                or ppid != snap_ppid or img != snap_img \
                or abs(start_ts - snap_ts) > 2.0:
            log.error("registered_tree_terminate_refused", status="refused", reason=role,
                      error_code="runtime_tree_identity_unverified", count=pid)
            return {"ok": False, "stopped": False, "reason": "identity_drift",
                    "error_code": "runtime_tree_identity_unverified", "terminated": []}

    # 终止顺序：到最深叶子的距离（高度）升序——叶子先终止，根最后。
    # 不能简单用"到根距离"（根的子节点与根同距=0，会并列导致根在子之前被杀）。
    # 高度为到最深后代的边数：根最大（最后终止），叶子最小（最先终止）。
    child_map: Dict[int, List[int]] = {}
    for c, (pp, _, _) in current.items():
        child_map.setdefault(pp, []).append(c)

    def _height(p: int) -> int:
        best = 0
        stack = [(p, 0)]
        while stack:
            node, d = stack.pop()
            if d > best:
                best = d
            for ch in child_map.get(node, []):
                stack.append((ch, d + 1))
        return best

    terminated: List[int] = []
    for pid in sorted(current.keys(), key=_height):
        if _deadline_hit():
            # P0-3（DGN-4.3）：期限中途到期 → 立即 fail-closed，绝不伪报成功。
            # 已终止的叶子可能使其余成员（child/root）仍存活，故返回 stopped=False，
            # 由调用方（stop_all）标记为 stop_incomplete 并阻止下次启动。
            log.error("registered_tree_terminate_deadline", status="failed", reason=role,
                      error_code="overall_deadline", count=len(terminated))
            return {"ok": False, "stopped": False, "reason": "overall_deadline",
                    "error_code": "overall_deadline", "terminated": terminated}
        # 终止前逐成员重核（防核验与终止之间 PID 复用 / 父子关系变化）
        if not pid_alive(pid):
            continue
        cur_ppid = _get_ppid(pid)
        cur_ts = process_start_time(pid)
        cur_img = process_image_name(pid)
        snap_ppid, snap_ts, snap_img = current[pid]
        if cur_ppid is None or cur_ts is None or cur_img is None or cur_img != snap_img \
                or snap_ts is None or abs(cur_ts - snap_ts) > 2.0 or cur_ppid != snap_ppid:
            log.error("registered_tree_terminate_refused", status="refused", reason=role,
                      error_code="runtime_tree_identity_unverified", count=pid)
            return {"ok": False, "stopped": False, "reason": "reverify_failed",
                    "error_code": "runtime_tree_identity_unverified", "terminated": terminated}
        _terminate_pid(pid)
        terminated.append(pid)

    # 退出轮询：受 deadline 约束
    while time.monotonic() < deadline:
        if not any(pid_alive(p) for p in current):
            break
        time.sleep(0.2)
    # P0-3（DGN-4.3）：成功前必须确认"全部"快照成员均退出，而非仅已终止成员。
    # 否则叶子已退出、但根/其他成员因期限到期未处理时会被误判为成功。
    survivors = [p for p in current if pid_alive(p)]
    if survivors:
        log.error("registered_tree_terminate_survivors", status="failed", reason=role,
                  error_code="runtime_tree_survivors", count=survivors[0])
        return {"ok": False, "stopped": False, "reason": "runtime_tree_survivors",
                "error_code": "runtime_tree_survivors", "terminated": terminated}
    return {"ok": True, "stopped": True, "reason": "process_tree_terminated",
            "error_code": "", "terminated": terminated}


def _stop_role_best_effort_terminate(
    role: str, entry: Dict[str, Any], deadline: Optional[float]
) -> None:
    """P0-2(#402.6-remediation) 兜底：栅栏取消失败时仍尽力清进程树，但不写 stopped。

    成功与否都不影响调用方返回 stop_incomplete=True（栅栏权威状态未变，禁止误判已停）。
    保守：缺快照 / 身份不可用 / 任何异常都静默放弃，交由人工处置。
    """
    try:
        eff = deadline if deadline is not None else (
            time.monotonic() + STOP_TIMEOUT[ROLE_SPECS[role]["kind"]]
        )
        _terminate_registered_runtime_tree(role, entry, eff)
    except Exception:  # noqa: BLE001 兜底清理不得外泄异常
        pass


# #402.7 Gap1 / #547 Step3：代次取消成功白名单（唯一口径，_stop_role 与 stop_all 共用）。
# missing（无栅栏）/ invalid_identity（无代次身份）/ invalid_role / corrupt /
# generation_mismatch / readback_failed（落盘复读失败）一律不算成功——代次权威状态
# 未知即不得判定已停。旧 #402.6 曾对 missing 等放行常规停机，已被 #402.7 Gap1 撤销。
FENCE_CANCEL_OK_RC = ("cancelled", "already_cancelled")


def _finalize_role_fence(role: str, entry: Dict[str, Any], reason: str) -> Dict[str, Any]:
    """角色进程确认退出后收口本代次栅栏：原子取消 + 写后复核（#547 Step3）。

    统一覆盖 outbox + 3 agent（worker）、hub、3 bridge 全部八角色的两条退出路径
    （graceful 自行退出 与 terminated 强制终止），使"正常停机"与超时硬停同样闭环。
    此前 stop_all 阶段 3 的 worker graceful 轮询直接判 stopped 而绕过取消，导致
    正常退出的代次栅栏长期停留 active——本函数即该缺口的统一收口点。

    - 幂等：同代次重复调用得 already_cancelled（不重写 sidecar）；
    - 不可覆盖其他代次：run_id/launch_nonce 不符 → generation_mismatch，不改文件；
    - 复核：取消后再 verify_launch_fence 一次，verdict 必须为 cancelled 才算闭环，
      堵住"cancel 返回成功但落盘件不可采信"的假绿；
    - safe-delete 无关性：取消 sidecar 是写新文件（不依赖任何 unlink），stop 标记等
      控制文件删除失败不会回滚已持久化的 cancel。

    返回 {"ok", "cancel_rc", "verify_verdict"}；ok=False 时调用方必须 fail-closed
    （stop_incomplete + launch_fence_cancel_failed），绝不记 role_stopped。
    """
    run_id = entry.get("run_id")
    nonce = entry.get("launch_nonce")
    try:
        rc = cancel_launch_fence(role, run_id, nonce, reason)
    except Exception as exc:  # noqa: BLE001 绝不吞异常成 stopped
        log.exception("launch_fence_cancel_error", exc, status="failed", reason=role)
        return {"ok": False, "cancel_rc": "exception", "verify_verdict": ""}
    if rc not in FENCE_CANCEL_OK_RC:
        log.error("launch_fence_cancel_failed", status="failed", reason=role,
                  error_code=rc or "unknown")
        return {"ok": False, "cancel_rc": rc, "verify_verdict": ""}
    try:
        verdict = verify_launch_fence(role, run_id, nonce).get("verdict", "")
    except Exception as exc:  # noqa: BLE001
        log.exception("launch_fence_verify_error", exc, status="failed", reason=role)
        return {"ok": False, "cancel_rc": rc, "verify_verdict": "exception"}
    if verdict != "cancelled":
        log.error("launch_fence_not_cancelled_after_stop", status="failed", reason=role,
                  error_code=verdict or "unknown")
        return {"ok": False, "cancel_rc": rc, "verify_verdict": verdict}
    return {"ok": True, "cancel_rc": rc, "verify_verdict": verdict}


def _fence_incomplete_result(role: str, fin: Dict[str, Any]) -> Dict[str, Any]:
    """栅栏未闭环的统一 fail-closed 返回（稳定码沿用 launch_fence_cancel_failed）。"""
    return {"role": role, "stopped": False, "stop_incomplete": True,
            "reason": "launch_fence_cancel_failed",
            "error_code": "launch_fence_cancel_failed",
            "cancel_rc": fin.get("cancel_rc"),
            "verify_verdict": fin.get("verify_verdict")}


def _stop_role(role: str, entry: Dict[str, Any], *, rollback: bool = False,
               skip_graceful: bool = False, deadline: Optional[float] = None) -> Dict[str, Any]:
    """停止单个角色。deadline 为全局截止 time.monotonic()，超时立即返回未停止。"""
    kind = ROLE_SPECS[role]["kind"]
    graceful = ROLE_SPECS[role]["graceful"] and not skip_graceful

    entry = entry or {}
    # SR-2 P0 #402 / #402.6-remediation：代次取消先原子标 cancelled（保留 ≥300s），
    # 再清进程树。覆盖 stop_all 与 _rollback 两条停机路径（二者都经 _stop_role）。
    # P0-1：必须传本角色 registry 中准确代次身份；P0-2：取消失败 fail-closed——
    # 绝不吞异常、绝不写 stopped，仍尽力清进程树但标记 stop_incomplete。
    _cancel_run = entry.get("run_id")
    _cancel_nonce = entry.get("launch_nonce")
    _cancel_rc = None
    try:
        _cancel_rc = cancel_launch_fence(role, _cancel_run, _cancel_nonce, "stop_role")
    except Exception as exc:  # noqa: BLE001
        log.exception("launch_fence_cancel_error", exc, status="failed", reason=role)
        _cancel_rc = "exception"
    # 代次取消结果判定（P0-2，#402.7 Gap1 收紧）：成功白名单见模块级 FENCE_CANCEL_OK_RC。
    # 旧 #402.6 策略曾对 missing / invalid_identity / invalid_role 放行常规停机，已被
    # #402.7 Gap1 撤销——无栅栏/无代次身份即代次权威状态未知，不得据此误判已停。
    if _cancel_rc not in FENCE_CANCEL_OK_RC:
        log.error("launch_fence_cancel_failed", status="failed", reason=role,
                  error_code=_cancel_rc or "unknown")
        _stop_role_best_effort_terminate(role, entry, deadline)
        return {"role": role, "stopped": False, "stop_incomplete": True,
                "reason": "launch_fence_cancel_failed",
                "error_code": "launch_fence_cancel_failed", "cancel_rc": _cancel_rc}
    if not any(entry.get(k) for k in ("runtime_pid", "spawn_pid", "pid")):
        return {"role": role, "stopped": True, "reason": "no_pid"}

    resolved = _resolve_stop_identity(role, entry)
    if resolved is None:
        # 拿不到可信身份：普通路径绝不按 spawn 壳 pid 或进程名杀；
        # 仅 start_all 失败回滚路径（rollback=True）允许按本轮 spawn_pid 清理
        # ready 前启动的受控进程树（Gate5-B1 P0，Codex 2026-08-12）。
        if rollback and _rollback_cleanup_spawn(role, entry):
            return {"role": role, "stopped": True, "reason": "rollback_spawn_cleanup",
                    "error_code": ""}
        log.error("stop_refused_identity_unverified", status="refused", reason=role,
                  error_code="manual_cleanup_required")
        return {"role": role, "stopped": False, "reason": "identity_unverified",
                "error_code": "manual_cleanup_required"}

    pid = resolved["pid"]
    ident = verify_pid_identity(pid, resolved["start_ts"], resolved["image"])
    if not ident["alive"]:
        # #547 Step3：先复核栅栏已闭环，再写 stopped——仅"进程退出 + cancel 有效"
        # 才允许判定已停。clear_stop_request 内部的 safe-delete 失败不影响已持久化
        # 的 cancel（sidecar 是新写文件，与 unlink 无关），故复核放在删除之前。
        _fin = _finalize_role_fence(role, entry, "stop_role_already_exited")
        if not _fin["ok"]:
            _stop_role_best_effort_terminate(role, entry, deadline)
            return _fence_incomplete_result(role, _fin)
        clear_stop_request(role)
        # 进程已经不在了，但它可能是被强杀/崩溃退出的，没来得及自己写 stopped。
        # 这里做幂等补写：已是 stopped 的会原样重写，身份字段一律保持不变。
        _supervisor_write_stopped(role, entry, pid)
        return {"role": role, "stopped": True, "reason": "already_exited"}
    if not ident["verified"]:
        # PID 可能被复用：绝不误杀别的进程
        log.error("stop_refused_pid_mismatch", status="refused", reason=role,
                  error_code="pid_identity_mismatch")
        return {"role": role, "stopped": False, "reason": "pid_identity_mismatch"}

    deadline = deadline if deadline is not None else time.monotonic() + STOP_TIMEOUT[kind]
    if graceful:
        request_stop(role)
        while time.monotonic() < deadline:
            if not pid_alive(pid):
                # #547 Step3：graceful 退出路径同样必须闭环取消栅栏并复核，
                # 仅"进程退出 + cancel 有效"才记 role_stopped。
                _fin = _finalize_role_fence(role, entry, "stop_role_graceful")
                if not _fin["ok"]:
                    return _fence_incomplete_result(role, _fin)
                clear_stop_request(role)
                # graceful 角色通常自己写过 stopped；这里兜底补写，防止它在
                # 写心跳之前就退出，留下一条永远卡在 running 的记录。
                _supervisor_write_stopped(role, entry, pid)
                log.info("role_stopped", status="stopped", reason=role)
                return {"role": role, "stopped": True, "reason": "graceful"}
            time.sleep(0.3)
        log.warn("graceful_stop_timeout", status="timeout", reason=role)

    # 硬停机（bridge / hub 无停机钩子；worker 超时兜底）
    if rollback:
        # rollback 路径：沿用本轮受控进程树快照（_TREE_RECORDS）清理 ready 前启动的进程树
        tree_ok = False
        if _TREE_RECORDS.get(role):
            tree_ok = _rollback_cleanup_spawn(role, entry)
        if tree_ok:
            clear_stop_request(role)
            _supervisor_write_stopped(role, entry, pid)
            return {"role": role, "stopped": True, "reason": "process_tree_terminated"}
        ok = _terminate_pid(pid)
        hard_deadline = min(deadline, time.monotonic() + 5.0)
        while time.monotonic() < hard_deadline and pid_alive(pid):
            time.sleep(0.2)
        stopped = not pid_alive(pid)
        clear_stop_request(role)
        if stopped:
            _supervisor_write_stopped(role, entry, pid)
        return {"role": role, "stopped": stopped, "reason": "terminated" if ok else "terminate_failed"}

    # 普通停机（DGN-4.2 P0-4）：基于持久化 runtime_registry 树快照，子到根校验终止。
    # 缺快照 / 未登记后代 / 身份漂移 → 整体拒绝人工清理，绝不回退 _terminate_pid(root)。
    tree_res = _terminate_registered_runtime_tree(role, entry, deadline)
    if tree_res.get("stopped"):
        # #547 Step3：terminated 路径同样复核栅栏闭环后才记 role_stopped。
        _fin = _finalize_role_fence(role, entry, "stop_role_terminated")
        if not _fin["ok"]:
            return _fence_incomplete_result(role, _fin)
        clear_stop_request(role)
        _supervisor_write_stopped(role, entry, pid)
        log.info("role_stopped", status="stopped", reason=role,
                 error_code="process_tree_terminated")
        return {"role": role, "stopped": True, "reason": "process_tree_terminated",
                "terminated": tree_res.get("terminated", [])}
    # 树不可用 / 校验失败：绝不回退 _terminate_pid(root_pid)，整体拒绝
    log.error("stop_refused_tree_unavailable", status="refused", reason=role,
              error_code=tree_res.get("error_code", "runtime_tree_identity_unverified"))
    return {"role": role, "stopped": False,
            "reason": tree_res.get("reason", "tree_unavailable"),
            "error_code": tree_res.get("error_code", "runtime_tree_identity_unverified")}


def stop_all() -> Dict[str, Any]:
    """分阶段停机（Gate5-B2-WB DGN-4.1 P0-1/P0-3）。

    - 唯一全局 deadline = time.monotonic() + 15.0，所有阶段用剩余预算。
    - bridge 集体处理 ≤2s；worker graceful ≤min(10s, 剩余-5s 保留)；worker 残留 ≤3s；Hub ≤2s。
    - 任一阶段耗尽总期限立即 stop_incomplete，不串行等待。
    - 仅确认退出写 status=stopped+stopped_at；失败写 stop_failed+stop_attempted_at（不写 stopped_at）。
    - 全部退出 last_status=stopped；有残留 last_status=stop_incomplete。
    - 公开只写角色和稳定错误码；PID 细节只进 owner-only 私有证据。
    """
    OVERALL_BUDGET = 15.0
    try:
        registry = load_registry()
    except RegistryCorruptError as exc:
        # P0-1（DGN-4.3）：registry 损坏 → fail-closed，绝不读取/终止任何进程
        log.error("stop_aborted", status="aborted", error_code="registry_corrupt",
                  detail=str(exc))
        return {"ok": False, "status": "stop_incomplete",
                "error_code": "registry_corrupt", "survivor_roles": [],
                "results": [], "elapsed_sec": 0.0}
    results: List[Dict[str, Any]] = []
    survivors: List[str] = []
    overall_deadline = time.monotonic() + OVERALL_BUDGET

    def _remaining() -> float:
        return max(0.0, overall_deadline - time.monotonic())

    def _mark_role(role: str, entry: Dict[str, Any], res: Dict[str, Any]) -> None:
        """状态闭环（P0-3）：仅确认退出写 stopped_at；失败写 stop_attempted_at。"""
        if res["stopped"]:
            entry["status"] = "stopped"
            entry["stopped_at"] = _now_iso()
            entry.pop("stop_attempted_at", None)
        else:
            entry["status"] = "stop_failed"
            entry["stop_attempted_at"] = _now_iso()
            entry.pop("stopped_at", None)
        registry["roles"][role] = entry
        save_registry(registry)

    def _role_entry(role: str) -> Optional[Dict[str, Any]]:
        return registry.get("roles", {}).get(role) or {}

    def _bus_remaining(label: str) -> bool:
        """返回 False 表示总期限已耗尽，调用方应停止继续等待。"""
        return _remaining() > 0

    # 阶段 1：先停三座 bridge（集体核验+终止+轮询，≤2s）
    bridge_roles = [r for r in STOP_ORDER if ROLE_SPECS[r]["kind"] == "bridge"]
    bridge_deadline = min(overall_deadline, time.monotonic() + 2.0)
    for role in bridge_roles:
        entry = _role_entry(role)
        if not entry:
            continue
        res = _stop_role(role, entry, deadline=bridge_deadline)
        results.append(res)
        _mark_role(role, entry, res)
        if not res["stopped"]:
            survivors.append(role)
        if _remaining() <= 0:
            break

    # 阶段 2：一次性向所有 worker 写停止请求（全发出再等待）
    worker_roles = [r for r in STOP_ORDER if ROLE_SPECS[r]["kind"] == "worker"]
    worker_entries = {r: _role_entry(r) for r in worker_roles}
    worker_results: Dict[str, Dict[str, Any]] = {}
    for role in worker_roles:
        entry = worker_entries[role]
        if not entry:
            # registry 无本角色记录 → 本轮未登记代次，无栅栏可取消，视为已停
            worker_results[role] = {"role": role, "stopped": True, "reason": "no_pid"}
            continue
        if not any(entry.get(k) for k in ("runtime_pid", "spawn_pid", "pid")):
            # #547 Step3：有代次记录但无 PID（spawn 未落 pid / 早退）——仍须闭环取消
            # 本代次栅栏，否则 active 栅栏遗留会阻断下一代次启动。
            _fin = _finalize_role_fence(role, entry, "stop_all_worker_no_pid")
            worker_results[role] = (
                {"role": role, "stopped": True, "reason": "no_pid"}
                if _fin["ok"] else _fence_incomplete_result(role, _fin)
            )
            continue
        request_stop(role)

    # 阶段 3：并行轮询 worker（graceful ≤min(10s, 剩余-5s 保留)）
    worker_deadline = min(
        overall_deadline - 5.0,  # 保留 5s 给残留核验+Hub
        time.monotonic() + 10.0,
    )
    remaining_workers = [r for r in worker_roles if r not in worker_results]
    while remaining_workers and time.monotonic() < worker_deadline:
        for role in list(remaining_workers):
            entry = worker_entries[role]
            resolved = _resolve_stop_identity(role, entry)
            if resolved is None:
                worker_results[role] = {"role": role, "stopped": False,
                                        "reason": "identity_unverified",
                                        "error_code": "manual_cleanup_required"}
                remaining_workers.remove(role)
                continue
            pid = resolved["pid"]
            if not pid_alive(pid):
                # #547 Step3（本轮主缺口修复）：此前该路径直接判 stopped 而绕过
                # _stop_role，导致 outbox + 3 agent 正常 graceful 退出时本代次栅栏
                # 从未取消、长期停留 active，下一代次启动被 blocked。现统一收口：
                # 仅"进程退出 + cancel 有效"才判 stopped。
                _fin = _finalize_role_fence(role, entry, "stop_all_worker_graceful")
                if not _fin["ok"]:
                    worker_results[role] = _fence_incomplete_result(role, _fin)
                    remaining_workers.remove(role)
                    continue
                clear_stop_request(role)
                _supervisor_write_stopped(role, entry, pid)
                worker_results[role] = {"role": role, "stopped": True, "reason": "graceful"}
                remaining_workers.remove(role)
        if remaining_workers:
            time.sleep(0.3)
    for role in remaining_workers:
        worker_results[role] = {"role": role, "stopped": False, "reason": "graceful_timeout"}

    # 阶段 4：对仍存活的 worker 核验后终止（集体 ≤3s，受全局期限约束）
    worker_hard_deadline = min(overall_deadline, time.monotonic() + 3.0)
    for role in worker_roles:
        res = worker_results[role]
        entry = worker_entries[role]
        if res["stopped"]:
            results.append(res)
            _mark_role(role, entry, res)
            continue
        if _remaining() <= 0:
            res2 = {"role": role, "stopped": False, "reason": "overall_deadline"}
            results.append(res2)
            _mark_role(role, entry, res2)
            survivors.append(role)
            continue
        res2 = _stop_role(role, entry, rollback=False, skip_graceful=True,
                          deadline=worker_hard_deadline)
        results.append(res2)
        _mark_role(role, entry, res2)
        if not res2["stopped"]:
            survivors.append(role)

    # 阶段 5：最后停 Hub（≤2s 或剩余预算）
    hub_entry = _role_entry("hub")
    if hub_entry:
        hub_deadline = min(overall_deadline, time.monotonic() + 2.0)
        res = _stop_role("hub", hub_entry, deadline=hub_deadline)
        results.append(res)
        _mark_role("hub", hub_entry, res)
        if not res["stopped"]:
            survivors.append("hub")

    total_elapsed = round(time.monotonic() - overall_deadline + OVERALL_BUDGET, 1)
    registry["last_action"] = "stop"
    # 状态闭环（P0-3）：全部退出→stopped；有残留→stop_incomplete
    registry["last_status"] = "stop_incomplete" if survivors else "stopped"
    save_registry(registry)
    all_stopped = not survivors
    log.info("runtime_stopped", status="stopped" if all_stopped else "stop_incomplete",
             elapsed_sec=total_elapsed, count=len(results))
    if survivors:
        return {
            "ok": False,
            "status": "stop_incomplete",
            "error_code": "prior_runtime_survivors",
            "survivor_roles": survivors,
            "results": results,
            "elapsed_sec": total_elapsed,
        }
    return {"ok": True, "results": results, "elapsed_sec": total_elapsed}


# ---------------------------------------------------------------- 状态
def _classify_heartbeat(role: str, entry: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """给心跳打信任标签（Codex 二次裁决约束）。

    write_heartbeat 允许写出缺令牌 / 非法令牌的 running 心跳（可观察但不可信），
    因此 --status 必须区分：
      - absent    ：无心跳文件
      - untrusted ：有心跳但不满足本轮身份（缺/非法/不匹配令牌、陈旧、PID 不一致）
                    -> supervised_state 一律降级为 "unmanaged"，绝不显示 running / ready
      - trusted   ：同轮 run_id + launch_nonce、未陈旧、runtime_pid 与已接管身份一致
    """
    hb = read_heartbeat(role)
    if not hb:
        return {"trust": "absent", "state": None, "age_sec": None,
                "supervised_state": None}

    try:
        age = round(time.time() - float(hb.get("updated_ts")), 1)
    except (TypeError, ValueError):
        age = None
    raw_state = hb.get("state")

    entry = entry or {}
    run_id = entry.get("run_id")
    launch_nonce = entry.get("launch_nonce")
    trusted = False
    if is_identity_token(run_id) and is_identity_token(launch_nonce):
        hb_pid = _heartbeat_identity(role, run_id, launch_nonce, require_running=False)
        if hb_pid:
            try:
                adopted = int(entry.get("runtime_pid") or 0)
            except (TypeError, ValueError):
                adopted = 0
            # 已接管则必须与接管身份一致；尚未接管时允许（接管流程另有 conflict 保护）
            trusted = adopted <= 0 or hb_pid == adopted

    return {
        "trust": "trusted" if trusted else "untrusted",
        "state": raw_state,
        "age_sec": age,
        "supervised_state": raw_state if trusted else "unmanaged",
    }


def status() -> Dict[str, Any]:
    # P0-1（DGN-4.3）：registry 损坏时 status 不崩溃，降级为"无角色"（只读报告，不终止）。
    try:
        registry = load_registry()
    except RegistryCorruptError:
        registry = {"version": 1, "updated_at": None, "roles": {}}
    roles: List[Dict[str, Any]] = []
    for role in START_ORDER:
        entry = registry.get("roles", {}).get(role)
        hb_info = _classify_heartbeat(role, entry)
        if not entry:
            # 注册表无条目 = 非本 supervisor 管理；若仍有心跳，必须标记 unmanaged
            roles.append({
                "role": role, "status": "not_started", "pid": None,
                "spawn_pid": None, "runtime_pid": None,
                "alive": False, "verified": False,
                "heartbeat_state": hb_info["state"],
                "heartbeat_trust": hb_info["trust"],
                "supervised_state": hb_info["supervised_state"],
                "heartbeat_age_sec": hb_info["age_sec"],
            })
            continue
        # 身份一律取 runtime_pid；未接管时不拿 spawn 壳 pid 冒充身份
        try:
            runtime_pid = int(entry.get("runtime_pid") or 0)
        except (TypeError, ValueError):
            runtime_pid = 0
        pid = runtime_pid
        ident = (
            verify_pid_identity(pid, entry.get("start_ts"), entry.get("image"))
            if pid > 0 else {"pid": 0, "alive": False, "verified": False}
        )
        roles.append({
            "role": role,
            "pid": pid or None,
            "spawn_pid": entry.get("spawn_pid"),
            "runtime_pid": runtime_pid or None,
            "recorded_status": entry.get("status"),
            "alive": ident["alive"],
            "verified": ident["verified"],
            "heartbeat_state": hb_info["state"],
            "heartbeat_trust": hb_info["trust"],
            "supervised_state": hb_info["supervised_state"],
            "heartbeat_age_sec": hb_info["age_sec"],
            "log_path": entry.get("log_path", SHARED_LOG_PATH),
        })
    # 受监督运行数：必须 OS 身份核验通过 且 心跳可信，二者缺一不可
    running = sum(1 for r in roles if r.get("verified") and r.get("heartbeat_trust") == "trusted")
    # Codex #404：status() 附 G9 只读报告（绝不归档、绝不终止，仅供观察/准入判断）
    try:
        g9 = g9_scan_unregistered_live_runtime()
    except Exception:  # noqa: BLE001 - status 只读报告，G9 异常不崩溃
        g9 = {"ok": False, "error_code": "g9_scan_error", "findings": []}
    return {
        "checked_at": _now_iso(),
        "bridge_dry_run": bool(config.BRIDGE_DRY_RUN),
        "hub_live_http": _http_get("/health/live"),
        "hub_ready_http": _http_get("/health/ready"),
        "roles_running": running,
        "roles_expected": len(START_ORDER),
        "roles": roles,
        "g9": {
            "ok": bool(g9.get("ok")),
            "error_code": g9.get("error_code"),
            "findings_count": len(g9.get("findings") or []),
        },
    }


# ---------------------------------------------------------------- G9（Codex #404）
def _scan_unregistered_role_processes() -> Tuple[List[Dict[str, Any]], bool]:
    """精确入口命令扫描：发现未登记的 Triad 角色进程（只检测，不自动终止）。

    Codex #404 条件 5：扫描 system-wide 进程，识别 argv 命中受管角色入口
    （main.py / run_outbox_worker.py / run_agent_worker.py / hub_bridge.py）的进程，
    且该 pid 未出现在 registry 的 runtime_pid/spawn_pid 中 → 未登记角色进程。
    返回脱敏列表（只含 pid / role / 入口名），绝不回显命令行全文、session、凭据。

    P0-2（Codex 2026-08-19）：返回 (found, scan_complete)。扫描不完整（psutil
    缺失、扫描异常、AccessDenied 跳过进程）→ scan_complete=False，调用方必须
    fail-closed（process_scan_incomplete），绝不把"扫不全"当"没有未登记进程"。
    """
    try:
        import psutil  # noqa: PLC0415
    except Exception:  # noqa: BLE001 - psutil 缺失 = 扫描不完整，fail-closed
        return [], False

    try:
        reg = load_registry()
    except RegistryCorruptError:
        reg = {}
    known: set = set()
    for entry in (reg.get("roles") or {}).values():
        for k in ("runtime_pid", "spawn_pid", "pid"):
            try:
                v = int(entry.get(k) or 0)
            except (TypeError, ValueError):
                v = 0
            if v > 0:
                known.add(v)

    # 入口文件 → role 的映射（只认精确入口 argv，杜绝按进程名批量匹配）
    entry_map = {
        "main.py": "hub",
        "run_outbox_worker.py": "outbox",
        "run_agent_worker.py": None,   # 具体角色看 --agent 参数
        "hub_bridge.py": None,          # 具体角色看第 1 个位置参数
    }
    found: List[Dict[str, Any]] = []
    scan_complete = True
    try:
        for p in psutil.process_iter(["pid", "name", "cmdline"]):
            try:
                cmd = list(p.info.get("cmdline") or [])
            except psutil.AccessDenied:
                # P0-2：无权限读到 cmdline = 扫描不完整，不得静默跳过
                scan_complete = False
                continue
            except psutil.NoSuchProcess:
                continue  # 进程刚退出属正常竞态，不算不完整
            if not cmd:
                continue
            base = None
            for part in cmd:
                low = os.path.basename(str(part)).lower()
                if low in entry_map:
                    base = low
                    break
            if base is None:
                continue
            pid = int(p.info.get("pid") or 0)
            if pid in known:
                continue
            role: Optional[str] = None
            if base == "run_agent_worker.py":
                for i, part in enumerate(cmd):
                    if part == "--agent" and i + 1 < len(cmd):
                        role = f"agent-{cmd[i+1]}"
                        break
            elif base == "hub_bridge.py":
                # 位置参数：hub_bridge.py <bot>
                for part in cmd:
                    if part in ("workbuddy", "hermes", "codex"):
                        role = f"bridge-{part}"
                        break
            elif base == "main.py":
                role = "hub"
            elif base == "run_outbox_worker.py":
                role = "outbox"
            if role and role in ROLE_SPECS:
                found.append({"pid": pid, "role": role, "entry": base})
    except Exception:  # noqa: BLE001 - 扫描异常 = 不完整，fail-closed
        return found, False
    return found, scan_complete


def g9_scan_unregistered_live_runtime() -> Dict[str, Any]:
    """G9：未登记活进程/陈旧心跳扫描（产品唯一只读检测，Codex #404）。

    七类阻断条件（sr2_defect_codex_reply.txt 63-69）命中任一 → 稳定错误码
    unregistered_live_runtime，阻止启动；只检测、只阻断，绝不自动终止、绝不自动归档：
      1) 新鲜 heartbeat 的 PID 仍存活，但 registry 无完全匹配的 role/run_id/
         runtime_pid/身份信息 → 阻断；
      2) heartbeat 显示 running/starting/reconnecting/connected，但 PID 死亡 → 阻断
         （要求调用方受控归档）；
      3) heartbeat 显示 stopped 但 PID 仍存活 → 阻断；
      4) 桥锁 PID 死亡、heartbeat PID 存活且二者不一致 → 阻断；
      5) 精确入口命令扫描发现未登记的 Triad 角色进程 → 阻断（只检测不自动终止）；
      6) PID 复用 / 身份不可读 / 信息矛盾 → fail-closed；
      7) 检查结果不回显物理 session / launch nonce / 飞书身份 / 凭据。

    返回 {"ok": bool, "error_code": str|None, "findings": [{code, role, detail}]}。
    preflight() / status() / sr2_qualify.py 一律调用本函数，不得各自复制规则。

    注意：心跳/桥锁读取一律走本模块 RUNTIME_DIR（与 preflight 锁检查同口径，
    也被测试 monkeypatch 隔离），不直接读 services.runtime_worker.RUNTIME_DIR，
    避免测试环境口径不一致。
    """
    findings: List[Dict[str, Any]] = []

    def add(code: str, role: str, detail: str = "") -> None:
        findings.append({"code": code, "role": role, "detail": detail})

    def _hb_at(role: str) -> Tuple[Optional[Dict[str, Any]], str]:
        """读取角色 heartbeat。返回 (hb, status)：status in ("ok", "unreadable", "missing")。

        P0-2（Codex 2026-08-19）：JSON 损坏/读取失败必须区分于"文件不存在"——
        不可读按 fail-closed 处理（产生 heartbeat_unreadable finding），不得静默当作 missing。
        """
        p = RUNTIME_DIR / f"{role}.heartbeat.json"
        if not p.exists():
            return None, "missing"
        try:
            d = json.loads(p.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            return None, "unreadable"
        if not isinstance(d, dict):
            return None, "unreadable"
        return d, "ok"

    try:
        reg = load_registry()
    except RegistryCorruptError:
        reg = {"roles": {}}
    entries = reg.get("roles") or {}

    # 桥锁：bot → 桥角色（条件 4）
    bridge_locks = {
        "workbuddy": RUNTIME_DIR / ".bridge_lock_workbuddy",
        "hermes": RUNTIME_DIR / ".bridge_lock_hermes",
        "codex": RUNTIME_DIR / ".bridge_lock_codex",
    }
    lock_holders: Dict[str, int] = {}
    for bot, lp in bridge_locks.items():
        try:
            raw = lp.read_text(encoding="utf-8").strip()
            try:
                holder = int(raw)
            except Exception:
                holder = int((json.loads(raw)).get("pid", 0) or 0)
        except Exception:
            holder = 0
        lock_holders[f"bridge-{bot}"] = holder

    for role in START_ORDER:
        entry = entries.get(role) or {}
        hb, hb_status = _hb_at(role)
        if hb_status == "unreadable":
            # P0-2：身份不可读必须 fail-closed（脱敏 finding，不产出内容）
            add("heartbeat_unreadable", role, "heartbeat corrupt or unreadable")
            continue
        if hb is None:
            continue
        try:
            hb_pid = int(hb.get("runtime_pid") or hb.get("pid") or 0)
        except (TypeError, ValueError):
            hb_pid = 0
        hb_alive = hb_pid > 0 and pid_alive(hb_pid)
        state = hb.get("state")

        # 条件 2：running/starting/reconnecting/connected 但 PID 死亡 → 阻断
        if state in ("running", "starting", "reconnecting", "connected") and hb_pid > 0 and not hb_alive:
            add("hb_active_pid_dead", role, "heartbeat active but pid dead")
            continue
        # 条件 3：stopped 但 PID 仍存活 → 阻断
        if state == "stopped" and hb_pid > 0 and hb_alive:
            add("hb_stopped_pid_alive", role, "heartbeat stopped but pid alive")
            continue
        # 条件 4：桥锁 PID 死亡、heartbeat PID 存活且二者不一致 → 阻断
        lock_pid = lock_holders.get(role, 0)
        if lock_pid > 0 and hb_alive and hb_pid != lock_pid and not pid_alive(lock_pid):
            add("bridge_lock_hb_conflict", role,
                "bridge lock pid dead but heartbeat pid alive and different")
            continue
        # 条件 6：身份不可读 / 信息矛盾 → fail-closed
        if hb_pid <= 0:
            add("hb_identity_unreadable", role, "heartbeat pid unreadable")
            continue
        try:
            reg_pid = int(entry.get("runtime_pid") or 0)
        except (TypeError, ValueError):
            reg_pid = 0
        if reg_pid > 0 and reg_pid != hb_pid:
            add("hb_registry_pid_conflict", role,
                "registry runtime_pid differs from heartbeat pid")
            continue
        # 条件 1：新鲜心跳 + PID 存活 + registry 无完全匹配 → 阻断
        try:
            fresh = (time.time() - float(hb.get("updated_ts") or 0)) <= HEARTBEAT_FRESH_SEC
        except (TypeError, ValueError):
            fresh = False
        if hb_alive and fresh:
            reg_run_id = entry.get("run_id")
            reg_nonce = entry.get("launch_nonce")
            hb_run_id = hb.get("run_id")
            hb_nonce = hb.get("launch_nonce")
            matched = (
                is_identity_token(reg_run_id) and reg_run_id == hb_run_id
                and is_identity_token(reg_nonce) and reg_nonce == hb_nonce
                and reg_pid > 0 and reg_pid == hb_pid
            )
            if not matched:
                add("unregistered_live_runtime", role,
                    "fresh heartbeat live but registry identity not fully matched")
                continue
            # P0-3（Codex 2026-08-19）：完全匹配后必须再做 PID 二次核验——
            # registry 的 start_ts + image 必须有效且与存活 PID 相符，防 PID 复用。
            try:
                reg_start_ts = float(entry.get("start_ts") or 0)
            except (TypeError, ValueError):
                reg_start_ts = 0.0
            reg_image = str(entry.get("image") or "").strip() or None
            if reg_start_ts <= 0 or not reg_image:
                add("unregistered_live_runtime", role,
                    "registry start_ts/image missing, pid identity unverifiable")
                continue
            ident = verify_pid_identity(hb_pid, reg_start_ts, reg_image)
            if not ident.get("verified"):
                add("unregistered_live_runtime", role,
                    "pid identity mismatch (start_ts/image), possible pid reuse")
                continue

    # 条件 5：精确入口命令扫描未登记角色进程（只检测不自动终止）
    found_procs, scan_complete = _scan_unregistered_role_processes()
    if not scan_complete:
        # P0-2：扫描不完整（psutil 缺失/异常/AccessDenied）→ fail-closed
        add("process_scan_incomplete", "?", "process scan incomplete (psutil unavailable or access denied)")
    else:
        for proc in found_procs:
            add("unregistered_role_process", proc.get("role", "?"),
                f"cmdline entry {proc.get('entry', '?')} pid={proc.get('pid')} not in registry")

    ok = not findings
    return {
        "ok": ok,
        "error_code": "unregistered_live_runtime" if not ok else None,
        "findings": findings,
    }


# ---------------------------------------------------------------- 受控 registry 恢复
def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# ---- SR-1.2a：文件操作注入点（统一 fail-closed，便于故障注入测试） ----
def _open_exclusive(path: Path):
    """独占创建；已存在则抛 FileExistsError（同名竞争绝不错覆盖）。"""
    return open(path, "xb")


def _copy_all(fsrc, fdst, chunk_size: int = 1 << 20) -> int:
    total = 0
    while True:
        chunk = fsrc.read(chunk_size)
        if not chunk:
            break
        fdst.write(chunk)
        total += len(chunk)
    fdst.flush()
    os.fsync(fdst.fileno())
    return total


def _stream_copy(src: Path, dst: Path) -> int:
    """独占创建 dst 并复制 src 字节（含 fsync）。dst 已存在→FileExistsError。"""
    with open(src, "rb") as fsrc:
        with _open_exclusive(dst) as fdst:
            return _copy_all(fsrc, fdst)


def _publish_atomic(src: Path, dst: Path) -> None:
    """原子替换 dst←src（同卷）。注入点：测试可 monkeypatch 模拟替换失败。"""
    os.replace(src, dst)


def _build_clean_registry(actual_sha: str, expected: str,
                          reused_stale: List[str]) -> Dict[str, Any]:
    clean_roles = {}
    for role in ROLE_SPECS:
        clean_roles[role] = {
            "role": role,
            "status": "stopped",
            "pid": None,
            "spawn_pid": None,
            "runtime_pid": None,
            "kind": ROLE_SPECS[role]["kind"],
            "process_tree": None,
            "snapshot_complete": True,
        }
    return {
        "version": 1,
        "updated_at": _now_iso(),
        "last_status": "stopped",
        "last_action": "recover_stale_registry",
        "roles": clean_roles,
        "recovery": {
            "recovered_by": "recover_stale_registry",
            "recovered_at": _now_iso(),
            "reason": ("manual_cleanup_required: registry was stop_incomplete with no "
                       "live Triad processes (Codex SR-1.2 Plan A)"),
            "original_sha256": actual_sha,
            "expected_sha256": expected,
            "reused_stale_pids": reused_stale,
            "note": "不伪造正常停机；仅清空 PID/process_tree 并标记人工恢复。",
        },
    }


def _validate_clean_registry(clean: Dict[str, Any]) -> None:
    """校验干净 registry schema；任一不符抛 ValueError（fail-closed）。"""
    if not isinstance(clean, dict):
        raise ValueError("clean not dict")
    if clean.get("version") != 1:
        raise ValueError("version!=1")
    if clean.get("last_status") != "stopped":
        raise ValueError("last_status!=stopped")
    roles = clean.get("roles")
    if not isinstance(roles, dict):
        raise ValueError("roles missing")
    for role in ROLE_SPECS:
        r = roles.get(role)
        if not isinstance(r, dict):
            raise ValueError(f"role {role} missing")
        if r.get("status") != "stopped":
            raise ValueError(f"role {role} status")
        if r.get("pid") is not None or r.get("spawn_pid") is not None \
                or r.get("runtime_pid") is not None:
            raise ValueError(f"role {role} has pid")
        if r.get("process_tree") is not None:
            raise ValueError(f"role {role} has tree")
        if r.get("snapshot_complete") is not True:
            raise ValueError(f"role {role} snapshot_complete")


def _write_clean_tmp(rp: Path, clean: Dict[str, Any]) -> Path:
    """把干净 registry 写入唯一临时文件并 fsync；返回临时路径。"""
    import tempfile
    fd, tmp_str = tempfile.mkstemp(
        prefix=".runtime_registry.clean.", suffix=".tmp", dir=str(rp.parent))
    tmp = Path(tmp_str)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(json.dumps(clean, ensure_ascii=False, indent=2))
            f.flush()
            os.fsync(f.fileno())
    except Exception:  # noqa: BLE001
        try:
            tmp.unlink()
        except OSError:  # noqa: BLE001
            pass
        raise
    return tmp


def _restore_from_archive(rp: Path, archive_path: Path, expected_sha: str) -> None:
    """从保留归档恢复原始字节到 rp（不移动/覆盖归档本身）。失败抛 OSError。"""
    import tempfile
    fd, tmp_str = tempfile.mkstemp(
        prefix=".runtime_registry.restore.", suffix=".tmp", dir=str(rp.parent))
    tmp = Path(tmp_str)
    try:
        with os.fdopen(fd, "wb") as f:
            data = archive_path.read_bytes()
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        _publish_atomic(tmp, rp)
    except Exception:  # noqa: BLE001
        try:
            tmp.unlink()
        except OSError:  # noqa: BLE001
            pass
        raise
    try:
        tmp.unlink()
    except OSError:  # noqa: BLE001
        pass
    if _sha256_file(rp) != expected_sha:
        raise OSError(f"sha mismatch after restore: {rp}")


def recover_stale_registry(dry_run: bool, expected_sha256: str) -> Dict[str, Any]:
    """受控恢复被 stop_incomplete 污染的默认 registry（Codex SR-1.2 Plan A / SR-1.2a 两阶段发布）。

    全程**绝不终止任何进程**。fail-closed：任一守卫/阶段失败即拒、原始文件不变、不返回 ok=true。

    只读守卫（dry-run 与 apply 共用）：
      1) supervisor 单实例锁；
      2) registry 存在且可读；
      3) 当前文件 SHA256 与 --expected-sha256 一致（未提供即拒；幂等也先比 SHA）；
      4) last_status 必须为 stop_incomplete（已 stopped 且 SHA 一致 → already_recovered）；
      5) 枚举 spawn_pid/runtime_pid/process_tree 逐 PID 身份核验
         （活且吻合→拒；复用不符→不终止；不可读→fail-closed）；
      6) 8900 空闲、无活动角色锁、无可信心跳。

    apply 两阶段发布（持 supervisor 锁，原始文件在最终原子替换前一字未改）：
      A-1) 重算 SHA 仍 == expected；独占创建归档（open 'xb'，绝不错覆盖）并流式复制
           + fsync + 复验 SHA；归档后原文件仍在原位、字节不变；
      A-2) 生成干净 registry 唯一临时文件并 schema 校验 + fsync；
      B) 原子替换正式 registry；写后复读校验；失败则从保留归档恢复原始字节并复验 SHA。
      回滚失败返回 rollback_failed（绝不 except:pass），归档始终保留、绝不移动/覆盖。

    dry_run=True 只跑只读守卫（含 SHA），不落任何写操作，结束后释放锁。
    """
    expected = (expected_sha256 or "").strip().lower()
    guards: List[Dict[str, Any]] = []

    def _g(name: str, ok: bool, detail: str = "") -> None:
        guards.append({"guard": name, "ok": bool(ok), "detail": detail})

    def _refuse(error_code: str, detail: str = "") -> Dict[str, Any]:
        # 拒绝路径统一释放 supervisor 锁（除非锁本身未拿到）
        release_role_lock(SUPERVISOR_ROLE)
        return {
            "ok": False,
            "action": "recover_stale_registry",
            "dry_run": dry_run,
            "all_guards_passed": False,
            "error_code": error_code,
            "detail": detail,
            "guards": guards,
        }

    # 守卫 1：supervisor 单实例锁
    if not acquire_role_lock(SUPERVISOR_ROLE):
        _g("supervisor_lock", False, "lock_held_by_another")
        return {
            "ok": False, "action": "recover_stale_registry", "dry_run": dry_run,
            "all_guards_passed": False, "error_code": "supervisor_lock_held",
            "guards": guards,
        }
    _g("supervisor_lock", True, "")

    rp = registry_path()

    # 守卫 2：文件存在 + 可读 + 状态要求
    if not rp.exists():
        _g("registry_present", False, "file_missing")
        return _refuse("registry_missing")
    try:
        reg = load_registry()
    except RegistryCorruptError as exc:
        _g("registry_readable", False, f"corrupt:{exc}")
        return _refuse("registry_corrupt", str(exc))
    _g("registry_readable", True, "")

    # 守卫 3：SHA 比对（幂等前先比 SHA，错 SHA 一律拒，杜绝错误 SHA 也成功）
    if not expected:
        _g("sha_matches_expected", False, "expected_sha256_required")
        return _refuse("expected_sha256_required")
    actual_sha = _sha256_file(rp)
    if actual_sha != expected:
        _g("sha_matches_expected", False,
           f"expected={expected[:16]} actual={actual_sha[:16]}")
        return _refuse("sha_mismatch", f"expected={expected[:16]}")
    _g("sha_matches_expected", True, actual_sha[:16])

    # 守卫 4：状态要求（已 stopped 且 SHA 一致 → 幂等）
    last_status = reg.get("last_status") or ""
    if last_status == "stopped":
        _g("requires_stop_incomplete", True, "already_stopped")
        release_role_lock(SUPERVISOR_ROLE)
        return {
            "ok": True, "action": "recover_stale_registry", "dry_run": dry_run,
            "all_guards_passed": True, "idempotent": True,
            "result": "already_recovered", "guards": guards,
        }
    if last_status != "stop_incomplete":
        _g("requires_stop_incomplete", False, f"last_status={last_status}")
        return _refuse("unexpected_last_status", last_status)
    _g("requires_stop_incomplete", True, "stop_incomplete")

    # 守卫 3/4：枚举 PID 并逐 PID 身份核验
    roles = reg.get("roles", {}) or {}
    candidates: List[Dict[str, Any]] = []
    for role, entry in roles.items():
        if not isinstance(entry, dict):
            continue
        for key in ("spawn_pid", "runtime_pid"):
            v = entry.get(key)
            if isinstance(v, int) and v > 0:
                candidates.append({"role": role, "kind": key, "pid": v,
                                    "start_ts": entry.get("start_ts"),
                                    "image": entry.get("image")})
        tree = entry.get("process_tree")
        if isinstance(tree, dict):
            for pk, tv in tree.items():
                try:
                    pki = int(pk)
                except (TypeError, ValueError):
                    continue
                if pki > 0:
                    exp_st = tv[1] if isinstance(tv, (list, tuple)) and len(tv) > 1 else None
                    exp_img = tv[2] if isinstance(tv, (list, tuple)) and len(tv) > 2 else None
                    candidates.append({"role": role, "kind": "process_tree", "pid": pki,
                                        "start_ts": exp_st, "image": exp_img})

    live_matching: List[str] = []
    reused_stale: List[str] = []
    for c in candidates:
        pid = c["pid"]
        if not pid_alive(pid):
            continue  # 已死：陈旧，无需处理也不终止
        try:
            st = process_start_time(pid)
            img = process_image_name(pid)
        except Exception:  # noqa: BLE001
            st, img = None, None
        if st is None or img is None:
            # 身份不可读 → fail-closed
            _g("pid_identity_readable", False,
               f"{c['role']}:{c['kind']}:pid={pid}:unreadable")
            return _refuse("pid_identity_unreadable",
                           f"{c['role']}:{c['kind']}:pid={pid}")
        verified = True
        if c["start_ts"] is not None:
            try:
                verified = verified and abs(float(st) - float(c["start_ts"])) <= 2.0
            except (TypeError, ValueError):
                verified = False
        if c["image"] is not None:
            verified = verified and str(img).lower() == str(c["image"]).lower()
        if verified:
            live_matching.append(f"{c['role']}:{c['kind']}:pid={pid}")
        else:
            reused_stale.append(f"{c['role']}:{c['kind']}:pid={pid} (reused, not terminated)")
    _g("no_live_matching_process", not live_matching,
       f"matching={len(live_matching)} reused={len(reused_stale)}")

    # 守卫 5：端口空闲 / 无活动锁 / 无同一 run_id/nonce 可信心跳
    port_busy = _port_in_use(config.HOST, config.PORT)
    _g("hub_port_free", not port_busy, "in_use" if port_busy else "")

    active_locks: List[str] = []
    for role in ROLE_SPECS:
        lock = RUNTIME_DIR / f".role_lock_{role}"
        if lock.exists():
            try:
                holder = int((lock.read_text(encoding="utf-8").strip() or "0"))
            except Exception:  # noqa: BLE001
                holder = 0
            if holder and pid_alive(holder):
                active_locks.append(role)
    for bot in ("workbuddy", "hermes", "codex"):
        blk = RUNTIME_DIR / f".bridge_lock_{bot}"
        if blk.exists():
            try:
                raw = blk.read_text(encoding="utf-8").strip()
                try:
                    holder = int(raw)
                except Exception:
                    holder = int((json.loads(raw)).get("pid", 0) or 0)
            except Exception:  # noqa: BLE001
                holder = 0
            if holder and pid_alive(holder):
                active_locks.append(f"bridge-{bot}")
    _g("no_active_locks", not active_locks, f"held={len(active_locks)}")

    trusted_hb: List[str] = []
    for role, entry in roles.items():
        if not isinstance(entry, dict):
            continue
        rid = entry.get("run_id")
        nonce = entry.get("launch_nonce")
        if not (is_identity_token(rid) and is_identity_token(nonce)):
            continue
        hb = read_heartbeat(role)
        if not hb:
            continue
        if hb.get("state") != "running":
            continue
        if hb.get("run_id") != rid or hb.get("launch_nonce") != nonce:
            continue
        try:
            up = float(hb.get("updated_ts"))
        except (TypeError, ValueError):
            up = 0.0
        if (time.time() - up) > HEARTBEAT_FRESH_SEC:
            continue
        hb_pid = hb.get("runtime_pid")
        if isinstance(hb_pid, int) and hb_pid > 0 and pid_alive(hb_pid):
            trusted_hb.append(role)
    _g("no_trusted_running_heartbeat", not trusted_hb,
       f"roles={','.join(trusted_hb)}")

    # 任一守卫未过 → 拒绝（不写）
    if live_matching or active_locks or trusted_hb or port_busy:
        reasons = []
        if live_matching:
            reasons.append("live_matching_process=" + ";".join(live_matching))
        if active_locks:
            reasons.append("active_locks=" + ",".join(active_locks))
        if trusted_hb:
            reasons.append("trusted_heartbeat=" + ",".join(trusted_hb))
        if port_busy:
            reasons.append("hub_port_busy")
        return _refuse("guard_blocked", ";".join(reasons))

    # ---- 守卫 1-6 全部通过 ----
    all_passed = all(g["ok"] for g in guards)
    if dry_run or not all_passed:
        release_role_lock(SUPERVISOR_ROLE)
        return {
            "ok": all_passed,
            "action": "recover_stale_registry",
            "dry_run": dry_run,
            "all_guards_passed": all_passed,
            "result": "dry_run_passed" if all_passed else "dry_run_blocked",
            "reused_stale_pids": reused_stale,
            "original_sha256": actual_sha,
            "guards": guards,
        }

    # ============ apply：两阶段发布（持 supervisor 锁） ============
    archive_dir = rp.parent / "archive"
    archive_dir.mkdir(parents=True, exist_ok=True)
    ts = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    archive_path = archive_dir / f"runtime_registry_recovered_{actual_sha[:16]}_{ts}.json"

    # 发布前最后重算 SHA（持锁期间检测并发改动）
    final_sha = _sha256_file(rp)
    if final_sha != expected:
        return _refuse("sha_changed_before_publish",
                       f"expected={expected[:16]} now={final_sha[:16]}")

    # 阶段 A-1：独占创建归档（原始 rp 始终未动，绝不错覆盖）
    try:
        _stream_copy(rp, archive_path)
    except FileExistsError:
        return _refuse("archive_path_collision", str(archive_path))
    except OSError as exc:  # noqa: BLE001
        return _refuse("archive_create_failed", f"{type(exc).__name__}:{exc}")
    if _sha256_file(archive_path) != actual_sha:
        try:
            archive_path.unlink()
        except OSError:  # noqa: BLE001
            pass
        return _refuse("archive_sha_mismatch", actual_sha[:16])
    _g("archive_no_overwrite", True, str(archive_path))
    _g("archive_sha_consistent", True, actual_sha[:16])

    # 阶段 A-2：生成干净 registry 临时文件 + schema 校验（rp 仍不动）
    clean = _build_clean_registry(actual_sha, expected, reused_stale)
    try:
        tmp = _write_clean_tmp(rp, clean)
    except OSError as exc:  # noqa: BLE001
        return _refuse("clean_write_failed", f"{type(exc).__name__}:{exc}")
    try:
        loaded = json.loads(Path(tmp).read_text(encoding="utf-8"))
        _validate_clean_registry(loaded)
    except Exception as exc:  # noqa: BLE001
        try:
            Path(tmp).unlink()
        except OSError:  # noqa: BLE001
            pass
        return _refuse("clean_validate_failed", f"{type(exc).__name__}:{exc}")

    # 阶段 B：原子替换正式 registry（此前 rp 一字未改）
    try:
        _publish_atomic(Path(tmp), rp)
    except OSError as exc:  # noqa: BLE001
        try:
            Path(tmp).unlink()
        except OSError:  # noqa: BLE001
            pass
        return _refuse("publish_replace_failed", f"{type(exc).__name__}:{exc}")

    # 写后复读校验；失败则从保留归档恢复原始字节（回滚失败返回 rollback_failed）
    try:
        reloaded = load_registry()
    except RegistryCorruptError as exc:
        try:
            _restore_from_archive(rp, archive_path, actual_sha)
        except OSError as exc2:  # noqa: BLE001
            return _refuse("rollback_failed", f"restore:{type(exc2).__name__}:{exc2}")
        return _refuse("clean_readback_corrupt", str(exc))
    if (reloaded.get("last_status") or "") != "stopped":
        try:
            _restore_from_archive(rp, archive_path, actual_sha)
        except OSError as exc2:  # noqa: BLE001
            return _refuse("rollback_failed", f"restore:{type(exc2).__name__}:{exc2}")
        return _refuse("clean_readback_status", reloaded.get("last_status"))

    release_role_lock(SUPERVISOR_ROLE)
    return {
        "ok": True,
        "action": "recover_stale_registry",
        "dry_run": False,
        "all_guards_passed": True,
        "result": "recovered",
        "original_sha256": actual_sha,
        "archive_path": str(archive_path),
        "registry_path": str(rp),
        "reused_stale_pids": reused_stale,
        "guards": guards,
    }


# ---------------------------------------------------------------- CLI
def main(argv=None) -> int:
    install_stream_redactor()
    parser = argparse.ArgumentParser(description="Triad 统一运行时 supervisor")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--preflight", action="store_true")
    group.add_argument("--start", action="store_true")
    group.add_argument("--status", action="store_true")
    group.add_argument("--stop", action="store_true")
    group.add_argument(
        "--recover-evidence",
        action="store_true",
        help="显式恢复 stdout 证据（Gate5-B2 v4）：处理 pending 登记与孤立 tmp，"
             "会修改数据库与文件；preflight 只做只读 audit 不恢复",
    )
    group.add_argument(
        "--recover-stale-registry",
        action="store_true",
        help="受控恢复被 stop_incomplete 污染的默认 registry（Codex SR-1.2 Plan A）："
             "先 --dry-run 验证全部守卫，再 --apply 一次。绝不终止进程。",
    )
    parser.add_argument(
        "--expected-sha256",
        default="",
        help="--recover-stale-registry 必须传入：当前 registry 文件 SHA256，"
             "与磁盘实际不符即拒绝（防误操作错误文件）。",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        default=False,
        help="--recover-stale-registry：只跑守卫 1-6，不落任何写操作。",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        default=False,
        help="--recover-stale-registry：守卫全过后执行归档+写干净 registry（仅一次）。",
    )
    parser.add_argument(
        "--require-live-bridges",
        action="store_true",
        default=False,
        help="要求 TRIAD_BRIDGE_DRY_RUN=false（Gate 4 正式接通时使用）",
    )
    args = parser.parse_args(argv)

    if args.preflight:
        out = preflight()
    elif args.start:
        out = start_all(dry_run_ok=not args.require_live_bridges)
    elif args.status:
        out = status()
    elif args.recover_evidence:
        from adapters.extract import recover_stdout_evidence
        out = recover_stdout_evidence()
        out["ok"] = True
    elif args.recover_stale_registry:
        if not args.expected_sha256:
            out = {
                "ok": False, "action": "recover_stale_registry",
                "all_guards_passed": False, "error_code": "expected_sha256_required",
                "guards": [],
            }
        elif args.apply:
            out = recover_stale_registry(dry_run=False, expected_sha256=args.expected_sha256)
        else:
            out = recover_stale_registry(dry_run=True, expected_sha256=args.expected_sha256)
    else:
        out = stop_all()

    print(json.dumps(out, ensure_ascii=False, indent=2))
    return 0 if out.get("ok", True) else 1


if __name__ == "__main__":
    sys.exit(main())
