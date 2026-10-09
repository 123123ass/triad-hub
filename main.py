"""Triad Hub 入口（Step 5.7 最小安全入口）。

只暴露：
- GET  /health/live
- GET  /health/ready
- POST /internal/feishu/events   （带 HMAC 鉴权的飞书内部入口）

旧入口 POST /event 与 POST /agent/wb 固定返回 410 endpoint_retired，
不得继续执行原逻辑、不得调用任何 Agent、不得发送飞书消息。

所有拒绝路径只返回稳定错误码，绝不回显 traceback、请求 body、HMAC、
sender 完整资料或原始飞书 content。
"""
from __future__ import annotations

import asyncio
import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

import db
import security
from config import config
from logging_config import get_logger
from services import feishu_ingress

app = FastAPI(title="Triad Hub")

logger = get_logger("hub.main")

MIGRATIONS_DIR = Path(__file__).resolve().parent / "migrations"

# 有界线程池：飞书入站入库等同步 DB 操作不得阻塞 FastAPI 事件循环
# （Gate5-B2-WB：锁故障时快速失败，禁止无界堆积）
_INGRESS_POOL = ThreadPoolExecutor(max_workers=4, thread_name_prefix="ingress")


def expected_migrations() -> list[str]:
    """迁移注册表（migrations/*.sql 文件名）按版本升序。

    Step 11 修正：此前硬编码 LATEST_MIGRATION="002_step5_feishu"，
    003~007 缺失时 /health/ready 依然返回 200，属于假就绪。
    """
    try:
        return sorted(f.stem for f in MIGRATIONS_DIR.glob("*.sql"))
    except OSError:
        return []


def latest_migration() -> str:
    versions = expected_migrations()
    return versions[-1] if versions else ""


# ---------------- 5.7.1 Live 检查 ----------------
@app.get("/health/live")
def health_live() -> JSONResponse:
    # 不访问外部 Agent、不访问 DB。
    return JSONResponse(
        status_code=200,
        content={"status": "ok", "service": "triad-hub"},
    )


# ---------------- 5.7.2 Ready 检查 ----------------
def check_database_readiness(
    *,
    write_probe_timeout_ms: int = 1500,
    read_timeout_ms: int = 500,
) -> dict:
    """数据库就绪检查（Gate5-B2-WB DGN-3）。

    返回固定结构：{"ready": bool, "error_code": str | None, "migration": str | None}

    执行顺序：
    1. 先 db.probe_db_write_lock(timeout_ms=1500)——被锁立即返回 db_write_locked，不做完整检查。
    2. 写锁可用后用 read_only 连接：SELECT 1 + 迁移检查 + PRAGMA quick_check(1)。
    - readiness 不做完整 PRAGMA integrity_check（留在 preflight）。
    - 只读连接 busy_timeout<=500ms。
    - 不回显异常全文/SQL/路径/PID/身份。
    """
    # 1) 写锁探针（非数据变更型）
    try:
        probe = db.probe_db_write_lock(timeout_ms=write_probe_timeout_ms)
    except Exception:  # noqa: BLE001
        return {"ready": False, "error_code": "db_unavailable", "migration": None}
    if not probe.get("ready"):
        return {"ready": False, "error_code": "db_write_locked", "migration": None}

    # 2) 只读检查（SELECT 1 + 迁移 + quick_check）
    try:
        conn = db.connect(read_only=True, busy_timeout_ms=read_timeout_ms)
        try:
            conn.execute("SELECT 1")
            row = conn.execute("PRAGMA quick_check(1)").fetchone()
            if row is None or tuple(row) != ("ok",):
                return {"ready": False, "error_code": "db_unavailable", "migration": None}
            expected = expected_migrations()
            applied = {
                r["version"] for r in conn.execute("SELECT version FROM schema_migrations")
            }
            if not (expected and all(v in applied for v in expected)):
                return {"ready": False, "error_code": "migration_missing",
                        "migration": latest_migration()}
            return {"ready": True, "error_code": None, "migration": latest_migration()}
        finally:
            conn.close()
    except Exception:  # noqa: BLE001 —— 不回显 DB 异常原文
        return {"ready": False, "error_code": "db_unavailable", "migration": None}


@app.get("/health/ready")
def health_ready() -> JSONResponse:
    error_codes: list[str] = []

    # 1) 回环绑定
    if not (config.LOOPBACK_ONLY and security.is_loopback(config.HOST)):
        error_codes.append("loopback_denied")

    # 2) 必填安全配置
    if config.missing_required():
        error_codes.append("missing_config")
    if not config.HUB_INTERNAL_HMAC_SECRET:
        error_codes.append("hmac_unconfigured")

    # 3) 三个 Bot Open ID 是否配置（只报是否，禁止返回完整值）
    open_ids = config.bot_open_ids()
    if not all(open_ids.values()):
        error_codes.append("bot_open_ids_missing")

    # 4) 数据库就绪（Gate5-B2-WB DGN-3：写锁探针优先，锁下快速 503 db_write_locked）
    db_state = check_database_readiness()
    if not db_state.get("ready"):
        db_code = db_state.get("error_code")
        if db_code == "db_write_locked":
            return JSONResponse(
                status_code=503,
                content={
                    "status": "not_ready",
                    "error_codes": ["db_write_locked"],
                    "db_write_ready": False,
                    "db_lock_holder_known": False,
                    "db_lock_holder_role": None,
                },
            )
        error_codes.append(db_code or "db_unavailable")

    if error_codes:
        return JSONResponse(
            status_code=503,
            content={"status": "not_ready", "error_codes": error_codes},
        )

    return JSONResponse(
        status_code=200,
        content={
            "status": "ready",
            "db": "ok",
            "security": "ok",
            "migration": db_state.get("migration") or latest_migration(),
            "bot_open_ids_configured": {
                "workbuddy": bool(open_ids["workbuddy"]),
                "codex": bool(open_ids["codex"]),
                "hermes": bool(open_ids["hermes"]),
            },
            "db_write_ready": True,
            "db_lock_holder_known": False,
            "db_lock_holder_role": None,
        },
    )


def db_lock_state() -> dict:
    """运行期写锁状态（只返回脱敏字段；锁持续超过阈值时 ready 应 503）。"""
    import os
    import time as _time

    from pathlib import Path as _Path

    runtime_dir = None
    try:
        runtime_dir = Path(config.RUNTIME_DIR) if hasattr(config, "RUNTIME_DIR") else (
            Path(config.DB_PATH).parent / "runtime"
        )
    except Exception:  # noqa: BLE001
        runtime_dir = Path(config.DB_PATH).parent / "runtime"

    holders = []
    now = _time.time()
    try:
        if runtime_dir and runtime_dir.exists():
            for f in runtime_dir.glob("db_tx_*.json"):
                try:
                    d = json.loads(f.read_text(encoding="utf-8"))
                    phase = d.get("phase")
                    if phase == "holding":
                        holders.append({
                            "role": d.get("role", "unknown"),
                            "pid": d.get("pid"),
                            "operation": d.get("operation", ""),
                        })
                except Exception:  # noqa: BLE001
                    continue
    except Exception:  # noqa: BLE001
        pass

    if holders:
        return {
            "db_write_ready": False,
            "db_lock_age_ms": None,
            "db_lock_holder_known": True,
            "db_lock_holder_role": holders[0].get("role"),
        }
    return {
        "db_write_ready": True,
        "db_lock_age_ms": None,
        "db_lock_holder_known": False,
        "db_lock_holder_role": None,
    }


# ---------------- 5.7.3 飞书内部入口 ----------------
def _status_to_http(result: Dict[str, Any]) -> tuple[int, Dict[str, Any]]:
    status = result.get("status")
    event_seq = result.get("event_seq")
    error_code = result.get("error_code")
    if status == "accepted":
        return 202, {"status": "accepted", "event_seq": event_seq, "error_code": None}
    if status == "duplicate":
        return 200, {"status": "duplicate", "event_seq": event_seq, "error_code": None}
    if status == "paused":
        return 409, {"status": "paused", "event_seq": None, "error_code": "paused"}
    # status == "rejected"
    code = error_code
    if code in (feishu_ingress.ERR_CHAT_DENIED,
                feishu_ingress.ERR_SENDER_DENIED,
                feishu_ingress.ERR_ADMIN_DENIED):
        http = 403
    elif code == feishu_ingress.ERR_SCHEMA_INVALID:
        http = 422
    elif code == feishu_ingress.ERR_DB_BUSY:
        http = 503
    else:
        http = 500  # internal_error_redacted
        code = "internal_error_redacted"
    return http, {"status": "rejected", "event_seq": None, "error_code": code}


@app.post("/internal/feishu/events")
async def internal_feishu_events(request: Request) -> JSONResponse:
    started = time.time()
    raw_body = await request.body()
    timestamp = request.headers.get("X-Triad-Timestamp")
    signature = request.headers.get("X-Triad-Signature")

    # 1) HMAC 鉴权
    hmac_code = security.verify_signature(raw_body, timestamp, signature)
    if hmac_code != security.OK:
        return JSONResponse(
            status_code=401,
            content={"status": "rejected", "event_seq": None, "error_code": hmac_code},
        )

    # 2) 解析 JSON
    try:
        payload = __import__("json").loads(raw_body)
    except Exception:  # noqa: BLE001 —— 不回显 body
        return JSONResponse(
            status_code=422,
            content={"status": "rejected", "event_seq": None, "error_code": "invalid_json"},
        )

    # 3) 入库（放有界线程池执行，不阻塞 FastAPI 事件循环；异常兜底 500）
    try:
        result = await asyncio.get_running_loop().run_in_executor(
            _INGRESS_POOL, feishu_ingress.ingest_feishu_event, payload
        )
    except Exception as exc:  # noqa: BLE001
        logger.exception("ingest_error", exc=exc, event="internal_feishu_events")
        return JSONResponse(
            status_code=500,
            content={"status": "rejected", "event_seq": None, "error_code": "internal_error_redacted"},
        )

    http_status, body = _status_to_http(result)
    logger.info(
        "internal_feishu_events",
        event_id=(payload or {}).get("raw_event", {}).get("event_id"),
        status=body["status"],
        event_seq=body.get("event_seq"),
        error_code=body.get("error_code"),
        duration_ms=int((time.time() - started) * 1000),
    )
    return JSONResponse(status_code=http_status, content=body)


# ---------------- 5.7.4 公共旧接口（已退役） ----------------
@app.post("/event")
def retired_event_endpoint() -> JSONResponse:
    return JSONResponse(
        status_code=410,
        content={"status": "rejected", "error_code": "endpoint_retired"},
    )


@app.post("/agent/wb")
def retired_wb_endpoint() -> JSONResponse:
    return JSONResponse(
        status_code=410,
        content={"status": "rejected", "error_code": "endpoint_retired"},
    )


HUB_ROLE = "hub"

# Hub 心跳刷新间隔（秒）。
#
# 必须显著小于 supervisor 的心跳过期窗口 run_triad_runtime.HEARTBEAT_FRESH_SEC（90s）。
# 原因（Gate4 B-2）：serve() 原本只在 uvicorn.run 之前写一次心跳，Hub 正常服务超过
# 90 秒后这份心跳必然被判 stale，--status 会把一个活得好好的 Hub 标成 untrusted /
# unmanaged，Gate4「Hub 运行 >90s 仍可信」这一条永远过不了。
HEARTBEAT_REFRESH_SEC = 20.0


def serve() -> None:
    """Hub 进程入口（Gate4 F-2 修复，Codex 批准：写在 __main__ 路径，不引 FastAPI lifespan）。

    先落一份真实 runtime_pid 心跳，再把控制权交给 uvicorn 阻塞运行。

    为什么不用 FastAPI lifespan：lifespan 会在 reload / 多 worker 场景下于子进程重复触发，
    身份归属反而歧义。这里 uvicorn.run 传的是 app 对象（不是 "main:app" 字符串），
    既不 reload 也不 fork，因此本函数中的 os.getpid() 就是真实 Hub 进程身份。

    没有这份心跳时，supervisor 只能拿到 Windows DETACHED_PROCESS 的瞬退壳 PID，
    停机会误判 already_exited，留下仍占着端口的孤儿 uvicorn，下一轮 preflight
    的 hub_port_free 必然失败并陷入死循环。
    """
    import uvicorn

    # 走模块属性而非 from-import：每次调用都取当前实现，便于离线测试替换，
    # 生产语义完全一致。
    from services import runtime_worker as _rw

    _rw.write_heartbeat(HUB_ROLE, state="running", last_status="serving")

    stop_refresh = threading.Event()

    def _refresh_loop() -> None:
        """周期续写同一身份的 running 心跳。

        身份令牌（run_id / launch_nonce）由 write_heartbeat 统一从
        TRIAD_RUN_ID / TRIAD_LAUNCH_NONCE 解析，与启动那次完全一致，不会漂移；
        runtime_pid 同为本进程 os.getpid()。
        """
        # 先等再写：避免刚启动就重复写一遍。
        while not stop_refresh.wait(max(float(HEARTBEAT_REFRESH_SEC), 0.001)):
            try:
                _rw.write_heartbeat(HUB_ROLE, state="running", last_status="serving")
            except Exception as exc:  # noqa: BLE001 - 刷新失败绝不允许拖垮 Hub 主流程
                # 不得静默、不得崩主流程、不得回显 nonce / run_id 等环境值：
                # 只记稳定错误码 + 异常类型名。
                logger.error(
                    "hub_heartbeat_refresh_failed",
                    status="degraded",
                    error_code="hub_heartbeat_refresh_failed",
                    reason=type(exc).__name__,
                )

    refresher = threading.Thread(
        target=_refresh_loop, name="hub-heartbeat-refresher", daemon=True
    )
    refresher.start()
    try:
        uvicorn.run(app, host=config.HOST, port=config.PORT)
    finally:
        # 顺序不可颠倒：先置停止事件并等线程回收，再写最终 stopped。
        # 否则刷新线程可能在 stopped 之后迟到一拍把心跳写回 running，
        # 留下"已停机却显示运行中"的假象。
        stop_refresh.set()
        refresher.join(timeout=max(float(HEARTBEAT_REFRESH_SEC) * 2.0, 5.0))
        _rw.write_heartbeat(HUB_ROLE, state="stopped", last_status="stopped")


if __name__ == "__main__":
    serve()
