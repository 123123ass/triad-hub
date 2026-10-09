"""tools/run_agent_worker.py —— 单个 Agent 常驻 worker 入口（Step 11 / Gate 1）。

用法：
    python tools/run_agent_worker.py --agent workbuddy --worker-id triad-wb-worker-1
    python tools/run_agent_worker.py --agent hermes   --worker-id triad-hermes-worker-1
    python tools/run_agent_worker.py --agent codex    --worker-id triad-codex-worker-1

行为：
- 启动即安装日志脱敏（install_stream_redactor）。
- 单实例角色锁：同一 agent 只允许一个 worker 进程。
- 注册 SIGINT/SIGTERM/SIGBREAK 正常退出：置位 stop_event，当前调用跑完即退。
- 周期写脱敏心跳文件 runtime/agent-<agent>.heartbeat.json（只含角色/PID/时间/状态）。

安全红线：
- 绝不打印或落盘 prompt、Agent 回复正文、stdout/stderr、命令行、凭据。
- result_unknown 一律不自动重试，只落稳定错误码等待人工复核。

退出码：0 正常停机；2 未拿到角色锁（已有实例在跑）；3 参数错误。
"""
from __future__ import annotations

import argparse
import os
import signal
import sys
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from logging_config import get_logger  # noqa: E402
from config import config  # noqa: E402
from redaction import install_stream_redactor  # noqa: E402
from services.runtime_worker import (  # noqa: E402
    AGENTS,
    acquire_role_lock,
    clear_stop_request,
    recover_runtime_state,
    release_role_lock,
    run_agent_loop,
    start_stop_file_watcher,
    write_heartbeat,
)

log = get_logger("run_agent_worker")

DEFAULT_WORKER_ID = {
    "workbuddy": "triad-wb-worker-1",
    "hermes": "triad-hermes-worker-1",
    "codex": "triad-codex-worker-1",
}


def _install_signal_handlers(stop_event: threading.Event) -> None:
    def _handler(signum, _frame):  # noqa: ANN001
        log.info("worker_signal", status="stopping", reason=str(signum))
        stop_event.set()

    for name in ("SIGINT", "SIGTERM", "SIGBREAK"):
        sig = getattr(signal, name, None)
        if sig is None:
            continue
        try:
            signal.signal(sig, _handler)
        except (ValueError, OSError):  # 非主线程或平台不支持
            pass


def main(argv=None) -> int:
    install_stream_redactor()
    parser = argparse.ArgumentParser(description="Triad Agent 常驻 worker")
    parser.add_argument("--agent", required=True, choices=list(AGENTS))
    parser.add_argument("--worker-id", default=None, help="稳定 worker 标识，重启后保持不变")
    parser.add_argument("--idle-wait-sec", type=float, default=0.25)
    parser.add_argument(
        "--recover-on-start",
        action="store_true",
        default=False,
        help="独立启动时才用；由 supervisor 统一拉起时不要开（避免多进程并发恢复）",
    )
    args = parser.parse_args(argv)

    agent = args.agent
    worker_id = args.worker_id or DEFAULT_WORKER_ID[agent]
    role = f"agent-{agent}"

    if not acquire_role_lock(role):
        log.error("worker_start_rejected", agent=agent, status="rejected", error_code="lock_held")
        return 2

    stop_event = threading.Event()
    _install_signal_handlers(stop_event)
    # 清掉上一次遗留的停机标记，再挂监听（否则一启动就退出）
    clear_stop_request(role)
    start_stop_file_watcher(role, stop_event)
    write_heartbeat(role, state="starting", last_status="init")

    # Gate5-B2-WB R2-FIX #518：agent-workbuddy 在宣布 ready 前，由本子进程自身执行
    # 只读 probe_wb_gateway() 验证「配置代次一致 / 鉴权成功」（含网关密码一致性）。
    # 鉴权失败（密码不一致 / 网关不可达 / 鉴权门未通过）必须写稳定错误码并非零退出；
    # Supervisor 的 _wait_ready 只认 state=="running"，故 state="error" 时绝不会被认作 ready。
    if agent == "workbuddy":
        from services.wb_gateway_health import probe_wb_gateway
        _gw = probe_wb_gateway()
        if not _gw.get("ready"):
            _gw_err = _gw.get("error_code") or "wb_gateway_unverified"
            write_heartbeat(role, state="error", last_status="wb_gateway_unverified",
                            error_code=_gw_err)
            log.error("worker_wb_gateway_unverified", agent=agent, status="rejected",
                      error_code=_gw_err)
            release_role_lock(role)
            return 4

    log.info("worker_started", agent=agent, status="running")

    exit_code = 0
    try:
        if args.recover_on_start:
            summary = recover_runtime_state()
            log.info(
                "worker_recovery",
                agent=agent,
                status="recovered",
                count=sum(int(v) for v in summary.values()),
            )

        def _heartbeat(payload):
            status = str(payload.get("last_status", ""))
            # The pre-start WB health probe has already succeeded. An immediate
            # idle poll must not erase its verified-ready marker before the
            # supervisor's 300ms readiness sample (a real startup race).
            if agent == "workbuddy" and status == "idle":
                status = ("wb_cli_binding_verified" if config.WB_TRANSPORT == "cli_fixed_session"
                          else "wb_gateway_verified")
            write_heartbeat(role, state="running", last_status=status)

        write_heartbeat(role, state="running",
                        last_status=(("wb_cli_binding_verified" if config.WB_TRANSPORT == 'cli_fixed_session'
                                      else "wb_gateway_verified") if agent == "workbuddy" else "idle"))
        run_agent_loop(
            agent,
            worker_id,
            stop_event,
            idle_wait_sec=args.idle_wait_sec,
            heartbeat=_heartbeat,
        )
    except KeyboardInterrupt:
        stop_event.set()
    except Exception as exc:  # noqa: BLE001
        log.exception("worker_crashed", exc, agent=agent, status="crashed")
        exit_code = 1
    finally:
        write_heartbeat(role, state="stopped", last_status="stopped")
        clear_stop_request(role)
        release_role_lock(role)
        log.info("worker_stopped", agent=agent, status="stopped")
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
