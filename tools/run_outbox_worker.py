"""tools/run_outbox_worker.py —— 飞书出站常驻 worker 入口（Step 11 / Gate 1）。

用法：
    python tools/run_outbox_worker.py --worker-id triad-outbox-1

行为：
- 启动即安装日志脱敏（install_stream_redactor）。
- 单实例角色锁：全局只允许一个 outbox worker（避免同一条 outbox 被并发发送）。
- 注册 SIGINT/SIGTERM/SIGBREAK 正常退出：置位 stop_event，当前发送跑完即退。
- 周期写脱敏心跳文件 runtime/outbox.heartbeat.json（只含角色/PID/时间/状态）。

安全红线：
- 幂等键固定为 outbox_id，本入口不生成任何新幂等键。
- delivery_unknown 一律不自动重发，只落稳定错误码等待人工复核。
- 绝不打印或落盘消息正文、凭据、完整 URL。

退出码：0 正常停机；2 未拿到角色锁（已有实例在跑）。
"""
from __future__ import annotations

import argparse
import signal
import sys
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from logging_config import get_logger  # noqa: E402
from redaction import install_stream_redactor  # noqa: E402
from services.runtime_worker import (  # noqa: E402
    acquire_role_lock,
    clear_stop_request,
    recover_runtime_state,
    release_role_lock,
    run_outbox_loop,
    start_stop_file_watcher,
    write_heartbeat,
)

log = get_logger("run_outbox_worker")

ROLE = "outbox"
DEFAULT_WORKER_ID = "triad-outbox-1"


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
        except (ValueError, OSError):
            pass


def main(argv=None) -> int:
    install_stream_redactor()
    parser = argparse.ArgumentParser(description="Triad 飞书出站常驻 worker")
    parser.add_argument("--worker-id", default=DEFAULT_WORKER_ID)
    parser.add_argument("--idle-wait-sec", type=float, default=0.25)
    parser.add_argument(
        "--recover-on-start",
        action="store_true",
        default=False,
        help="独立启动时才用；由 supervisor 统一拉起时不要开",
    )
    args = parser.parse_args(argv)

    if not acquire_role_lock(ROLE):
        log.error("worker_start_rejected", status="rejected", error_code="lock_held")
        return 2

    stop_event = threading.Event()
    _install_signal_handlers(stop_event)
    clear_stop_request(ROLE)
    start_stop_file_watcher(ROLE, stop_event)
    write_heartbeat(ROLE, state="starting", last_status="init")
    log.info("worker_started", status="running")

    exit_code = 0
    try:
        if args.recover_on_start:
            summary = recover_runtime_state()
            log.info(
                "worker_recovery",
                status="recovered",
                count=sum(int(v) for v in summary.values()),
            )

        def _heartbeat(payload):
            write_heartbeat(ROLE, state="running", last_status=str(payload.get("last_status", "")))

        write_heartbeat(ROLE, state="running", last_status="idle")
        run_outbox_loop(
            args.worker_id,
            stop_event,
            idle_wait_sec=args.idle_wait_sec,
            heartbeat=_heartbeat,
        )
    except KeyboardInterrupt:
        stop_event.set()
    except Exception as exc:  # noqa: BLE001
        log.exception("worker_crashed", exc, status="crashed")
        exit_code = 1
    finally:
        write_heartbeat(ROLE, state="stopped", last_status="stopped")
        clear_stop_request(ROLE)
        release_role_lock(ROLE)
        log.info("worker_stopped", status="stopped")
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
