"""services/wb_gateway_health.py —— WB Gateway 就绪探测（Gate5-B2-WB R2，Codex 裁决）。

职责边界：
    - 只读探测：绝不调用 POST /api/v1/runs，绝不创建任务/消息/Agent 调用。
    - 仅 BRIDGE_DRY_RUN=false 时作为 preflight 强制门槛；dry-run 不做任何网络探测。
    - 输出只含稳定字段，不含 URL 敏感部分、Bearer、响应正文或进程命令全文。
    - 总超时 5 秒，零重试。
"""
from __future__ import annotations

import json
import socket
import time
import urllib.error
import urllib.request
from typing import Any, Dict, Optional
from urllib.parse import urlparse

from config import config

# 稳定错误码
ERR_NOT_CONFIGURED = "wb_gateway_not_configured"
ERR_NOT_LOOPBACK = "wb_gateway_not_loopback"
ERR_TCP_UNREACHABLE = "wb_gateway_tcp_unreachable"
ERR_ROOT_HTTP = "wb_gateway_root_http_failed"
ERR_AUTH_GATE = "wb_gateway_auth_gate_failed"

_TIMEOUT = 5  # 秒，总探测超时


def _is_loopback_url(url: str) -> bool:
    """URL 必须是 http + 回环 host（127.0.0.1/localhost/::1），禁止凭据与查询参数。"""
    try:
        p = urlparse(url)
    except Exception:  # noqa: BLE001
        return False
    if p.scheme != "http":
        return False
    if p.hostname not in ("127.0.0.1", "localhost", "::1", "0:0:0:0:0:0:0:1"):
        return False
    if p.username or p.password or p.query or p.fragment:
        return False
    return True


def _tcp_connect(host: str, port: int, timeout: float = _TIMEOUT) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _http_get(url: str, bearer: Optional[str] = None, timeout: float = _TIMEOUT) -> Dict[str, Any]:
    """GET 只读请求；返回 {"status": int, "ok": bool}，绝不回显正文。"""
    req = urllib.request.Request(url, method="GET")
    # WorkBuddy 2026.9 起程序化 API 必须显式标记；缺此头时正确 Bearer 也会 403。
    req.add_header("x-codebuddy-request", "1")
    if bearer:
        req.add_header("Authorization", f"Bearer {bearer}")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            # 读取并丢弃正文（校验可用），不回显
            resp.read(256)
            return {"status": resp.status, "ok": 200 <= resp.status < 400}
    except urllib.error.HTTPError as e:
        return {"status": e.code, "ok": 200 <= e.code < 400}
    except Exception:  # noqa: BLE001 —— 网络类错误
        return {"status": 0, "ok": False}


def probe_wb_gateway() -> Dict[str, Any]:
    """只读探测 WB Gateway 就绪状态（dry-run 下零网络探测）。

    返回稳定字段：configured / loopback / tcp_ready / root_http_ready /
    auth_gate_ready / ready / error_code。
    """
    if config.WB_TRANSPORT == 'cli_fixed_session':
        try:
            from adapters.wb_cli import WBCLIAdapter
            from repository import get_binding
            check = WBCLIAdapter().verify_binding(get_binding('workbuddy'))
            return {'ready': check.ok, 'transport': 'cli_fixed_session',
                    'auth_live_verified': False,
                    'error_code': check.error_code if not check.ok else None}
        except Exception:
            return {'ready': False, 'error_code': 'wb_cli_binding_unverified'}
    if config.WB_TRANSPORT != 'gateway_http':
        return {'ready': False, 'error_code': 'wb_transport_unknown'}
    started = time.monotonic()
    url = str(config.WB_GATEWAY_URL or "").strip()
    bearer = str(config.WB_GATEWAY_PASSWORD or "")

    if not url or not bearer:
        return {
            "configured": bool(url and bearer),
            "loopback": False,
            "tcp_ready": False,
            "root_http_ready": False,
            "auth_gate_ready": False,
            "ready": False,
            "error_code": ERR_NOT_CONFIGURED,
        }

    if not _is_loopback_url(url):
        return {
            "configured": True,
            "loopback": False,
            "tcp_ready": False,
            "root_http_ready": False,
            "auth_gate_ready": False,
            "ready": False,
            "error_code": ERR_NOT_LOOPBACK,
        }

    p = urlparse(url)
    host = str(p.hostname)
    port = p.port or 80
    if host == "localhost":
        host = "127.0.0.1"

    tcp_ok = _tcp_connect(host, port, _TIMEOUT)
    if not tcp_ok:
        return {
            "configured": True,
            "loopback": True,
            "tcp_ready": False,
            "root_http_ready": False,
            "auth_gate_ready": False,
            "ready": False,
            "error_code": ERR_TCP_UNREACHABLE,
        }

    root = _http_get(url, timeout=_TIMEOUT)
    root_ok = root["ok"]
    if not root_ok:
        return {
            "configured": True,
            "loopback": True,
            "tcp_ready": True,
            "root_http_ready": False,
            "auth_gate_ready": False,
            "ready": False,
            "error_code": ERR_ROOT_HTTP,
        }

    # 鉴权门探测：随机、确定不存在的 runId。
    # 错误 Bearer 必须 401/AUTH_REQUIRED；正确 Bearer 必须通过鉴权层（非 401）。
    # 只读 GET，绝不 POST /api/v1/runs。
    probe_id = "probe_" + json.dumps({"t": time.time_ns()}).encode("utf-8").hex()[:24]
    run_url = f"{url}/api/v1/runs/{probe_id}"

    bad = _http_get(run_url, bearer="invalid_probe_bearer", timeout=_TIMEOUT)
    good = _http_get(run_url, bearer=bearer, timeout=_TIMEOUT)

    bad_401 = bad["status"] in (401, 403)
    good_not_401 = good["status"] not in (401, 403) and good["status"] != 0

    if not (bad_401 and good_not_401):
        return {
            "configured": True,
            "loopback": True,
            "tcp_ready": True,
            "root_http_ready": True,
            "auth_gate_ready": False,
            "ready": False,
            "error_code": ERR_AUTH_GATE,
        }

    elapsed = time.monotonic() - started
    return {
        "configured": True,
        "loopback": True,
        "tcp_ready": True,
        "root_http_ready": True,
        "auth_gate_ready": True,
        "ready": True,
        "error_code": "",
        "elapsed_ms": int(elapsed * 1000),
    }
