"""
feishu.py —— 飞书 adapter（官方 SDK lark-oapi 实现）。

三大能力：
  1. 长连接收事件：三个机器人各起一条官方 SDK 长连接（免公网），事件回调到 on_event(bot, normalized)
  2. 发消息：send_message(text, bot, idempotency_key) 返回 FeishuSendResult
  3. 门禁：is_allowed_group / is_owner

凭据全部从本机 .env 读取（config），绝不硬编码、不进日志。
adapter 层只做原始事件保真与发送，不做业务判定、不调用任何 Agent。
"""
import hashlib
import json
import os
import re
import socket
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable, Optional

from config import config
from redaction import OUTLET_FEISHU, assert_no_secret, for_feishu

import lark_oapi as lark
from lark_oapi.api.im.v1 import P2ImMessageReceiveV1

# ── 根因修复：lark-oapi 在 websockets>=15 下于 _ws_connect_kwargs() 硬编码
#    {"proxy": None}，导致长连接直连（不吃 HTTPS_PROXY）。本机飞书 ws 必须走代理
#    7890 才能建起 TLS 隧道，故在此 monkeypatch，强制 ws 走代理。──
import lark_oapi.ws.client as _lark_ws_client  # noqa: E402


def _patched_ws_connect_kwargs():
    proxy = (
        config.HTTPS_PROXY
        or os.environ.get("HTTPS_PROXY")
        or os.environ.get("HTTP_PROXY")
    )
    if proxy:
        return {"proxy": proxy}
    return {}


_lark_ws_client._ws_connect_kwargs = _patched_ws_connect_kwargs

TOKEN_URL = "https://open.feishu.cn/open-apis/auth/v3/tenant_access_token/internal"
SEND_URL = "https://open.feishu.cn/open-apis/im/v1/messages?receive_id_type=chat_id"

EVENT_TYPE_MESSAGE_RECEIVED = "im.message.message_received_v1"

# 三个机器人：(app_id, app_secret) —— 凭据从本机 .env 读取，绝不硬编码
BOTS = {
    "workbuddy": (config.FEISHU_WB_APP_ID, config.FEISHU_WB_APP_SECRET),
    "codex": (config.FEISHU_CODEX_APP_ID, config.FEISHU_CODEX_APP_SECRET),
    "hermes": (config.FEISHU_HERMES_APP_ID, config.FEISHU_HERMES_APP_SECRET),
}


# ---------------- 5.3.1 发送返回值 ----------------
@dataclass(frozen=True)
class FeishuSendResult:
    status: str
    message_id: Optional[str]
    error_code: Optional[str]
    delivery_unknown: bool = False


# ---------------- 5.3.2 Bot Open ID 映射 ----------------
def bot_open_id_map() -> dict[str, str]:
    """返回三个Bot身份到Open ID的配置映射。"""
    return config.bot_open_ids()


def _get(obj: Any, name: str) -> Any:
    """同时支持 SDK 对象属性与测试字典；取不到返回 None。"""
    if obj is None:
        return None
    if isinstance(obj, dict):
        return obj.get(name)
    return getattr(obj, name, None)


# ---------------- 5.3.3 提取事件头 ----------------
def extract_event_header(data: Any) -> dict[str, Optional[str]]:
    """安全提取飞书官方事件头，不抛出凭据或原始对象。"""
    header = _get(data, "header")
    event_id = _get(header, "event_id")
    create_time = _get(header, "create_time")
    event_type = _get(header, "event_type")
    return {
        "event_id": str(event_id) if event_id else None,
        "event_create_time": str(create_time) if create_time else None,
        "event_type": str(event_type) if event_type else None,
    }


# ---------------- 5.3.4 派生事件ID ----------------
def derive_event_id(normalized_event: dict[str, Any]) -> str:
    """官方event_id缺失时生成稳定替代ID。

    只使用消息本身的稳定标识，绝不掺入 receiving_bot、官方 event_id、随机数或当前时间，
    否则三个 Bot 看到同一条消息会派生出三个不同 ID。
    发送者身份优先 union_id（全局唯一）；仅非操作员且确实无 union_id 时才回退 open_id。
    """
    sender_identity = (
        normalized_event.get("sender_union_id")
        or normalized_event.get("sender_open_id")
        or ""
    )
    canonical = "|".join([
        str(normalized_event.get("message_id") or ""),
        str(sender_identity),
        str(normalized_event.get("chat_id") or ""),
        str(normalized_event.get("message_create_time") or ""),
    ])
    if not normalized_event.get("message_id"):
        content_hash = hashlib.sha256(
            str(normalized_event.get("content") or "").encode("utf-8")
        ).hexdigest()
        canonical = canonical + "|" + content_hash
    return "derived_" + hashlib.sha256(
        canonical.encode("utf-8")
    ).hexdigest()


# ---------------- 5.3.5 标准化SDK事件 ----------------
def normalize_sdk_event(
    bot_name: str,
    data: Any,
) -> dict[str, Any]:
    """把飞书 SDK 回调对象（或测试字典）转成固定 schema 的归一化事件。"""
    header = extract_event_header(data)
    event = _get(data, "event")
    message = _get(event, "message")
    sender = _get(event, "sender")
    sender_id = _get(sender, "sender_id")

    mentions = []
    for m in (_get(message, "mentions") or []):
        mentions.append({
            "key": _get(m, "key"),
            "name": _get(m, "name"),
            "open_id": _get(_get(m, "id"), "open_id") or _get(m, "open_id"),
        })

    message_id = _get(message, "message_id")
    message_create_time = _get(message, "create_time")
    message_type = _get(message, "message_type")
    chat_id = _get(message, "chat_id")
    sender_open_id = _get(sender_id, "open_id")
    sender_union_id = _get(sender_id, "union_id")
    content = _get(message, "content")

    normalized: dict[str, Any] = {
        "schema_version": "1.0",
        "event_id": "",
        "event_id_source": "official",
        "event_create_time": header["event_create_time"],
        "event_type": EVENT_TYPE_MESSAGE_RECEIVED,
        "message_id": str(message_id) if message_id else None,
        "message_create_time": str(message_create_time) if message_create_time else None,
        "message_type": str(message_type) if message_type else None,
        "chat_id": str(chat_id or ""),
        "sender_open_id": str(sender_open_id or ""),
        "sender_union_id": str(sender_union_id or ""),
        "mentions": mentions,
        "content": str(content or ""),
        "receiving_bot": str(bot_name),
    }

    if header["event_id"]:
        normalized["event_id"] = header["event_id"]
        normalized["event_id_source"] = "official"
    else:
        normalized["event_id"] = derive_event_id(normalized)
        normalized["event_id_source"] = "derived"
    return normalized


# ---------------- 5.3.6 清理群消息文本 ----------------
_AT_TAG = re.compile(r"<at\b[^>]*>.*?</at>", re.IGNORECASE | re.DOTALL)
_AT_TAG_SELF_CLOSING = re.compile(r"<at\b[^>]*/?>", re.IGNORECASE)
_AT_USER_PLACEHOLDER = re.compile(r"@_user_\d+")
_AT_ALL = re.compile(r"@_all\b")


def extract_clean_text(
    content: str,
) -> str:
    """从飞书 content 中提取用户原始文字，去掉 @ 占位符与 at 标签。"""
    text = content
    try:
        parsed = json.loads(content)
        if isinstance(parsed, dict):
            if isinstance(parsed.get("text"), str):
                text = parsed["text"]
            else:
                # 飞书桌面端在“真正艾特 + 粘贴正文”时可能发送 post 富文本；
                # 其正文位于 content_v2/content 的二维节点数组，而非顶层 text。
                # 只拼接显式 text 节点，忽略 at/图片/附件等结构，避免把 bot 名
                # 当作用户正文或把结构化元数据带入路由与签名。
                blocks = parsed.get("content_v2") or parsed.get("content") or []
                parts: list[str] = []

                def _collect_text_nodes(node: Any) -> None:
                    if isinstance(node, list):
                        for child in node:
                            _collect_text_nodes(child)
                    elif isinstance(node, dict) and node.get("tag") == "text":
                        value = node.get("text")
                        if isinstance(value, str):
                            parts.append(value)

                _collect_text_nodes(blocks)
                text = "".join(parts)
    except Exception:  # noqa: BLE001
        text = content
    if not isinstance(text, str):
        text = ""
    text = _AT_TAG.sub(" ", text)
    text = _AT_TAG_SELF_CLOSING.sub(" ", text)
    text = _AT_USER_PLACEHOLDER.sub(" ", text)
    text = _AT_ALL.sub(" ", text)
    return re.sub(r"\s+", " ", text).strip()


def get_tenant_token(app_id, app_secret):
    if not app_id or not app_secret:
        raise RuntimeError("飞书凭据未配置（app_id/app_secret 为空）")
    body = json.dumps({"app_id": app_id, "app_secret": app_secret}).encode()
    req = urllib.request.Request(
        TOKEN_URL, data=body, headers={"Content-Type": "application/json"}
    )
    resp = json.loads(urllib.request.urlopen(req, timeout=10).read())
    if resp.get("code") != 0:
        raise RuntimeError("获取 tenant_access_token 失败")
    return resp["tenant_access_token"]


# ---------------- 5.3.7 飞书发送函数 ----------------
def send_message(
    text: str,
    bot: str = "workbuddy",
    idempotency_key: Optional[str] = None,
) -> FeishuSendResult:
    """以指定机器人身份向飞书群发送文本消息。

    绝不返回原始异常字符串、不写飞书完整响应、不把 tenant token 带进异常。
    网络超时后不在此函数内重复发送。
    """
    if bot not in BOTS:
        return FeishuSendResult(
            status="failed",
            message_id=None,
            error_code="feishu_bot_unknown",
            delivery_unknown=False,
        )
    if not config.FEISHU_CHAT_ID:
        return FeishuSendResult(
            status="failed",
            message_id=None,
            error_code="feishu_chat_unconfigured",
            delivery_unknown=False,
        )

    text = for_feishu(text)
    assert_no_secret(text, outlet=OUTLET_FEISHU)

    app_id, app_secret = BOTS[bot]
    try:
        token = get_tenant_token(app_id, app_secret)  # 仅存在内存
    except RuntimeError:
        return FeishuSendResult(
            status="failed",
            message_id=None,
            error_code="feishu_auth_failed",
            delivery_unknown=False,
        )
    except Exception:  # noqa: BLE001 —— 网络层问题，请求尚未发出，可安全重试
        return FeishuSendResult(
            status="retry",
            message_id=None,
            error_code="feishu_token_unavailable",
            delivery_unknown=False,
        )

    payload = {
        "receive_id": config.FEISHU_CHAT_ID,
        "msg_type": "text",
        "content": json.dumps({"text": text}),
    }
    if idempotency_key:
        # 飞书 im/v1/messages 支持 uuid 幂等参数；必须复用稳定 outbox_id，禁止随机生成
        payload["uuid"] = str(idempotency_key)
    body = json.dumps(payload).encode()
    req = urllib.request.Request(
        SEND_URL,
        data=body,
        headers={"Content-Type": "application/json", "Authorization": "Bearer " + token},
    )
    try:
        raw = urllib.request.urlopen(req, timeout=10).read()
    except urllib.error.HTTPError as e:
        status_code = getattr(e, "code", 0)
        if status_code == 429:
            return FeishuSendResult(
                status="retry",
                message_id=None,
                error_code="feishu_rate_limited",
                delivery_unknown=False,
            )
        if 500 <= status_code < 600:
            return FeishuSendResult(
                status="retry",
                message_id=None,
                error_code=f"feishu_http_{status_code}",
                delivery_unknown=False,
            )
        if status_code in (401, 403):
            return FeishuSendResult(
                status="failed",
                message_id=None,
                error_code="feishu_auth_failed",
                delivery_unknown=False,
            )
        return FeishuSendResult(
            status="failed",
            message_id=None,
            error_code=f"feishu_http_{status_code}",
            delivery_unknown=False,
        )
    except (socket.timeout, TimeoutError):
        # 请求已写出但未读到响应：可能已送达，禁止自动重发
        return FeishuSendResult(
            status="delivery_unknown",
            message_id=None,
            error_code="feishu_response_timeout",
            delivery_unknown=True,
        )
    except urllib.error.URLError as e:
        if isinstance(getattr(e, "reason", None), (socket.timeout, TimeoutError)):
            return FeishuSendResult(
                status="delivery_unknown",
                message_id=None,
                error_code="feishu_response_timeout",
                delivery_unknown=True,
            )
        # 发送前连接失败：请求未发出，可安全重试
        return FeishuSendResult(
            status="retry",
            message_id=None,
            error_code="feishu_connect_failed",
            delivery_unknown=False,
        )
    except Exception:  # noqa: BLE001 —— 结果不可判定，按未知处理
        return FeishuSendResult(
            status="delivery_unknown",
            message_id=None,
            error_code="feishu_send_unknown",
            delivery_unknown=True,
        )

    try:
        resp = json.loads(raw)
    except Exception:  # noqa: BLE001
        return FeishuSendResult(
            status="delivery_unknown",
            message_id=None,
            error_code="feishu_response_unparsable",
            delivery_unknown=True,
        )

    if resp.get("code") == 0:
        return FeishuSendResult(
            status="sent",
            message_id=(resp.get("data") or {}).get("message_id"),
            error_code=None,
            delivery_unknown=False,
        )
    return FeishuSendResult(
        status="failed",
        message_id=None,
        error_code="feishu_send_rejected",
        delivery_unknown=False,
    )


def is_allowed_group(group_id):
    return bool(config.FEISHU_CHAT_ID) and group_id == config.FEISHU_CHAT_ID


def is_owner(user_id):
    return bool(config.FEISHU_OPERATOR_USER_ID) and user_id == config.FEISHU_OPERATOR_USER_ID


# ---- 官方 SDK 长连接 ----
# 每个机器人一个客户端。回调统一转成 on_event(bot_name, normalized_event)。

def _build_client(
    bot_name: str,
    app_id: str,
    app_secret: str,
    on_event: Callable[[str, dict[str, Any]], None],
):
    def do_message(data: P2ImMessageReceiveV1) -> None:
        normalized = normalize_sdk_event(bot_name, data)
        on_event(bot_name, normalized)

    def do_bot_added(data: lark.CustomizedEvent) -> None:
        on_event(bot_name, {
            "type": "im.chat.member.bot.added_v1",
            "event": {"chat_id": (data.event or {}).get("chat_id")},
        })

    handler = (
        lark.EventDispatcherHandler.builder("", "")
        .register_p2_im_message_receive_v1(do_message)
        .register_p1_customized_event("im.chat.member.bot.added_v1", do_bot_added)
        .build()
    )
    cli = lark.ws.Client(app_id, app_secret, event_handler=handler, log_level=lark.LogLevel.INFO)
    return cli


def start_longconn(on_event, stop_event=None):
    """为三个机器人各起一条官方 SDK 长连接（守护线程）。返回线程列表。"""
    import threading

    threads = []
    for name, (aid, sec) in BOTS.items():
        if not aid or not sec:
            continue
        cli = _build_client(name, aid, sec, on_event)

        def _run(c=cli, n=name):
            try:
                c.start()
            except Exception as e:  # noqa: BLE001
                print(f"[{n}] SDK 长连接异常: {e!r}", flush=True)

        t = threading.Thread(target=_run, daemon=True)
        t.start()
        threads.append(t)
    return threads
