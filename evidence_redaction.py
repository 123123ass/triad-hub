"""Evidence 专用脱敏层（Step 8 安全收尾 a / Gate3 P0-A 扩展）。

职责边界（与 redaction.py 分工）：
    redaction.py            —— 凭据类（Bearer / token / password / secret / JWT ...）
    evidence_redaction.py   —— 物理会话标识（physical session id）
                               + 飞书身份标识（open_id / chat_id / union_id）

铁律：
  1. 任何写入 evidence 目录的字节，必须先过 sanitize_evidence()。
  2. 物理 session ID 一律替换为「前 8 位显示值 + session_id_hash(sha256 全量)」，
     绝不保留完整明文。
  3. 解析与一致性校验一律在内存中对**原始 stdout** 完成，落盘的只有脱敏副本。
  4. 落盘前必须 assert_evidence_clean()，命中残留即抛错拒绝写入。

替换形态（JSON 字符串安全，无引号/反斜杠）：
    SESSION_REDACTED[display=019fc06d,sha256=<64 hex>]
    FEISHU_ID_REDACTED[kind=ou,sha256=<64 hex>]

覆盖的 session 形态：
    A) Codex thread/session UUID   8-4-4-4-12 hex
    B) Hermes 固定 session         YYYYMMDD_HHMMSS_xxxxxx

覆盖的飞书身份形态（Gate3 P0-A，Codex 裁决 Q1 方案 A）：
    C) ou_<20+ alnum>  open_id（用户 / 机器人）
    D) oc_<20+ alnum>  chat_id（群会话）
    E) on_<20+ alnum>  union_id

作用域声明（Codex 裁决原文）：
    「不要把数据库内部的合法身份映射直接改成脱敏值；本规则针对日志、报告、
      公开证据出口。」
    ⇒ agent_bindings / feishu 路由表里的 open_id 是业务必需的路由标识，保持原值；
      本模块只作用于 evidence / 日志 / 报告 的**写出**路径。
"""
from __future__ import annotations

import hashlib
import re
from typing import Any, Iterable, List

import redaction

# ---- 物理会话标识形态 ----
# 边界必须用 ASCII 显式否定环视，不能用 \b：
#   Python re 的 \w 包含 CJK，`...57e349；` 这类"明文紧跟中文标点"的情形下 \b 不成立，
#   会整段漏过（Step 8 安全收尾实测踩到）。
# 边界只排除"会把标识本身延长"的十六进制字符，宁可多脱敏也不漏：
#   `..._57e349_suffix` / `prefix_20260729_...` / `...952，` 都必须命中。
_UUID_RE = re.compile(
    r"(?<![0-9a-fA-F])"
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
    r"(?![0-9a-fA-F])"
)
_HERMES_RE = re.compile(r"(?<!\d)\d{8}_\d{6}_[0-9a-fA-F]{6}(?![0-9a-fA-F])")
SESSION_PATTERNS = (_UUID_RE, _HERMES_RE)

# ---- 飞书身份标识形态（Gate3 P0-A，正则由 Codex 裁决 Q1 指定，逐字符照抄）----
# 边界同样用 ASCII 显式否定环视：`会话ou_xxx，` / `"open_id":"ou_xxx"` / URL 内均须命中；
# `xou_xxx` / `ou_xxx_tail` 这类"会把标识本身延长"的情形不视为完整标识。
_FEISHU_ID_RE = re.compile(
    r"(?<![A-Za-z0-9_])(?P<kind>ou|oc|on)_[A-Za-z0-9]{20,}(?![A-Za-z0-9_])"
)
FEISHU_ID_PATTERNS = (_FEISHU_ID_RE,)

# 已脱敏 token 自身的形态（幂等性检查用）
_TOKEN_RE = re.compile(r"SESSION_REDACTED\[display=[0-9a-zA-Z_]{1,8},sha256=[0-9a-f]{64}\]")
_FEISHU_TOKEN_RE = re.compile(
    r"FEISHU_ID_REDACTED\[kind=(?:ou|oc|on),sha256=[0-9a-f]{64}\]"
)

DISPLAY_PREFIX_LEN = 8
FEISHU_KIND_LEN = 2


def session_id_hash(session_id: str) -> str:
    """物理 session ID 的 sha256 全量十六进制摘要。"""
    return hashlib.sha256(session_id.encode("utf-8")).hexdigest()


def session_display(session_id: str) -> str:
    """前 8 位显示值（人类可辨识、不可反推）。"""
    return session_id[:DISPLAY_PREFIX_LEN]


def session_token(session_id: str) -> str:
    """evidence 内使用的脱敏 token：前 8 位显示值 + 全量 sha256。"""
    return (
        f"SESSION_REDACTED[display={session_display(session_id)},"
        f"sha256={session_id_hash(session_id)}]"
    )


def doc_reference(session_id: str, logical_name: str, hash_len: int = 16) -> str:
    """文档/报告内的人读引用：逻辑名 + 前 8 位 + 短哈希（不含完整明文）。"""
    return (
        f"{logical_name}（物理会话 {session_display(session_id)}… / "
        f"sha256:{session_id_hash(session_id)[:hash_len]}）"
    )


def find_plaintext_sessions(text: str) -> List[str]:
    """返回文本中出现的物理 session 明文（去重、保持出现顺序）。"""
    if not isinstance(text, str) or not text:
        return []
    # 先剔除已脱敏 token，避免把 token 内的 sha256 误判（sha256 不匹配 session 形态，
    # 但 display 段可能与 hermes 形态前缀相似，统一先屏蔽更稳妥）
    scrubbed = _TOKEN_RE.sub("", text)
    out: List[str] = []
    for pattern in SESSION_PATTERNS:
        for m in pattern.findall(scrubbed):
            if m not in out:
                out.append(m)
    return out


def contains_plaintext_session(text: str) -> bool:
    return bool(find_plaintext_sessions(text))


def redact_session_ids(text: str) -> str:
    """把所有物理 session 明文替换成脱敏 token（幂等）。"""
    if not isinstance(text, str) or not text:
        return text
    out = text
    for pattern in SESSION_PATTERNS:
        out = pattern.sub(lambda m: session_token(m.group(0)), out)
    return out


# ---------------------------------------------------------------------------
# 飞书身份标识（Gate3 P0-A）
# ---------------------------------------------------------------------------
def feishu_id_hash(feishu_id: str) -> str:
    """飞书身份标识的 sha256 全量小写十六进制摘要（同值恒等，便于审计比对）。"""
    return hashlib.sha256(feishu_id.encode("utf-8")).hexdigest()


def feishu_id_kind(feishu_id: str) -> str:
    """标识类别前缀：ou / oc / on。"""
    return feishu_id[:FEISHU_KIND_LEN]


def feishu_id_token(feishu_id: str) -> str:
    """evidence 内使用的脱敏 token（格式由 Codex 裁决 Q1 固定，不得变动）。

    与 session_token 不同：**不保留任何明文前缀**。
    飞书 ID 的前缀段本身可用于定位真人/真群，因此只留 kind + 全量摘要。
    """
    return f"FEISHU_ID_REDACTED[kind={feishu_id_kind(feishu_id)},sha256={feishu_id_hash(feishu_id)}]"


def find_plaintext_feishu_ids(text: str) -> List[str]:
    """返回文本中出现的飞书身份标识明文（去重、保持出现顺序）。"""
    if not isinstance(text, str) or not text:
        return []
    # 先剔除已脱敏 token，避免占位符内部字符被再次判定为明文
    scrubbed = _FEISHU_TOKEN_RE.sub("", text)
    out: List[str] = []
    for pattern in FEISHU_ID_PATTERNS:
        for m in pattern.finditer(scrubbed):
            value = m.group(0)
            if value not in out:
                out.append(value)
    return out


def contains_plaintext_feishu_id(text: str) -> bool:
    return bool(find_plaintext_feishu_ids(text))


def redact_feishu_ids(text: str) -> str:
    """把所有飞书身份标识明文替换成脱敏 token（幂等）。"""
    if not isinstance(text, str) or not text:
        return text
    out = text
    for pattern in FEISHU_ID_PATTERNS:
        out = pattern.sub(lambda m: feishu_id_token(m.group(0)), out)
    return out


def sanitize_evidence(text: str, extra_secrets: Iterable[str] = ()) -> str:
    """evidence 落盘唯一入口：先去物理会话，再去飞书身份，最后去凭据。

    顺序说明：
      1. session 与 feishu 两类形态互不重叠（前者要连字符/时间戳，后者要 ou_/oc_/on_
         前缀），先后无歧义；两者产出的占位符尾段都是 64 位纯 hex，不会被对方命中。
      2. 凭据层放最后：redaction 会把命中值整体抹成掩码，若先跑会吃掉 ou_/oc_ 前缀，
         导致本层再也无法给出可审计的 sha256 摘要。
    """
    if not isinstance(text, str):
        text = "" if text is None else str(text)
    out = redact_session_ids(text)
    out = redact_feishu_ids(out)
    out = redaction.redact_text(out, extra_secrets)
    return out


def assert_evidence_clean(text: str, where: str = "evidence") -> None:
    """落盘前自检：命中物理会话明文或飞书身份明文即拒绝写入。

    错误信息只带类别/计数/摘要前缀，绝不回显明文（Gate3 脱敏红线）。
    """
    hits = find_plaintext_sessions(text)
    if hits:
        raise ValueError(
            f"plaintext_session_in_evidence at {where}; "
            f"count={len(hits)} display={[session_display(h) for h in hits]}"
        )
    feishu_hits = find_plaintext_feishu_ids(text)
    if feishu_hits:
        raise ValueError(
            f"plaintext_feishu_id_in_evidence at {where}; "
            f"count={len(feishu_hits)} "
            f"kinds={sorted({feishu_id_kind(h) for h in feishu_hits})} "
            f"sha256_prefix={[feishu_id_hash(h)[:8] for h in feishu_hits]}"
        )


def sanitize_and_assert(text: str, where: str = "evidence",
                        extra_secrets: Iterable[str] = ()) -> str:
    cleaned = sanitize_evidence(text, extra_secrets)
    assert_evidence_clean(cleaned, where)
    return cleaned


def matches_session(observed: Any, expected_session_id: str) -> bool:
    """比较"从 evidence 解析出的会话值"与"库里记录的明文会话"。

    脱敏后 evidence 里的 thread_id 已变成 token，因此明文相等与 token 相等都算命中。
    """
    if not isinstance(observed, str) or not expected_session_id:
        return False
    return observed == expected_session_id or observed == session_token(expected_session_id)
