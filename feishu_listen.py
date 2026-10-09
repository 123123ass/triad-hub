"""
feishu_listen.py —— 单机器人长连接监听（每个机器人一个进程，规避 SDK 全局事件循环冲突）。

用法：.venv/Scripts/python.exe feishu_listen.py <bot_key>   (workbuddy|codex|hermes)
收到群消息事件 → 打印 + 写入 events.jsonl（append-only，供 Hub 消费）。
"""
import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from dotenv import load_dotenv

load_dotenv()

from config import config
from adapters import feishu

BOT = sys.argv[1] if len(sys.argv) > 1 else "hermes"
OUT = Path(__file__).resolve().parent / "feishu_events.jsonl"


def on_event(bot, evt):
    evt_type = (evt.get("header") or {}).get("event_type") or evt.get("type")
    data = evt.get("event", {})
    row = {"ts": time.time(), "bot": bot, "type": evt_type, "event": data}
    with open(OUT, "a", encoding="utf-8") as f:
        f.write(json.dumps(row, ensure_ascii=False) + "\n")
    print(json.dumps(row, ensure_ascii=False), flush=True)


if __name__ == "__main__":
    print(f"[{BOT}] 监听启动（进程 PID={os.getpid()}）", flush=True)
    cli = feishu._build_client(BOT, *feishu.BOTS[BOT], on_event)
    try:
        cli.start()
    except Exception as e:
        print(f"[{BOT}] 连接异常: {e!r}", flush=True)
