"""
start_bridges.py —— 一键启动三个飞书自动回复桥（Hermes / Codex / WB）。

用法：
  .venv/Scripts/python.exe start_bridges.py          # 前台顺序启动（调试用）
  # 或后台常驻（推荐）：见 start_bridges_bg.bat

每个桥是独立进程，崩溃/退出不影响其他两个。
注意：飞书事件 websocket 一个 app 仅允许一条连接，重启前务必先停旧进程。
"""
import subprocess
import sys
import time
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from dotenv import load_dotenv

load_dotenv()

VENV_PY = os.path.join(".venv", "Scripts", "python.exe")
BOTS = ["hermes", "codex", "workbuddy"]
PROCS = []


def main():
    for bot in BOTS:
        p = subprocess.Popen(
            [VENV_PY, "feishu_reply.py", bot],
            cwd=os.path.dirname(os.path.abspath(__file__)),
        )
        PROCS.append(p)
        print(f"[{bot}] 已启动 PID={p.pid}")
        time.sleep(1)  # 错开启动，避免飞书连接风暴
    print("三个桥已启动，按 Ctrl+C 退出（会逐个释放连接）")
    try:
        for p in PROCS:
            p.wait()
    except KeyboardInterrupt:
        for p in PROCS:
            p.terminate()
        print("已发送退出信号")


if __name__ == "__main__":
    main()
