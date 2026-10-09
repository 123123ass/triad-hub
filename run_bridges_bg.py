"""run_bridges_bg.py —— 后台常驻启动三个飞书桥，stdout/stderr 重定向到 bridge_logs/。

用法：
  .venv/Scripts/python.exe run_bridges_bg.py
每个桥以 DETACHED_PROCESS 脱离父 shell，崩溃不影响其他两个；锁机制保证同 bot 单实例。
"""
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
VENV_PY = os.path.join(HERE, ".venv", "Scripts", "python.exe")
LOG_DIR = os.path.join(HERE, "bridge_logs")
os.makedirs(LOG_DIR, exist_ok=True)

BOTS = ["hermes", "codex", "workbuddy"]
procs = []

for bot in BOTS:
    log_path = os.path.join(LOG_DIR, f"bridge_{bot}.log")
    logf = open(log_path, "a", encoding="utf-8")
    p = subprocess.Popen(
        [VENV_PY, "feishu_reply.py", bot],
        cwd=HERE,
        stdout=logf,
        stderr=logf,
        # 脱离父进程，关闭继承的 stdin，避免随启动 shell 退出
        creationflags=0x00000008,  # DETACHED_PROCESS
        close_fds=True,
    )
    procs.append((bot, p.pid))
    print(f"[{bot}] 已后台启动 PID={p.pid} -> {log_path}")
    time.sleep(1)  # 错开启动，避免飞书连接风暴

print("三桥已在后台启动（DETACHED）。查看 bridge_logs/ 各文件确认连接状态。")
