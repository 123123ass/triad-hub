"""旧入口兼容层。

旧启动脚本仍可调用 feishu_reply.py，但实际只能进入Hub ingress bridge，
不能再直连任何Agent。
"""
from hub_bridge import main

if __name__ == "__main__":
    main()
