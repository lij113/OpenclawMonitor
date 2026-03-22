import os
import sys
import json
import socket
import subprocess
from pathlib import Path
import webbrowser
import threading
import time


def check_python():
    version = sys.version_info
    if version < (3, 9):
        print("错误: 需要Python 3.9+")
        sys.exit(1)

    print(f"✓ Python版本: {version.major}.{version.minor}")


def check_openclaw_home():
    openclaw_home = os.environ.get(
        "OPENCLAW_HOME",
        str(Path.home() / ".openclaw")
    )

    if not os.path.isdir(openclaw_home):
        print(f"错误: OpenClaw目录不存在: {openclaw_home}")
        print("提示: 设置OPENCLAW_HOME环境变量")
        sys.exit(1)

    print(f"✓ OpenClaw目录: {openclaw_home}")
    return openclaw_home


def port_in_use(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(("127.0.0.1", port)) == 0


def check_port(port):
    if port_in_use(port):
        print(f"警告: 端口 {port} 已被占用")
        print("请手动关闭占用端口的程序")


def load_config(path):
    if not os.path.exists(path):
        print("未找到config.json")
        sys.exit(1)

    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_config(path, cfg):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)


def handle_llm_config(cfg, config_path):
    enable = cfg.get("alerts", {}).get("enable_llm_evaluation", True)
    api_key = cfg.get("bailian", {}).get("api_key", "")

    if enable and not api_key:
        print()
        print("检测到未配置百炼API Key")
        use_llm = input("是否启用百炼GLM-5评估? [Y/n] (默认:Y): ").strip()

        if use_llm == "":
            use_llm = "Y"

        if use_llm.lower() == "y":
            api_key = input("请输入百炼API Key: ").strip()
            cfg["bailian"]["api_key"] = api_key
            save_config(config_path, cfg)
            print("✓ 已保存API Key")

        else:
            cfg["alerts"]["enable_llm_evaluation"] = False
            save_config(config_path, cfg)
            print("✓ 已禁用LLM评估")


def open_browser(port):
    time.sleep(1)
    webbrowser.open(f"http://localhost:{port}")


def main():

    print("🦞 OpenClaw Monitor启动器")
    print()
    check_python()

    openclaw_home = check_openclaw_home()
    port = int(os.environ.get("MONITOR_PORT", 8765))

    script_dir = Path(__file__).resolve().parent
    os.chdir(script_dir)

    config_path = script_dir / "config.json"
    cfg = load_config(config_path)
    handle_llm_config(cfg, config_path)

    check_port(port)

    print()
    print("启动监控服务...")
    print(f"访问地址: http://localhost:{port}")
    print("按 Ctrl+C 停止服务")
    print()

    threading.Thread(target=open_browser, args=(port,), daemon=True).start()
    subprocess.run([sys.executable, "server.py"])


if __name__ == "__main__":
    main()