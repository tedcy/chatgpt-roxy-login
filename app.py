"""Run from anywhere; paths always resolve beside this file."""
import logging
from pathlib import Path
import signal
import sys
import threading
import webbrowser

from roxy_demo.app import create_app
from roxy_demo.startup import BindError, InstanceLock, start_server
from roxy_demo.storage import StoreError


def main():
    lock = InstanceLock(Path(__file__).resolve().parent / "data")
    try:
        if not lock.acquire():
            port = lock.current_port()
            if port:
                url = f"http://127.0.0.1:{port}"
                print(f"服务已经运行，打开 {url}", flush=True)
                webbrowser.open(url)
            else:
                print("服务正在启动或退出，请稍后重新打开启动脚本。", flush=True)
            return 0
        return run(lock)
    finally:
        lock.close()


def run(lock):
    logging.getLogger("werkzeug").setLevel(logging.ERROR)
    app = create_app()
    store = app.extensions["demo_store"]
    config = store.get_settings()
    preferred_port = config["WEB_PORT"]
    manager = app.extensions["demo_manager"]
    server, changed = start_server(app, preferred_port)
    port = server.server_port
    try:
        if changed:
            config["WEB_PORT"] = port
            store.save_settings(config)
            print(f"端口 {preferred_port} 不可用，已自动改用 {port} 并保存到配置。", flush=True)
        lock.publish(port)
        return serve(server, manager, port)
    finally:
        server.server_close()


def serve(server, manager, port):
    stopping = threading.Event()

    def stop(*_args):
        if not stopping.is_set():
            stopping.set()
            threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)
    print(f"Roxy Demo: http://127.0.0.1:{port}  (Ctrl+C 关闭并保存会话)", flush=True)
    webbrowser.open(f"http://127.0.0.1:{port}")
    try:
        server.serve_forever()
    finally:
        manager.shutdown()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except BindError as exc:
        code = getattr(exc.cause, "winerror", None) or exc.cause.errno
        print(f"无法监听本机网页端口（系统错误 {code}），请检查系统网络访问限制。", flush=True)
        sys.exit(1)
    except (StoreError, OSError, ValueError) as exc:
        print(f"启动失败：{exc}", flush=True)
        sys.exit(1)
