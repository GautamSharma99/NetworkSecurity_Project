"""Start the TraceBack dashboard: python run.py [--port 8000] [--no-browser]"""

import argparse
import threading
import webbrowser

import uvicorn


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the TraceBack dashboard")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--lan", action="store_true",
                        help="also allow other devices on the same Wi-Fi to open it")
    parser.add_argument("--no-browser", action="store_true", help="don't open a browser tab")
    args = parser.parse_args()

    host = "0.0.0.0" if args.lan else "127.0.0.1"
    url = f"http://127.0.0.1:{args.port}"
    if not args.no_browser:
        threading.Timer(1.2, lambda: webbrowser.open(url)).start()
    print(f"TraceBack running at {url}  (Ctrl+C to stop)")
    if args.lan:
        print(f"Other devices on your network: http://{_lan_ip()}:{args.port}")
    uvicorn.run("server.app:app", host=host, port=args.port, log_level="warning")


def _lan_ip() -> str:
    import socket

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        try:
            s.connect(("10.255.255.255", 1))  # no packet is sent; just picks the LAN interface
            return s.getsockname()[0]
        except OSError:
            return "<your-computer-ip>"


if __name__ == "__main__":
    main()
