"""Pager for the demo: prints the decoy's canary alerts as they arrive.

Start this first, then start the decoy with the webhook pointed here:
    python -m scripts.alert_listener
    set CERDA_ALERT_WEBHOOK=http://127.0.0.1:9099/        (PowerShell: $env:CERDA_ALERT_WEBHOOK="http://127.0.0.1:9099/")
    python decoy_server.py --tarpit
"""
import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

from rich.console import Console
from rich.panel import Panel

console = Console()


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        try:
            text = json.loads(body).get("text") or body.decode()
        except ValueError:
            text = body.decode(errors="replace")
        console.print(Panel(text, title="CERDA canary alert", border_style="red"))
        sys.stdout.write("\a")
        sys.stdout.flush()
        self.send_response(200)
        self.end_headers()

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 9099
    console.print(f"[bold]Waiting for alerts on http://127.0.0.1:{port}/[/]")
    HTTPServer(("127.0.0.1", port), Handler).serve_forever()
