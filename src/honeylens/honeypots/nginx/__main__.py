"""CLI entry point: python3 -m honeypot --bind 0.0.0.0 --port 8080"""

import argparse
import sys

from .eventlog import EventLog
from .server import serve


def main():
    ap = argparse.ArgumentParser(description="Multi-CVE NGINX honeypot")
    ap.add_argument("--bind", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--log", default="nginx-honeypot.json", help="JSON-lines event log path")
    ap.add_argument("--quiet", action="store_true", help="do not also echo events to stdout")
    args = ap.parse_args()

    event_log = EventLog(path=args.log, also_stdout=not args.quiet)
    httpd = serve(args.bind, args.port, event_log)
    print(f"[*] NGINX honeypot on {args.bind}:{args.port}; events -> {args.log}", file=sys.stderr)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.shutdown()
    return 0


if __name__ == "__main__":
    sys.exit(main())
