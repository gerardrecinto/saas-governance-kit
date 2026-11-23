import argparse
import os

import uvicorn

from .app import create_app
from .store import ScimStore


def main() -> None:
    p = argparse.ArgumentParser(description="Run the SCIM 2.0 server")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8080)
    p.add_argument("--store", default=None, help="JSON file for persistence (default: in-memory)")
    args = p.parse_args()
    token = os.environ.get("SCIM_BEARER_TOKEN")
    if not token:
        raise SystemExit("Set SCIM_BEARER_TOKEN")
    uvicorn.run(create_app(ScimStore(args.store), token), host=args.host, port=args.port)


if __name__ == "__main__":
    main()
