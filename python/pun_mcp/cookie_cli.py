"""Standalone offline cookie utility; never opens a bridge or calls MCP/cloud services."""
from __future__ import annotations

import getpass
import json
import sys
from .cookie_codec import inspect_cookie_header, inspect_value, verify_hash_candidate


def main():
    command = sys.argv[1] if len(sys.argv) > 1 else "inspect"
    if command == "inspect":
        header = getpass.getpass("Cookie header or single encoded value (hidden input): ")
        if '=' in header or ';' in header:
            result = inspect_cookie_header(header, include_values=True)
        else:
            result = inspect_value(header, include_values=True)
        print("LOCAL ONLY — this output can contain session secrets. Do not paste it into AI chats.")
        print(json.dumps(result, indent=2, ensure_ascii=False))
    elif command == "verify":
        digest = getpass.getpass("MD5/SHA hex digest (hidden): ").strip()
        candidate = getpass.getpass("Candidate plaintext (hidden): ")
        try:
            print(json.dumps(verify_hash_candidate(digest, candidate), indent=2))
        except ValueError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            raise SystemExit(2) from exc
    else:
        print("Usage: python -m pun_mcp.cookie_cli [inspect|verify]", file=sys.stderr)
        raise SystemExit(2)


if __name__ == "__main__":
    main()
