"""Normalize common indicators of compromise without external lookups."""
from __future__ import annotations

import argparse
import ipaddress
import json
import re
from pathlib import Path
from urllib.parse import urlparse

HASH_RE = re.compile(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$")
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[A-Za-z]{2,63}$")


def classify(value: str) -> dict:
    original = value.strip()
    lowered = original.lower().rstrip(".")
    try:
        return {"input": original, "type": "ip", "normalized": str(ipaddress.ip_address(lowered))}
    except ValueError:
        pass
    if lowered.startswith(("http://", "https://")):
        parsed = urlparse(lowered)
        return {"input": original, "type": "url", "normalized": parsed.geturl(), "host": parsed.hostname}
    if HASH_RE.fullmatch(lowered):
        return {"input": original, "type": f"hash-{len(lowered) * 4}", "normalized": lowered}
    if DOMAIN_RE.fullmatch(lowered):
        return {"input": original, "type": "domain", "normalized": lowered}
    return {"input": original, "type": "unknown", "normalized": lowered}


def normalize(lines: list[str]) -> list[dict]:
    seen = set()
    output = []
    for line in lines:
        item = classify(line)
        key = (item["type"], item["normalized"])
        if item["normalized"] and key not in seen:
            output.append(item)
            seen.add(key)
    return output


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", type=Path)
    args = parser.parse_args()
    print(json.dumps(normalize(args.file.read_text(encoding="utf-8").splitlines()), indent=2))


if __name__ == "__main__":
    main()
