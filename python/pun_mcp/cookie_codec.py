"""Local-only cookie/opaque-value inspection. Never pass raw session material to MCP.

Decoding is bounded, deterministic, and offline. Hash recognition != hash reversal.
"""
from __future__ import annotations

import base64
import binascii
import gzip
import hashlib
import hmac
import json
import re
from urllib.parse import unquote

MAX_INPUT = 8192
MAX_STEPS = 5
MAX_COOKIES = 48
MAX_KEYS = 30
HASHES = {32: "MD5-like (128-bit hex)", 40: "SHA-1-like (160-bit hex)",
          64: "SHA-256-like (256-bit hex)", 128: "SHA-512-like (512-bit hex)"}
HEX = re.compile(r"^[a-fA-F0-9]+$")
BASE64 = re.compile(r"^[A-Za-z0-9+/=_-]+$")
KEY = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]{0,60}$")


def hash_family(value: str) -> str | None:
    if len(value) in HASHES and HEX.fullmatch(value):
        return HASHES[len(value)]
    return None


def json_keys(value: str) -> list[str]:
    try:
        obj = json.loads(value)
    except (ValueError, TypeError):
        return []
    keys: set[str] = set()

    def gather(item: object, depth: int):
        if depth > 3 or len(keys) >= MAX_KEYS:
            return
        if isinstance(item, dict):
            for key, child in list(item.items())[:MAX_KEYS]:
                if isinstance(key, str) and KEY.fullmatch(key):
                    keys.add(key)
                gather(child, depth + 1)
        elif isinstance(item, list):
            for child in item[:3]:
                gather(child, depth + 1)
    gather(obj, 0)
    return sorted(keys)[:MAX_KEYS]


def _text(data: bytes) -> str | None:
    if len(data) > MAX_INPUT:
        return None
    try:
        value = data.decode("utf-8", "strict")
    except UnicodeDecodeError:
        return None
    # Drop binary/control payload, no escape sequence injection into clients.
    if any(ord(c) < 32 and c not in '\t\r\n' for c in value):
        return None
    return value


def _b64(value: str) -> bytes | None:
    if not 8 <= len(value) <= MAX_INPUT or not BASE64.fullmatch(value):
        return None
    value = value.rstrip("=")
    if len(value) % 4 == 1:
        return None
    try:
        result = base64.b64decode((value.replace('-', '+').replace('_', '/') + '=' * (-len(value) % 4)),
                                  validate=True)
        # Strict round-trip prevents random strings from being over-decoded.
        if base64.b64encode(result).decode().rstrip('=') != value.replace('-', '+').replace('_', '/'):
            return None
        return result
    except (ValueError, binascii.Error):
        return None


def inspect_value(value: str, *, include_values: bool = False) -> dict:
    """Return redacted metadata by default; include_values=True for local CLI only."""
    if not isinstance(value, str) or len(value) > MAX_INPUT:
        return {"encoding_chain": [], "error": "invalid or oversized input"}
    current = value.strip().strip('"')
    layers: list[str] = []
    family = hash_family(current)
    jwt = None
    if current.count('.') == 2:
        parts = current.split('.')
        header, payload = _b64(parts[0]), _b64(parts[1])
        if header and payload:
            h, p = _text(header), _text(payload)
            if h is not None and p is not None:
                hk, pk = json_keys(h), json_keys(p)
                if hk and pk:
                    jwt = {"header_keys": hk, "claim_keys": pk,
                           "signature_present": bool(parts[2])}
                    try:
                        alg = json.loads(h).get("alg")
                        if isinstance(alg, str) and len(alg) <= 32 and re.fullmatch(r'[A-Za-z0-9_-]+', alg):
                            jwt["algorithm"] = alg
                            if alg.lower() == "none":
                                jwt["review_hint"] = "JWT advertises alg=none; validation is unknown"
                    except ValueError:
                        pass
                    layers.append("jwt")
                    if include_values:
                        jwt["header_local"] = h
                        jwt["payload_local"] = p
    if not jwt and not family:
        for _ in range(MAX_STEPS):
            previous = current
            if '%' in current:
                try:
                    decoded = unquote(current, encoding='utf-8', errors='strict')
                    if decoded != current and len(decoded) <= MAX_INPUT:
                        current = decoded
                        layers.append("url-percent")
                except UnicodeDecodeError:
                    pass
            if current == previous and not hash_family(current):
                raw = _b64(current)
                if raw is not None:
                    plain = _text(raw)
                    if plain is None and raw[:2] == b'\x1f\x8b':
                        try:
                            with gzip.GzipFile(fileobj=__import__("io").BytesIO(raw)) as compressed:
                                plain = _text(compressed.read(MAX_INPUT + 1))
                            if plain is not None:
                                layers.extend(["base64", "gzip"])
                        except (OSError, EOFError):
                            pass
                    elif plain is not None:
                        layers.append("base64url" if '-' in current or '_' in current else "base64")
                    if plain is not None and plain != current:
                        current = plain
                elif len(current) % 2 == 0 and len(current) >= 4 and HEX.fullmatch(current):
                    try:
                        decoded = _text(bytes.fromhex(current))
                        if decoded is not None and decoded != current:
                            current = decoded
                            layers.append("hex")
                    except ValueError:
                        pass
            if current == previous:
                break
            if hash_family(current):
                break
    family = family or hash_family(current)
    keys = json_keys(current)
    structure = "jwt" if jwt else "json" if keys else "hash" if family else "text"
    result = {"encoding_chain": layers, "structure": structure,
              "json_keys": keys, "hash_family": family,
              "needs_review": ["A hash cannot be decoded; only candidates can be verified"] if family else []}
    if jwt:
        result["jwt"] = jwt
    if include_values:
        result["decoded_local"] = current  # Do not export to MCP/cloud model.
    return result


def inspect_cookie_header(header: str, *, include_values: bool = False) -> list[dict]:
    """Split common Cookie headers. Untrusted values and names are capped."""
    if not isinstance(header, str):
        return []
    entries: list[dict] = []
    for segment in header[:MAX_INPUT * MAX_COOKIES].split(';')[:MAX_COOKIES]:
        if '=' not in segment:
            continue
        name, value = segment.strip().split('=', 1)
        name = name.strip()
        if not KEY.fullmatch(name):
            continue
        analysis = inspect_value(value, include_values=include_values)
        entries.append({"name": name, **analysis})
    return entries


def verify_hash_candidate(digest: str, candidate: str) -> dict:
    """Local-only verification against ONE caller-provided candidate. No hash reversal."""
    names = {32: "md5", 40: "sha1", 64: "sha256", 128: "sha512"}
    if not isinstance(digest, str) or not HEX.fullmatch(digest) or len(digest) not in names:
        raise ValueError("Expected a hex MD5/SHA1/SHA256/SHA512 digest")
    algorithm = names[len(digest)]
    calculated = hashlib.new(algorithm, candidate.encode("utf-8")).hexdigest()
    return {"algorithm": algorithm.upper(), "matches_candidate": hmac.compare_digest(calculated, digest.lower()),
            "warning": "One candidate match does not establish the cookie's security properties"}
