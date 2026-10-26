"""
extractor.py  —  Deterministic IoC Extractor
Sujet 2.2 : LLM-Augmented Reverse Engineering

Handles 4 obfuscation levels:
  1. Plain text
  2. Base64-encoded strings
  3. XOR-encoded byte arrays (constant key)
  4. Stack strings (char-by-char assignment)
"""

import re
import base64
import json
import sys
import os
from pathlib import Path


# ─────────────────────────────────────────────────────────────────────────────
# REGEX PATTERNS
# ─────────────────────────────────────────────────────────────────────────────

# IPv4 address
RE_IP = re.compile(
    r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b'
)

# Domain name (at least one dot, known TLDs + .test for synthetic samples)
RE_DOMAIN = re.compile(
    r'\b([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.'
    r'(?:[a-zA-Z0-9\-]{1,61}\.)*'
    r'(?:com|net|org|io|test|ru|cn|tk|xyz|info|biz|co))\b'
)

# Windows registry keys
RE_REG = re.compile(
    r'(HK(?:CU|LM|CR|U|CC)\\[\\A-Za-z0-9 _\-\.\(\)]+)',
    re.IGNORECASE
)

# Base64 string literals (min 8 chars, valid b64 alphabet)
RE_B64 = re.compile(
    r'"([A-Za-z0-9+/]{8,}={0,2})"'
)

# XOR byte array:  { 0x70, 0x72, ... , 0x00 }
RE_XOR_ARRAY = re.compile(
    r'\{((?:\s*0x[0-9a-fA-F]{2}\s*,\s*)+0x00\s*)\}'
)

# Stack string: varname[N] = 0xHH;
RE_STACK = re.compile(
    r'(\w+)\[(\d+)\]\s*=\s*0x([0-9a-fA-F]{2})\s*;'
)


# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def is_valid_ip(ip: str) -> bool:
    parts = ip.split(".")
    return all(0 <= int(p) <= 255 for p in parts)


def extract_iocs_from_text(text: str) -> dict:
    """Run all three regex patterns on a plain text string."""
    ips      = {m for m in RE_IP.findall(text)     if is_valid_ip(m)}
    domains  = {m for m in RE_DOMAIN.findall(text) if "." in m}
    reg_keys = {m.strip() for m in RE_REG.findall(text)}
    return {"ips": ips, "domains": domains, "registry_keys": reg_keys}


def merge(base: dict, extra: dict) -> dict:
    for key in base:
        base[key] |= extra[key]
    return base


# ─────────────────────────────────────────────────────────────────────────────
# LEVEL 1 : PLAIN TEXT
# ─────────────────────────────────────────────────────────────────────────────

def extract_plain(code: str) -> dict:
    return extract_iocs_from_text(code)


# ─────────────────────────────────────────────────────────────────────────────
# LEVEL 2 : BASE64
# ─────────────────────────────────────────────────────────────────────────────

def extract_base64(code: str) -> dict:
    found = {"ips": set(), "domains": set(), "registry_keys": set()}
    for match in RE_B64.finditer(code):
        candidate = match.group(1)
        # pad if necessary
        padded = candidate + "=" * (-len(candidate) % 4)
        try:
            decoded = base64.b64decode(padded).decode("utf-8", errors="ignore")
            iocs = extract_iocs_from_text(decoded)
            merge(found, iocs)
        except Exception:
            pass
    return found


# ─────────────────────────────────────────────────────────────────────────────
# LEVEL 3 : XOR
# ─────────────────────────────────────────────────────────────────────────────

COMMON_XOR_KEYS = [0x42, 0x41, 0x13, 0x37, 0xFF, 0x01, 0xAA, 0x55]

def parse_xor_array(raw: str) -> list[int]:
    """Parse '0x70, 0x72, ..., 0x00' into list of ints (without the null)."""
    tokens = re.findall(r'0x([0-9a-fA-F]{2})', raw)
    values = [int(t, 16) for t in tokens]
    # remove trailing null
    if values and values[-1] == 0:
        values = values[:-1]
    return values

def xor_decode(byte_list: list[int], key: int) -> str:
    try:
        return bytes(b ^ key for b in byte_list).decode("utf-8", errors="ignore")
    except Exception:
        return ""

def extract_xor(code: str) -> dict:
    found = {"ips": set(), "domains": set(), "registry_keys": set()}
    for match in RE_XOR_ARRAY.finditer(code):
        raw     = match.group(1)
        byte_arr = parse_xor_array(raw)
        if not byte_arr:
            continue
        for key in COMMON_XOR_KEYS:
            decoded = xor_decode(byte_arr, key)
            iocs    = extract_iocs_from_text(decoded)
            merge(found, iocs)
    return found


# ─────────────────────────────────────────────────────────────────────────────
# LEVEL 4 : STACK STRINGS
# ─────────────────────────────────────────────────────────────────────────────

def extract_stack_strings(code: str) -> dict:
    found = {"ips": set(), "domains": set(), "registry_keys": set()}

    # Group assignments by variable name
    buffers: dict[str, dict[int, int]] = {}
    for match in RE_STACK.finditer(code):
        varname = match.group(1)
        index   = int(match.group(2))
        value   = int(match.group(3), 16)
        if value == 0:          # null terminator — skip
            continue
        buffers.setdefault(varname, {})[index] = value

    # Reconstruct each buffer into a string
    for varname, char_map in buffers.items():
        if not char_map:
            continue
        max_idx = max(char_map.keys())
        chars   = [char_map.get(i, 0) for i in range(max_idx + 1)]
        try:
            reconstructed = bytes(chars).decode("utf-8", errors="ignore")
            iocs = extract_iocs_from_text(reconstructed)
            merge(found, iocs)
        except Exception:
            pass

    return found


# ─────────────────────────────────────────────────────────────────────────────
# MAIN EXTRACTOR
# ─────────────────────────────────────────────────────────────────────────────

def extract(filepath: str) -> dict:
    code = Path(filepath).read_text(encoding="utf-8", errors="ignore")

    result = {"ips": set(), "domains": set(), "registry_keys": set()}

    merge(result, extract_plain(code))
    merge(result, extract_base64(code))
    merge(result, extract_xor(code))
    merge(result, extract_stack_strings(code))

    # Convert sets to sorted lists for clean output
    return {k: sorted(v) for k, v in result.items()}


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python extractor.py <file.c>  [file2.c ...]")
        sys.exit(1)

    for path in sys.argv[1:]:
        print(f"\n{'='*60}")
        print(f"  FILE : {path}")
        print(f"{'='*60}")
        iocs = extract(path)
        print(json.dumps(iocs, indent=2))
