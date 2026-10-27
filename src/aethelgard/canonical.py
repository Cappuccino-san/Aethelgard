"""RFC 8785 JSON Canonicalization Scheme (JCS) implementation."""

import json
import math
from typing import Any


def _encode_string(value: str) -> str:
    """RFC 8785 Section 3.2.2.2 string serialization."""
    out = ['"']
    for ch in value:
        code = ord(ch)
        if code == 0x08:
            out.append(r"\b")
        elif code == 0x09:
            out.append(r"\t")
        elif code == 0x0A:
            out.append(r"\n")
        elif code == 0x0C:
            out.append(r"\f")
        elif code == 0x0D:
            out.append(r"\r")
        elif code == 0x22:
            out.append(r"\"")
        elif code == 0x5C:
            out.append(r"\\")
        elif code < 0x20:
            out.append(f"\\u{code:04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _utf16_sort_key(key: str) -> bytes:
    """RFC 8785 Section 3.2.3 lexicographic sorting by UTF-16 code units."""
    return key.encode("utf-16-be")


def _encode_number(value: int | float) -> str:
    """RFC 8785 Section 3.2.2.3 IEEE 754 number serialization."""
    if isinstance(value, int) and not isinstance(value, bool):
        return str(value)
    if math.isnan(value) or math.isinf(value):
        raise ValueError("RFC 8785 does not permit NaN or Infinity in canonical JSON")
    if value == 0.0:
        return "0"
    if value.is_integer() and abs(value) < 1e21:
        return str(int(value))
    return json.dumps(value)


def canonicalize_json(obj: Any) -> str:
    """Serialize a Python object to RFC 8785 Canonical JSON string."""
    if obj is None:
        return "null"
    if obj is True:
        return "true"
    if obj is False:
        return "false"
    if isinstance(obj, (int, float)):
        return _encode_number(obj)
    if isinstance(obj, str):
        return _encode_string(obj)
    if isinstance(obj, (list, tuple)):
        return "[" + ",".join(canonicalize_json(item) for item in obj) + "]"
    if isinstance(obj, dict):
        sorted_items = sorted(obj.items(), key=lambda kv: _utf16_sort_key(str(kv[0])))
        members = [
            f"{_encode_string(str(k))}:{canonicalize_json(v)}"
            for k, v in sorted_items
        ]
        return "{" + ",".join(members) + "}"
    raise TypeError(f"Unsupported type for RFC 8785 canonicalization: {type(obj)!r}")
