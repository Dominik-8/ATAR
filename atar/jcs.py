"""JSON Canonicalization Scheme (JCS, RFC 8785) — self-contained subset.

Used by the VC bridge (``atar.vc``) for the ``eddsa-jcs-2022`` Data Integrity
cryptosuite: signer and verifier must canonicalize to byte-identical output.
No dependencies; covers the full JSON data model.

The one genuinely tricky part is ECMAScript ``Number::toString`` semantics for
floats; ``_number`` implements it (shortest round-trip digits via ``repr``,
JS-style exponent formatting, plain notation below 1e21).
"""

from __future__ import annotations

import math

_STRING_ESCAPES = {
    '"': '\\"', "\\": "\\\\",
    "\b": "\\b", "\f": "\\f", "\n": "\\n", "\r": "\\r", "\t": "\\t",
}


def _quote(s: str) -> str:
    out = ['"']
    for ch in s:
        esc = _STRING_ESCAPES.get(ch)
        if esc is not None:
            out.append(esc)
        elif ord(ch) < 0x20:
            out.append("\\u%04x" % ord(ch))
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _number(n) -> str:
    if isinstance(n, bool):  # bool is an int subclass — guard first
        raise TypeError("bool is not a JSON number")
    if isinstance(n, int):
        if abs(n) > 2**53 - 1:
            raise ValueError("JCS/JSON interop: integer outside the safe range (±2^53)")
        return str(n)
    if isinstance(n, float):
        if math.isnan(n) or math.isinf(n):
            raise ValueError("JCS rejects non-finite numbers")
        if n == 0:
            return "0"  # covers -0.0 (ECMAScript prints "0")
        if n.is_integer() and abs(n) < 1e21:
            return str(int(n))
        text = repr(n)  # shortest round-trip digits, same as ECMAScript
        if "e" in text or "E" in text:
            mantissa, _, exp = text.lower().partition("e")
            sign = ""
            if exp.startswith(("+", "-")):
                sign, exp = exp[0], exp[1:]
            return f"{mantissa}e{sign}{int(exp)}"
        return text
    raise TypeError(f"not a JSON number: {type(n)}")


def _serialize(obj) -> str:
    if obj is None:
        return "null"
    if obj is True:
        return "true"
    if obj is False:
        return "false"
    if isinstance(obj, str):
        return _quote(obj)
    if isinstance(obj, (int, float)):
        return _number(obj)
    if isinstance(obj, list):
        return "[" + ",".join(_serialize(v) for v in obj) + "]"
    if isinstance(obj, dict):
        # RFC 8785: sort keys by UTF-16 code units
        keys = sorted(obj.keys(), key=lambda k: k.encode("utf-16-be"))
        return "{" + ",".join(_quote(k) + ":" + _serialize(obj[k]) for k in keys) + "}"
    raise TypeError(f"not JSON-serializable: {type(obj)}")


def canonicalize(obj) -> bytes:
    """RFC 8785 canonical JSON bytes for a Python data structure."""
    return _serialize(obj).encode("utf-8")
