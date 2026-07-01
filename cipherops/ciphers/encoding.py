"""Encoding schemes treated as ciphers in the training corpus."""

from __future__ import annotations

import base64
import struct

# PAM-5 dibit mode: 2 bits → one of four data levels (0–3); level 4 reserved (control / DC balance in PHY).
_PAM5_DIBIT_TO_LEVEL = (0, 1, 2, 3)
_PAM5_LEVEL_TO_DIBIT = ("00", "01", "10", "11")


def base64_encode(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def base64_decode(text: str) -> str:
    return base64.b64decode(text.encode("ascii")).decode("utf-8")


def _bytes_to_bitstring(data: bytes) -> str:
    return "".join(f"{byte:08b}" for byte in data)


def _bitstring_to_bytes(bits: str) -> bytes:
    if len(bits) % 8:
        raise ValueError("Bitstring length must be a multiple of 8")
    return bytes(int(bits[i : i + 8], 2) for i in range(0, len(bits), 8))


def pam5_encode(text: str) -> str:
    """
    PAM-5 dibit encoding: length-prefixed UTF-8 → bit stream → pairs mapped to symbols 0–3.

    Uses four of five PAM amplitude levels for data (IEEE 1000BASE-T style teaching model).
    Level 4 is reserved and must not appear in encoded output.
    """
    data = text.encode("utf-8")
    payload = struct.pack(">I", len(data)) + data
    bits = _bytes_to_bitstring(payload)
    if len(bits) % 2:
        bits += "0"
    out: list[str] = []
    for i in range(0, len(bits), 2):
        dibit = int(bits[i : i + 2], 2)
        out.append(str(_PAM5_DIBIT_TO_LEVEL[dibit]))
    return "".join(out)


def pam5_decode(symbols: str) -> str:
    """Decode PAM-5 dibit symbol string (digits 0–3) back to UTF-8 text."""
    bits: list[str] = []
    for ch in symbols:
        if not ch.isdigit():
            continue
        level = int(ch)
        if level == 4:
            raise ValueError("PAM-5 dibit mode: level 4 is reserved (control), not data")
        if level > 4:
            raise ValueError(f"Invalid PAM-5 level: {level}")
        bits.append(_PAM5_LEVEL_TO_DIBIT[level])
    if not bits:
        return ""
    bitstr = "".join(bits)
    if len(bitstr) % 8:
        bitstr = bitstr[: len(bitstr) - (len(bitstr) % 8)]
    payload = _bitstring_to_bytes(bitstr)
    if len(payload) < 4:
        raise ValueError("PAM-5 payload too short for length prefix")
    length = struct.unpack(">I", payload[:4])[0]
    return payload[4 : 4 + length].decode("utf-8")
