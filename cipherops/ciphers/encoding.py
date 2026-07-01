"""Encoding schemes treated as ciphers in the training corpus."""

from __future__ import annotations

import base64


def base64_encode(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def base64_decode(text: str) -> str:
    return base64.b64decode(text.encode("ascii")).decode("utf-8")
