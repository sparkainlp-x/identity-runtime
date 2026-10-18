"""Small shared helpers: canonical JSON, hashing, text normalisation."""

from __future__ import annotations

import copy
import hashlib
import json
import re
import unicodedata
from typing import Any

ZERO_WIDTH = dict.fromkeys(map(ord, "\u200b\u200c\u200d\u2060\ufeff\u00ad"), None)


def canonical_json(obj: Any) -> str:
    """Deterministic JSON text: sorted keys, no extra whitespace, UTF-8 kept."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def sha256_hex(data: str | bytes) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def checksum(obj: Any) -> str:
    return sha256_hex(canonical_json(obj))


def frozen_copy(obj: Any) -> Any:
    """Deep copy through JSON so the result holds only plain JSON types."""
    return json.loads(canonical_json(obj))


def deep_copy(obj: Any) -> Any:
    return copy.deepcopy(obj)


def normalize_text(text: str) -> str:
    """NFKC, strip zero-width characters, casefold, collapse non-alphanumerics.

    Used only for pattern screening. It narrows trivial evasions (homoglyph
    width variants, zero-width joiners, odd punctuation) but cannot catch
    paraphrases.
    """
    text = unicodedata.normalize("NFKC", text).translate(ZERO_WIDTH).casefold()
    text = re.sub(r"[^0-9a-z]+", " ", text)
    return " ".join(text.split())


def iter_strings(obj: Any, path: str = "$"):
    """Yield (json_path, string) for every string key and value in obj."""
    if isinstance(obj, str):
        yield path, obj
    elif isinstance(obj, dict):
        for key, value in obj.items():
            yield f"{path}.{key}<key>", str(key)
            yield from iter_strings(value, f"{path}.{key}")
    elif isinstance(obj, list):
        for i, value in enumerate(obj):
            yield from iter_strings(value, f"{path}[{i}]")
