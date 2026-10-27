"""
Evasion-resistant normalization layer.

Regex signature matching is trivially defeated by:
  - base64-encoding the payload
  - inserting zero-width/invisible Unicode characters between letters
    (e.g. "i\u200bgnore\u200b all" still reads as "ignore all" to a human/LLM,
    but defeats a naive \bignore\b regex)
  - swapping ASCII letters for Unicode homoglyphs (Cyrillic "а" instead of Latin "a")
  - full/half-width Unicode forms, combining diacritics, etc.

normalize() reverses these as far as reasonably possible BEFORE the signature and
semantic layers run, and decode_embedded_payloads() recursively pulls out and decodes
any base64 blobs found, so their *decoded* content also gets scanned.
"""

import base64
import binascii
import re
import unicodedata

ZERO_WIDTH_CHARS = [
    "\u200b", "\u200c", "\u200d", "\u2060", "\ufeff", "\u00ad",
]

# A small, non-exhaustive homoglyph table covering the most common Cyrillic/Greek
# lookalikes seen in real-world evasion attempts. Not a complete confusables table
# (Unicode's own confusables.txt has thousands of entries) -- see README limitations.
HOMOGLYPH_MAP = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
    "і": "i", "ѕ": "s", "ј": "j", "ԁ": "d", "ԛ": "q", "һ": "h", "ԝ": "w",
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O",
    "Р": "P", "С": "C", "Т": "T", "У": "Y", "Х": "X", "І": "I", "Ѕ": "S",
    "ο": "o", "α": "a", "ρ": "p", "υ": "u", "ν": "v", "Α": "A", "Β": "B",
    "Ε": "E", "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O", "Τ": "T",
    "Υ": "Y", "Χ": "X", "Ζ": "Z",
}

BASE64_CANDIDATE_RE = re.compile(rb"[A-Za-z0-9+/]{20,}={0,2}")


def strip_zero_width(text: str) -> str:
    for ch in ZERO_WIDTH_CHARS:
        text = text.replace(ch, "")
    return text


def normalize_homoglyphs(text: str) -> str:
    return "".join(HOMOGLYPH_MAP.get(ch, ch) for ch in text)


def normalize(text: str) -> str:
    """Full normalization pass: Unicode NFKC fold (handles full/half-width forms and
    many compatibility equivalents), zero-width stripping, homoglyph substitution."""
    text = unicodedata.normalize("NFKC", text)
    text = strip_zero_width(text)
    text = normalize_homoglyphs(text)
    return text


def decode_embedded_payloads(text: str, max_depth: int = 2) -> list[str]:
    """Find base64-looking substrings and attempt to decode them. Returns a list of
    successfully-decoded strings (which the caller should also run through scan_prompt),
    recursing up to max_depth to catch base64-inside-base64. Silently skips anything
    that doesn't decode to printable-ish text, to avoid false positives on incidental
    base64-shaped substrings (hashes, tokens, etc. that aren't hiding an attack)."""
    found = []
    _decode_recursive(text.encode("utf-8", errors="ignore"), max_depth, found)
    return found


def _decode_recursive(data: bytes, depth: int, found: list[str]) -> None:
    if depth <= 0:
        return
    for m in BASE64_CANDIDATE_RE.finditer(data):
        candidate = m.group(0)
        try:
            decoded = base64.b64decode(candidate, validate=True)
        except (binascii.Error, ValueError):
            continue
        try:
            decoded_text = decoded.decode("utf-8")
        except UnicodeDecodeError:
            continue
        printable_ratio = sum(1 for c in decoded_text if c.isprintable()) / max(1, len(decoded_text))
        if printable_ratio > 0.85 and len(decoded_text.strip()) >= 4:
            found.append(decoded_text)
            _decode_recursive(decoded, depth - 1, found)
