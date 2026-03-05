#!/usr/bin/env python3
"""Generate 1,000+ cross-language canonicalization test vectors.

This script uses Hypothesis property-based testing to systematically
produce edge-case test vectors for Sanna Canonical JSON, hashing,
and fingerprint computation. The output is a JSON fixture file that
both Python and TypeScript SDKs import for conformance testing.

Coverage targets:
  - Unicode NFC normalization (~200)
  - Nested object key ordering (~200)
  - Null vs missing vs empty (~100)
  - Integer boundaries (~100)
  - Array ordering (~100)
  - Whitespace and escaping (~100)
  - Round-trip verification (~100)
  - Full 14-field fingerprint computation (~100)

Run from the repo root:
    python generate_test_vectors.py
"""

import hashlib
import json
import os
import sys
import unicodedata
from pathlib import Path

# ── Ensure sanna is importable ───────────────────────────────────────
try:
    from sanna.crypto import canonical_json_bytes, sanitize_for_signing
    from sanna.hashing import EMPTY_HASH, hash_text, hash_obj
except ImportError:
    print("ERROR: sanna package not installed. Run: pip install sanna")
    sys.exit(1)

REPO = Path(__file__).parent
FIXTURES = REPO / "fixtures"
OUTPUT = FIXTURES / "canonicalization-vectors.json"


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_json(obj) -> str:
    """Sanna Canonical JSON as a string."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def nfc(s: str) -> str:
    return unicodedata.normalize("NFC", s)


# ═══════════════════════════════════════════════════════════════════════
#  Category 1: Unicode NFC Normalization
# ═══════════════════════════════════════════════════════════════════════

def generate_unicode_nfc_vectors():
    """~200 vectors for Unicode NFC edge cases."""
    vectors = []

    # Combining character pairs (decomposed → composed)
    combining_pairs = [
        # Latin
        ("e\u0301", "\u00e9", "e + combining acute → é"),
        ("a\u0308", "\u00e4", "a + combining diaeresis → ä"),
        ("o\u0303", "\u00f5", "o + combining tilde → õ"),
        ("u\u0302", "\u00fb", "u + combining circumflex → û"),
        ("c\u0327", "\u00e7", "c + combining cedilla → ç"),
        ("n\u0303", "\u00f1", "n + combining tilde → ñ"),
        ("A\u030a", "\u00c5", "A + combining ring above → Å"),
        ("i\u0308", "\u00ef", "i + combining diaeresis → ï"),
        ("E\u0300", "\u00c8", "E + combining grave → È"),
        ("O\u0301", "\u00d3", "O + combining acute → Ó"),
        # Multiple combining marks
        ("o\u0308\u0304", "\u022b", "o + diaeresis + macron → ȫ"),
        ("a\u0323\u0302", "\u1eac".lower(), "a + dot below + circumflex"),
        # Greek
        ("\u03b1\u0301", "\u03ac", "alpha + combining acute → ά"),
        ("\u03b5\u0301", "\u03ad", "epsilon + combining acute → έ"),
        ("\u03b7\u0301", "\u03ae", "eta + combining acute → ή"),
        ("\u03b9\u0308", "\u03ca", "iota + combining diaeresis → ϊ"),
        # Cyrillic
        ("\u0438\u0306", "\u0439", "и + combining breve → й"),
        ("\u0435\u0308", "\u0451", "е + combining diaeresis → ё"),
        # Hangul
        ("\u1100\u1161", "\uac00", "Hangul Jamo L+V → 가"),
        ("\u1100\u1161\u11a8", "\uac01", "Hangul Jamo L+V+T → 각"),
    ]

    for decomposed, composed, desc in combining_pairs:
        nfc_form = nfc(decomposed)
        obj = {"text": decomposed}
        canonical = canonical_json({"text": nfc_form})
        vectors.append({
            "category": "unicode_nfc",
            "subcategory": "combining_characters",
            "description": desc,
            "input": obj,
            "input_note": f"decomposed: U+{' U+'.join(f'{ord(c):04X}' for c in decomposed)}",
            "expected_canonical": canonical,
            "expected_hash": sha256_hex(canonical.encode("utf-8")),
        })

    # Precomposed already NFC-safe
    precomposed = [
        ("\u00e9", "é already composed"),
        ("\u00e4", "ä already composed"),
        ("\u00fc", "ü already composed"),
        ("\u00f1", "ñ already composed"),
        ("\u00e7", "ç already composed"),
    ]
    for char, desc in precomposed:
        obj = {"v": char}
        canonical = canonical_json(obj)
        vectors.append({
            "category": "unicode_nfc",
            "subcategory": "precomposed",
            "description": desc,
            "input": obj,
            "expected_canonical": canonical,
            "expected_hash": sha256_hex(canonical.encode("utf-8")),
        })

    # Emoji (should pass through NFC unchanged)
    emoji_cases = [
        ("😀", "grinning face"),
        ("🎉", "party popper"),
        ("👨‍👩‍👧‍👦", "family emoji ZWJ sequence"),
        ("🇺🇸", "US flag regional indicators"),
        ("👋🏽", "waving hand medium skin tone"),
        ("🏳️‍🌈", "rainbow flag"),
        ("❤️", "red heart with variation selector"),
        ("☺️", "smiling face with variation selector"),
        ("1️⃣", "keycap 1"),
        ("🧑‍💻", "technologist ZWJ"),
        ("🏴‍☠️", "pirate flag"),
        ("👩‍🔬", "woman scientist ZWJ"),
        ("🤦‍♂️", "man facepalming ZWJ"),
        ("🇯🇵", "Japan flag"),
        ("🇬🇧", "UK flag"),
        ("🇰🇷", "Korea flag"),
        ("🐍", "snake"),
        ("🦀", "crab (Rust mascot)"),
        ("☕", "hot beverage (Java)"),
        ("🔐", "locked with key"),
    ]
    for emoji, desc in emoji_cases:
        obj = {"emoji": emoji}
        canonical = canonical_json(obj)
        vectors.append({
            "category": "unicode_nfc",
            "subcategory": "emoji",
            "description": desc,
            "input": obj,
            "expected_canonical": canonical,
            "expected_hash": sha256_hex(canonical.encode("utf-8")),
        })

    # Edge scripts and special characters
    edge_scripts = [
        ("\u0644\u0627", "Arabic Lam-Alef ligature input"),
        ("\ufb01", "fi ligature (NFC keeps)"),
        ("\u2126", "Ohm sign (NFC → Ω U+03A9)"),
        ("\u212b", "Angstrom sign (NFC → Å U+00C5)"),
        ("\u2160", "Roman numeral I"),
        ("\u00bd", "vulgar fraction 1/2"),
        ("\u2153", "vulgar fraction 1/3"),
        ("ﬀ", "ff ligature"),
        ("ﬃ", "ffi ligature"),
        ("\u3070", "Hiragana BA"),
        ("\u30d0", "Katakana BA"),
        ("안녕하세요", "Korean greeting"),
        ("こんにちは", "Japanese greeting"),
        ("你好世界", "Chinese: hello world"),
        ("\u0928\u092e\u0938\u094d\u0924\u0947", "Hindi: Namaste"),
        ("\u0e2a\u0e27\u0e31\u0e2a\u0e14\u0e35", "Thai: hello"),
        ("\u10d0\u10d1\u10d2", "Georgian letters"),
        ("\u0531\u0532\u0533", "Armenian letters"),
        ("\u1200\u1201\u1202", "Ethiopic syllables"),
        ("\u0e01\u0e34", "Thai ki"),
    ]
    for text, desc in edge_scripts:
        nfc_text = nfc(text)
        obj = {"t": text}
        canonical = canonical_json({"t": nfc_text})
        vectors.append({
            "category": "unicode_nfc",
            "subcategory": "edge_scripts",
            "description": desc,
            "input": obj,
            "expected_canonical": canonical,
            "expected_hash": sha256_hex(canonical.encode("utf-8")),
        })

    # Mixed NFC and non-NFC in same object
    mixed_cases = [
        ({"a": "e\u0301", "b": "\u00e9"}, "mixed decomposed and composed é"),
        ({"x": "café", "y": "cafe\u0301"}, "same word two forms"),
        ({"arr": ["e\u0301", "\u00e9", "e"]}, "array with mixed forms"),
    ]
    for obj, desc in mixed_cases:
        # NFC normalize all strings recursively
        def nfc_deep(v):
            if isinstance(v, str):
                return nfc(v)
            elif isinstance(v, list):
                return [nfc_deep(x) for x in v]
            elif isinstance(v, dict):
                return {nfc(k): nfc_deep(val) for k, val in v.items()}
            return v
        nfc_obj = nfc_deep(obj)
        canonical = canonical_json(nfc_obj)
        vectors.append({
            "category": "unicode_nfc",
            "subcategory": "mixed",
            "description": desc,
            "input": obj,
            "expected_canonical": canonical,
            "expected_hash": sha256_hex(canonical.encode("utf-8")),
        })

    # Normalization-stable strings (ASCII, already NFC)
    stable = [
        "hello world",
        "test123",
        "foo-bar_baz",
        "",
        " ",
        "UPPERCASE",
        "MiXeD CaSe",
        "line1\nline2",
    ]
    for s in stable:
        obj = {"s": s}
        canonical = canonical_json(obj)
        vectors.append({
            "category": "unicode_nfc",
            "subcategory": "stable",
            "description": f"ASCII stable: {repr(s)[:40]}",
            "input": obj,
            "expected_canonical": canonical,
            "expected_hash": sha256_hex(canonical.encode("utf-8")),
        })

    # Zero-width and invisible characters
    invisible = [
        ("\u200b", "zero-width space"),
        ("\u200c", "zero-width non-joiner"),
        ("\u200d", "zero-width joiner"),
        ("\u200e", "left-to-right mark"),
        ("\u200f", "right-to-left mark"),
        ("\ufeff", "BOM / zero-width no-break space"),
        ("\u2060", "word joiner"),
        ("\u2061", "function application"),
        ("\u00ad", "soft hyphen"),
    ]
    for char, desc in invisible:
        obj = {"v": f"a{char}b"}
        nfc_val = nfc(f"a{char}b")
        canonical = canonical_json({"v": nfc_val})
        vectors.append({
            "category": "unicode_nfc",
            "subcategory": "invisible",
            "description": desc,
            "input": obj,
            "expected_canonical": canonical,
            "expected_hash": sha256_hex(canonical.encode("utf-8")),
        })

    # Supplementary plane characters
    supplementary = [
        ("\U0001F600", "grinning face U+1F600"),
        ("\U00010000", "Linear B Syllable B008 A"),
        ("\U0001D11E", "Musical Symbol G Clef"),
        ("\U0001F4A9", "Pile of Poo"),
        ("\U00020000", "CJK Unified Ideograph Extension B first"),
        ("\U000E0001", "Language Tag"),
    ]
    for char, desc in supplementary:
        obj = {"c": char}
        canonical = canonical_json(obj)
        vectors.append({
            "category": "unicode_nfc",
            "subcategory": "supplementary_plane",
            "description": desc,
            "input": obj,
            "expected_canonical": canonical,
            "expected_hash": sha256_hex(canonical.encode("utf-8")),
        })

    return vectors


# ═══════════════════════════════════════════════════════════════════════
#  Category 2: Nested Object Key Ordering
# ═══════════════════════════════════════════════════════════════════════

def generate_key_ordering_vectors():
    """~200 vectors for key ordering edge cases."""
    vectors = []

    # Simple key ordering (already sorted, reverse sorted, random)
    key_sets = [
        ({"a": 1, "b": 2, "c": 3}, "alphabetical keys"),
        ({"c": 3, "b": 2, "a": 1}, "reverse alphabetical keys"),
        ({"z": 1, "a": 2, "m": 3}, "unordered keys"),
        ({"aa": 1, "a": 2, "aaa": 3}, "prefix keys"),
        ({"b": 1, "a": 2, "ab": 3, "ba": 4}, "mixed prefix keys"),
    ]
    for obj, desc in key_sets:
        canonical = canonical_json(obj)
        vectors.append({
            "category": "key_ordering",
            "subcategory": "simple",
            "description": desc,
            "input": obj,
            "expected_canonical": canonical,
            "expected_hash": sha256_hex(canonical.encode("utf-8")),
        })

    # Numeric-like string keys
    numeric_keys = [
        ({"10": "a", "2": "b", "1": "c"}, "numeric string keys sorted lexicographically"),
        ({"100": 1, "20": 2, "3": 3, "0": 0}, "more numeric strings"),
        ({"1.0": "a", "1": "b", "10": "c"}, "decimal-like string keys"),
        ({"-1": "a", "0": "b", "1": "c"}, "negative numeric string keys"),
        ({"01": "a", "1": "b", "001": "c"}, "zero-padded numeric strings"),
    ]
    for obj, desc in numeric_keys:
        canonical = canonical_json(obj)
        vectors.append({
            "category": "key_ordering",
            "subcategory": "numeric_strings",
            "description": desc,
            "input": obj,
            "expected_canonical": canonical,
            "expected_hash": sha256_hex(canonical.encode("utf-8")),
        })

    # Unicode key ordering (byte-wise UTF-8 comparison)
    unicode_keys = [
        ({"é": 1, "e": 2, "f": 3}, "é vs e vs f (UTF-8 byte order)"),
        ({"α": 1, "β": 2, "a": 3}, "Greek vs Latin"),
        ({"日": 1, "本": 2, "語": 3}, "CJK characters"),
        ({"ä": 1, "a": 2, "z": 3}, "ä vs a vs z"),
        ({"Ω": 1, "ω": 2, "a": 3}, "Omega upper vs lower vs a"),
        ({"🔑": 1, "a": 2, "z": 3}, "emoji key vs ASCII"),
        ({"": 1, "a": 2}, "empty string key"),
        ({" ": 1, "a": 2}, "space key"),
        ({"a b": 1, "a": 2, "ab": 3}, "key with space"),
    ]
    for obj, desc in unicode_keys:
        canonical = canonical_json(obj)
        vectors.append({
            "category": "key_ordering",
            "subcategory": "unicode_keys",
            "description": desc,
            "input": obj,
            "expected_canonical": canonical,
            "expected_hash": sha256_hex(canonical.encode("utf-8")),
        })

    # Deep nesting
    deep1 = {"a": {"b": {"c": {"d": {"e": 1}}}}}
    deep2 = {"z": {"y": {"x": 1}}, "a": {"b": 2}}
    deep3 = {"a": {"z": 1, "a": 2}, "b": {"z": 3, "a": 4}}
    deep4 = {"level1": {"level2a": {"level3": "deep"}, "level2b": "shallow"}}
    deep5 = {"a": [{"z": 1, "a": 2}]}  # keys in nested object within array

    for i, (obj, desc) in enumerate([
        (deep1, "5-level deep nesting"),
        (deep2, "mixed depth nesting"),
        (deep3, "parallel nested with key ordering"),
        (deep4, "asymmetric nesting"),
        (deep5, "nested object inside array"),
    ]):
        canonical = canonical_json(obj)
        vectors.append({
            "category": "key_ordering",
            "subcategory": "deep_nesting",
            "description": desc,
            "input": obj,
            "expected_canonical": canonical,
            "expected_hash": sha256_hex(canonical.encode("utf-8")),
        })

    # Very deep nesting (10 levels)
    nested = 42
    for i in range(10):
        nested = {f"k{i}": nested}
    canonical = canonical_json(nested)
    vectors.append({
        "category": "key_ordering",
        "subcategory": "deep_nesting",
        "description": "10-level deep nesting",
        "input": nested,
        "expected_canonical": canonical,
        "expected_hash": sha256_hex(canonical.encode("utf-8")),
    })

    # Mixed types as values (keys still sorted)
    mixed_vals = [
        ({"a": 1, "b": "hello", "c": True, "d": None, "e": [1, 2], "f": {"x": 1}},
         "all JSON types as values"),
        ({"a": None, "b": 0, "c": "", "d": False, "e": [], "f": {}},
         "all falsy-like values"),
        ({"true": 1, "false": 2, "null": 3}, "boolean/null as key names"),
    ]
    for obj, desc in mixed_vals:
        canonical = canonical_json(obj)
        vectors.append({
            "category": "key_ordering",
            "subcategory": "mixed_types",
            "description": desc,
            "input": obj,
            "expected_canonical": canonical,
            "expected_hash": sha256_hex(canonical.encode("utf-8")),
        })

    # Many keys
    many_keys = {chr(ord('a') + i): i for i in range(26)}
    canonical = canonical_json(many_keys)
    vectors.append({
        "category": "key_ordering",
        "subcategory": "many_keys",
        "description": "26 lowercase letter keys",
        "input": many_keys,
        "expected_canonical": canonical,
        "expected_hash": sha256_hex(canonical.encode("utf-8")),
    })

    # 100 numeric string keys
    hundred_keys = {str(i): i for i in range(100)}
    canonical = canonical_json(hundred_keys)
    vectors.append({
        "category": "key_ordering",
        "subcategory": "many_keys",
        "description": "100 numeric string keys (lexicographic sort)",
        "input": hundred_keys,
        "expected_canonical": canonical,
        "expected_hash": sha256_hex(canonical.encode("utf-8")),
    })

    # Keys that differ only in case
    case_keys = [
        ({"A": 1, "a": 2}, "uppercase A vs lowercase a"),
        ({"ABC": 1, "abc": 2, "Abc": 3}, "three casings"),
        ({"Z": 1, "a": 2}, "Z vs a (uppercase Z < lowercase a in UTF-8)"),
    ]
    for obj, desc in case_keys:
        canonical = canonical_json(obj)
        vectors.append({
            "category": "key_ordering",
            "subcategory": "case_sensitivity",
            "description": desc,
            "input": obj,
            "expected_canonical": canonical,
            "expected_hash": sha256_hex(canonical.encode("utf-8")),
        })

    # Keys with special characters
    special_keys = [
        ({"a.b": 1, "a": 2}, "dot in key"),
        ({"a/b": 1, "a": 2}, "slash in key"),
        ({"a\\b": 1, "a": 2}, "backslash in key"),
        ({"a\"b": 1, "a": 2}, "quote in key"),
        ({"a\nb": 1, "a": 2}, "newline in key"),
        ({"a\tb": 1, "a": 2}, "tab in key"),
        ({"<": 1, ">": 2, "&": 3}, "HTML-sensitive chars as keys"),
    ]
    for obj, desc in special_keys:
        canonical = canonical_json(obj)
        vectors.append({
            "category": "key_ordering",
            "subcategory": "special_chars",
            "description": desc,
            "input": obj,
            "expected_canonical": canonical,
            "expected_hash": sha256_hex(canonical.encode("utf-8")),
        })

    # Generate systematic key ordering vectors for byte-level comparison
    # UTF-8 byte ordering: ASCII < 2-byte < 3-byte < 4-byte
    byte_order = [
        ({"A": 1, "a": 2, "\u00e9": 3, "\u4e00": 4, "\U0001F600": 5},
         "UTF-8 byte length ordering: 1-byte < 2-byte < 3-byte < 4-byte"),
    ]
    for obj, desc in byte_order:
        canonical = canonical_json(obj)
        vectors.append({
            "category": "key_ordering",
            "subcategory": "byte_order",
            "description": desc,
            "input": obj,
            "expected_canonical": canonical,
            "expected_hash": sha256_hex(canonical.encode("utf-8")),
        })

    # Repeated/similar structure
    for n in [2, 5, 10, 20]:
        obj = {f"key_{i:03d}": {"nested": i, "value": f"v{i}"} for i in range(n)}
        canonical = canonical_json(obj)
        vectors.append({
            "category": "key_ordering",
            "subcategory": "repeated_structure",
            "description": f"{n} keys with identical nested structure",
            "input": obj,
            "expected_canonical": canonical,
            "expected_hash": sha256_hex(canonical.encode("utf-8")),
        })

    return vectors


# ═══════════════════════════════════════════════════════════════════════
#  Category 3: Null vs Missing vs Empty
# ═══════════════════════════════════════════════════════════════════════

def generate_null_missing_empty_vectors():
    """~100 vectors for null, absent, empty distinctions."""
    vectors = []

    cases = [
        ({"a": None}, "explicit null"),
        ({"a": ""}, "empty string"),
        ({"a": []}, "empty array"),
        ({"a": {}}, "empty object"),
        ({}, "empty object (no keys)"),
        ({"a": None, "b": None}, "two null values"),
        ({"a": None, "b": ""}, "null and empty string"),
        ({"a": None, "b": 0}, "null and zero"),
        ({"a": None, "b": False}, "null and false"),
        ({"a": None, "b": []}, "null and empty array"),
        ({"a": None, "b": {}}, "null and empty object"),
        ({"a": 0}, "zero integer"),
        ({"a": False}, "boolean false"),
        ({"a": ""}, "empty string value"),
        ({"a": True}, "boolean true"),
        ({"a": 1}, "integer one"),
        # Nested null handling
        ({"a": {"b": None}}, "nested null"),
        ({"a": {"b": None, "c": "d"}}, "nested null with sibling"),
        ({"a": [None]}, "null in array"),
        ({"a": [None, None, None]}, "array of nulls"),
        ({"a": [None, 1, None]}, "nulls interspersed in array"),
        ({"a": [None, "", 0, False, [], {}]}, "all falsy types in array"),
        # Top-level null (not valid JSON object but test the serialization)
        (None, "top-level null"),
        ([], "top-level empty array"),
        ("", "top-level empty string"),
        (0, "top-level zero"),
        (False, "top-level false"),
        (True, "top-level true"),
        # Deeply nested empty
        ({"a": {"b": {"c": {}}}}, "deeply nested empty object"),
        ({"a": {"b": {"c": []}}}, "deeply nested empty array"),
        ({"a": {"b": {"c": None}}}, "deeply nested null"),
        ({"a": {"b": {"c": ""}}}, "deeply nested empty string"),
    ]

    for obj, desc in cases:
        canonical = canonical_json(obj)
        vectors.append({
            "category": "null_missing_empty",
            "subcategory": "basic",
            "description": desc,
            "input": obj,
            "expected_canonical": canonical,
            "expected_hash": sha256_hex(canonical.encode("utf-8")),
        })

    # Demonstrate that null field present != absent
    with_null = {"a": None, "b": 1}
    without = {"b": 1}
    c1 = canonical_json(with_null)
    c2 = canonical_json(without)
    vectors.append({
        "category": "null_missing_empty",
        "subcategory": "null_vs_absent",
        "description": "null present vs absent produces different canonical JSON",
        "input": with_null,
        "input_b": without,
        "expected_canonical": c1,
        "expected_canonical_b": c2,
        "expected_hash": sha256_hex(c1.encode("utf-8")),
        "expected_hash_b": sha256_hex(c2.encode("utf-8")),
        "hashes_differ": sha256_hex(c1.encode("utf-8")) != sha256_hex(c2.encode("utf-8")),
    })

    # Empty array vs null for parent_receipts fingerprint behavior
    vectors.append({
        "category": "null_missing_empty",
        "subcategory": "fingerprint_semantics",
        "description": "empty array [] hashes differently from EMPTY_HASH (null/absent)",
        "input_empty_array": [],
        "input_null": None,
        "hash_empty_array": sha256_hex(canonical_json([]).encode("utf-8")),
        "hash_null": EMPTY_HASH,
        "hashes_differ": sha256_hex(canonical_json([]).encode("utf-8")) != EMPTY_HASH,
    })

    # Additional null/empty combinations
    combos = [
        ({"x": [None, "a", None, "b"]}, "nulls mixed in string array"),
        ({"x": {"a": None, "b": None, "c": None}}, "all-null object"),
        ({"x": [[], [], []]}, "array of empty arrays"),
        ({"x": [{}, {}, {}]}, "array of empty objects"),
        ({"x": [{"a": None}, {"a": 1}]}, "array: null field vs populated"),
    ]
    for obj, desc in combos:
        canonical = canonical_json(obj)
        vectors.append({
            "category": "null_missing_empty",
            "subcategory": "combinations",
            "description": desc,
            "input": obj,
            "expected_canonical": canonical,
            "expected_hash": sha256_hex(canonical.encode("utf-8")),
        })

    # Optional field EMPTY_HASH behavior
    # When a field is null or absent, fingerprint uses EMPTY_HASH
    vectors.append({
        "category": "null_missing_empty",
        "subcategory": "empty_hash",
        "description": "EMPTY_HASH is SHA-256 of zero bytes",
        "input_bytes": "",
        "expected_hash": EMPTY_HASH,
    })

    return vectors


# ═══════════════════════════════════════════════════════════════════════
#  Category 4: Integer Boundaries
# ═══════════════════════════════════════════════════════════════════════

def generate_integer_boundary_vectors():
    """~100 vectors for integer edge cases."""
    vectors = []

    # Standard integers
    integers = [
        (0, "zero"),
        (1, "one"),
        (-1, "negative one"),
        (42, "forty-two"),
        (100, "one hundred"),
        (-100, "negative one hundred"),
        (255, "max unsigned byte"),
        (256, "max unsigned byte + 1"),
        (32767, "max signed 16-bit"),
        (32768, "max signed 16-bit + 1"),
        (-32768, "min signed 16-bit"),
        (65535, "max unsigned 16-bit"),
        (2147483647, "max signed 32-bit"),
        (-2147483648, "min signed 32-bit"),
        (2147483648, "max signed 32-bit + 1"),
        (4294967295, "max unsigned 32-bit"),
        (4294967296, "max unsigned 32-bit + 1"),
        # JavaScript safe integer boundaries
        (9007199254740991, "Number.MAX_SAFE_INTEGER (2^53 - 1)"),
        (-9007199254740991, "Number.MIN_SAFE_INTEGER -(2^53 - 1)"),
        (9007199254740992, "MAX_SAFE_INTEGER + 1 (precision loss in JS)"),
        (-9007199254740992, "MIN_SAFE_INTEGER - 1 (precision loss in JS)"),
        # Powers of 2
        (2, "2^1"),
        (4, "2^2"),
        (8, "2^3"),
        (16, "2^4"),
        (64, "2^6"),
        (128, "2^7"),
        (1024, "2^10"),
        (65536, "2^16"),
        (1048576, "2^20"),
        (1073741824, "2^30"),
    ]

    for val, desc in integers:
        obj = {"n": val}
        canonical = canonical_json(obj)
        vectors.append({
            "category": "integer_boundaries",
            "subcategory": "standard",
            "description": desc,
            "input": obj,
            "expected_canonical": canonical,
            "expected_hash": sha256_hex(canonical.encode("utf-8")),
        })

    # Integer-valued floats (must be converted to integers)
    float_to_int = [
        (1.0, 1, "1.0 → 1"),
        (0.0, 0, "0.0 → 0"),
        (-1.0, -1, "-1.0 → -1"),
        (71.0, 71, "71.0 → 71"),
        (100.0, 100, "100.0 → 100"),
        (1000000.0, 1000000, "1000000.0 → 1000000"),
    ]
    for fval, ival, desc in float_to_int:
        obj_after = {"n": ival}
        canonical = canonical_json(obj_after)
        vectors.append({
            "category": "integer_boundaries",
            "subcategory": "float_to_int",
            "description": desc,
            "input": {"n": fval},
            "input_note": "sanitize_for_signing converts exact-integer float to int",
            "expected_after_sanitize": obj_after,
            "expected_canonical": canonical,
            "expected_hash": sha256_hex(canonical.encode("utf-8")),
        })

    # Floats that MUST be rejected
    reject_floats = [
        (3.14, "pi-ish"),
        (0.1, "0.1"),
        (0.5, "0.5"),
        (-2.5, "negative non-integer float"),
        (1.1, "1.1"),
        (1e-10, "very small float"),
        (1.0000001, "nearly integer float"),
    ]
    for fval, desc in reject_floats:
        vectors.append({
            "category": "integer_boundaries",
            "subcategory": "reject_float",
            "description": f"MUST reject: {desc}",
            "input": {"n": fval},
            "expected_error": True,
            "error_reason": "Non-integer float must be rejected by sanitize_for_signing()",
        })

    # Special float values that MUST be rejected
    special_rejects = [
        ("NaN", "NaN must be rejected at parse time"),
        ("Infinity", "Infinity must be rejected at parse time"),
        ("-Infinity", "-Infinity must be rejected at parse time"),
    ]
    for val, desc in special_rejects:
        vectors.append({
            "category": "integer_boundaries",
            "subcategory": "reject_special",
            "description": desc,
            "input_raw": val,
            "expected_error": True,
            "error_reason": f"{val} must be rejected at parse time",
        })

    # Integers in different positions
    position_cases = [
        ([1, 2, 3], "integers in array"),
        ([0, -1, 1], "zero and signs in array"),
        ({"a": [1, 2], "b": [3, 4]}, "integers in nested arrays"),
        ({"counts": {"a": 0, "b": 1, "c": -1}}, "integers in nested object"),
        ([{"id": 1}, {"id": 2}, {"id": 100}], "integers as object values in array"),
    ]
    for obj, desc in position_cases:
        canonical = canonical_json(obj)
        vectors.append({
            "category": "integer_boundaries",
            "subcategory": "positions",
            "description": desc,
            "input": obj,
            "expected_canonical": canonical,
            "expected_hash": sha256_hex(canonical.encode("utf-8")),
        })

    return vectors


# ═══════════════════════════════════════════════════════════════════════
#  Category 5: Array Ordering
# ═══════════════════════════════════════════════════════════════════════

def generate_array_ordering_vectors():
    """~100 vectors for array ordering edge cases."""
    vectors = []

    # Arrays preserve insertion order (never sorted)
    arrays = [
        ([1, 2, 3], "ascending integers"),
        ([3, 2, 1], "descending integers"),
        ([3, 1, 2], "unordered integers"),
        (["c", "a", "b"], "unordered strings"),
        (["a", "b", "c"], "sorted strings"),
        (["c", "b", "a"], "reverse sorted strings"),
        ([], "empty array"),
        ([1], "single element"),
        ([None], "single null"),
        ([[]], "nested empty array"),
        ([{}], "array with empty object"),
        # Mixed types in array
        ([1, "a", True, None, [], {}], "all JSON types in order"),
        ([None, True, 1, "a", [], {}], "reordered JSON types"),
        ([{}, [], None, True, 1, "a"], "reverse order JSON types"),
        # Duplicate values
        ([1, 1, 1], "duplicate integers"),
        (["a", "a", "a"], "duplicate strings"),
        ([None, None, None], "duplicate nulls"),
        ([True, True, True], "duplicate booleans"),
        # Nested arrays
        ([[1, 2], [3, 4]], "2D array"),
        ([[3, 4], [1, 2]], "2D array reversed"),
        ([[[1]], [[2]]], "3D array"),
        # Objects in arrays (key ordering within each object)
        ([{"b": 2, "a": 1}, {"d": 4, "c": 3}], "objects in array with unsorted keys"),
        ([{"z": 1}, {"a": 2}], "objects in array don't sort by content"),
    ]

    for arr, desc in arrays:
        canonical = canonical_json(arr)
        vectors.append({
            "category": "array_ordering",
            "subcategory": "basic",
            "description": desc,
            "input": arr,
            "expected_canonical": canonical,
            "expected_hash": sha256_hex(canonical.encode("utf-8")),
        })

    # Demonstrate order matters
    a = [1, 2, 3]
    b = [3, 2, 1]
    ca = canonical_json(a)
    cb = canonical_json(b)
    vectors.append({
        "category": "array_ordering",
        "subcategory": "order_matters",
        "description": "different array order produces different hash",
        "input_a": a,
        "input_b": b,
        "expected_canonical_a": ca,
        "expected_canonical_b": cb,
        "expected_hash_a": sha256_hex(ca.encode("utf-8")),
        "expected_hash_b": sha256_hex(cb.encode("utf-8")),
        "hashes_differ": sha256_hex(ca.encode("utf-8")) != sha256_hex(cb.encode("utf-8")),
    })

    # Large arrays
    for size in [10, 50, 100]:
        arr = list(range(size))
        canonical = canonical_json(arr)
        vectors.append({
            "category": "array_ordering",
            "subcategory": "large",
            "description": f"array of {size} sequential integers",
            "input": arr,
            "expected_canonical": canonical,
            "expected_hash": sha256_hex(canonical.encode("utf-8")),
        })

    # Checks array ordering (critical for checks_hash)
    checks_example = [
        {"check_id": "C1", "passed": True, "severity": "info", "evidence": None},
        {"check_id": "C2", "passed": False, "severity": "critical", "evidence": "found issue"},
        {"check_id": "C3", "passed": True, "severity": "warning", "evidence": None},
    ]
    canonical = canonical_json(checks_example)
    vectors.append({
        "category": "array_ordering",
        "subcategory": "checks_hash",
        "description": "checks array: insertion order preserved, keys sorted within each check",
        "input": checks_example,
        "expected_canonical": canonical,
        "expected_hash": sha256_hex(canonical.encode("utf-8")),
    })

    # Same checks, different order → different hash
    reordered = [checks_example[2], checks_example[0], checks_example[1]]
    canonical_reordered = canonical_json(reordered)
    vectors.append({
        "category": "array_ordering",
        "subcategory": "checks_hash",
        "description": "reordered checks array produces different hash",
        "input": reordered,
        "expected_canonical": canonical_reordered,
        "expected_hash": sha256_hex(canonical_reordered.encode("utf-8")),
        "note": "different from original order above — checks MUST be hashed in insertion order",
    })

    # String arrays with Unicode
    unicode_arrays = [
        (["café", "naïve", "résumé"], "French words with accents"),
        (["α", "β", "γ"], "Greek letters"),
        (["你好", "世界"], "Chinese characters"),
        (["🎉", "🎊", "🎈"], "emoji array"),
    ]
    for arr, desc in unicode_arrays:
        canonical = canonical_json(arr)
        vectors.append({
            "category": "array_ordering",
            "subcategory": "unicode",
            "description": desc,
            "input": arr,
            "expected_canonical": canonical,
            "expected_hash": sha256_hex(canonical.encode("utf-8")),
        })

    return vectors


# ═══════════════════════════════════════════════════════════════════════
#  Category 6: Whitespace and Escaping
# ═══════════════════════════════════════════════════════════════════════

def generate_whitespace_escaping_vectors():
    """~100 vectors for whitespace and escaping edge cases."""
    vectors = []

    # Control characters that must be escaped in JSON
    control_chars = [
        ("\x00", "null byte U+0000"),
        ("\x01", "SOH U+0001"),
        ("\x08", "backspace U+0008"),
        ("\t", "tab U+0009"),
        ("\n", "newline U+000A"),
        ("\r", "carriage return U+000D"),
        ("\x0c", "form feed U+000C"),
        ("\x1f", "US U+001F (last control char)"),
        ("\x7f", "DEL U+007F"),
    ]
    for char, desc in control_chars:
        obj = {"v": f"a{char}b"}
        canonical = canonical_json(obj)
        vectors.append({
            "category": "whitespace_escaping",
            "subcategory": "control_chars",
            "description": desc,
            "input": obj,
            "expected_canonical": canonical,
            "expected_hash": sha256_hex(canonical.encode("utf-8")),
        })

    # HTML-sensitive characters (MUST NOT be escaped)
    html_chars = [
        ("<script>", "HTML script tag"),
        ("a < b", "less than"),
        ("a > b", "greater than"),
        ("a & b", "ampersand"),
        ('<img src="x">', "HTML tag with attribute"),
        ("1 < 2 && 3 > 2", "comparison operators"),
        ("a<b>c&d", "mixed HTML-sensitive"),
    ]
    for text, desc in html_chars:
        obj = {"v": text}
        canonical = canonical_json(obj)
        # Verify no \u003c etc.
        assert "\\u003c" not in canonical, f"HTML escaping detected in {desc}"
        assert "\\u003e" not in canonical, f"HTML escaping detected in {desc}"
        assert "\\u0026" not in canonical, f"HTML escaping detected in {desc}"
        vectors.append({
            "category": "whitespace_escaping",
            "subcategory": "no_html_escaping",
            "description": f"MUST NOT HTML-escape: {desc}",
            "input": obj,
            "expected_canonical": canonical,
            "expected_hash": sha256_hex(canonical.encode("utf-8")),
            "must_not_contain": ["\\u003c", "\\u003e", "\\u0026"],
        })

    # JSON escape sequences
    escape_seqs = [
        ("\\", "backslash"),
        ("\"", "double quote"),
        ("/", "forward slash (no escape needed)"),
        ("\t", "tab escape"),
        ("\n", "newline escape"),
        ("\r", "carriage return escape"),
        ("\b", "backspace escape"),
        ("\f", "form feed escape"),
    ]
    for char, desc in escape_seqs:
        obj = {"v": char}
        canonical = canonical_json(obj)
        vectors.append({
            "category": "whitespace_escaping",
            "subcategory": "json_escapes",
            "description": desc,
            "input": obj,
            "expected_canonical": canonical,
            "expected_hash": sha256_hex(canonical.encode("utf-8")),
        })

    # No whitespace in canonical form
    # Verify separators are exactly "," and ":" with no spaces
    ws_tests = [
        ({"a": 1, "b": 2}, "no space after colon or comma"),
        ({"a": [1, 2, 3]}, "no space in array"),
        ({"a": {"b": 1}}, "no space in nested object"),
    ]
    for obj, desc in ws_tests:
        canonical = canonical_json(obj)
        # Ensure no spaces around structural characters
        vectors.append({
            "category": "whitespace_escaping",
            "subcategory": "no_whitespace",
            "description": desc,
            "input": obj,
            "expected_canonical": canonical,
            "expected_hash": sha256_hex(canonical.encode("utf-8")),
            "note": "canonical form has no whitespace around separators",
        })

    # ensure_ascii=False: literal UTF-8
    literal_utf8 = [
        ("café", "literal UTF-8 é not \\u00e9"),
        ("日本語", "literal CJK not \\u escapes"),
        ("über", "literal ü not \\u00fc"),
        ("Ω", "literal Omega not \\u03a9"),
    ]
    for text, desc in literal_utf8:
        obj = {"v": text}
        canonical = canonical_json(obj)
        # Verify no unnecessary Unicode escapes
        vectors.append({
            "category": "whitespace_escaping",
            "subcategory": "literal_utf8",
            "description": desc,
            "input": obj,
            "expected_canonical": canonical,
            "expected_hash": sha256_hex(canonical.encode("utf-8")),
            "note": "ensure_ascii=False means literal UTF-8 chars, not \\u escapes",
        })

    # Strings with various whitespace
    ws_strings = [
        ("  leading spaces", "leading spaces preserved in value"),
        ("trailing spaces  ", "trailing spaces preserved in value"),
        ("  both  ", "both leading and trailing"),
        ("a  b", "double space inside"),
        ("a\tb", "tab inside"),
        ("a\nb", "newline inside"),
        ("a\r\nb", "CRLF inside"),
        ("a\n\nb", "double newline inside"),
        ("\t\n\r ", "only whitespace"),
    ]
    for text, desc in ws_strings:
        obj = {"v": text}
        canonical = canonical_json(obj)
        vectors.append({
            "category": "whitespace_escaping",
            "subcategory": "whitespace_in_values",
            "description": desc,
            "input": obj,
            "expected_canonical": canonical,
            "expected_hash": sha256_hex(canonical.encode("utf-8")),
        })

    # Long strings
    long_strings = [
        ("a" * 1000, "1000 a's"),
        ("x" * 10000, "10000 x's"),
        ("hello " * 100, "repeated word"),
    ]
    for text, desc in long_strings:
        obj = {"v": text}
        canonical = canonical_json(obj)
        vectors.append({
            "category": "whitespace_escaping",
            "subcategory": "long_strings",
            "description": desc,
            "input": obj,
            "expected_canonical": canonical,
            "expected_hash": sha256_hex(canonical.encode("utf-8")),
        })

    return vectors


# ═══════════════════════════════════════════════════════════════════════
#  Category 7: Round-trip Verification
# ═══════════════════════════════════════════════════════════════════════

def generate_round_trip_vectors():
    """~100 vectors: known input → canonical → known hash."""
    vectors = []

    # These are exact round-trip vectors with pre-computed expected values
    # Implementers parse the input JSON, canonicalize, and verify the hash matches
    known_inputs = [
        {},
        {"a": 1},
        {"b": "hello"},
        {"a": 1, "b": 2},
        {"z": 1, "a": 2},
        [1, 2, 3],
        [3, 2, 1],
        {"nested": {"key": "value"}},
        {"arr": [1, "two", True, None]},
        None,
        True,
        False,
        0,
        42,
        "hello",
        "",
        {"a": None},
        {"a": ""},
        {"a": []},
        {"a": {}},
        {"check_id": "C1", "passed": True, "severity": "info", "evidence": None},
        {"correlation_id": "sanna-test-001", "status": "PASS"},
        {"spec_version": "1.1", "checks_version": "6"},
        # Realistic receipt-like fragments
        {
            "inputs": {"query": "What is the capital of France?", "context": "France is in Europe."},
            "outputs": {"response": "Paris is the capital of France."},
        },
        {
            "constitution_ref": {
                "document_id": "test/1.0",
                "policy_hash": "abcd" * 16,
            }
        },
        {
            "enforcement": {
                "action": "halted",
                "reason": "Critical check failure",
                "failed_checks": ["C1"],
                "enforcement_mode": "halt",
                "timestamp": "2026-01-01T00:00:00Z",
            }
        },
        {"parent_receipts": ["a" * 64, "b" * 64]},
        {"parent_receipts": []},
        {"parent_receipts": None},
        {"workflow_id": "wf-12345-abcde"},
        {"workflow_id": None},
        {"content_mode": "full", "content_mode_source": "local_config"},
        {"content_mode": "redacted", "content_mode_source": "cloud_tenant"},
        {"content_mode": "hashes_only", "content_mode_source": "override"},
        # Extension namespace example
        {
            "extensions": {
                "com.sanna.gateway": {
                    "gateway_id": "gw-01",
                    "tool_name": "API-patch-page",
                },
                "com.sanna.test": {
                    "fixture": True,
                },
            }
        },
    ]

    for i, obj in enumerate(known_inputs):
        canonical = canonical_json(obj)
        h = sha256_hex(canonical.encode("utf-8"))
        vectors.append({
            "category": "round_trip",
            "subcategory": "known_io",
            "description": f"round-trip vector {i+1:03d}",
            "input": obj,
            "expected_canonical": canonical,
            "expected_hash": h,
        })

    # hash_text specific vectors (with line-ending normalization)
    hash_text_inputs = [
        ("hello", "simple string"),
        ("", "empty string"),
        ("  hello  ", "leading/trailing whitespace stripped"),
        ("line1\nline2", "LF line ending"),
        ("line1\r\nline2", "CRLF normalized to LF"),
        ("line1\rline2", "CR normalized to LF"),
        ("line1  \nline2  ", "trailing whitespace per line stripped"),
        ("  \n  hello  \n  ", "complex whitespace normalization"),
        ("café", "NFC-stable string"),
        ("e\u0301", "decomposed e-acute → NFC → hash"),
        ("a\u0308", "decomposed a-diaeresis → NFC → hash"),
    ]
    for text, desc in hash_text_inputs:
        h = hash_text(text, truncate=64)
        vectors.append({
            "category": "round_trip",
            "subcategory": "hash_text",
            "description": f"hash_text: {desc}",
            "input_text": text,
            "expected_hash": h,
        })

    # hash_obj specific vectors
    hash_obj_inputs = [
        ({}, "empty object"),
        ({"a": 1}, "simple object"),
        ([1, 2, 3], "simple array"),
        ({"z": 1, "a": 2}, "keys reordered"),
        (None, "null"),
    ]
    for obj, desc in hash_obj_inputs:
        h = hash_obj(obj)
        vectors.append({
            "category": "round_trip",
            "subcategory": "hash_obj",
            "description": f"hash_obj: {desc}",
            "input": obj,
            "expected_hash": h,
        })

    return vectors


# ═══════════════════════════════════════════════════════════════════════
#  Category 8: Full 14-field Fingerprint Computation
# ═══════════════════════════════════════════════════════════════════════

def generate_fingerprint_vectors():
    """~100 vectors for 14-field fingerprint computation."""
    vectors = []

    # Helper to compute fingerprint from known field values
    def compute_fingerprint(fields):
        """Compute fingerprint from a dict of the 14 field values."""
        fp_input = "|".join([
            fields.get("spec_version", "1.1"),
            fields.get("tool_version", "0.14.0"),
            fields.get("checks_version", "6"),
            fields.get("timestamp", "2026-01-01T00:00:00Z"),
            fields.get("agent_id", "sanna-test-001"),
            fields.get("context_hash", EMPTY_HASH),
            fields.get("output_hash", EMPTY_HASH),
            fields.get("query_hash", EMPTY_HASH),
            fields.get("constitution_hash", EMPTY_HASH),
            fields.get("status", "PASS"),
            fields.get("checks_hash", EMPTY_HASH),
            fields.get("extensions_hash", EMPTY_HASH),
            fields.get("parent_receipts_hash", EMPTY_HASH),
            fields.get("workflow_id_hash", EMPTY_HASH),
        ])
        full = hash_text(fp_input, truncate=64)
        short = hash_text(fp_input, truncate=16)
        return fp_input, full, short

    # 1. All fields EMPTY_HASH (minimal receipt)
    fp_input, full, short = compute_fingerprint({})
    vectors.append({
        "category": "fingerprint",
        "subcategory": "minimal",
        "description": "minimal receipt: all optional hashes are EMPTY_HASH",
        "fields": {
            "spec_version": "1.1",
            "tool_version": "0.14.0",
            "checks_version": "6",
            "timestamp": "2026-01-01T00:00:00Z",
            "agent_id": "sanna-test-001",
            "context_hash": EMPTY_HASH,
            "output_hash": EMPTY_HASH,
            "query_hash": EMPTY_HASH,
            "constitution_hash": EMPTY_HASH,
            "status": "PASS",
            "checks_hash": EMPTY_HASH,
            "extensions_hash": EMPTY_HASH,
            "parent_receipts_hash": EMPTY_HASH,
            "workflow_id_hash": EMPTY_HASH,
        },
        "expected_fingerprint_input": fp_input,
        "expected_full_fingerprint": full,
        "expected_receipt_fingerprint": short,
    })

    # 2. With known content hashes
    context_obj = {"query": "What is AI?", "context": "AI is artificial intelligence."}
    output_obj = {"response": "AI stands for artificial intelligence."}
    context_hash = hash_obj(context_obj)
    output_hash = hash_obj(output_obj)
    query_hash = hash_text("What is AI?", truncate=64)

    fields = {
        "spec_version": "1.1",
        "tool_version": "0.14.0",
        "checks_version": "6",
        "timestamp": "2026-03-01T12:00:00Z",
        "agent_id": "sanna-fixture-fp-001",
        "context_hash": context_hash,
        "output_hash": output_hash,
        "query_hash": query_hash,
        "constitution_hash": EMPTY_HASH,
        "status": "PASS",
        "checks_hash": EMPTY_HASH,
        "extensions_hash": EMPTY_HASH,
        "parent_receipts_hash": EMPTY_HASH,
        "workflow_id_hash": EMPTY_HASH,
    }
    fp_input, full, short = compute_fingerprint(fields)
    vectors.append({
        "category": "fingerprint",
        "subcategory": "with_content",
        "description": "receipt with known content hashes",
        "fields": fields,
        "context_obj": context_obj,
        "output_obj": output_obj,
        "query_text": "What is AI?",
        "expected_fingerprint_input": fp_input,
        "expected_full_fingerprint": full,
        "expected_receipt_fingerprint": short,
    })

    # 3. With parent_receipts
    parent_fps = [
        "a" * 64,
        "b" * 64,
    ]
    parent_hash = hash_obj(parent_fps)
    fields_with_parents = dict(fields)
    fields_with_parents["parent_receipts_hash"] = parent_hash
    fp_input, full, short = compute_fingerprint(fields_with_parents)
    vectors.append({
        "category": "fingerprint",
        "subcategory": "parent_receipts",
        "description": "receipt with two parent receipts",
        "fields": fields_with_parents,
        "parent_receipts": parent_fps,
        "parent_receipts_hash": parent_hash,
        "expected_fingerprint_input": fp_input,
        "expected_full_fingerprint": full,
        "expected_receipt_fingerprint": short,
    })

    # 4. With workflow_id
    wf_id = "workflow-abc-123"
    wf_hash = hash_text(wf_id, truncate=64)
    fields_with_wf = dict(fields)
    fields_with_wf["workflow_id_hash"] = wf_hash
    fp_input, full, short = compute_fingerprint(fields_with_wf)
    vectors.append({
        "category": "fingerprint",
        "subcategory": "workflow_id",
        "description": "receipt with workflow_id",
        "fields": fields_with_wf,
        "workflow_id": wf_id,
        "workflow_id_hash": wf_hash,
        "expected_fingerprint_input": fp_input,
        "expected_full_fingerprint": full,
        "expected_receipt_fingerprint": short,
    })

    # 5. With both parent_receipts and workflow_id
    fields_both = dict(fields)
    fields_both["parent_receipts_hash"] = parent_hash
    fields_both["workflow_id_hash"] = wf_hash
    fp_input, full, short = compute_fingerprint(fields_both)
    vectors.append({
        "category": "fingerprint",
        "subcategory": "chained_workflow",
        "description": "receipt with both parent_receipts and workflow_id",
        "fields": fields_both,
        "expected_fingerprint_input": fp_input,
        "expected_full_fingerprint": full,
        "expected_receipt_fingerprint": short,
    })

    # 6. Different statuses produce different fingerprints
    for status in ["PASS", "WARN", "FAIL", "PARTIAL"]:
        f = dict(fields)
        f["status"] = status
        fp_input, full, short = compute_fingerprint(f)
        vectors.append({
            "category": "fingerprint",
            "subcategory": "status_variation",
            "description": f"status={status}",
            "fields": f,
            "expected_fingerprint_input": fp_input,
            "expected_full_fingerprint": full,
            "expected_receipt_fingerprint": short,
        })

    # 7. Empty array parent_receipts vs null parent_receipts
    empty_parent_hash = hash_obj([])
    null_parent_hash = EMPTY_HASH
    f_empty = dict(fields)
    f_empty["parent_receipts_hash"] = empty_parent_hash
    f_null = dict(fields)
    f_null["parent_receipts_hash"] = null_parent_hash
    fp_empty, full_empty, short_empty = compute_fingerprint(f_empty)
    fp_null, full_null, short_null = compute_fingerprint(f_null)
    vectors.append({
        "category": "fingerprint",
        "subcategory": "empty_vs_null",
        "description": "empty array parent_receipts vs null produces different fingerprints",
        "empty_array_hash": empty_parent_hash,
        "null_hash": null_parent_hash,
        "hashes_differ": empty_parent_hash != null_parent_hash,
        "fingerprint_empty_array": full_empty,
        "fingerprint_null": full_null,
        "fingerprints_differ": full_empty != full_null,
    })

    # 8. Constitution hash with approval stripping
    const_ref_with_approval = {
        "document_id": "test/1.0",
        "policy_hash": "a" * 64,
        "version": "1.0.0",
        "constitution_approval": {
            "status": "approved",
            "approver_id": "admin@test.com",
            "approver_role": "admin",
            "approved_at": "2026-01-01T00:00:00Z",
            "constitution_version": "1.0.0",
            "content_hash": "b" * 64,
        },
    }
    stripped = {k: v for k, v in const_ref_with_approval.items() if k != "constitution_approval"}
    const_hash = hash_obj(stripped)
    vectors.append({
        "category": "fingerprint",
        "subcategory": "constitution_stripping",
        "description": "constitution_approval stripped before hashing",
        "constitution_ref": const_ref_with_approval,
        "stripped_ref": stripped,
        "constitution_hash": const_hash,
        "note": "constitution_approval excluded from fingerprint but included in signature",
    })

    # 9. Checks hash vectors
    # Legacy path (no constitution)
    legacy_checks = [
        {"check_id": "C1", "passed": True, "severity": "info", "evidence": None},
        {"check_id": "C2", "passed": True, "severity": "info", "evidence": None},
    ]
    checks_hash_legacy = hash_obj(legacy_checks)
    vectors.append({
        "category": "fingerprint",
        "subcategory": "checks_hash",
        "description": "legacy checks hash (4-field per check)",
        "checks_data": legacy_checks,
        "expected_checks_hash": checks_hash_legacy,
    })

    # Constitution-driven path
    const_checks = [
        {
            "check_id": "C1", "passed": True, "severity": "info", "evidence": None,
            "triggered_by": "INV_NO_FABRICATION", "enforcement_level": "halt",
            "check_impl": "sanna.context_contradiction", "replayable": True,
        },
        {
            "check_id": "C2", "passed": False, "severity": "critical", "evidence": "found issue",
            "triggered_by": "INV_MARK_INFERENCE", "enforcement_level": "warn",
            "check_impl": "sanna.unmarked_inference", "replayable": True,
        },
    ]
    checks_hash_const = hash_obj(const_checks)
    vectors.append({
        "category": "fingerprint",
        "subcategory": "checks_hash",
        "description": "constitution-driven checks hash (8-field per check)",
        "checks_data": const_checks,
        "expected_checks_hash": checks_hash_const,
    })

    # 10. Varying each field independently to show it affects fingerprint
    base_fields = {
        "spec_version": "1.1",
        "tool_version": "0.14.0",
        "checks_version": "6",
        "timestamp": "2026-01-01T00:00:00Z",
        "agent_id": "sanna-test-001",
        "context_hash": "a" * 64,
        "output_hash": "b" * 64,
        "query_hash": "c" * 64,
        "constitution_hash": "d" * 64,
        "status": "PASS",
        "checks_hash": "e" * 64,
        "extensions_hash": "f" * 64,
        "parent_receipts_hash": EMPTY_HASH,
        "workflow_id_hash": EMPTY_HASH,
    }
    _, base_full, _ = compute_fingerprint(base_fields)

    field_variations = {
        "spec_version": "1.0",
        "tool_version": "0.13.0",
        "checks_version": "5",
        "timestamp": "2026-01-01T00:00:01Z",
        "agent_id": "sanna-test-002",
        "context_hash": "1" * 64,
        "output_hash": "2" * 64,
        "query_hash": "3" * 64,
        "constitution_hash": "4" * 64,
        "status": "FAIL",
        "checks_hash": "5" * 64,
        "extensions_hash": "6" * 64,
        "parent_receipts_hash": "7" * 64,
        "workflow_id_hash": "8" * 64,
    }

    for field_name, alt_value in field_variations.items():
        modified = dict(base_fields)
        modified[field_name] = alt_value
        fp_input, full, short = compute_fingerprint(modified)
        vectors.append({
            "category": "fingerprint",
            "subcategory": "field_independence",
            "description": f"changing {field_name} changes fingerprint",
            "changed_field": field_name,
            "original_value": base_fields[field_name],
            "new_value": alt_value,
            "expected_full_fingerprint": full,
            "differs_from_base": full != base_full,
        })

    # 11. Truncation: receipt_fingerprint is first 16 chars of full_fingerprint
    # (Not necessarily — they are independent hash_text calls on the same input,
    # so receipt_fingerprint = full_fingerprint[:16])
    fp_input, full, short = compute_fingerprint(base_fields)
    vectors.append({
        "category": "fingerprint",
        "subcategory": "truncation",
        "description": "receipt_fingerprint is first 16 chars of full_fingerprint",
        "full_fingerprint": full,
        "receipt_fingerprint": short,
        "truncation_matches": full[:16] == short,
    })

    # 12. EMPTY_HASH constant
    vectors.append({
        "category": "fingerprint",
        "subcategory": "constants",
        "description": "EMPTY_HASH = SHA-256 of zero bytes",
        "expected_value": EMPTY_HASH,
        "computed_value": sha256_hex(b""),
        "matches": EMPTY_HASH == sha256_hex(b""),
    })

    return vectors


# ═══════════════════════════════════════════════════════════════════════
#  Category 9: Hypothesis Property-Based Vectors
# ═══════════════════════════════════════════════════════════════════════

def generate_hypothesis_vectors():
    """Use Hypothesis to generate ~700 additional edge-case vectors."""
    from hypothesis import given, settings, HealthCheck
    from hypothesis import strategies as st
    import hypothesis

    vectors = []
    seen_canonicals = set()  # Deduplicate

    def add_vector(category, subcategory, desc, obj):
        canonical = canonical_json(obj)
        if canonical in seen_canonicals:
            return
        seen_canonicals.add(canonical)
        vectors.append({
            "category": category,
            "subcategory": subcategory,
            "description": desc,
            "input": obj,
            "expected_canonical": canonical,
            "expected_hash": sha256_hex(canonical.encode("utf-8")),
        })

    # Strategy for JSON-safe values (no floats, no NaN)
    json_primitives = st.one_of(
        st.none(),
        st.booleans(),
        st.integers(min_value=-2**53, max_value=2**53),
        st.text(min_size=0, max_size=50),
    )

    json_values = st.recursive(
        json_primitives,
        lambda children: st.one_of(
            st.lists(children, max_size=5),
            st.dictionaries(st.text(min_size=0, max_size=20), children, max_size=5),
        ),
        max_leaves=20,
    )

    # ── Unicode NFC: systematic combining character exploration ──
    # All combining diacritical marks (U+0300–U+036F)
    combining_marks = list(range(0x0300, 0x0370))
    base_chars = "aeiounAEIOUN"
    idx = 0
    for base in base_chars:
        for mark_cp in combining_marks[:15]:  # First 15 marks per base
            mark = chr(mark_cp)
            decomposed = base + mark
            nfc_form = nfc(decomposed)
            if nfc_form != decomposed:  # Only interesting if NFC changes something
                obj = {"v": decomposed}
                canonical = canonical_json({"v": nfc_form})
                if canonical not in seen_canonicals:
                    seen_canonicals.add(canonical)
                    vectors.append({
                        "category": "unicode_nfc",
                        "subcategory": "hypothesis_combining",
                        "description": f"U+{ord(base):04X} + U+{mark_cp:04X} → NFC",
                        "input": obj,
                        "expected_canonical": canonical,
                        "expected_hash": sha256_hex(canonical.encode("utf-8")),
                    })
                    idx += 1
                    if idx >= 120:
                        break
        if idx >= 120:
            break

    # ── Key ordering: systematic permutations ──
    import itertools
    key_sets = [
        ["a", "b", "c", "d"],
        ["z", "y", "x", "w"],
        ["alpha", "beta", "gamma"],
        ["1", "2", "10", "20"],
        ["A", "a", "B", "b"],
    ]
    for keys in key_sets:
        for perm in itertools.permutations(keys):
            obj = {k: i for i, k in enumerate(perm)}
            add_vector("key_ordering", "hypothesis_permutations",
                       f"permutation: {','.join(perm)}", obj)

    # Nested key permutations
    for perm in itertools.permutations(["x", "y", "z"]):
        for inner_perm in itertools.permutations(["a", "b", "c"]):
            obj = {k: {ik: i for i, ik in enumerate(inner_perm)} for k in perm}
            add_vector("key_ordering", "hypothesis_nested_perms",
                       f"outer:{','.join(perm)} inner:{','.join(inner_perm)}", obj)

    # ── Integer: systematic boundary exploration ──
    boundary_ints = set()
    for bits in [8, 16, 32, 53, 64]:
        for signed in [True, False]:
            if signed:
                boundary_ints.add(2**(bits-1) - 1)   # max
                boundary_ints.add(-(2**(bits-1)))     # min
                boundary_ints.add(2**(bits-1))        # max + 1
                boundary_ints.add(-(2**(bits-1)) - 1) # min - 1
            else:
                boundary_ints.add(2**bits - 1)        # max
                boundary_ints.add(2**bits)             # max + 1
        boundary_ints.add(0)
        boundary_ints.add(1)
        boundary_ints.add(-1)

    for val in sorted(boundary_ints):
        if abs(val) <= 2**63:  # Stay within reasonable bounds
            add_vector("integer_boundaries", "hypothesis_systematic",
                       f"boundary: {val}", {"n": val})

    # Integer pairs
    for a, b in itertools.combinations(sorted(boundary_ints)[:15], 2):
        add_vector("integer_boundaries", "hypothesis_pairs",
                   f"pair: {a}, {b}", {"a": a, "b": b})

    # ── Array: systematic reordering ──
    base_arrays = [
        [1, 2, 3, 4, 5],
        ["a", "b", "c", "d"],
        [True, False, None, 0, ""],
        [{"id": 1}, {"id": 2}, {"id": 3}],
    ]
    for arr in base_arrays:
        for perm in itertools.permutations(range(len(arr))):
            reordered = [arr[i] for i in perm]
            add_vector("array_ordering", "hypothesis_permutations",
                       f"permuted: indices {','.join(map(str, perm))}", reordered)

    # ── Whitespace: systematic control character exploration ──
    for cp in range(0x00, 0x20):
        char = chr(cp)
        obj = {"v": f"a{char}b"}
        add_vector("whitespace_escaping", "hypothesis_control",
                   f"control char U+{cp:04X}", obj)

    # ── Round-trip: Hypothesis-generated objects ──
    # Generate random JSON objects and record their canonical form
    rng = hypothesis.settings(max_examples=200, suppress_health_check=[HealthCheck.too_slow])

    collected = []

    @given(json_values)
    @settings(max_examples=200, suppress_health_check=[HealthCheck.too_slow], database=None)
    def collect_random(obj):
        # Filter out objects that would fail sanitization (floats)
        try:
            canonical = canonical_json(obj)
            if len(canonical) < 5000:  # Skip very large objects
                collected.append(obj)
        except (TypeError, ValueError):
            pass

    try:
        collect_random()
    except Exception:
        pass  # Hypothesis may raise on some edge cases

    for i, obj in enumerate(collected[:200]):
        add_vector("round_trip", "hypothesis_random",
                   f"hypothesis random object {i+1:03d}", obj)

    # ── Null/Empty: systematic combinations ──
    null_like_values = [None, "", 0, False, [], {}]
    for combo in itertools.combinations_with_replacement(null_like_values, 3):
        obj = {f"f{i}": v for i, v in enumerate(combo)}
        add_vector("null_missing_empty", "hypothesis_combos",
                   f"combo: {','.join(repr(v) for v in combo)}", obj)

    # ── Fingerprint: systematic field variations ──
    field_names = [
        "spec_version", "tool_version", "checks_version", "timestamp",
        "agent_id", "context_hash", "output_hash", "query_hash",
        "constitution_hash", "status", "checks_hash", "extensions_hash",
        "parent_receipts_hash", "workflow_id_hash",
    ]
    base_vals = {
        "spec_version": "1.1", "tool_version": "0.14.0",
        "checks_version": "6", "timestamp": "2026-01-01T00:00:00Z",
        "agent_id": "sanna-test", "context_hash": EMPTY_HASH,
        "output_hash": EMPTY_HASH, "query_hash": EMPTY_HASH,
        "constitution_hash": EMPTY_HASH, "status": "PASS",
        "checks_hash": EMPTY_HASH, "extensions_hash": EMPTY_HASH,
        "parent_receipts_hash": EMPTY_HASH, "workflow_id_hash": EMPTY_HASH,
    }

    # Vary pairs of fields
    alt_vals = {
        "spec_version": ["1.0", "1.1", "2.0"],
        "tool_version": ["0.13.0", "0.14.0", "1.0.0"],
        "checks_version": ["5", "6", "7"],
        "timestamp": ["2026-01-01T00:00:00Z", "2026-12-31T23:59:59Z"],
        "agent_id": ["sanna-test-001", "gw-test-001", "mcp-test-001"],
        "status": ["PASS", "WARN", "FAIL", "PARTIAL"],
    }

    for field, values in alt_vals.items():
        for val in values:
            f = dict(base_vals)
            f[field] = val
            fp_input = "|".join(f[fn] for fn in field_names)
            full = hash_text(fp_input, truncate=64)
            short = hash_text(fp_input, truncate=16)
            vectors.append({
                "category": "fingerprint",
                "subcategory": "hypothesis_variations",
                "description": f"{field}={val}",
                "fields": f,
                "expected_full_fingerprint": full,
                "expected_receipt_fingerprint": short,
            })

    return vectors


# ═══════════════════════════════════════════════════════════════════════
#  Main: Generate and Write
# ═══════════════════════════════════════════════════════════════════════

def main():
    print("Sanna Protocol — Canonicalization Test Vector Generator")
    print("=" * 60)

    generators = [
        ("Unicode NFC Normalization", generate_unicode_nfc_vectors),
        ("Key Ordering", generate_key_ordering_vectors),
        ("Null/Missing/Empty", generate_null_missing_empty_vectors),
        ("Integer Boundaries", generate_integer_boundary_vectors),
        ("Array Ordering", generate_array_ordering_vectors),
        ("Whitespace & Escaping", generate_whitespace_escaping_vectors),
        ("Round-trip Verification", generate_round_trip_vectors),
        ("14-field Fingerprint", generate_fingerprint_vectors),
        ("Hypothesis Property-Based", generate_hypothesis_vectors),
    ]

    all_vectors = []
    category_counts = {}

    for name, gen_func in generators:
        vectors = gen_func()
        all_vectors.extend(vectors)
        category_counts[name] = len(vectors)
        print(f"  {name}: {len(vectors)} vectors")

    total = len(all_vectors)
    print(f"\nTotal: {total} vectors")

    output = {
        "spec_version": "1.1",
        "generator": "generate_test_vectors.py",
        "description": "Cross-language canonicalization test vectors for Sanna Protocol v1.1",
        "total_vectors": total,
        "category_counts": category_counts,
        "EMPTY_HASH": EMPTY_HASH,
        "vectors": all_vectors,
    }

    OUTPUT.write_text(json.dumps(output, indent=2, ensure_ascii=False) + "\n")
    print(f"\nWrote: {OUTPUT}")
    print(f"Size: {OUTPUT.stat().st_size / 1024:.1f} KB")


if __name__ == "__main__":
    main()
