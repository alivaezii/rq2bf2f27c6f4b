"""Minimal canonical-serialization and hash-linked chain validation.

Implements RFC 8785 (JSON Canonicalization Scheme) and a closed-schema,
hash-linked, append-only record chain: each record's declared predecessor
hash must equal the exact canonical SHA-256 of the immediately preceding
record, sequence numbers increment by exactly one from a single record at
position zero, and no two records may canonicalize to the same bytes.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import unicodedata
from datetime import datetime
from typing import Dict, List, Optional, Sequence, Tuple

ORIGIN_SENTINEL = "0" * 64


class ValidationError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(f"[{code}] {message}")
        self.code = code


def _nfc(value: str) -> str:
    return unicodedata.normalize("NFC", value)


def _utf16_units(value: str) -> Tuple[int, ...]:
    encoded = value.encode("utf-16-be")
    return tuple(int.from_bytes(encoded[i : i + 2], "big") for i in range(0, len(encoded), 2))


def _encode(value: object) -> str:
    if isinstance(value, bool):
        raise ValidationError("NONCANONICAL", "booleans are not part of this schema")
    if isinstance(value, str):
        return json.dumps(_nfc(value), ensure_ascii=False)
    if isinstance(value, int):
        if value < 0 or value >= 2**53:
            raise ValidationError("NONCANONICAL", "integer out of the safe representable range")
        return str(value)
    if isinstance(value, dict):
        for key in value:
            if not isinstance(key, str):
                raise ValidationError("NONCANONICAL", "object keys must be strings")
        normalized = {k: _nfc(k) for k in value}
        if len(set(normalized.values())) != len(normalized):
            raise ValidationError("NONCANONICAL", "object keys collide after NFC normalization")
        ordered = sorted(value, key=lambda k: _utf16_units(normalized[k]))
        parts = [f"{json.dumps(normalized[k], ensure_ascii=False)}:{_encode(value[k])}" for k in ordered]
        return "{" + ",".join(parts) + "}"
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(_encode(v) for v in value) + "]"
    raise ValidationError("NONCANONICAL", f"unsupported value type: {type(value).__name__}")


def canonicalize(value: object) -> bytes:
    try:
        return _encode(value).encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValidationError("NONCANONICAL", f"not representable as valid UTF-8: {exc}") from exc


def canonical_sha256(value: object) -> str:
    return hashlib.sha256(canonicalize(value)).hexdigest()


def _reject_constant(text: str) -> None:
    raise ValidationError("NONCANONICAL", f"disallowed numeric constant token {text!r}")


def _strict_pairs(pairs: List[Tuple[str, object]]) -> Dict[str, object]:
    seen: Dict[str, object] = {}
    for key, value in pairs:
        if key in seen:
            raise ValidationError("NONCANONICAL", f"duplicate object key {key!r}")
        seen[key] = value
    return seen


def parse_canonical(raw: bytes) -> Dict[str, object]:
    if raw.startswith(b"\xef\xbb\xbf"):
        raise ValidationError("NONCANONICAL", "byte-order mark present")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValidationError("NONCANONICAL", f"not valid UTF-8: {exc}") from exc
    try:
        decoded = json.loads(text, object_pairs_hook=_strict_pairs, parse_constant=_reject_constant)
    except json.JSONDecodeError as exc:
        raise ValidationError("NONCANONICAL", f"not valid JSON: {exc}") from exc
    if canonicalize(decoded) != raw:
        raise ValidationError("NONCANONICAL", "bytes are not the canonical serialization of their own decoded value")
    if not isinstance(decoded, dict):
        raise ValidationError("NONCANONICAL", "top-level value must be a JSON object")
    return decoded


_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
_TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_FINGERPRINT_RE = re.compile(r"^SHA256:[A-Za-z0-9+/]{43}$")


def _check_id(name: str, value: object) -> None:
    if not isinstance(value, str) or not _ID_RE.match(value):
        raise ValidationError("SCHEMA", f"{name!r} must match ^[A-Za-z0-9][A-Za-z0-9._-]{{0,127}}$")


def _check_hex64(name: str, value: object) -> None:
    if not isinstance(value, str) or not _HEX64_RE.match(value):
        raise ValidationError("SCHEMA", f"{name!r} must be 64 lowercase hex characters")


def _check_nonneg(name: str, value: object) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValidationError("SCHEMA", f"{name!r} must be a non-negative integer")


def _check_timestamp(name: str, value: object) -> None:
    if not isinstance(value, str) or not _TIMESTAMP_RE.match(value):
        raise ValidationError("SCHEMA", f"{name!r} must be an RFC 3339 UTC whole-second timestamp")
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise ValidationError("SCHEMA", f"{name!r} is not a valid calendar timestamp: {exc}") from exc


def _check_fingerprint(name: str, value: object) -> None:
    if not isinstance(value, str) or not _FINGERPRINT_RE.match(value):
        raise ValidationError("SCHEMA", f"{name!r} must be 'SHA256:<43-char unpadded base64>'")
    encoded = value[len("SHA256:") :]
    try:
        decoded = base64.b64decode(encoded + "=", validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValidationError("SCHEMA", f"{name!r} does not decode as valid base64: {exc}") from exc
    if len(decoded) != 32:
        raise ValidationError("SCHEMA", f"{name!r} must decode to exactly 32 bytes")
    if base64.b64encode(decoded).decode("ascii").rstrip("=") != encoded:
        raise ValidationError("SCHEMA", f"{name!r} is not canonically encoded")


RECORD_FIELDS = frozenset(
    {
        "schema_version",
        "entry_id",
        "entry_sha256",
        "byte_length",
        "sequence_number",
        "previous_entry_sha256",
        "signer_key_fingerprint",
        "signature_sha256",
        "signing_payload_sha256",
        "registry_version",
        "registry_sha256",
    }
)
assert len(RECORD_FIELDS) == 11

_FIELD_CHECKS = {
    "schema_version": _check_id,
    "entry_id": _check_id,
    "entry_sha256": _check_hex64,
    "byte_length": _check_nonneg,
    "sequence_number": _check_nonneg,
    "previous_entry_sha256": _check_hex64,
    "signer_key_fingerprint": _check_fingerprint,
    "signature_sha256": _check_hex64,
    "signing_payload_sha256": _check_hex64,
    "registry_version": _check_id,
    "registry_sha256": _check_hex64,
}
assert set(_FIELD_CHECKS) == RECORD_FIELDS


def validate_record(record: object) -> None:
    if not isinstance(record, dict):
        raise ValidationError("SCHEMA", "record must be a JSON object")
    present = set(record.keys())
    unknown = present - RECORD_FIELDS
    if unknown:
        raise ValidationError("SCHEMA", f"record carries field(s) outside the closed allowlist: {sorted(unknown)}")
    missing = RECORD_FIELDS - present
    if missing:
        raise ValidationError("SCHEMA", f"record is missing required field(s): {sorted(missing)}")
    for field, check in _FIELD_CHECKS.items():
        check(field, record[field])


def _anchor_consistent(record: Dict[str, object], origin: Dict[str, object], position: int) -> None:
    if record["schema_version"] != origin["schema_version"]:
        raise ValidationError("ANCHOR_MISMATCH", f"record at position {position} schema_version diverges from the origin record")
    if record["registry_version"] != origin["registry_version"] or record["registry_sha256"] != origin["registry_sha256"]:
        raise ValidationError("ANCHOR_MISMATCH", f"record at position {position} registry binding diverges from the origin record")


def validate_chain(records: Sequence[Dict[str, object]], previously_seen: Optional[Dict[int, str]] = None) -> None:
    if not records:
        raise ValidationError("MISSING_ORIGIN", "empty chain has no record at position zero")
    for record in records:
        validate_record(record)

    origin_positions = [i for i, r in enumerate(records) if r["sequence_number"] == 0]
    if not origin_positions:
        raise ValidationError("MISSING_ORIGIN", "no record with sequence_number == 0")
    if len(origin_positions) > 1:
        raise ValidationError("MULTIPLE_ORIGIN", f"{len(origin_positions)} records claim sequence_number == 0")
    if origin_positions[0] != 0:
        raise ValidationError("REORDERED", "the sequence_number == 0 record is not first in the supplied order")
    if records[0]["previous_entry_sha256"] != ORIGIN_SENTINEL:
        raise ValidationError("MISSING_ORIGIN", "the first record's previous_entry_sha256 is not the all-zero sentinel")

    origin = records[0]
    seen_sequences: Dict[int, str] = {}
    seen_predecessors: Dict[str, int] = {}
    seen_hashes: Dict[str, int] = {}
    prior_hash: Optional[str] = None

    for i, record in enumerate(records):
        _anchor_consistent(record, origin, i)
        seq = record["sequence_number"]
        assert isinstance(seq, int)

        if seq in seen_sequences:
            raise ValidationError("DUPLICATE_SEQUENCE", f"sequence_number {seq} appears more than once")

        if i > 0:
            expected = records[i - 1]["sequence_number"] + 1  # type: ignore[operator]
            if seq != expected:
                code = "SKIPPED_SEQUENCE" if seq > expected else "REORDERED"
                raise ValidationError(code, f"expected sequence_number {expected} at position {i}, found {seq}")

        predecessor = record["previous_entry_sha256"]
        assert isinstance(predecessor, str)
        if predecessor in seen_predecessors:
            code = "MULTIPLE_ORIGIN" if predecessor == ORIGIN_SENTINEL else "FORK"
            raise ValidationError(code, f"previous_entry_sha256 {predecessor!r} claimed by more than one record")

        own_hash = canonical_sha256(record)
        if own_hash in seen_hashes:
            raise ValidationError("REPLAY", f"record at position {i} duplicates an earlier record's canonical bytes")

        if i > 0 and predecessor != prior_hash:
            raise ValidationError("HASH_MISMATCH", f"record at position {i} predecessor does not match the immediately preceding record's canonical hash")

        if previously_seen is not None and seq in previously_seen and own_hash != previously_seen[seq]:
            raise ValidationError("REPLACED", f"record at sequence_number {seq} no longer matches a previously validated hash at that position")

        seen_sequences[seq] = own_hash
        seen_predecessors[predecessor] = i
        seen_hashes[own_hash] = i
        prior_hash = own_hash
