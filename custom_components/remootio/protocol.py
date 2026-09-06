"""Strict Remootio WebSocket API v3 protocol primitives.

This module deliberately contains no Home Assistant imports. It is kept as a
small, independently testable protocol boundary so it can later be extracted
into the external Python package required for a Home Assistant Core submission.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
from base64 import b64decode, b64encode
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Final

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

API_VERSION: Final = 3
ACTION_ID_MODULUS: Final = 0x7FFFFFFF
AES_KEY_BYTES: Final = 32
AES_BLOCK_BYTES: Final = 16
HMAC_BYTES: Final = 32
MAX_FRAME_BYTES: Final = 65_536

_HEX_KEY_PATTERN = re.compile(r"^[0-9a-fA-F]{64}$")


class RemootioError(Exception):
    """Base error for the Remootio client."""


class RemootioProtocolError(RemootioError):
    """A frame violated the Remootio protocol."""


class RemootioIntegrityError(RemootioProtocolError):
    """An encrypted frame failed authentication."""


class RemootioAuthenticationError(RemootioError):
    """The supplied credentials were rejected."""


class RemootioConnectionError(RemootioError):
    """The device connection failed."""


class RemootioDisconnectedError(RemootioConnectionError):
    """The connection was lost while performing an action."""


class RemootioTimeoutError(RemootioConnectionError):
    """A bounded protocol operation timed out."""


class RemootioNotReadyError(RemootioConnectionError):
    """The persistent connection is not authenticated."""


class RemootioIdentityError(RemootioProtocolError):
    """The host answered as a different Remootio device."""


class RemootioCommandRejectedError(RemootioError):
    """The device explicitly rejected an action."""

    def __init__(self, action_type: ActionType, error_code: str) -> None:
        """Initialize the rejection without including sensitive data."""
        self.action_type = action_type
        self.error_code = error_code or "unknown_error"
        super().__init__(f"{action_type} rejected: {self.error_code}")


class DoorState(StrEnum):
    """Authoritative state values exposed by Remootio."""

    OPEN = "open"
    CLOSED = "closed"
    NO_SENSOR = "no sensor"


class ActionType(StrEnum):
    """Actions supported by WebSocket API v3."""

    QUERY = "QUERY"
    TRIGGER = "TRIGGER"
    TRIGGER_SECONDARY = "TRIGGER_SECONDARY"
    OPEN = "OPEN"
    CLOSE = "CLOSE"
    RESTART = "RESTART"


@dataclass(frozen=True, slots=True)
class DeviceIdentity:
    """Stable identity returned in SERVER_HELLO."""

    serial_number: str
    model: str
    api_version: int


@dataclass(frozen=True, slots=True)
class Challenge:
    """Authentication challenge contents."""

    session_key: bytes
    initial_action_id: int


@dataclass(frozen=True, slots=True)
class ActionResponse:
    """Validated action response."""

    action_type: ActionType
    action_id: int
    success: bool
    state: DoorState
    uptime_100ms: int
    relay_triggered: bool
    error_code: str


@dataclass(frozen=True, slots=True)
class DeviceEvent:
    """Validated event common fields."""

    counter: int
    event_type: str
    state: DoorState
    uptime_100ms: int
    data: Mapping[str, Any] | None


def decode_hex_key(value: str, *, field: str = "key") -> bytes:
    """Validate and decode a 64-character hexadecimal API key."""
    if not isinstance(value, str) or _HEX_KEY_PATTERN.fullmatch(value) is None:
        raise RemootioProtocolError(
            f"{field} must be exactly 64 hexadecimal characters"
        )
    decoded = bytes.fromhex(value)
    if len(decoded) != AES_KEY_BYTES:  # pragma: no cover - guarded by regex length
        raise RemootioProtocolError(f"{field} must decode to 32 bytes")
    return decoded


def next_action_id(last_action_id: int) -> int:
    """Return the next action ID using the protocol's 31-bit modulo."""
    _require_int(
        last_action_id, "lastActionId", minimum=0, maximum=ACTION_ID_MODULUS - 1
    )
    return (last_action_id + 1) % ACTION_ID_MODULUS


def parse_json_object(raw: str | bytes) -> dict[str, Any]:
    """Parse a bounded JSON object while rejecting duplicate keys."""
    if isinstance(raw, bytes):
        if len(raw) > MAX_FRAME_BYTES:
            raise RemootioProtocolError("frame exceeds maximum size")
        try:
            raw = raw.decode("utf-8")
        except UnicodeDecodeError as err:
            raise RemootioProtocolError("frame is not valid UTF-8") from err
    elif not isinstance(raw, str):
        raise RemootioProtocolError("frame must be text")
    try:
        encoded = raw.encode("utf-8")
    except UnicodeEncodeError as err:
        raise RemootioProtocolError("frame is not valid Unicode text") from err
    if len(encoded) > MAX_FRAME_BYTES:
        raise RemootioProtocolError("frame exceeds maximum size")

    def object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise RemootioProtocolError(f"duplicate JSON field: {key}")
            result[key] = value
        return result

    def reject_constant(value: str) -> None:
        raise RemootioProtocolError(f"non-standard JSON constant: {value}")

    try:
        value = json.loads(
            raw,
            object_pairs_hook=object_pairs,
            parse_constant=reject_constant,
        )
    except RemootioProtocolError:
        raise
    except (json.JSONDecodeError, UnicodeError) as err:
        raise RemootioProtocolError("frame contains malformed JSON") from err
    if not isinstance(value, dict):
        raise RemootioProtocolError("frame root must be an object")
    return value


def compact_json(value: Mapping[str, Any]) -> str:
    """Encode JSON exactly as required by Remootio's MAC construction."""
    return json.dumps(
        value,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )


def encrypt_frame(
    payload: Mapping[str, Any],
    encryption_key: bytes,
    auth_key: bytes,
    *,
    iv: bytes | None = None,
) -> dict[str, Any]:
    """Encrypt and authenticate an unencrypted payload."""
    _require_key(encryption_key, "encryption key")
    _require_key(auth_key, "authentication key")
    actual_iv = secrets.token_bytes(AES_BLOCK_BYTES) if iv is None else iv
    if not isinstance(actual_iv, bytes) or len(actual_iv) != AES_BLOCK_BYTES:
        raise RemootioProtocolError("IV must be exactly 16 bytes")
    if not isinstance(payload, Mapping):
        raise RemootioProtocolError("payload must be an object")

    try:
        plaintext = compact_json(payload).encode("latin-1")
    except (TypeError, UnicodeEncodeError, ValueError) as err:
        raise RemootioProtocolError("payload is not protocol-compatible JSON") from err

    padder = padding.PKCS7(AES_BLOCK_BYTES * 8).padder()
    padded = padder.update(plaintext) + padder.finalize()
    encryptor = Cipher(algorithms.AES(encryption_key), modes.CBC(actual_iv)).encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    iv_b64 = b64encode(actual_iv).decode("ascii")
    payload_b64 = b64encode(ciphertext).decode("ascii")
    data = {"iv": iv_b64, "payload": payload_b64}
    mac = hmac.new(
        auth_key, compact_json(data).encode("ascii"), hashlib.sha256
    ).digest()
    return {
        "type": "ENCRYPTED",
        "data": data,
        "mac": b64encode(mac).decode("ascii"),
    }


def decrypt_frame(
    frame: Mapping[str, Any], encryption_key: bytes, auth_key: bytes
) -> dict[str, Any]:
    """Authenticate, decrypt, unpad, and parse an ENCRYPTED frame."""
    _require_key(encryption_key, "encryption key")
    _require_key(auth_key, "authentication key")
    _require_exact_keys(frame, {"type", "data", "mac"}, "encrypted frame")
    if frame.get("type") != "ENCRYPTED":
        raise RemootioProtocolError("expected ENCRYPTED frame")
    data = frame.get("data")
    if not isinstance(data, dict):
        raise RemootioProtocolError("encrypted data must be an object")
    _require_exact_keys(data, {"iv", "payload"}, "encrypted data")

    iv_text = data.get("iv")
    payload_text = data.get("payload")
    mac_text = frame.get("mac")
    iv = _strict_b64(iv_text, "iv", expected_length=AES_BLOCK_BYTES)
    ciphertext = _strict_b64(payload_text, "payload")
    received_mac = _strict_b64(mac_text, "mac", expected_length=HMAC_BYTES)
    if not ciphertext or len(ciphertext) % AES_BLOCK_BYTES:
        raise RemootioProtocolError("ciphertext must be a non-empty AES block multiple")

    expected_mac = hmac.new(
        auth_key,
        compact_json({"iv": iv_text, "payload": payload_text}).encode("ascii"),
        hashlib.sha256,
    ).digest()
    if not hmac.compare_digest(expected_mac, received_mac):
        raise RemootioIntegrityError("encrypted frame MAC verification failed")

    decryptor = Cipher(algorithms.AES(encryption_key), modes.CBC(iv)).decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(AES_BLOCK_BYTES * 8).unpadder()
    try:
        plaintext = unpadder.update(padded) + unpadder.finalize()
    except ValueError as err:
        raise RemootioProtocolError(
            "encrypted frame has invalid PKCS7 padding"
        ) from err
    try:
        text = plaintext.decode("latin-1")
    except UnicodeDecodeError as err:  # pragma: no cover - latin-1 is total
        raise RemootioProtocolError("decrypted payload is not Latin-1") from err
    return parse_json_object(text)


def parse_server_hello(frame: Mapping[str, Any]) -> DeviceIdentity:
    """Validate SERVER_HELLO and return stable identity data."""
    _require_fields(
        frame,
        {"type", "apiVersion", "message", "serialNumber", "remootioVersion"},
        "SERVER_HELLO",
    )
    if frame.get("type") != "SERVER_HELLO":
        raise RemootioProtocolError("expected SERVER_HELLO")
    api_version = _require_int(frame.get("apiVersion"), "apiVersion", minimum=1)
    if api_version != API_VERSION:
        raise RemootioProtocolError(f"unsupported API version: {api_version}")
    serial = _require_string(frame.get("serialNumber"), "serialNumber", maximum=128)
    model = _require_string(frame.get("remootioVersion"), "remootioVersion", maximum=64)
    _require_string(frame.get("message"), "message", maximum=256)
    return DeviceIdentity(serial, model, api_version)


def parse_challenge(payload: Mapping[str, Any]) -> Challenge:
    """Validate and decode the authentication challenge."""
    # The prose example includes ``type: CHALLENGE``, while the published
    # authentication ciphertext test vector decrypts to only ``challenge``.
    # Accept exactly those two documented wire variants.
    if set(payload) not in ({"challenge"}, {"type", "challenge"}):
        raise RemootioProtocolError("challenge payload has invalid fields")
    if "type" in payload and payload.get("type") != "CHALLENGE":
        raise RemootioProtocolError("expected CHALLENGE payload")
    challenge = payload.get("challenge")
    if not isinstance(challenge, dict):
        raise RemootioProtocolError("challenge must be an object")
    _require_fields(challenge, {"sessionKey", "initialActionId"}, "challenge")
    session_key = _strict_b64(
        challenge.get("sessionKey"), "sessionKey", expected_length=AES_KEY_BYTES
    )
    initial_action_id = _require_int(
        challenge.get("initialActionId"),
        "initialActionId",
        minimum=0,
        maximum=ACTION_ID_MODULUS - 1,
    )
    return Challenge(session_key, initial_action_id)


def parse_action_response(payload: Mapping[str, Any]) -> ActionResponse:
    """Validate an action response payload."""
    _require_exact_keys(payload, {"response"}, "response payload")
    response = payload.get("response")
    if not isinstance(response, dict):
        raise RemootioProtocolError("response must be an object")
    required = {
        "type",
        "id",
        "success",
        "state",
        "t100ms",
        "relayTriggered",
        "errorCode",
    }
    _require_fields(response, required, "response")
    response_type = response.get("type")
    if not isinstance(response_type, str):
        raise RemootioProtocolError("response type must be a string")
    try:
        action_type = ActionType(response_type)
    except ValueError as err:
        raise RemootioProtocolError("response has unknown action type") from err
    action_id = _require_int(
        response.get("id"), "response id", minimum=0, maximum=ACTION_ID_MODULUS - 1
    )
    success = response.get("success")
    if not isinstance(success, bool):
        raise RemootioProtocolError("response success must be boolean")
    state = _parse_state(response.get("state"))
    uptime = _require_int(response.get("t100ms"), "t100ms", minimum=0)
    relay_triggered = response.get("relayTriggered")
    if not isinstance(relay_triggered, bool):
        raise RemootioProtocolError("relayTriggered must be boolean")
    error_code = response.get("errorCode")
    if not isinstance(error_code, str) or len(error_code) > 128:
        raise RemootioProtocolError("errorCode must be a bounded string")
    return ActionResponse(
        action_type,
        action_id,
        success,
        state,
        uptime,
        relay_triggered,
        error_code,
    )


def parse_event(payload: Mapping[str, Any]) -> DeviceEvent:
    """Validate common event fields while preserving extensible event data."""
    _require_exact_keys(payload, {"event"}, "event payload")
    event = payload.get("event")
    if not isinstance(event, dict):
        raise RemootioProtocolError("event must be an object")
    _require_fields(event, {"cnt", "type", "state", "t100ms"}, "event")
    counter = _require_int(event.get("cnt"), "event counter", minimum=0)
    event_type = _require_string(event.get("type"), "event type", maximum=128)
    state = _parse_state(event.get("state"))
    uptime = _require_int(event.get("t100ms"), "t100ms", minimum=0)
    data = event.get("data")
    if data is not None and not isinstance(data, dict):
        raise RemootioProtocolError("event data must be an object")
    return DeviceEvent(counter, event_type, state, uptime, data)


def build_action(action_type: ActionType, action_id: int) -> dict[str, Any]:
    """Build an unencrypted action payload."""
    _require_int(action_id, "action id", minimum=0, maximum=ACTION_ID_MODULUS - 1)
    return {"action": {"type": action_type.value, "id": action_id}}


def _strict_b64(value: Any, field: str, *, expected_length: int | None = None) -> bytes:
    if not isinstance(value, str) or not value:
        raise RemootioProtocolError(f"{field} must be a non-empty base64 string")
    try:
        decoded = b64decode(value, validate=True)
    except (ValueError, TypeError) as err:
        raise RemootioProtocolError(f"{field} is not valid base64") from err
    if b64encode(decoded).decode("ascii") != value:
        raise RemootioProtocolError(f"{field} is not canonical base64")
    if expected_length is not None and len(decoded) != expected_length:
        raise RemootioProtocolError(f"{field} has an invalid decoded length")
    return decoded


def _require_key(value: bytes, field: str) -> None:
    if not isinstance(value, bytes) or len(value) != AES_KEY_BYTES:
        raise RemootioProtocolError(f"{field} must be exactly 32 bytes")


def _require_exact_keys(
    value: Mapping[str, Any], expected: set[str], field: str
) -> None:
    if not isinstance(value, Mapping) or set(value) != expected:
        raise RemootioProtocolError(f"{field} has invalid fields")


def _require_fields(value: Mapping[str, Any], required: set[str], field: str) -> None:
    if not isinstance(value, Mapping) or not required.issubset(value):
        raise RemootioProtocolError(f"{field} is missing required fields")


def _require_int(
    value: Any, field: str, *, minimum: int, maximum: int | None = None
) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise RemootioProtocolError(f"{field} must be an integer")
    if value < minimum or (maximum is not None and value > maximum):
        raise RemootioProtocolError(f"{field} is outside the allowed range")
    return value


def _require_string(value: Any, field: str, *, maximum: int) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise RemootioProtocolError(f"{field} must be a bounded non-empty string")
    return value


def _parse_state(value: Any) -> DoorState:
    try:
        return DoorState(value)
    except (TypeError, ValueError) as err:
        raise RemootioProtocolError("invalid door state") from err
