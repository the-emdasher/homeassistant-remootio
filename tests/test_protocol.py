"""Tests for strict Remootio API v3 framing and validation."""

from __future__ import annotations

import copy
import hashlib
import hmac
import json
from base64 import b64decode, b64encode

import pytest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from custom_components.remootio.protocol import (
    ACTION_ID_MODULUS,
    ActionType,
    DoorState,
    RemootioIntegrityError,
    RemootioProtocolError,
    build_action,
    compact_json,
    decode_hex_key,
    decrypt_frame,
    encrypt_frame,
    next_action_id,
    parse_action_response,
    parse_challenge,
    parse_event,
    parse_json_object,
    parse_server_hello,
)

API_SECRET = "EFD0E4BF75D49BDD4F5CD5492D55C92FE96040E9CD74BED9F19ACA2658EA0FA9"
API_AUTH = "7B456E7AE95E55F714E2270983C33360514DAD96C93AE1990AFE35FD5BF00A72"
SESSION_KEY_B64 = "yzEI7RWCjYDEwFrgc5YrmWo82kXEjFNStbtN+wFM2Qk="

AUTH_VECTOR = {
    "type": "ENCRYPTED",
    "data": {
        "iv": "4kbmkg6iU29Zlpi3NCDM4g==",
        "payload": (
            "ZTQwhEWXMV2ZxkzDJiJWyCD52FF88pha8lJbpD2KYk5B6TGQvBaTJlA7apd+"
            "lO38mu44NA7heNVZOc6B6jVwqvdqMSrEdV33KgaHMZY7yNXBq4aP3+Z2ai4T"
            "J8Smgnj6Z77J4qeT6MqBbr0FTLYkEg=="
        ),
    },
    "mac": "qko4r2/Eucwh8FqJIXucKn/w/ftR9+vs05E8A1/y++Q=",
}

QUERY_RESPONSE_VECTOR = {
    "type": "ENCRYPTED",
    "data": {
        "iv": "S7Mt0PR3MCADhHOPqhJPLA==",
        "payload": (
            "pSw+jH9iR3/nOO2+78EpQct3w+vJGKku+8ynSaYra6WsU4dHQJfMg1KNJkooVb1/"
            "WYhT28NyGznEHEKt97SYTMG15KjWcQUuqRSlpGD3JzWi/5LG+JPvIg3ptivsFrRZR"
            "3wzHAtZI6CekFujm8dhjeK/o6w+daK4FdvVh78pVigX6tBuNHEjoRQfUL9TRS9W"
        ),
    },
    "mac": "cD4IpRARmeWoUjkL4Kh40uhOMbs7P9prP497qZUapwQ=",
}


def test_official_authentication_decryption_vector() -> None:
    """Decrypt the official challenge and validate every challenge field."""
    payload = decrypt_frame(
        AUTH_VECTOR, decode_hex_key(API_SECRET), decode_hex_key(API_AUTH)
    )
    challenge = parse_challenge(payload)
    assert b64encode(challenge.session_key).decode() == SESSION_KEY_B64
    assert challenge.initial_action_id == 808411243


def test_official_query_encryption_vector() -> None:
    """Reproduce the official deterministic encrypted QUERY example."""
    frame = encrypt_frame(
        build_action(ActionType.QUERY, 808411244),
        b64decode(SESSION_KEY_B64),
        decode_hex_key(API_AUTH),
        iv=b64decode("vz3r424R6v9XFchkkgWQTw=="),
    )
    assert frame["data"]["payload"] == (
        "L6eTyvyY/q4I7oDAfdeDyz17x0vMUqmqvnCYl73zG2UxnYpIKVIQ0DooAWxcm3WT"
    )
    assert frame["mac"] == "legB+2ZnikMtX54VpkPVc8P7o17s61y1JqGDvFrxbts="


def test_official_query_response_vector() -> None:
    """Decrypt and validate the official QUERY response."""
    payload = decrypt_frame(
        QUERY_RESPONSE_VECTOR,
        b64decode(SESSION_KEY_B64),
        decode_hex_key(API_AUTH),
    )
    response = parse_action_response(payload)
    assert response.action_type is ActionType.QUERY
    assert response.action_id == 808411244
    assert response.state is DoorState.NO_SENSOR
    assert response.success is True


def test_altered_mac_rejected_before_decrypt() -> None:
    """Reject an altered but well-formed MAC."""
    frame = json.loads(json.dumps(QUERY_RESPONSE_VECTOR))
    mac = bytearray(b64decode(frame["mac"]))
    mac[0] ^= 1
    frame["mac"] = b64encode(mac).decode()
    with pytest.raises(RemootioIntegrityError, match="MAC"):
        decrypt_frame(frame, b64decode(SESSION_KEY_B64), decode_hex_key(API_AUTH))


def test_altered_ciphertext_rejected_by_mac() -> None:
    """Authenticate ciphertext before attempting CBC decryption."""
    frame = json.loads(json.dumps(QUERY_RESPONSE_VECTOR))
    ciphertext = bytearray(b64decode(frame["data"]["payload"]))
    ciphertext[0] ^= 1
    frame["data"]["payload"] = b64encode(ciphertext).decode()
    with pytest.raises(RemootioIntegrityError, match="MAC"):
        decrypt_frame(frame, b64decode(SESSION_KEY_B64), decode_hex_key(API_AUTH))


def test_invalid_padding_rejected_after_valid_mac() -> None:
    """Reject invalid PKCS7 even when the attacker knows the test MAC key."""
    key = b64decode(SESSION_KEY_B64)
    auth = decode_hex_key(API_AUTH)
    iv = bytes(16)
    invalid_padded_plaintext = b"x" * 15 + b"\x00"
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    ciphertext = encryptor.update(invalid_padded_plaintext) + encryptor.finalize()
    data = {"iv": b64encode(iv).decode(), "payload": b64encode(ciphertext).decode()}
    mac = hmac.new(auth, compact_json(data).encode(), hashlib.sha256).digest()
    frame = {"type": "ENCRYPTED", "data": data, "mac": b64encode(mac).decode()}
    with pytest.raises(RemootioProtocolError, match="padding"):
        decrypt_frame(frame, key, auth)


def test_malformed_decrypted_json_rejected() -> None:
    """Reject authenticated plaintext that is not valid JSON."""
    key = b64decode(SESSION_KEY_B64)
    auth = decode_hex_key(API_AUTH)
    iv = bytes(16)
    plaintext = b"not-json" + bytes([8] * 8)
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    data = {"iv": b64encode(iv).decode(), "payload": b64encode(ciphertext).decode()}
    mac = hmac.new(auth, compact_json(data).encode(), hashlib.sha256).digest()
    frame = {"type": "ENCRYPTED", "data": data, "mac": b64encode(mac).decode()}
    with pytest.raises(RemootioProtocolError, match="malformed JSON"):
        decrypt_frame(frame, key, auth)


@pytest.mark.parametrize(
    "value",
    ["", "0" * 63, "0" * 65, "g" * 64, 123],
)
def test_invalid_api_key_rejected(value: object) -> None:
    """Require exactly 32 bytes represented by 64 hexadecimal characters."""
    with pytest.raises(RemootioProtocolError):
        decode_hex_key(value)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("iv", "!!!!"),
        ("iv", b64encode(b"short").decode()),
        ("payload", "not base64"),
        ("payload", b64encode(b"short").decode()),
        ("mac", b64encode(b"short").decode()),
    ],
)
def test_invalid_encrypted_field_rejected(field: str, value: str) -> None:
    """Reject malformed base64 and invalid cryptographic lengths."""
    frame = json.loads(json.dumps(QUERY_RESPONSE_VECTOR))
    if field == "mac":
        frame[field] = value
    else:
        frame["data"][field] = value
    with pytest.raises(RemootioProtocolError):
        decrypt_frame(frame, b64decode(SESSION_KEY_B64), decode_hex_key(API_AUTH))


def test_missing_and_duplicate_fields_rejected() -> None:
    """Reject missing protocol fields and duplicate JSON keys."""
    with pytest.raises(RemootioProtocolError, match="missing"):
        parse_action_response({"response": {"type": "QUERY"}})
    with pytest.raises(RemootioProtocolError, match="duplicate"):
        parse_json_object('{"type":"PING","type":"PONG"}')
    with pytest.raises(RemootioProtocolError, match="root"):
        parse_json_object("[]")


def test_action_id_rollover_and_input_validation() -> None:
    """Use the exact protocol modulus rather than a bit mask."""
    assert next_action_id(ACTION_ID_MODULUS - 2) == ACTION_ID_MODULUS - 1
    assert next_action_id(ACTION_ID_MODULUS - 1) == 0
    assert next_action_id(0) == 1
    with pytest.raises(RemootioProtocolError):
        next_action_id(ACTION_ID_MODULUS)
    with pytest.raises(RemootioProtocolError):
        next_action_id(True)


def test_server_hello_and_event_validation() -> None:
    """Validate identity and authoritative event common fields."""
    identity = parse_server_hello({
        "type": "SERVER_HELLO",
        "apiVersion": 3,
        "message": "This is the Remootio Websocket API",
        "serialNumber": "serial-1",
        "remootioVersion": "remootio-2",
    })
    assert identity.serial_number == "serial-1"
    event = parse_event({
        "event": {
            "cnt": 4,
            "type": "StateChange",
            "state": "open",
            "t100ms": 99,
        }
    })
    assert event.state is DoorState.OPEN
    with pytest.raises(RemootioProtocolError, match="unsupported"):
        parse_server_hello({
            "type": "SERVER_HELLO",
            "apiVersion": 2,
            "message": "old",
            "serialNumber": "serial-1",
            "remootioVersion": "remootio-1",
        })
    with pytest.raises(RemootioProtocolError, match="event data"):
        parse_event({
            "event": {
                "cnt": 1,
                "type": "StateChange",
                "state": "open",
                "t100ms": 1,
                "data": "invalid",
            }
        })


def test_encrypt_rejects_invalid_crypto_inputs() -> None:
    """Reject invalid key and IV sizes before invoking cryptography."""
    with pytest.raises(RemootioProtocolError, match="encryption key"):
        encrypt_frame({}, b"short", bytes(32))
    with pytest.raises(RemootioProtocolError, match="authentication key"):
        encrypt_frame({}, bytes(32), b"short")
    with pytest.raises(RemootioProtocolError, match="IV"):
        encrypt_frame({}, bytes(32), bytes(32), iv=b"short")


def test_json_parser_rejects_binary_and_size_edge_cases() -> None:
    """Bound both text and bytes inputs and require valid UTF-8 text."""
    with pytest.raises(RemootioProtocolError, match="maximum"):
        parse_json_object(b"x" * 65537)
    with pytest.raises(RemootioProtocolError, match="UTF-8"):
        parse_json_object(b"\xff")
    with pytest.raises(RemootioProtocolError, match="text"):
        parse_json_object(1)  # type: ignore[arg-type]
    with pytest.raises(RemootioProtocolError, match="maximum"):
        parse_json_object("x" * 65537)
    with pytest.raises(RemootioProtocolError, match="Unicode"):
        parse_json_object('"\ud800"')
    with pytest.raises(RemootioProtocolError, match="non-standard"):
        parse_json_object('{"value":NaN}')


def test_encrypt_and_decrypt_reject_non_objects_and_shapes() -> None:
    """Reject non-JSON payloads and malformed encrypted envelopes."""
    key = bytes(32)
    with pytest.raises(RemootioProtocolError, match="payload must"):
        encrypt_frame([], key, key)  # type: ignore[arg-type]
    with pytest.raises(RemootioProtocolError, match="protocol-compatible"):
        encrypt_frame({"value": object()}, key, key)
    with pytest.raises(RemootioProtocolError, match="protocol-compatible"):
        encrypt_frame({"value": float("nan")}, key, key)

    good = encrypt_frame({}, key, key, iv=bytes(16))
    wrong_type = copy.deepcopy(good)
    wrong_type["type"] = "PLAIN"
    with pytest.raises(RemootioProtocolError, match="expected ENCRYPTED"):
        decrypt_frame(wrong_type, key, key)
    wrong_data = copy.deepcopy(good)
    wrong_data["data"] = "invalid"
    with pytest.raises(RemootioProtocolError, match="data must"):
        decrypt_frame(wrong_data, key, key)
    extra_field = {**good, "extra": True}
    with pytest.raises(RemootioProtocolError, match="invalid fields"):
        decrypt_frame(extra_field, key, key)


def test_server_hello_rejects_wrong_type_and_bad_strings() -> None:
    """Require the exact greeting type and bounded identity strings."""
    hello = {
        "type": "SERVER_HELLO",
        "apiVersion": 3,
        "message": "hello",
        "serialNumber": "serial",
        "remootioVersion": "remootio-2",
    }
    with pytest.raises(RemootioProtocolError, match="expected SERVER_HELLO"):
        parse_server_hello({**hello, "type": "HELLO"})
    with pytest.raises(RemootioProtocolError, match="serialNumber"):
        parse_server_hello({**hello, "serialNumber": ""})


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"type": "WRONG", "challenge": {}},
        {"challenge": "invalid"},
    ],
)
def test_challenge_rejects_invalid_shapes(payload: dict[str, object]) -> None:
    """Accept only the two documented challenge envelope variants."""
    with pytest.raises(RemootioProtocolError):
        parse_challenge(payload)


def test_challenge_rejects_bad_session_key_and_action_id() -> None:
    """Validate decoded key length and the 31-bit action range."""
    with pytest.raises(RemootioProtocolError, match="sessionKey"):
        parse_challenge({
            "challenge": {
                "sessionKey": b64encode(b"short").decode(),
                "initialActionId": 1,
            }
        })
    with pytest.raises(RemootioProtocolError, match="outside"):
        parse_challenge({
            "challenge": {
                "sessionKey": b64encode(bytes(32)).decode(),
                "initialActionId": ACTION_ID_MODULUS,
            }
        })


def _valid_response() -> dict[str, dict[str, object]]:
    return {
        "response": {
            "type": "QUERY",
            "id": 1,
            "success": True,
            "state": "closed",
            "t100ms": 1,
            "relayTriggered": False,
            "errorCode": "",
        }
    }


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("type", 1),
        ("type", "UNKNOWN"),
        ("success", 1),
        ("state", "moving"),
        ("relayTriggered", 1),
        ("errorCode", 1),
        ("errorCode", "x" * 129),
    ],
)
def test_action_response_rejects_invalid_values(field: str, value: object) -> None:
    """Reject semantically invalid values even when every field is present."""
    payload = _valid_response()
    payload["response"][field] = value
    with pytest.raises(RemootioProtocolError):
        parse_action_response(payload)


def test_response_and_event_require_object_envelopes() -> None:
    """Require inner response/event objects and valid event state."""
    with pytest.raises(RemootioProtocolError, match="response must"):
        parse_action_response({"response": None})
    with pytest.raises(RemootioProtocolError, match="event must"):
        parse_event({"event": None})
    with pytest.raises(RemootioProtocolError, match="invalid door state"):
        parse_event({
            "event": {
                "cnt": 1,
                "type": "StateChange",
                "state": "unknown",
                "t100ms": 1,
            }
        })


def test_base64_canonical_form_and_build_action_bounds() -> None:
    """Reject alternate encodings and out-of-range outgoing action IDs."""
    frame = copy.deepcopy(QUERY_RESPONSE_VECTOR)
    frame["data"]["iv"] = "AB=="
    with pytest.raises(RemootioProtocolError, match="canonical"):
        decrypt_frame(frame, b64decode(SESSION_KEY_B64), decode_hex_key(API_AUTH))
    frame["data"]["iv"] = ""
    with pytest.raises(RemootioProtocolError, match="non-empty"):
        decrypt_frame(frame, b64decode(SESSION_KEY_B64), decode_hex_key(API_AUTH))
    with pytest.raises(RemootioProtocolError, match="outside"):
        build_action(ActionType.OPEN, ACTION_ID_MODULUS)
