"""Tests for the persistent single-socket Remootio client."""

from __future__ import annotations

import asyncio
import base64
import json
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any
from unittest.mock import AsyncMock

import pytest
from aiohttp import ClientConnectionError, WSMsgType

from custom_components.remootio import client as client_module
from custom_components.remootio.client import RemootioClient, async_probe_device
from custom_components.remootio.protocol import (
    ActionType,
    DoorState,
    RemootioAuthenticationError,
    RemootioCommandRejectedError,
    RemootioConnectionError,
    RemootioDisconnectedError,
    RemootioNotReadyError,
    RemootioProtocolError,
    RemootioTimeoutError,
    compact_json,
    decrypt_frame,
    encrypt_frame,
    parse_json_object,
)

SECRET_HEX = "11" * 32
AUTH_HEX = "22" * 32
SECRET = bytes.fromhex(SECRET_HEX)
AUTH = bytes.fromhex(AUTH_HEX)
SESSION = bytes(range(32))
SERIAL = "abc123"


@dataclass(slots=True)
class FakeMessage:
    """Minimal aiohttp-compatible incoming message."""

    type: WSMsgType
    data: str | None = None


ActionHandler = Callable[["FakeWebSocket", str, int], None]


class FakeDevice:
    """Protocol-aware deterministic Remootio simulator."""

    def __init__(self) -> None:
        self.connections = 0
        self.max_connections = 0
        self.sockets: list[FakeWebSocket] = []
        self.actions: list[tuple[str, int]] = []
        self.action_handler: ActionHandler | None = None
        self.state = DoorState.CLOSED
        self.model = "remootio-2"
        self.uptime = 100
        self.initial_action_id = 100
        self.handshake_events: list[dict[str, Any]] = []

    async def connect(self) -> FakeWebSocket:
        self.connections += 1
        self.max_connections = max(self.max_connections, self.connections)
        websocket = FakeWebSocket(self)
        self.sockets.append(websocket)
        return websocket

    def response_frame(
        self,
        action_type: str,
        action_id: int,
        *,
        success: bool = True,
        error_code: str = "",
    ) -> dict[str, Any]:
        return encrypt_frame(
            {
                "response": {
                    "type": action_type,
                    "id": action_id,
                    "success": success,
                    "state": self.state.value,
                    "t100ms": self.uptime,
                    "relayTriggered": action_type != "QUERY" and success,
                    "errorCode": error_code,
                }
            },
            SESSION,
            AUTH,
            iv=bytes([len(self.actions) % 256]) * 16,
        )

    def event_frame(
        self,
        counter: int,
        state: DoorState,
        *,
        event_type: str = "StateChange",
        uptime: int | None = None,
    ) -> dict[str, Any]:
        return encrypt_frame(
            {
                "event": {
                    "cnt": counter,
                    "type": event_type,
                    "state": state.value,
                    "t100ms": self.uptime if uptime is None else uptime,
                }
            },
            SESSION,
            AUTH,
            iv=bytes([(counter + 32) % 256]) * 16,
        )


class FakeSession:
    """ClientSession-compatible factory that tracks concurrent sockets."""

    def __init__(self, device: FakeDevice) -> None:
        self.device = device

    async def ws_connect(self, url: Any, **kwargs: Any) -> FakeWebSocket:
        assert str(url) == "ws://remootio.local:8080"
        assert kwargs["heartbeat"] is None
        return await self.device.connect()


class FakeWebSocket:
    """WebSocket endpoint backed by the deterministic device simulator."""

    def __init__(self, device: FakeDevice) -> None:
        self.device = device
        self.incoming: asyncio.Queue[FakeMessage] = asyncio.Queue()
        self.sent: list[str] = []
        self.closed = False
        self._initial_query_seen = False

    async def send_str(self, data: str) -> None:
        self.sent.append(data)
        frame = parse_json_object(data)
        frame_type = frame.get("type")
        if frame_type == "HELLO":
            self.queue_json({
                "type": "SERVER_HELLO",
                "apiVersion": 3,
                "message": "This is the Remootio Websocket API",
                "serialNumber": SERIAL,
                "remootioVersion": self.device.model,
            })
            return
        if frame_type == "AUTH":
            self.queue_json(
                encrypt_frame(
                    {
                        "type": "CHALLENGE",
                        "challenge": {
                            "sessionKey": (
                                "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
                            ),
                            "initialActionId": self.device.initial_action_id,
                        },
                    },
                    SECRET,
                    AUTH,
                    iv=bytes(16),
                )
            )
            return
        if frame_type == "PING":
            self.queue_json({"type": "PONG"})
            return
        if frame_type != "ENCRYPTED":
            raise AssertionError(f"unexpected outgoing frame: {frame}")
        payload = decrypt_frame(frame, SESSION, AUTH)
        action = payload["action"]
        action_type = action["type"]
        action_id = action["id"]
        self.device.actions.append((action_type, action_id))
        if action_type == "QUERY" and not self._initial_query_seen:
            self._initial_query_seen = True
            for event in self.device.handshake_events:
                self.queue_json(event)
        if self.device.action_handler is not None:
            self.device.action_handler(self, action_type, action_id)
        else:
            self.queue_json(self.device.response_frame(action_type, action_id))

    async def receive(self) -> FakeMessage:
        return await self.incoming.get()

    async def close(self) -> bool:
        if self.closed:
            return False
        self.closed = True
        self.device.connections -= 1
        self.incoming.put_nowait(FakeMessage(WSMsgType.CLOSED))
        return True

    def queue_json(self, frame: dict[str, Any]) -> None:
        self.incoming.put_nowait(FakeMessage(WSMsgType.TEXT, compact_json(frame)))

    def disconnect(self) -> None:
        if not self.closed:
            self.incoming.put_nowait(FakeMessage(WSMsgType.CLOSE))


async def _start_client(
    device: FakeDevice,
    *,
    states: list[DoorState] | None = None,
    availability: list[bool] | None = None,
) -> RemootioClient:
    client = RemootioClient(
        FakeSession(device),  # type: ignore[arg-type]
        "remootio.local",
        SECRET_HEX,
        AUTH_HEX,
        expected_serial=SERIAL,
        state_callback=(
            (lambda state, _uptime: states.append(state))
            if states is not None
            else None
        ),
        availability_callback=(
            availability.append if availability is not None else None
        ),
    )
    await client.async_start()
    return client


async def _wait_until(predicate: Callable[[], bool], timeout: float = 1.0) -> None:
    async with asyncio.timeout(timeout):
        while not predicate():
            await asyncio.sleep(0)


@pytest.mark.asyncio
async def test_probe_is_read_only_and_closes() -> None:
    """A probe performs HELLO, AUTH, QUERY and no relay action."""
    device = FakeDevice()
    client = RemootioClient(
        FakeSession(device),  # type: ignore[arg-type]
        "remootio.local",
        SECRET_HEX,
        AUTH_HEX,
    )
    result = await client.async_probe()
    assert result.identity.serial_number == SERIAL
    assert result.state is DoorState.CLOSED
    assert [action for action, _ in device.actions] == ["QUERY"]
    assert device.connections == 0


@pytest.mark.asyncio
async def test_command_success_and_concurrent_serialization() -> None:
    """Concurrent HA calls share one socket and advance one action at a time."""
    device = FakeDevice()

    def delayed_response(
        socket: FakeWebSocket, action_type: str, action_id: int
    ) -> None:
        async def respond() -> None:
            await asyncio.sleep(0.01)
            socket.queue_json(device.response_frame(action_type, action_id))

        task = asyncio.create_task(respond())
        task.add_done_callback(lambda done: done.exception())

    device.action_handler = delayed_response
    client = await _start_client(device)
    first, second = await asyncio.gather(
        client.async_execute(ActionType.OPEN),
        client.async_execute(ActionType.CLOSE),
    )
    assert first.action_type is ActionType.OPEN
    assert second.action_type is ActionType.CLOSE
    assert [action for action, _ in device.actions] == ["QUERY", "OPEN", "CLOSE"]
    assert [action_id for _, action_id in device.actions] == [101, 102, 103]
    assert device.max_connections == 1
    await client.async_stop()


@pytest.mark.asyncio
async def test_explicit_rejection_surfaces_and_session_remains_usable() -> None:
    """Turn success=false into a typed action failure, not a false success."""
    device = FakeDevice()

    def reject_open(socket: FakeWebSocket, action_type: str, action_id: int) -> None:
        socket.queue_json(
            device.response_frame(
                action_type,
                action_id,
                success=action_type != "OPEN",
                error_code="ERR_RELAY_BUSY" if action_type == "OPEN" else "",
            )
        )

    device.action_handler = reject_open
    client = await _start_client(device)
    with pytest.raises(RemootioCommandRejectedError, match="ERR_RELAY_BUSY"):
        await client.async_execute(ActionType.OPEN)
    assert (await client.async_execute(ActionType.CLOSE)).success
    assert client.available
    await client.async_stop()


@pytest.mark.asyncio
async def test_command_timeout_fails_and_retires_session(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Never acknowledge a command for which no matching response arrived."""
    device = FakeDevice()

    def ignore_open(socket: FakeWebSocket, action_type: str, action_id: int) -> None:
        if action_type != "OPEN":
            socket.queue_json(device.response_frame(action_type, action_id))

    device.action_handler = ignore_open
    monkeypatch.setattr(client_module, "ACTION_TIMEOUT", 0.01)
    monkeypatch.setattr(client_module, "BACKOFF_INITIAL", 0.01)
    client = await _start_client(device)
    with pytest.raises(RemootioTimeoutError):
        await client.async_execute(ActionType.OPEN)
    await _wait_until(lambda: not client.available)
    await client.async_stop()


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["disconnect", "mismatch", "bad_mac"])
async def test_disconnect_or_malformed_response_fails_action(
    failure: str,
) -> None:
    """Disconnects and invalid correlations/integrity are action failures."""
    device = FakeDevice()

    def fail(socket: FakeWebSocket, action_type: str, action_id: int) -> None:
        if action_type != "OPEN":
            socket.queue_json(device.response_frame(action_type, action_id))
            return
        if failure == "disconnect":
            socket.disconnect()
        elif failure == "mismatch":
            socket.queue_json(device.response_frame("CLOSE", action_id))
        else:
            frame = device.response_frame(action_type, action_id)
            mac = bytearray(base64.b64decode(frame["mac"], validate=True))
            mac[0] ^= 0x01
            frame["mac"] = base64.b64encode(mac).decode()
            socket.queue_json(frame)

    device.action_handler = fail
    client = await _start_client(device)
    expected = (
        RemootioDisconnectedError if failure == "disconnect" else RemootioProtocolError
    )
    with pytest.raises(expected):
        await client.async_execute(ActionType.OPEN)
    await client.async_stop()


@pytest.mark.asyncio
async def test_state_authority_replay_duplicate_gap_and_reconciliation() -> None:
    """Only QUERY/StateChange update state; duplicates drop and gaps query."""
    device = FakeDevice()
    device.handshake_events = [
        device.event_frame(1, DoorState.OPEN, uptime=90),
        device.event_frame(1, DoorState.OPEN, uptime=90),
    ]
    states: list[DoorState] = []
    client = await _start_client(device, states=states)
    # Replayed state arrives, then the authoritative cold-start QUERY supersedes it.
    assert states == [DoorState.OPEN, DoorState.CLOSED]

    socket = device.sockets[-1]
    socket.queue_json(device.event_frame(3, DoorState.OPEN, uptime=110))
    await _wait_until(lambda: len(states) >= 4)
    assert [action for action, _ in device.actions] == ["QUERY", "QUERY"]
    assert states[-2:] == [DoorState.OPEN, DoorState.CLOSED]

    # A command response carries state but cannot update authoritative state.
    device.state = DoorState.OPEN
    before = list(states)
    await client.async_execute(ActionType.CLOSE)
    assert states == before
    await client.async_stop()


@pytest.mark.asyncio
async def test_reconnect_replays_deduplicate_and_detects_restart(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Reconnect on the same client and reset event epoch after lower uptime."""
    device = FakeDevice()
    device.handshake_events = [device.event_frame(10, DoorState.OPEN, uptime=100)]
    states: list[DoorState] = []
    availability: list[bool] = []
    monkeypatch.setattr(client_module, "BACKOFF_INITIAL", 0.01)
    client = await _start_client(device, states=states, availability=availability)
    first_socket = device.sockets[-1]
    first_socket.disconnect()
    await _wait_until(lambda: len(device.sockets) >= 2)
    # Same replayed counter is ignored on a same-uptime reconnect.
    assert states.count(DoorState.OPEN) == 1

    device.uptime = 5
    device.handshake_events = [
        device.event_frame(0, DoorState.CLOSED, event_type="Restart", uptime=1),
        device.event_frame(1, DoorState.OPEN, uptime=2),
    ]
    device.sockets[-1].disconnect()
    await _wait_until(lambda: len(device.sockets) >= 3)
    await _wait_until(lambda: states.count(DoorState.OPEN) == 2)
    assert availability[:3] == [True, False, True]
    assert device.max_connections == 1
    await client.async_stop()


@pytest.mark.asyncio
async def test_no_sensor_and_ping_pong() -> None:
    """Preserve literal no-sensor authority and use application keepalive."""
    device = FakeDevice()
    device.state = DoorState.NO_SENSOR
    states: list[DoorState] = []
    client = await _start_client(device, states=states)
    assert states == [DoorState.NO_SENSOR]
    await client._ping(device.sockets[-1])
    assert parse_json_object(device.sockets[-1].sent[-1]) == {"type": "PING"}
    await client.async_stop()


@pytest.mark.asyncio
async def test_identity_mismatch_rejected() -> None:
    """Never silently bind an existing serial-number entry to another device."""
    device = FakeDevice()
    client = RemootioClient(
        FakeSession(device),  # type: ignore[arg-type]
        "remootio.local",
        SECRET_HEX,
        AUTH_HEX,
        expected_serial="different",
    )
    with pytest.raises(RemootioProtocolError, match="different"):
        await client.async_start()
    assert device.connections == 0


@pytest.mark.asyncio
async def test_authentication_error_frame() -> None:
    """Map the device's explicit authentication error to invalid credentials."""
    device = FakeDevice()

    class AuthErrorSocket(FakeWebSocket):
        async def send_str(self, data: str) -> None:
            frame = json.loads(data)
            if frame.get("type") == "AUTH":
                self.queue_json({
                    "type": "ERROR",
                    "errorMessage": "authentication error",
                })
                return
            await super().send_str(data)

    async def connect() -> FakeWebSocket:
        device.connections += 1
        socket = AuthErrorSocket(device)
        device.sockets.append(socket)
        return socket

    device.connect = connect  # type: ignore[method-assign]
    client = RemootioClient(
        FakeSession(device),  # type: ignore[arg-type]
        "remootio.local",
        SECRET_HEX,
        AUTH_HEX,
    )
    with pytest.raises(RemootioAuthenticationError):
        await client.async_start()


@pytest.mark.asyncio
async def test_start_twice_and_execute_while_unavailable() -> None:
    """Reject duplicate ownership and actions without a healthy session."""
    device = FakeDevice()
    client = RemootioClient(
        FakeSession(device),  # type: ignore[arg-type]
        "remootio.local",
        SECRET_HEX,
        AUTH_HEX,
    )
    with pytest.raises(RemootioNotReadyError):
        await client.async_execute(ActionType.OPEN)
    await client.async_start()
    assert client.host == "remootio.local"
    with pytest.raises(RuntimeError, match="already started"):
        await client.async_start()
    await client.async_stop()


@pytest.mark.asyncio
async def test_startup_timeout_cancels_hung_connection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Bound startup even when the networking stack never returns."""

    class HangingSession:
        async def ws_connect(self, url: Any, **kwargs: Any) -> FakeWebSocket:
            await asyncio.Event().wait()
            raise AssertionError("unreachable")

    monkeypatch.setattr(client_module, "STARTUP_TIMEOUT", 0.01)
    client = RemootioClient(
        HangingSession(),  # type: ignore[arg-type]
        "remootio.local",
        SECRET_HEX,
        AUTH_HEX,
    )
    with pytest.raises(RemootioTimeoutError, match="initial"):
        await client.async_start()
    assert client._supervisor_task is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (TimeoutError(), RemootioTimeoutError),
        (ClientConnectionError(), RemootioConnectionError),
        (OSError(), RemootioConnectionError),
    ],
)
async def test_open_socket_maps_transport_errors(
    error: Exception, expected: type[Exception]
) -> None:
    """Normalize connect timeout, aiohttp, and OS failures."""

    class ErrorSession:
        async def ws_connect(self, url: Any, **kwargs: Any) -> FakeWebSocket:
            raise error

    client = RemootioClient(
        ErrorSession(),  # type: ignore[arg-type]
        "::1",
        SECRET_HEX,
        AUTH_HEX,
    )
    with pytest.raises(expected):
        await client._open_socket()


@pytest.mark.asyncio
async def test_probe_helper_and_query_pong() -> None:
    """The public probe helper tolerates a keepalive during its QUERY."""
    device = FakeDevice()

    def pong_then_response(
        socket: FakeWebSocket, action_type: str, action_id: int
    ) -> None:
        socket.queue_json({"type": "PONG"})
        socket.queue_json(device.response_frame(action_type, action_id))

    device.action_handler = pong_then_response
    result = await async_probe_device(
        FakeSession(device),  # type: ignore[arg-type]
        "remootio.local",
        SECRET_HEX,
        AUTH_HEX,
    )
    assert result.state is DoorState.CLOSED


@pytest.mark.asyncio
async def test_handshake_rejects_plain_challenge_and_failed_query() -> None:
    """Authentication requires an encrypted challenge and successful QUERY."""
    device = FakeDevice()

    class PlainAuthSocket(FakeWebSocket):
        async def send_str(self, data: str) -> None:
            if parse_json_object(data).get("type") == "AUTH":
                self.queue_json({"type": "PONG"})
                return
            await super().send_str(data)

    plain = PlainAuthSocket(device)
    client = RemootioClient(
        FakeSession(device),  # type: ignore[arg-type]
        "remootio.local",
        SECRET_HEX,
        AUTH_HEX,
    )
    with pytest.raises(RemootioProtocolError, match="challenge"):
        await client._handshake(plain)

    def reject_query(socket: FakeWebSocket, action_type: str, action_id: int) -> None:
        socket.queue_json(device.response_frame(action_type, action_id, success=False))

    device.action_handler = reject_query
    with pytest.raises(RemootioAuthenticationError, match="QUERY"):
        await client.async_probe()


@pytest.mark.asyncio
async def test_receive_frame_error_matrix(monkeypatch: pytest.MonkeyPatch) -> None:
    """Classify receive timeout, transport closure, and binary frames."""
    device = FakeDevice()
    client = RemootioClient(
        FakeSession(device),  # type: ignore[arg-type]
        "remootio.local",
        SECRET_HEX,
        AUTH_HEX,
    )
    socket = FakeWebSocket(device)
    monkeypatch.setattr(socket, "receive", AsyncMock(side_effect=OSError()))
    with pytest.raises(RemootioDisconnectedError, match="receive"):
        await client._receive_frame(socket, None)

    for message_type, expected in [
        (WSMsgType.CLOSING, RemootioDisconnectedError),
        (WSMsgType.BINARY, RemootioProtocolError),
    ]:
        monkeypatch.setattr(
            socket, "receive", AsyncMock(return_value=FakeMessage(message_type))
        )
        with pytest.raises(expected):
            await client._receive_frame(socket, None)

    monkeypatch.setattr(socket, "receive", AsyncMock(side_effect=TimeoutError()))
    with pytest.raises(RemootioTimeoutError, match="response"):
        await client._receive_frame(socket, 0.1)


@pytest.mark.asyncio
async def test_unsolicited_frames_and_ping_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Reject unsolicited response/PONG frames and bound keepalive."""
    device = FakeDevice()
    client = RemootioClient(
        FakeSession(device),  # type: ignore[arg-type]
        "remootio.local",
        SECRET_HEX,
        AUTH_HEX,
    )
    socket = FakeWebSocket(device)
    socket.queue_json({"type": "PONG"})
    with pytest.raises(RemootioProtocolError, match="unsolicited PONG"):
        await client._reader(socket)

    client._session_key = SESSION
    socket.queue_json(device.response_frame("QUERY", 1))
    with pytest.raises(RemootioProtocolError, match="unsolicited action"):
        await client._reader(socket)

    class NoPongSocket(FakeWebSocket):
        async def send_str(self, data: str) -> None:
            self.sent.append(data)

    monkeypatch.setattr(client_module, "PONG_TIMEOUT", 0.01)
    with pytest.raises(RemootioTimeoutError, match="PONG"):
        await client._ping(NoPongSocket(device))


def test_internal_guards_and_error_frames() -> None:
    """Exercise guards that protect session-only operations."""
    client = RemootioClient(
        FakeSession(FakeDevice()),  # type: ignore[arg-type]
        "remootio.local",
        SECRET_HEX,
        AUTH_HEX,
    )
    with pytest.raises(RemootioProtocolError, match="session frame"):
        client._decrypt_session_frame({"type": "ENCRYPTED"})
    with pytest.raises(RemootioNotReadyError, match="session key"):
        client._encrypted_action(ActionType.OPEN, 1)
    with pytest.raises(RemootioNotReadyError, match="counter"):
        client._advance_action_id()
    with pytest.raises(RemootioProtocolError, match="malformed"):
        client._raise_basic_error({"type": "ERROR"})
    with pytest.raises(RemootioProtocolError, match="device error"):
        client._raise_basic_error({"type": "ERROR", "errorMessage": "busy"})
    client._raise_basic_error({"type": "PONG"})


@pytest.mark.asyncio
async def test_reconnect_auth_failure_requests_reauth(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Credential rejection after setup stops retries and requests HA reauth."""
    device = FakeDevice()
    original_connect = device.connect

    class ReauthSocket(FakeWebSocket):
        async def send_str(self, data: str) -> None:
            if parse_json_object(data).get("type") == "AUTH":
                self.queue_json({
                    "type": "ERROR",
                    "errorMessage": "authentication error",
                })
                return
            await super().send_str(data)

    async def connect() -> FakeWebSocket:
        if device.sockets:
            device.connections += 1
            socket = ReauthSocket(device)
            device.sockets.append(socket)
            return socket
        return await original_connect()

    device.connect = connect  # type: ignore[method-assign]
    reauth: list[bool] = []
    monkeypatch.setattr(client_module, "BACKOFF_INITIAL", 0.01)
    client = RemootioClient(
        FakeSession(device),  # type: ignore[arg-type]
        "remootio.local",
        SECRET_HEX,
        AUTH_HEX,
        auth_failure_callback=lambda: reauth.append(True),
    )
    await client.async_start()
    device.sockets[-1].disconnect()
    await _wait_until(lambda: bool(reauth))
    assert not client.available
    await client.async_stop()


@pytest.mark.asyncio
async def test_raw_transport_failure_after_setup_retries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The supervisor also retries raw networking failures defensively."""
    device = FakeDevice()
    client = RemootioClient(
        FakeSession(device),  # type: ignore[arg-type]
        "remootio.local",
        SECRET_HEX,
        AUTH_HEX,
    )
    original_open = client._open_socket
    calls = 0

    async def flaky_open() -> FakeWebSocket:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("temporary")
        return await original_open()

    monkeypatch.setattr(client, "_open_socket", flaky_open)
    monkeypatch.setattr(client_module, "BACKOFF_INITIAL", 0.01)
    await client.async_start()
    device.sockets[-1].disconnect()
    await _wait_until(lambda: len(device.sockets) == 2)
    assert calls >= 3
    await client.async_stop()


@pytest.mark.asyncio
async def test_supervisor_normalizes_unexpected_session_exception(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An unexpected child-task exception becomes a connection failure."""
    device = FakeDevice()
    client = await _start_client(device)
    await client.async_stop()

    async def bad_reader(websocket: FakeWebSocket) -> None:
        raise ValueError("unexpected")

    async def waiting_writer(websocket: FakeWebSocket) -> None:
        await asyncio.Event().wait()

    monkeypatch.setattr(client, "_reader", bad_reader)
    monkeypatch.setattr(client, "_writer", waiting_writer)
    with pytest.raises(RemootioConnectionError, match="session failed"):
        await client._run_authenticated_session(FakeWebSocket(device))


@pytest.mark.asyncio
async def test_fail_actions_and_internal_future_consumer() -> None:
    """Fail queued actions and safely consume internal completion states."""
    client = RemootioClient(
        FakeSession(FakeDevice()),  # type: ignore[arg-type]
        "remootio.local",
        SECRET_HEX,
        AUTH_HEX,
    )
    queued = asyncio.get_running_loop().create_future()
    client._queue.put_nowait(client_module._QueuedAction(ActionType.OPEN, queued))
    pong = asyncio.get_running_loop().create_future()
    client._pong_waiter = pong
    error = RemootioDisconnectedError("gone")
    client._fail_actions(error)
    with pytest.raises(RemootioDisconnectedError):
        await queued
    with pytest.raises(RemootioDisconnectedError):
        await pong

    cancelled = asyncio.get_running_loop().create_future()
    cancelled.cancel()
    client_module._consume_future_exception(cancelled)
