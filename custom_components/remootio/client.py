"""Persistent single-connection client for Remootio WebSocket API v3."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from typing import Any, Protocol, cast

from aiohttp import ClientError, ClientSession, WSMsgType
from yarl import URL

from .protocol import (
    MAX_FRAME_BYTES,
    ActionResponse,
    ActionType,
    DeviceEvent,
    DeviceIdentity,
    DoorState,
    RemootioAuthenticationError,
    RemootioCommandRejectedError,
    RemootioConnectionError,
    RemootioDisconnectedError,
    RemootioError,
    RemootioIdentityError,
    RemootioNotReadyError,
    RemootioProtocolError,
    RemootioTimeoutError,
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

_LOGGER = logging.getLogger(__name__)

CONNECT_TIMEOUT = 10.0
HELLO_TIMEOUT = 5.0
AUTH_TIMEOUT = 10.0
ACTION_TIMEOUT = 10.0
PONG_TIMEOUT = 10.0
PING_INTERVAL = 60.0
SHUTDOWN_TIMEOUT = 5.0
STARTUP_TIMEOUT = CONNECT_TIMEOUT + HELLO_TIMEOUT + AUTH_TIMEOUT + ACTION_TIMEOUT
BACKOFF_INITIAL = 2.0
BACKOFF_MAX = 60.0


class WebSocketLike(Protocol):
    """Small aiohttp WebSocket surface used by the protocol client."""

    @property
    def closed(self) -> bool:
        """Return whether the socket is closed."""

    async def send_str(self, data: str) -> None:
        """Send a text frame."""

    async def receive(self) -> Any:
        """Receive the next WebSocket message."""

    async def close(self) -> bool:
        """Close the socket."""


@dataclass(frozen=True, slots=True)
class ProbeResult:
    """Read-only connection result used by config flows and initial setup."""

    identity: DeviceIdentity
    state: DoorState
    uptime_100ms: int


@dataclass(slots=True)
class _QueuedAction:
    action_type: ActionType
    result: asyncio.Future[ActionResponse]


@dataclass(slots=True)
class _PendingAction:
    action_type: ActionType
    action_id: int
    response: asyncio.Future[ActionResponse]
    result: asyncio.Future[ActionResponse]


class _EventTracker:
    """Deduplicate replayed events and identify counter gaps or restarts."""

    def __init__(self) -> None:
        self.last_counter: int | None = None
        self.last_uptime_100ms: int | None = None

    def prepare_reconnect(self, query_uptime_100ms: int) -> bool:
        """Reset the event epoch when QUERY proves that the device restarted."""
        restarted = (
            self.last_uptime_100ms is not None
            and query_uptime_100ms < self.last_uptime_100ms
        )
        if restarted:
            self.reset()
        return restarted

    def accept(self, event: DeviceEvent) -> tuple[bool, bool]:
        """Return ``(accepted, gap_detected)`` for a validated event."""
        if event.event_type == "Restart" and event.counter == 0:
            self.reset()
        elif self.last_counter is not None and event.counter <= self.last_counter:
            # Replayed frames from the device's retained event buffer are stale.
            return False, False

        gap = self.last_counter is not None and event.counter > self.last_counter + 1
        self.last_counter = event.counter
        self.last_uptime_100ms = event.uptime_100ms
        return True, gap

    def observe_query(self, uptime_100ms: int) -> None:
        """Record the latest device uptime reported by an authoritative query."""
        self.last_uptime_100ms = uptime_100ms

    def reset(self) -> None:
        """Start a new device event-counter epoch."""
        self.last_counter = None
        self.last_uptime_100ms = None


class RemootioClient:
    """Own the one allowed authenticated WebSocket connection to a device."""

    def __init__(
        self,
        session: ClientSession,
        host: str,
        api_secret_key: str,
        api_auth_key: str,
        *,
        port: int = 8080,
        expected_serial: str | None = None,
        state_callback: Callable[[DoorState, int], None] | None = None,
        availability_callback: Callable[[bool], None] | None = None,
        identity_callback: Callable[[DeviceIdentity], None] | None = None,
        auth_failure_callback: Callable[[], None] | None = None,
    ) -> None:
        """Initialize a client without opening a connection."""
        self._session = session
        self._host = host
        self._port = port
        self._secret_key = decode_hex_key(api_secret_key, field="API secret key")
        self._auth_key = decode_hex_key(api_auth_key, field="API auth key")
        self._expected_serial = expected_serial
        self._state_callback = state_callback or (lambda _state, _uptime: None)
        self._availability_callback = availability_callback or (lambda _available: None)
        self._identity_callback = identity_callback or (lambda _identity: None)
        self._auth_failure_callback = auth_failure_callback or (lambda: None)

        self._queue: asyncio.Queue[_QueuedAction] = asyncio.Queue()
        self._pending: _PendingAction | None = None
        self._pong_waiter: asyncio.Future[None] | None = None
        self._session_key: bytes | None = None
        self._last_action_id: int | None = None
        self._websocket: WebSocketLike | None = None
        self._supervisor_task: asyncio.Task[None] | None = None
        self._ready: asyncio.Future[ProbeResult] | None = None
        self._stop_event = asyncio.Event()
        self._event_tracker = _EventTracker()
        self._reconcile_queued = False
        self._available = False

    @property
    def available(self) -> bool:
        """Return whether the persistent session is authenticated and healthy."""
        return self._available

    @property
    def host(self) -> str:
        """Return the configured network host."""
        return self._host

    async def async_start(self) -> ProbeResult:
        """Start the supervisor and wait for the first authenticated QUERY."""
        if self._supervisor_task is not None:
            raise RuntimeError("Remootio client is already started")
        self._stop_event.clear()
        self._ready = asyncio.get_running_loop().create_future()
        self._supervisor_task = asyncio.create_task(
            self._supervisor(), name=f"remootio-{self._host}"
        )
        try:
            return await asyncio.wait_for(asyncio.shield(self._ready), STARTUP_TIMEOUT)
        except TimeoutError as err:
            await self.async_stop()
            raise RemootioTimeoutError("initial device connection timed out") from err
        except BaseException:
            await self.async_stop()
            raise

    async def async_stop(self) -> None:
        """Stop all work, fail queued actions, and close within a fixed deadline."""
        self._stop_event.set()
        task = self._supervisor_task
        self._supervisor_task = None
        if task is not None:
            task.cancel()
            with suppress(asyncio.CancelledError):
                await task
        websocket = self._websocket
        if websocket is not None and not websocket.closed:
            with suppress(Exception):
                await asyncio.wait_for(websocket.close(), SHUTDOWN_TIMEOUT)
        self._set_available(False)
        self._fail_actions(RemootioDisconnectedError("Remootio client stopped"))

    async def async_execute(self, action_type: ActionType) -> ActionResponse:
        """Serialize an action and return only its matching successful response."""
        if not self._available or self._supervisor_task is None:
            raise RemootioNotReadyError("Remootio connection is unavailable")
        result: asyncio.Future[ActionResponse] = (
            asyncio.get_running_loop().create_future()
        )
        await self._queue.put(_QueuedAction(action_type, result))
        return await result

    async def async_probe(self) -> ProbeResult:
        """Perform one bounded, read-only HELLO/AUTH/QUERY session and close it."""
        websocket = await self._open_socket()
        try:
            return await self._handshake(websocket)
        finally:
            with suppress(Exception):
                await asyncio.wait_for(websocket.close(), SHUTDOWN_TIMEOUT)

    async def _supervisor(self) -> None:
        backoff = BACKOFF_INITIAL
        first_attempt = True
        while not self._stop_event.is_set():
            error: RemootioError | None = None
            try:
                websocket = await self._open_socket()
                self._websocket = websocket
                probe = await self._handshake(websocket)
                if self._ready is not None and not self._ready.done():
                    self._ready.set_result(probe)
                first_attempt = False
                backoff = BACKOFF_INITIAL
                self._set_available(True)
                await self._run_authenticated_session(websocket)
                if not self._stop_event.is_set():
                    raise RemootioDisconnectedError("device closed the WebSocket")
            except asyncio.CancelledError:
                raise
            except (RemootioAuthenticationError, RemootioIdentityError) as err:
                error = err
                if self._ready is not None and not self._ready.done():
                    self._ready.set_exception(err)
                if isinstance(err, RemootioAuthenticationError) and not first_attempt:
                    self._auth_failure_callback()
                break
            except RemootioError as err:
                error = err
                if self._ready is not None and not self._ready.done():
                    self._ready.set_exception(err)
                if first_attempt:
                    break
                _LOGGER.debug(
                    "Lost connection to Remootio at %s; retrying in %.0f seconds",
                    self._host,
                    backoff,
                )
            except (ClientError, OSError, TimeoutError) as err:
                error = RemootioConnectionError("unable to connect to Remootio")
                if self._ready is not None and not self._ready.done():
                    self._ready.set_exception(error)
                if first_attempt:
                    break
                _LOGGER.debug(
                    "Lost connection to Remootio at %s; retrying in %.0f seconds",
                    self._host,
                    backoff,
                )
                _LOGGER.debug("Remootio transport error: %s", type(err).__name__)
            finally:
                self._set_available(False)
                self._fail_actions(
                    error or RemootioDisconnectedError("connection ended")
                )
                closing_websocket = self._websocket
                self._websocket = None
                self._session_key = None
                self._last_action_id = None
                if closing_websocket is not None and not closing_websocket.closed:
                    with suppress(Exception):
                        await asyncio.wait_for(
                            closing_websocket.close(), SHUTDOWN_TIMEOUT
                        )

            if self._stop_event.is_set() or first_attempt:
                break
            try:
                await asyncio.wait_for(self._stop_event.wait(), backoff)
            except TimeoutError:
                backoff = min(backoff * 2, BACKOFF_MAX)

    async def _open_socket(self) -> WebSocketLike:
        # URL.build brackets IPv6 literals correctly and rejects accidental
        # path/query interpretation.
        url = URL.build(scheme="ws", host=self._host, port=self._port)
        try:
            websocket = await asyncio.wait_for(
                self._session.ws_connect(
                    url,
                    autoping=True,
                    heartbeat=None,
                    max_msg_size=MAX_FRAME_BYTES,
                ),
                CONNECT_TIMEOUT,
            )
        except TimeoutError as err:
            raise RemootioTimeoutError("WebSocket connection timed out") from err
        except (ClientError, OSError) as err:
            raise RemootioConnectionError("unable to connect to Remootio") from err
        return cast(WebSocketLike, websocket)

    async def _handshake(self, websocket: WebSocketLike) -> ProbeResult:
        await websocket.send_str('{"type":"HELLO"}')
        hello_frame = await self._receive_basic(websocket, HELLO_TIMEOUT)
        identity = parse_server_hello(hello_frame)
        if (
            self._expected_serial is not None
            and identity.serial_number != self._expected_serial
        ):
            raise RemootioIdentityError("host answered as a different Remootio device")
        self._identity_callback(identity)

        await websocket.send_str('{"type":"AUTH"}')
        auth_frame = await self._receive_frame(websocket, AUTH_TIMEOUT)
        self._raise_basic_error(auth_frame)
        if auth_frame.get("type") != "ENCRYPTED":
            raise RemootioProtocolError("expected encrypted authentication challenge")
        challenge_payload = decrypt_frame(auth_frame, self._secret_key, self._auth_key)
        challenge = parse_challenge(challenge_payload)
        self._session_key = challenge.session_key
        self._last_action_id = challenge.initial_action_id

        query_id = self._advance_action_id()
        await websocket.send_str(self._encrypted_action(ActionType.QUERY, query_id))
        replayed_events: list[DeviceEvent] = []
        deadline = asyncio.get_running_loop().time() + ACTION_TIMEOUT
        while True:
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                raise RemootioTimeoutError("authentication QUERY timed out")
            frame = await self._receive_frame(websocket, remaining)
            self._raise_basic_error(frame)
            if frame.get("type") == "PONG":
                continue
            payload = self._decrypt_session_frame(frame)
            if set(payload) == {"event"}:
                replayed_events.append(parse_event(payload))
                continue
            response = parse_action_response(payload)
            self._validate_correlation(response, ActionType.QUERY, query_id)
            if not response.success:
                raise RemootioAuthenticationError("authentication QUERY was rejected")

            self._event_tracker.prepare_reconnect(response.uptime_100ms)
            for event in replayed_events:
                self._process_event(event)
            self._event_tracker.observe_query(response.uptime_100ms)
            self._state_callback(response.state, response.uptime_100ms)
            return ProbeResult(identity, response.state, response.uptime_100ms)

    async def _run_authenticated_session(self, websocket: WebSocketLike) -> None:
        reader = asyncio.create_task(self._reader(websocket), name="remootio-reader")
        writer = asyncio.create_task(self._writer(websocket), name="remootio-writer")
        tasks = {reader, writer}
        try:
            done, _pending = await asyncio.wait(
                tasks, return_when=asyncio.FIRST_COMPLETED
            )
            session_error: RemootioError | None = None
            for task in done:
                exception = task.exception()
                if isinstance(exception, RemootioError):
                    session_error = exception
                    break
                if exception is not None:
                    session_error = RemootioConnectionError(
                        "authenticated session failed"
                    )
                    break
            if session_error is not None:
                self._fail_actions(session_error)
                raise session_error
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _reader(self, websocket: WebSocketLike) -> None:
        while not self._stop_event.is_set():
            frame = await self._receive_frame(websocket, None)
            self._raise_basic_error(frame)
            frame_type = frame.get("type")
            if frame_type == "PONG":
                if self._pong_waiter is None or self._pong_waiter.done():
                    raise RemootioProtocolError("received an unsolicited PONG")
                self._pong_waiter.set_result(None)
                continue
            payload = self._decrypt_session_frame(frame)
            if set(payload) == {"event"}:
                self._process_event(parse_event(payload))
                continue
            response = parse_action_response(payload)
            pending = self._pending
            if pending is None:
                raise RemootioProtocolError("received an unsolicited action response")
            self._validate_correlation(response, pending.action_type, pending.action_id)
            if not pending.response.done():
                pending.response.set_result(response)

    async def _writer(self, websocket: WebSocketLike) -> None:
        while not self._stop_event.is_set():
            try:
                queued = await asyncio.wait_for(self._queue.get(), PING_INTERVAL)
            except TimeoutError:
                await self._ping(websocket)
                continue

            action_id = self._advance_action_id()
            response_future: asyncio.Future[ActionResponse] = (
                asyncio.get_running_loop().create_future()
            )
            self._pending = _PendingAction(
                queued.action_type, action_id, response_future, queued.result
            )
            try:
                await websocket.send_str(
                    self._encrypted_action(queued.action_type, action_id)
                )
                try:
                    response = await asyncio.wait_for(response_future, ACTION_TIMEOUT)
                except TimeoutError as err:
                    timeout_failure = RemootioTimeoutError(
                        f"{queued.action_type.value} response timed out"
                    )
                    if not queued.result.done():
                        queued.result.set_exception(timeout_failure)
                    raise timeout_failure from err

                if not response.success:
                    rejection = RemootioCommandRejectedError(
                        response.action_type, response.error_code
                    )
                    if not queued.result.done():
                        queued.result.set_exception(rejection)
                    continue
                if response.action_type is ActionType.QUERY:
                    self._event_tracker.observe_query(response.uptime_100ms)
                    self._state_callback(response.state, response.uptime_100ms)
                if not queued.result.done():
                    queued.result.set_result(response)
            finally:
                self._pending = None
                if queued.action_type is ActionType.QUERY:
                    self._reconcile_queued = False

    async def _ping(self, websocket: WebSocketLike) -> None:
        self._pong_waiter = asyncio.get_running_loop().create_future()
        await websocket.send_str('{"type":"PING"}')
        try:
            await asyncio.wait_for(self._pong_waiter, PONG_TIMEOUT)
        except TimeoutError as err:
            raise RemootioTimeoutError("PONG response timed out") from err
        finally:
            self._pong_waiter = None

    async def _receive_basic(
        self, websocket: WebSocketLike, timeout: float
    ) -> dict[str, Any]:
        frame = await self._receive_frame(websocket, timeout)
        self._raise_basic_error(frame)
        return frame

    async def _receive_frame(
        self, websocket: WebSocketLike, timeout: float | None
    ) -> dict[str, Any]:
        try:
            if timeout is None:
                message = await websocket.receive()
            else:
                message = await asyncio.wait_for(websocket.receive(), timeout)
        except TimeoutError as err:
            raise RemootioTimeoutError("device response timed out") from err
        except (ClientError, OSError) as err:
            raise RemootioDisconnectedError("WebSocket receive failed") from err

        message_type = getattr(message, "type", None)
        if message_type == WSMsgType.TEXT:
            return parse_json_object(message.data)
        if message_type in {
            WSMsgType.CLOSE,
            WSMsgType.CLOSING,
            WSMsgType.CLOSED,
            WSMsgType.ERROR,
        }:
            raise RemootioDisconnectedError("device closed the WebSocket")
        raise RemootioProtocolError("device sent a non-text WebSocket frame")

    def _decrypt_session_frame(self, frame: dict[str, Any]) -> dict[str, Any]:
        if frame.get("type") != "ENCRYPTED" or self._session_key is None:
            raise RemootioProtocolError("expected encrypted session frame")
        return decrypt_frame(frame, self._session_key, self._auth_key)

    def _encrypted_action(self, action_type: ActionType, action_id: int) -> str:
        if self._session_key is None:
            raise RemootioNotReadyError("session key is unavailable")
        frame = encrypt_frame(
            build_action(action_type, action_id), self._session_key, self._auth_key
        )
        return compact_json(frame)

    def _advance_action_id(self) -> int:
        if self._last_action_id is None:
            raise RemootioNotReadyError("action counter is unavailable")
        self._last_action_id = next_action_id(self._last_action_id)
        return self._last_action_id

    def _process_event(self, event: DeviceEvent) -> None:
        accepted, gap = self._event_tracker.accept(event)
        if not accepted:
            return
        if event.event_type == "StateChange":
            self._state_callback(event.state, event.uptime_100ms)
        if gap:
            self._queue_reconciliation()

    def _queue_reconciliation(self) -> None:
        if self._reconcile_queued or not self._available:
            return
        self._reconcile_queued = True
        future: asyncio.Future[ActionResponse] = (
            asyncio.get_running_loop().create_future()
        )
        future.add_done_callback(_consume_future_exception)
        self._queue.put_nowait(_QueuedAction(ActionType.QUERY, future))

    @staticmethod
    def _validate_correlation(
        response: ActionResponse, expected_type: ActionType, expected_id: int
    ) -> None:
        if (
            response.action_type is not expected_type
            or response.action_id != expected_id
        ):
            raise RemootioProtocolError("action response correlation mismatch")

    @staticmethod
    def _raise_basic_error(frame: dict[str, Any]) -> None:
        if frame.get("type") != "ERROR":
            return
        if set(frame) != {"type", "errorMessage"} or not isinstance(
            frame.get("errorMessage"), str
        ):
            raise RemootioProtocolError("malformed ERROR frame")
        if frame["errorMessage"] == "authentication error":
            raise RemootioAuthenticationError("Remootio authentication failed")
        raise RemootioProtocolError(f"device error: {frame['errorMessage']}")

    def _set_available(self, available: bool) -> None:
        if self._available == available:
            return
        self._available = available
        self._availability_callback(available)

    def _fail_actions(self, error: RemootioError) -> None:
        pending = self._pending
        if pending is not None:
            if not pending.response.done():
                pending.response.cancel()
            if not pending.result.done():
                pending.result.set_exception(error)
        self._pending = None
        pong = self._pong_waiter
        if pong is not None and not pong.done():
            pong.set_exception(error)
        self._pong_waiter = None
        while not self._queue.empty():
            with suppress(asyncio.QueueEmpty):
                queued = self._queue.get_nowait()
                if not queued.result.done():
                    queued.result.set_exception(error)
        self._reconcile_queued = False


async def async_probe_device(
    session: ClientSession,
    host: str,
    api_secret_key: str,
    api_auth_key: str,
    *,
    port: int = 8080,
    expected_serial: str | None = None,
) -> ProbeResult:
    """Run the bounded non-triggering connection probe used by config flows."""
    client = RemootioClient(
        session,
        host,
        api_secret_key,
        api_auth_key,
        port=port,
        expected_serial=expected_serial,
    )
    return await client.async_probe()


def _consume_future_exception(future: asyncio.Future[Any]) -> None:
    """Retrieve an internal action exception to avoid an asyncio warning."""
    if future.cancelled():
        return
    with suppress(Exception):
        future.result()
