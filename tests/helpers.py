"""Shared deterministic data and runtime client for Home Assistant tests."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, ClassVar

from custom_components.remootio.client import ProbeResult
from custom_components.remootio.protocol import (
    ActionResponse,
    ActionType,
    DeviceIdentity,
    DoorState,
    RemootioError,
)

SECRET_HEX = "11" * 32
AUTH_HEX = "22" * 32
SERIAL = "abc123"

ENTRY_DATA: dict[str, Any] = {
    "host": "remootio.local",
    "port": 8080,
    "api_secret_key": SECRET_HEX,
    "api_auth_key": AUTH_HEX,
    "serial_number": SERIAL,
    "model": "remootio-2",
    "secondary_relay": False,
}


def probe_result(
    *,
    state: DoorState = DoorState.CLOSED,
    model: str = "remootio-2",
    serial: str = SERIAL,
) -> ProbeResult:
    """Build a deterministic successful probe."""
    return ProbeResult(DeviceIdentity(serial, model, 3), state, 100)


class FakeRuntimeClient:
    """In-memory replacement for the transport at the HA boundary."""

    instances: ClassVar[list[FakeRuntimeClient]] = []
    startup_state: ClassVar[DoorState] = DoorState.CLOSED
    startup_model: ClassVar[str] = "remootio-2"
    startup_error: ClassVar[RemootioError | None] = None

    def __init__(
        self,
        session: Any,
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
        self.host = host
        self.port = port
        self.expected_serial = expected_serial
        self.state_callback = state_callback or (lambda _state, _uptime: None)
        self.availability_callback = availability_callback or (lambda _available: None)
        self.identity_callback = identity_callback or (lambda _identity: None)
        self.auth_failure_callback = auth_failure_callback or (lambda: None)
        self.actions: list[ActionType] = []
        self.stopped = False
        type(self).instances.append(self)

    async def async_start(self) -> ProbeResult:
        """Publish the same identity/state ordering as a real handshake."""
        if self.startup_error is not None:
            raise self.startup_error
        self.stopped = False
        identity = DeviceIdentity(SERIAL, self.startup_model, 3)
        self.identity_callback(identity)
        self.state_callback(self.startup_state, 100)
        self.availability_callback(True)
        return ProbeResult(identity, self.startup_state, 100)

    async def async_stop(self) -> None:
        """Mark this fake stopped and publish unavailability."""
        self.stopped = True
        self.availability_callback(False)

    async def async_execute(self, action_type: ActionType) -> ActionResponse:
        """Record an action and return a matching success."""
        self.actions.append(action_type)
        return ActionResponse(
            action_type,
            len(self.actions),
            True,
            self.startup_state,
            100,
            True,
            "",
        )

    @classmethod
    def reset(cls) -> None:
        """Reset class-controlled behavior between tests."""
        cls.instances.clear()
        cls.startup_state = DoorState.CLOSED
        cls.startup_model = "remootio-2"
        cls.startup_error = None
