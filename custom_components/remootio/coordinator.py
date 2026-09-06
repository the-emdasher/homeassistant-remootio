"""Push coordinator for the Remootio integration."""

from __future__ import annotations

import logging
from dataclasses import dataclass, replace

from aiohttp import ClientSession
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator

from .client import ProbeResult, RemootioClient, async_probe_device
from .const import (
    CONF_API_AUTH_KEY,
    CONF_API_SECRET_KEY,
    CONF_MODEL,
    CONF_SECONDARY_RELAY,
    CONF_SERIAL_NUMBER,
    DOMAIN,
)
from .protocol import (
    ActionResponse,
    ActionType,
    DeviceIdentity,
    DoorState,
    RemootioError,
)

_LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class RemootioData:
    """Current runtime data derived only from authoritative protocol sources."""

    available: bool = False
    state: DoorState | None = None
    sensor_present: bool | None = None
    serial_number: str | None = None
    model: str | None = None
    uptime_100ms: int | None = None


type RemootioConfigEntry = ConfigEntry["RemootioCoordinator"]


class RemootioCoordinator(DataUpdateCoordinator[RemootioData]):
    """Bridge the protocol client's push updates into Home Assistant."""

    def __init__(
        self,
        hass: HomeAssistant,
        entry: RemootioConfigEntry,
        session: ClientSession,
    ) -> None:
        """Initialize the coordinator and its one persistent client."""
        super().__init__(
            hass,
            _LOGGER,
            config_entry=entry,
            name=DOMAIN,
        )
        self.entry = entry
        self.data = RemootioData(
            serial_number=entry.unique_id or entry.data.get(CONF_SERIAL_NUMBER),
            model=entry.data.get(CONF_MODEL),
        )
        self._session = session
        self._was_available = False
        self._expected_disconnect = False
        self.client = self._build_client()

    def _build_client(self) -> RemootioClient:
        return RemootioClient(
            self._session,
            self.entry.data["host"],
            self.entry.data[CONF_API_SECRET_KEY],
            self.entry.data[CONF_API_AUTH_KEY],
            port=self.entry.data["port"],
            expected_serial=self.entry.unique_id,
            state_callback=self._handle_state,
            availability_callback=self._handle_availability,
            identity_callback=self._handle_identity,
            auth_failure_callback=self._handle_auth_failure,
        )

    async def async_setup(self) -> ProbeResult:
        """Connect, authenticate, and obtain initial authoritative state."""
        return await self.client.async_start()

    async def async_shutdown(self) -> None:
        """Close the connection and cancel all client work."""
        self._expected_disconnect = True
        await self.client.async_stop()

    async def async_execute(self, action_type: ActionType) -> ActionResponse:
        """Execute an action through the client's serialized queue."""
        return await self.client.async_execute(action_type)

    async def async_validate_candidate(
        self,
        host: str,
        port: int,
        api_secret_key: str,
        api_auth_key: str,
    ) -> ProbeResult:
        """Validate reconfiguration without violating the one-connection limit."""
        self._expected_disconnect = True
        await self.client.async_stop()
        try:
            return await async_probe_device(
                self._session,
                host,
                api_secret_key,
                api_auth_key,
                port=port,
                expected_serial=self.entry.unique_id,
            )
        finally:
            # Restore the current entry until Home Assistant applies and reloads
            # the candidate configuration. Failure leaves entities unavailable.
            try:
                await self.client.async_start()
            except RemootioError:
                _LOGGER.warning(
                    "Unable to restore the existing Remootio connection after "
                    "validation"
                )
            finally:
                self._expected_disconnect = False

    @callback
    def _handle_state(self, state: DoorState, uptime_100ms: int) -> None:
        sensor_present = state is not DoorState.NO_SENSOR
        authoritative_state = state if sensor_present else None
        self.async_set_updated_data(
            replace(
                self.data,
                state=authoritative_state,
                sensor_present=sensor_present,
                uptime_100ms=uptime_100ms,
            )
        )

    @callback
    def _handle_availability(self, available: bool) -> None:
        if available != self._was_available:
            if not self._expected_disconnect:
                if available:
                    _LOGGER.info("Reconnected to Remootio at %s", self.client.host)
                elif self._was_available:
                    _LOGGER.warning("Remootio at %s is unavailable", self.client.host)
            self._was_available = available
        self.async_set_updated_data(replace(self.data, available=available))

    @callback
    def _handle_identity(self, identity: DeviceIdentity) -> None:
        self.async_set_updated_data(
            replace(
                self.data,
                serial_number=identity.serial_number,
                model=identity.model,
            )
        )

    @callback
    def _handle_auth_failure(self) -> None:
        self.entry.async_start_reauth(self.hass)

    @property
    def secondary_relay_enabled(self) -> bool:
        """Return the user's explicit secondary free-relay declaration."""
        return bool(self.entry.data.get(CONF_SECONDARY_RELAY, False))
