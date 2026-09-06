"""Real Home Assistant lifecycle and entity tests for Remootio."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest
from homeassistant.components.button import DOMAIN as BUTTON_DOMAIN
from homeassistant.components.cover import DOMAIN as COVER_DOMAIN
from homeassistant.const import ATTR_ENTITY_ID, STATE_CLOSED, STATE_UNAVAILABLE
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import (
    ConfigEntryAuthFailed,
    ConfigEntryNotReady,
    HomeAssistantError,
)
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers import entity_registry as er
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.remootio import (
    _async_reload_entry,
    async_setup_entry,
    async_unload_entry,
)
from custom_components.remootio.const import DOMAIN
from custom_components.remootio.cover import RemootioCover
from custom_components.remootio.protocol import (
    ActionType,
    DoorState,
    RemootioAuthenticationError,
    RemootioCommandRejectedError,
    RemootioConnectionError,
)

from .helpers import ENTRY_DATA, SERIAL, FakeRuntimeClient
from .helpers import probe_result as make_probe_result


@pytest.fixture(autouse=True)
def reset_fake_client() -> None:
    """Reset deterministic client behavior for every integration test."""
    FakeRuntimeClient.reset()


async def _setup_entry(
    hass: HomeAssistant, *, data: dict[str, object] | None = None
) -> MockConfigEntry:
    entry = MockConfigEntry(
        domain=DOMAIN,
        title=f"Remootio {SERIAL}",
        unique_id=SERIAL,
        data=data or ENTRY_DATA,
    )
    entry.add_to_hass(hass)
    with patch(
        "custom_components.remootio.coordinator.RemootioClient",
        FakeRuntimeClient,
    ):
        assert await hass.config_entries.async_setup(entry.entry_id)
        await hass.async_block_till_done()
    return entry


def _entity_id(hass: HomeAssistant, platform: str, unique_id: str) -> str:
    entity_id = er.async_get(hass).async_get_entity_id(platform, DOMAIN, unique_id)
    assert entity_id is not None
    return entity_id


async def test_sensor_device_creates_cover_and_executes_conditioned_actions(
    hass: HomeAssistant,
) -> None:
    """A status sensor creates a cover whose open/close calls stay distinct."""
    entry = await _setup_entry(hass)
    entity_id = _entity_id(hass, COVER_DOMAIN, f"{SERIAL}_door")
    assert hass.states.get(entity_id).state == STATE_CLOSED
    assert (
        er.async_get(hass).async_get_entity_id(
            BUTTON_DOMAIN, DOMAIN, f"{SERIAL}_primary_trigger"
        )
        is None
    )

    await hass.services.async_call(
        COVER_DOMAIN, "open_cover", {ATTR_ENTITY_ID: entity_id}, blocking=True
    )
    await hass.services.async_call(
        COVER_DOMAIN, "close_cover", {ATTR_ENTITY_ID: entity_id}, blocking=True
    )
    assert FakeRuntimeClient.instances[-1].actions == [
        ActionType.OPEN,
        ActionType.CLOSE,
    ]

    device_entry = dr.async_get(hass).async_get_device_by_identifier(
        (DOMAIN, SERIAL), entry.entry_id
    )
    assert device_entry is not None
    assert device_entry.manufacturer == "Remootio"
    assert device_entry.serial_number == SERIAL
    assert await hass.config_entries.async_unload(entry.entry_id)
    assert FakeRuntimeClient.instances[-1].stopped


async def test_no_sensor_device_creates_stateless_trigger_button(
    hass: HomeAssistant,
) -> None:
    """No-sensor mode never fabricates an open/closed cover state."""
    FakeRuntimeClient.startup_state = DoorState.NO_SENSOR
    entry = await _setup_entry(hass)
    assert (
        er.async_get(hass).async_get_entity_id(COVER_DOMAIN, DOMAIN, f"{SERIAL}_door")
        is None
    )
    entity_id = _entity_id(hass, BUTTON_DOMAIN, f"{SERIAL}_primary_trigger")

    await hass.services.async_call(
        BUTTON_DOMAIN, "press", {ATTR_ENTITY_ID: entity_id}, blocking=True
    )
    assert FakeRuntimeClient.instances[-1].actions == [ActionType.TRIGGER]
    await hass.config_entries.async_unload(entry.entry_id)


async def test_declared_secondary_relay_creates_separate_button(
    hass: HomeAssistant,
) -> None:
    """The user-declared free relay gets its own stateless button."""
    entry = await _setup_entry(hass, data={**ENTRY_DATA, "secondary_relay": True})
    entity_id = _entity_id(hass, BUTTON_DOMAIN, f"{SERIAL}_secondary_relay")
    await hass.services.async_call(
        BUTTON_DOMAIN, "press", {ATTR_ENTITY_ID: entity_id}, blocking=True
    )
    assert FakeRuntimeClient.instances[-1].actions == [ActionType.TRIGGER_SECONDARY]
    await hass.config_entries.async_unload(entry.entry_id)


async def test_connection_availability_does_not_overwrite_last_state(
    hass: HomeAssistant,
) -> None:
    """Disconnect marks unavailable and preserves the last authoritative state."""
    entry = await _setup_entry(hass)
    entity_id = _entity_id(hass, COVER_DOMAIN, f"{SERIAL}_door")
    client = FakeRuntimeClient.instances[-1]
    client.availability_callback(False)
    await hass.async_block_till_done()
    assert hass.states.get(entity_id).state == STATE_UNAVAILABLE
    assert entry.runtime_data.data.state is DoorState.CLOSED

    client.availability_callback(True)
    await hass.async_block_till_done()
    assert hass.states.get(entity_id).state == STATE_CLOSED
    await hass.config_entries.async_unload(entry.entry_id)


async def test_action_rejection_surfaces_as_home_assistant_error(
    hass: HomeAssistant,
) -> None:
    """A device rejection is never reported to Home Assistant as success."""
    entry = await _setup_entry(hass)
    entity_id = _entity_id(hass, COVER_DOMAIN, f"{SERIAL}_door")
    entry.runtime_data.async_execute = AsyncMock(
        side_effect=RemootioCommandRejectedError(ActionType.OPEN, "ERR_BUSY")
    )
    with pytest.raises(HomeAssistantError):
        await hass.services.async_call(
            COVER_DOMAIN,
            "open_cover",
            {ATTR_ENTITY_ID: entity_id},
            blocking=True,
        )
    await hass.config_entries.async_unload(entry.entry_id)


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (RemootioAuthenticationError("bad key"), ConfigEntryAuthFailed),
        (RemootioConnectionError("offline"), ConfigEntryNotReady),
    ],
)
async def test_setup_maps_transport_failures(
    hass: HomeAssistant, error: Exception, expected: type[Exception]
) -> None:
    """Initial setup maps auth and reachability to HA lifecycle exceptions."""
    FakeRuntimeClient.startup_error = error  # type: ignore[assignment]
    entry = MockConfigEntry(domain=DOMAIN, unique_id=SERIAL, data=ENTRY_DATA)
    with (
        patch(
            "custom_components.remootio.coordinator.RemootioClient",
            FakeRuntimeClient,
        ),
        pytest.raises(expected),
    ):
        await async_setup_entry(hass, entry)  # type: ignore[arg-type]


async def test_unload_failure_keeps_connection_and_reload_delegates(
    hass: HomeAssistant,
) -> None:
    """A failed platform unload keeps runtime alive; updates request a reload."""
    entry = await _setup_entry(hass)
    coordinator = entry.runtime_data
    with patch.object(
        hass.config_entries,
        "async_unload_platforms",
        new=AsyncMock(return_value=False),
    ):
        assert not await async_unload_entry(hass, entry)  # type: ignore[arg-type]
    assert not coordinator.client.stopped

    with patch.object(
        hass.config_entries, "async_reload", new=AsyncMock()
    ) as reload_entry:
        await _async_reload_entry(hass, entry)  # type: ignore[arg-type]
    reload_entry.assert_awaited_once_with(entry.entry_id)
    await hass.config_entries.async_unload(entry.entry_id)


async def test_candidate_validation_pauses_and_restores_connection(
    hass: HomeAssistant,
) -> None:
    """Reconfiguration probing never creates a second persistent connection."""
    entry = await _setup_entry(hass)
    coordinator = entry.runtime_data
    client = coordinator.client
    with patch(
        "custom_components.remootio.coordinator.async_probe_device",
        new=AsyncMock(return_value=make_probe_result()),
    ) as probe:
        result = await coordinator.async_validate_candidate(
            "new.local", 8081, "33" * 32, "44" * 32
        )
    assert result.identity.serial_number == SERIAL
    assert not client.stopped
    probe.assert_awaited_once()

    with patch.object(type(entry), "async_start_reauth") as start_reauth:
        coordinator._handle_auth_failure()
    start_reauth.assert_called_once_with(hass)
    await hass.config_entries.async_unload(entry.entry_id)


async def test_unknown_cover_state_and_generic_command_failure(
    hass: HomeAssistant,
) -> None:
    """Unknown state stays unknown and communication errors reach the caller."""
    entry = await _setup_entry(hass)
    coordinator = entry.runtime_data
    coordinator.data = coordinator.data.__class__(
        available=True,
        state=None,
        sensor_present=True,
        serial_number=SERIAL,
        model="remootio-2",
        uptime_100ms=100,
    )
    assert RemootioCover(coordinator).is_closed is None

    entity_id = _entity_id(hass, COVER_DOMAIN, f"{SERIAL}_door")
    coordinator.async_execute = AsyncMock(
        side_effect=RemootioConnectionError("disconnected")
    )
    with pytest.raises(HomeAssistantError):
        await hass.services.async_call(
            COVER_DOMAIN,
            "open_cover",
            {ATTR_ENTITY_ID: entity_id},
            blocking=True,
        )
    await hass.config_entries.async_unload(entry.entry_id)
