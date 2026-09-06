"""Stateless button platform for Remootio relay triggers."""

from __future__ import annotations

from homeassistant.components.button import ButtonEntity
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

from .coordinator import RemootioConfigEntry, RemootioCoordinator
from .entity import RemootioEntity
from .protocol import ActionType

PARALLEL_UPDATES = 0


async def async_setup_entry(
    hass: HomeAssistant,
    entry: RemootioConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    """Set up only relay controls whose capability is known."""
    coordinator = entry.runtime_data
    entities: list[ButtonEntity] = []
    if coordinator.data.sensor_present is False:
        entities.append(RemootioPrimaryTriggerButton(coordinator))
    if coordinator.secondary_relay_enabled:
        entities.append(RemootioSecondaryRelayButton(coordinator))
    async_add_entities(entities)


class RemootioPrimaryTriggerButton(RemootioEntity, ButtonEntity):
    """Operate the primary relay on a device without a status sensor."""

    _attr_translation_key = "primary_trigger"

    def __init__(self, coordinator: RemootioCoordinator) -> None:
        """Initialize the primary trigger."""
        super().__init__(coordinator, "primary_trigger")

    @property
    def available(self) -> bool:
        """Return availability only while no status sensor is reported."""
        return super().available and self.coordinator.data.sensor_present is False

    async def async_press(self) -> None:
        """Pulse the primary output without asserting a resulting state."""
        await self._async_execute(ActionType.TRIGGER)


class RemootioSecondaryRelayButton(RemootioEntity, ButtonEntity):
    """Operate a user-declared secondary free relay."""

    _attr_translation_key = "secondary_relay"

    def __init__(self, coordinator: RemootioCoordinator) -> None:
        """Initialize the secondary relay button."""
        super().__init__(coordinator, "secondary_relay")

    async def async_press(self) -> None:
        """Pulse the secondary free relay."""
        await self._async_execute(ActionType.TRIGGER_SECONDARY)
