"""Cover platform for sensor-equipped Remootio devices."""

from __future__ import annotations

from typing import Any

from homeassistant.components.cover import (
    CoverDeviceClass,
    CoverEntity,
    CoverEntityFeature,
)
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddConfigEntryEntitiesCallback

from .coordinator import RemootioConfigEntry, RemootioCoordinator
from .entity import RemootioEntity
from .protocol import ActionType, DoorState

PARALLEL_UPDATES = 0


async def async_setup_entry(
    hass: HomeAssistant,
    entry: RemootioConfigEntry,
    async_add_entities: AddConfigEntryEntitiesCallback,
) -> None:
    """Set up a cover only when QUERY reports a status sensor."""
    coordinator = entry.runtime_data
    if coordinator.data.sensor_present:
        async_add_entities([RemootioCover(coordinator)])


class RemootioCover(RemootioEntity, CoverEntity):
    """A binary garage/gate cover backed by authoritative Remootio state."""

    _attr_device_class = CoverDeviceClass.GARAGE
    _attr_supported_features = CoverEntityFeature.OPEN | CoverEntityFeature.CLOSE
    _attr_translation_key = "door"

    def __init__(self, coordinator: RemootioCoordinator) -> None:
        """Initialize the cover."""
        super().__init__(coordinator, "door")

    @property
    def available(self) -> bool:
        """Return availability only for a sensor-equipped device."""
        return super().available and self.coordinator.data.sensor_present is True

    @property
    def is_closed(self) -> bool | None:
        """Return the last authoritative open/closed state."""
        state = self.coordinator.data.state
        if state is None:
            return None
        return state is DoorState.CLOSED

    async def async_open_cover(self, **kwargs: Any) -> None:
        """Ask Remootio to pulse its relay only if its sensor reports closed."""
        await self._async_execute(ActionType.OPEN)

    async def async_close_cover(self, **kwargs: Any) -> None:
        """Ask Remootio to pulse its relay only if its sensor reports open."""
        await self._async_execute(ActionType.CLOSE)
