"""Shared entity support for Remootio."""

from __future__ import annotations

from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .coordinator import RemootioCoordinator
from .protocol import (
    ActionType,
    RemootioCommandRejectedError,
    RemootioError,
)


class RemootioEntity(CoordinatorEntity[RemootioCoordinator]):
    """Base class for entities belonging to one Remootio controller."""

    _attr_has_entity_name = True

    def __init__(self, coordinator: RemootioCoordinator, suffix: str) -> None:
        """Initialize a stable serial-number entity."""
        super().__init__(coordinator)
        serial = coordinator.data.serial_number
        if serial is None:
            raise RuntimeError("Remootio serial number is unavailable")
        self._attr_unique_id = f"{serial}_{suffix}"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, serial)},
            manufacturer="Remootio",
            model=coordinator.data.model,
            name=coordinator.entry.title,
            serial_number=serial,
        )

    @property
    def available(self) -> bool:
        """Return true only while the authenticated connection is healthy."""
        return super().available and self.coordinator.data.available

    async def _async_execute(self, action_type: ActionType) -> None:
        """Translate protocol failures into visible Home Assistant action errors."""
        try:
            await self.coordinator.async_execute(action_type)
        except RemootioCommandRejectedError as err:
            raise HomeAssistantError(
                translation_domain=DOMAIN,
                translation_key="command_rejected",
                translation_placeholders={
                    "command": err.action_type.value,
                    "error": err.error_code,
                },
            ) from err
        except RemootioError as err:
            raise HomeAssistantError(
                translation_domain=DOMAIN,
                translation_key="command_failed",
                translation_placeholders={"command": action_type.value},
            ) from err
