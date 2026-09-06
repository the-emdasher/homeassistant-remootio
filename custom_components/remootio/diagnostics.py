"""Privacy-preserving diagnostics for Remootio."""

from __future__ import annotations

from typing import Any

from homeassistant.core import HomeAssistant

from .coordinator import RemootioConfigEntry


async def async_get_config_entry_diagnostics(
    hass: HomeAssistant, entry: RemootioConfigEntry
) -> dict[str, Any]:
    """Return an allowlisted report that can never include API credentials."""
    data = entry.runtime_data.data
    return {
        "entry": {
            "title": "**REDACTED**",
            "host": "**REDACTED**",
            "port": entry.data["port"],
            "unique_id": "**REDACTED**",
            "secondary_relay": entry.runtime_data.secondary_relay_enabled,
        },
        "device": {
            "available": data.available,
            "model": data.model,
            "sensor_present": data.sensor_present,
            "state": data.state.value if data.state is not None else None,
            "uptime_100ms": data.uptime_100ms,
        },
    }
