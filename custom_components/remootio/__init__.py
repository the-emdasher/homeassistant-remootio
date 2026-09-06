"""The Remootio integration."""

from __future__ import annotations

from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed, ConfigEntryNotReady
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .const import PLATFORMS
from .coordinator import RemootioConfigEntry, RemootioCoordinator
from .protocol import RemootioAuthenticationError, RemootioError


async def async_setup_entry(hass: HomeAssistant, entry: RemootioConfigEntry) -> bool:
    """Set up Remootio from a config entry."""
    coordinator = RemootioCoordinator(hass, entry, async_get_clientsession(hass))
    try:
        await coordinator.async_setup()
    except RemootioAuthenticationError as err:
        raise ConfigEntryAuthFailed("Remootio authentication failed") from err
    except RemootioError as err:
        raise ConfigEntryNotReady("Unable to connect to Remootio") from err

    entry.runtime_data = coordinator
    entry.async_on_unload(entry.add_update_listener(_async_reload_entry))
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: RemootioConfigEntry) -> bool:
    """Unload platforms before releasing the one device connection."""
    if not await hass.config_entries.async_unload_platforms(entry, PLATFORMS):
        return False
    await entry.runtime_data.async_shutdown()
    return True


async def _async_reload_entry(hass: HomeAssistant, entry: RemootioConfigEntry) -> None:
    """Reload when config-entry data changes."""
    await hass.config_entries.async_reload(entry.entry_id)
