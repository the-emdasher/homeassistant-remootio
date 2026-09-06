"""Tests for credential-safe diagnostics."""

from __future__ import annotations

import json
from unittest.mock import patch

from homeassistant.core import HomeAssistant
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.remootio.const import DOMAIN
from custom_components.remootio.diagnostics import (
    async_get_config_entry_diagnostics,
)

from .helpers import AUTH_HEX, ENTRY_DATA, SECRET_HEX, SERIAL, FakeRuntimeClient


async def test_diagnostics_are_allowlisted_and_json_serializable(
    hass: HomeAssistant,
) -> None:
    """Diagnostics contain useful state but no host, identity, or API key."""
    FakeRuntimeClient.reset()
    entry = MockConfigEntry(
        domain=DOMAIN,
        title=f"Remootio {SERIAL}",
        unique_id=SERIAL,
        data={**ENTRY_DATA, "secondary_relay": True},
    )
    entry.add_to_hass(hass)
    with patch(
        "custom_components.remootio.coordinator.RemootioClient",
        FakeRuntimeClient,
    ):
        assert await hass.config_entries.async_setup(entry.entry_id)
        await hass.async_block_till_done()

    diagnostics = await async_get_config_entry_diagnostics(hass, entry)
    serialized = json.dumps(diagnostics)
    assert diagnostics["entry"]["host"] == "**REDACTED**"
    assert diagnostics["entry"]["title"] == "**REDACTED**"
    assert diagnostics["entry"]["unique_id"] == "**REDACTED**"
    assert diagnostics["device"]["state"] == "closed"
    assert diagnostics["entry"]["secondary_relay"] is True
    assert SECRET_HEX not in serialized
    assert AUTH_HEX not in serialized
    assert ENTRY_DATA["host"] not in serialized
    assert SERIAL not in serialized
    await hass.config_entries.async_unload(entry.entry_id)
