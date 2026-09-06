"""Tests for Remootio setup, discovery, reauth, and reconfiguration."""

from __future__ import annotations

import ipaddress
from unittest.mock import AsyncMock, patch

import pytest
import voluptuous as vol
import voluptuous_serialize
from homeassistant.config_entries import (
    SOURCE_REAUTH,
    SOURCE_RECONFIGURE,
    SOURCE_USER,
)
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResultType
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.service_info.zeroconf import ZeroconfServiceInfo
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.remootio.config_flow import _api_key, _host
from custom_components.remootio.const import DOMAIN
from custom_components.remootio.protocol import (
    RemootioAuthenticationError,
    RemootioConnectionError,
    RemootioIdentityError,
    RemootioProtocolError,
)

from .helpers import AUTH_HEX, ENTRY_DATA, SECRET_HEX, SERIAL, probe_result

USER_INPUT = {
    "host": "remootio.local",
    "port": 8080,
    "api_secret_key": SECRET_HEX,
    "api_auth_key": AUTH_HEX,
}


@pytest.fixture(autouse=True)
def prevent_entry_setup() -> object:
    """Keep config-flow tests read-only after Home Assistant creates an entry."""
    with patch(
        "custom_components.remootio.async_setup_entry",
        new=AsyncMock(return_value=True),
    ) as setup_entry:
        yield setup_entry


async def test_user_setup_remootio_2_declares_secondary(
    hass: HomeAssistant,
) -> None:
    """A Remootio 2 asks the user about its non-queryable output mode."""
    with patch(
        "custom_components.remootio.config_flow.async_probe_device",
        new=AsyncMock(return_value=probe_result()),
    ) as probe:
        result = await hass.config_entries.flow.async_init(
            DOMAIN, context={"source": SOURCE_USER}
        )
        assert result["type"] is FlowResultType.FORM
        result = await hass.config_entries.flow.async_configure(
            result["flow_id"], USER_INPUT
        )
        assert result["step_id"] == "secondary_relay"
        result = await hass.config_entries.flow.async_configure(
            result["flow_id"], {"secondary_relay": True}
        )

    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert result["title"] == f"Remootio {SERIAL}"
    assert result["data"]["serial_number"] == SERIAL
    assert result["data"]["secondary_relay"] is True
    assert probe.await_args.kwargs["expected_serial"] is None


async def test_user_form_schema_is_frontend_serializable(
    hass: HomeAssistant,
) -> None:
    """The HTTP config-flow API can serialize every initial form field."""
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": SOURCE_USER}
    )

    serialized = voluptuous_serialize.convert(
        result["data_schema"], custom_serializer=cv.custom_serializer
    )

    assert {field["name"] for field in serialized} == {
        "host",
        "port",
        "api_secret_key",
        "api_auth_key",
    }
    secret_field = next(
        field for field in serialized if field["name"] == "api_secret_key"
    )
    assert secret_field["selector"]["text"]["type"] == "password"


async def test_user_input_validation_returns_field_errors_before_probe(
    hass: HomeAssistant,
) -> None:
    """Strict non-serializable rules run after the UI submits its form."""
    with patch(
        "custom_components.remootio.config_flow.async_probe_device",
        new=AsyncMock(),
    ) as probe:
        result = await hass.config_entries.flow.async_init(
            DOMAIN,
            context={"source": SOURCE_USER},
            data={**USER_INPUT, "host": "ws://bad", "api_secret_key": "short"},
        )

    assert result["type"] is FlowResultType.FORM
    assert result["errors"] == {
        "host": "invalid_host",
        "api_secret_key": "invalid_key",
    }
    probe.assert_not_awaited()


async def test_user_setup_remootio_1_skips_secondary(
    hass: HomeAssistant,
) -> None:
    """A Remootio 1 cannot expose a secondary relay declaration."""
    with patch(
        "custom_components.remootio.config_flow.async_probe_device",
        new=AsyncMock(return_value=probe_result(model="remootio-1")),
    ):
        result = await hass.config_entries.flow.async_init(
            DOMAIN, context={"source": SOURCE_USER}, data=USER_INPUT
        )

    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert result["data"]["secondary_relay"] is False


@pytest.mark.parametrize(
    ("error", "reason"),
    [
        (RemootioAuthenticationError("bad"), "invalid_auth"),
        (RemootioConnectionError("offline"), "cannot_connect"),
        (RemootioProtocolError("bad frame"), "invalid_response"),
    ],
)
async def test_user_setup_errors(
    hass: HomeAssistant, error: Exception, reason: str
) -> None:
    """Transport failure classes map to actionable form errors."""
    with patch(
        "custom_components.remootio.config_flow.async_probe_device",
        new=AsyncMock(side_effect=error),
    ):
        result = await hass.config_entries.flow.async_init(
            DOMAIN, context={"source": SOURCE_USER}, data=USER_INPUT
        )

    assert result["type"] is FlowResultType.FORM
    assert result["errors"] == {"base": reason}


async def test_discovery_confirms_credentials_and_serial(
    hass: HomeAssistant,
) -> None:
    """mDNS supplies routing/identity while the user supplies credentials."""
    discovery = ZeroconfServiceInfo(
        ip_address=ipaddress.ip_address("192.0.2.10"),
        ip_addresses=[ipaddress.ip_address("192.0.2.10")],
        port=8080,
        hostname="remootio.local.",
        type="_remootio._tcp.local.",
        name=f"{SERIAL}._remootio._tcp.local.",
        properties={},
    )
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": "zeroconf"}, data=discovery
    )
    assert result["type"] is FlowResultType.FORM
    assert result["step_id"] == "zeroconf_confirm"

    with patch(
        "custom_components.remootio.config_flow.async_probe_device",
        new=AsyncMock(return_value=probe_result()),
    ) as probe:
        result = await hass.config_entries.flow.async_configure(
            result["flow_id"],
            {"api_secret_key": SECRET_HEX, "api_auth_key": AUTH_HEX},
        )
        result = await hass.config_entries.flow.async_configure(
            result["flow_id"], {"secondary_relay": False}
        )

    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert result["data"]["host"] == "192.0.2.10"
    assert probe.await_args.kwargs["expected_serial"] == SERIAL


async def test_discovery_updates_existing_host(hass: HomeAssistant) -> None:
    """A known serial discovered at a new address updates routing and aborts."""
    entry = MockConfigEntry(
        domain=DOMAIN,
        unique_id=SERIAL,
        data={**ENTRY_DATA, "host": "old.local"},
    )
    entry.add_to_hass(hass)
    discovery = ZeroconfServiceInfo(
        ip_address=ipaddress.ip_address("192.0.2.11"),
        ip_addresses=[ipaddress.ip_address("192.0.2.11")],
        port=None,
        hostname="new.local.",
        type="_remootio._tcp.local.",
        name=f"{SERIAL}._remootio._tcp.local.",
        properties={},
    )

    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": "zeroconf"}, data=discovery
    )

    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "already_configured"
    assert entry.data["host"] == "192.0.2.11"
    assert entry.data["port"] == 8080


async def test_discovery_wrong_device(hass: HomeAssistant) -> None:
    """A discovery response cannot silently bind to another serial number."""
    discovery = ZeroconfServiceInfo(
        ip_address=ipaddress.ip_address("192.0.2.10"),
        ip_addresses=[ipaddress.ip_address("192.0.2.10")],
        port=8080,
        hostname="remootio.local.",
        type="_remootio._tcp.local.",
        name=f"{SERIAL}._remootio._tcp.local.",
        properties={},
    )
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": "zeroconf"}, data=discovery
    )
    with patch(
        "custom_components.remootio.config_flow.async_probe_device",
        new=AsyncMock(side_effect=RemootioIdentityError("wrong")),
    ):
        result = await hass.config_entries.flow.async_configure(
            result["flow_id"],
            {"api_secret_key": SECRET_HEX, "api_auth_key": AUTH_HEX},
        )
    assert result["errors"] == {"base": "wrong_device"}


async def test_reauth_updates_only_credentials(hass: HomeAssistant) -> None:
    """Reauthentication verifies the serial and preserves routing settings."""
    entry = MockConfigEntry(domain=DOMAIN, unique_id=SERIAL, data=ENTRY_DATA)
    entry.add_to_hass(hass)
    new_secret = "33" * 32
    new_auth = "44" * 32
    with patch(
        "custom_components.remootio.config_flow.async_probe_device",
        new=AsyncMock(return_value=probe_result()),
    ):
        result = await hass.config_entries.flow.async_init(
            DOMAIN,
            context={"source": SOURCE_REAUTH, "entry_id": entry.entry_id},
            data=entry.data,
        )
        result = await hass.config_entries.flow.async_configure(
            result["flow_id"],
            {"api_secret_key": new_secret, "api_auth_key": new_auth},
        )

    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "reauth_successful"
    assert entry.data["api_secret_key"] == new_secret
    assert entry.data["api_auth_key"] == new_auth
    assert entry.data["host"] == ENTRY_DATA["host"]


async def test_reconfigure_model_gates_secondary(hass: HomeAssistant) -> None:
    """Reconfigure exposes output 2 only on hardware that can support it."""
    entry = MockConfigEntry(
        domain=DOMAIN,
        unique_id=SERIAL,
        data={**ENTRY_DATA, "model": "remootio-1", "secondary_relay": True},
    )
    entry.add_to_hass(hass)
    with patch(
        "custom_components.remootio.config_flow.async_probe_device",
        new=AsyncMock(return_value=probe_result(model="remootio-1")),
    ):
        result = await hass.config_entries.flow.async_init(
            DOMAIN,
            context={"source": SOURCE_RECONFIGURE, "entry_id": entry.entry_id},
        )
        assert "secondary_relay" not in result["data_schema"].schema
        result = await hass.config_entries.flow.async_configure(
            result["flow_id"], {"host": "new.local", "port": 8081}
        )

    assert result["type"] is FlowResultType.ABORT
    assert entry.data["host"] == "new.local"
    assert entry.data["secondary_relay"] is False


def test_input_validators_reject_ambiguous_hosts_and_keys() -> None:
    """Do not accept URLs, paths, whitespace, or malformed API keys."""
    assert _host(" remootio.local. ") == "remootio.local"
    assert _api_key(SECRET_HEX) == SECRET_HEX
    for host in (1, "", "ws://host", "host/path", "two words"):
        with pytest.raises(vol.Invalid):
            _host(host)
    for key in (1, "short"):
        with pytest.raises(vol.Invalid):
            _api_key(key)


async def test_empty_discovery_name_aborts(hass: HomeAssistant) -> None:
    """Ignore malformed mDNS records without a serial-number instance name."""
    discovery = ZeroconfServiceInfo(
        ip_address=ipaddress.ip_address("192.0.2.10"),
        ip_addresses=[ipaddress.ip_address("192.0.2.10")],
        port=8080,
        hostname="remootio.local.",
        type="_remootio._tcp.local.",
        name="._remootio._tcp.local.",
        properties={},
    )
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": "zeroconf"}, data=discovery
    )
    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "invalid_discovery"


@pytest.mark.parametrize(
    ("source", "error", "reason"),
    [
        (SOURCE_REAUTH, RemootioAuthenticationError("bad"), "invalid_auth"),
        (SOURCE_REAUTH, RemootioIdentityError("wrong"), "wrong_device"),
        (SOURCE_REAUTH, RemootioConnectionError("offline"), "cannot_connect"),
        (SOURCE_REAUTH, RemootioProtocolError("frame"), "invalid_response"),
        (SOURCE_RECONFIGURE, RemootioAuthenticationError("bad"), "invalid_auth"),
        (SOURCE_RECONFIGURE, RemootioIdentityError("wrong"), "wrong_device"),
        (SOURCE_RECONFIGURE, RemootioConnectionError("offline"), "cannot_connect"),
        (SOURCE_RECONFIGURE, RemootioProtocolError("frame"), "invalid_response"),
    ],
)
async def test_existing_entry_flow_errors(
    hass: HomeAssistant, source: str, error: Exception, reason: str
) -> None:
    """Reauth and reconfigure retain their form with classified failures."""
    entry = MockConfigEntry(domain=DOMAIN, unique_id=SERIAL, data=ENTRY_DATA)
    entry.add_to_hass(hass)
    context = {"source": source, "entry_id": entry.entry_id}
    initial_data = entry.data if source == SOURCE_REAUTH else None
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context=context, data=initial_data
    )
    user_input = (
        {"api_secret_key": SECRET_HEX, "api_auth_key": AUTH_HEX}
        if source == SOURCE_REAUTH
        else {
            "host": ENTRY_DATA["host"],
            "port": ENTRY_DATA["port"],
            "secondary_relay": False,
        }
    )
    with patch(
        "custom_components.remootio.config_flow.async_probe_device",
        new=AsyncMock(side_effect=error),
    ):
        result = await hass.config_entries.flow.async_configure(
            result["flow_id"], user_input
        )
    assert result["type"] is FlowResultType.FORM
    assert result["errors"] == {"base": reason}


async def test_reconfigure_remootio_2_exposes_secondary(
    hass: HomeAssistant,
) -> None:
    """Remootio 2 reconfiguration retains the explicit output-2 declaration."""
    entry = MockConfigEntry(domain=DOMAIN, unique_id=SERIAL, data=ENTRY_DATA)
    entry.add_to_hass(hass)
    result = await hass.config_entries.flow.async_init(
        DOMAIN,
        context={"source": SOURCE_RECONFIGURE, "entry_id": entry.entry_id},
    )
    assert any(
        marker.schema == "secondary_relay" for marker in result["data_schema"].schema
    )
