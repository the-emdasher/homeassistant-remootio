"""Config flow for Remootio."""

from __future__ import annotations

from typing import Any

import voluptuous as vol
from homeassistant.config_entries import ConfigFlow, ConfigFlowResult
from homeassistant.const import CONF_HOST, CONF_PORT
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.selector import (
    TextSelector,
    TextSelectorConfig,
    TextSelectorType,
)
from homeassistant.helpers.service_info.zeroconf import ZeroconfServiceInfo

from .client import ProbeResult, async_probe_device
from .const import (
    CONF_API_AUTH_KEY,
    CONF_API_SECRET_KEY,
    CONF_MODEL,
    CONF_SECONDARY_RELAY,
    CONF_SERIAL_NUMBER,
    DEFAULT_PORT,
    DOMAIN,
    MODEL_REMOOTIO_2,
)
from .coordinator import RemootioConfigEntry, RemootioCoordinator
from .protocol import (
    RemootioAuthenticationError,
    RemootioConnectionError,
    RemootioIdentityError,
    RemootioProtocolError,
    decode_hex_key,
)


def _api_key(value: Any) -> str:
    """Voluptuous validator for an exact 32-byte hexadecimal key."""
    if not isinstance(value, str):
        raise vol.Invalid("API key must be text")
    try:
        decode_hex_key(value)
    except RemootioProtocolError as err:
        raise vol.Invalid("API key must be exactly 64 hexadecimal characters") from err
    return value


def _host(value: Any) -> str:
    """Normalize a hostname or IP without accepting a URL or path."""
    if not isinstance(value, str):
        raise vol.Invalid("host must be text")
    normalized = value.strip().rstrip(".")
    if not normalized or "://" in normalized or "/" in normalized or " " in normalized:
        raise vol.Invalid("enter a hostname or IP address without a scheme or path")
    return normalized


API_KEY_SELECTOR = TextSelector(TextSelectorConfig(type=TextSelectorType.PASSWORD))

KEY_SCHEMA = {
    vol.Required(CONF_API_SECRET_KEY): API_KEY_SELECTOR,
    vol.Required(CONF_API_AUTH_KEY): API_KEY_SELECTOR,
}


def _normalize_input(
    user_input: dict[str, Any], *, host: bool = False, keys: bool = False
) -> tuple[dict[str, Any], dict[str, str]]:
    """Apply strict validation that cannot be represented by a UI schema."""
    data = dict(user_input)
    errors: dict[str, str] = {}
    if host:
        try:
            data[CONF_HOST] = _host(data[CONF_HOST])
        except vol.Invalid:
            errors[CONF_HOST] = "invalid_host"
    if keys:
        for field in (CONF_API_SECRET_KEY, CONF_API_AUTH_KEY):
            try:
                data[field] = _api_key(data[field])
            except vol.Invalid:
                errors[field] = "invalid_key"
    return data, errors


class RemootioConfigFlow(ConfigFlow, domain=DOMAIN):
    """Handle setup, discovery, reauthentication, and reconfiguration."""

    VERSION = 1

    def __init__(self) -> None:
        """Initialize transient flow state."""
        self._pending_data: dict[str, Any] | None = None
        self._pending_probe: ProbeResult | None = None
        self._discovery_host: str | None = None
        self._discovery_port = DEFAULT_PORT
        self._discovery_serial: str | None = None

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Handle manual setup."""
        errors: dict[str, str] = {}
        if user_input is not None:
            data, errors = _normalize_input(user_input, host=True, keys=True)
            if not errors:
                try:
                    probe = await self._async_probe(data)
                except RemootioAuthenticationError:
                    errors["base"] = "invalid_auth"
                except RemootioConnectionError:
                    errors["base"] = "cannot_connect"
                except RemootioProtocolError:
                    errors["base"] = "invalid_response"
                else:
                    return await self._async_finish_new_entry(data, probe)

        schema = vol.Schema({
            vol.Required(CONF_HOST): str,
            vol.Required(CONF_PORT, default=DEFAULT_PORT): vol.All(
                vol.Coerce(int), vol.Range(min=1, max=65535)
            ),
            **KEY_SCHEMA,
        })
        return self.async_show_form(step_id="user", data_schema=schema, errors=errors)

    async def async_step_zeroconf(
        self, discovery_info: ZeroconfServiceInfo
    ) -> ConfigFlowResult:
        """Handle `_remootio._tcp.local.` discovery without connecting."""
        serial = discovery_info.name.split("._remootio._tcp.local.", 1)[0].rstrip(".")
        if not serial:
            return self.async_abort(reason="invalid_discovery")
        port = discovery_info.port or DEFAULT_PORT
        await self.async_set_unique_id(serial)
        self._abort_if_unique_id_configured(
            updates={
                CONF_HOST: str(discovery_info.host),
                CONF_PORT: port,
            }
        )
        self._discovery_host = str(discovery_info.host)
        self._discovery_port = port
        self._discovery_serial = serial
        self.context["title_placeholders"] = {"name": f"Remootio {serial}"}
        return await self.async_step_zeroconf_confirm()

    async def async_step_zeroconf_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Collect credentials for a discovered Remootio."""
        if self._discovery_host is None or self._discovery_serial is None:
            return self.async_abort(reason="invalid_discovery")
        errors: dict[str, str] = {}
        if user_input is not None:
            validated, errors = _normalize_input(user_input, keys=True)
            data = {
                CONF_HOST: self._discovery_host,
                CONF_PORT: self._discovery_port,
                **validated,
            }
            if not errors:
                try:
                    probe = await self._async_probe(data, self._discovery_serial)
                except RemootioAuthenticationError:
                    errors["base"] = "invalid_auth"
                except RemootioIdentityError:
                    errors["base"] = "wrong_device"
                except RemootioConnectionError:
                    errors["base"] = "cannot_connect"
                except RemootioProtocolError:
                    errors["base"] = "invalid_response"
                else:
                    return await self._async_finish_new_entry(data, probe)
        return self.async_show_form(
            step_id="zeroconf_confirm",
            data_schema=vol.Schema(KEY_SCHEMA),
            errors=errors,
            description_placeholders={"serial": self._discovery_serial},
        )

    async def _async_finish_new_entry(
        self, data: dict[str, Any], probe: ProbeResult
    ) -> ConfigFlowResult:
        await self.async_set_unique_id(probe.identity.serial_number)
        self._abort_if_unique_id_configured()
        data.update({
            CONF_SERIAL_NUMBER: probe.identity.serial_number,
            CONF_MODEL: probe.identity.model,
        })
        self._pending_data = data
        self._pending_probe = probe
        if probe.identity.model == MODEL_REMOOTIO_2:
            return await self.async_step_secondary_relay()
        data[CONF_SECONDARY_RELAY] = False
        return self.async_create_entry(
            title=f"Remootio {probe.identity.serial_number}", data=data
        )

    async def async_step_secondary_relay(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Collect the only safe source of secondary free-relay capability."""
        if self._pending_data is None or self._pending_probe is None:
            return self.async_abort(reason="invalid_discovery")
        if user_input is not None:
            self._pending_data[CONF_SECONDARY_RELAY] = user_input[CONF_SECONDARY_RELAY]
            return self.async_create_entry(
                title=f"Remootio {self._pending_probe.identity.serial_number}",
                data=self._pending_data,
            )
        return self.async_show_form(
            step_id="secondary_relay",
            data_schema=vol.Schema({
                vol.Required(CONF_SECONDARY_RELAY, default=False): bool
            }),
        )

    async def async_step_reauth(self, entry_data: dict[str, Any]) -> ConfigFlowResult:
        """Start a reauthentication flow."""
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Validate replacement credentials against the same serial number."""
        entry = self._get_reauth_entry()
        errors: dict[str, str] = {}
        if user_input is not None:
            validated, errors = _normalize_input(user_input, keys=True)
            candidate = {**entry.data, **validated}
            if not errors:
                try:
                    probe = await self._async_validate_existing(entry, candidate)
                    await self.async_set_unique_id(probe.identity.serial_number)
                    self._abort_if_unique_id_mismatch()
                except RemootioAuthenticationError:
                    errors["base"] = "invalid_auth"
                except RemootioIdentityError:
                    errors["base"] = "wrong_device"
                except RemootioConnectionError:
                    errors["base"] = "cannot_connect"
                except RemootioProtocolError:
                    errors["base"] = "invalid_response"
                else:
                    return self.async_update_reload_and_abort(
                        entry,
                        data_updates={
                            CONF_API_SECRET_KEY: validated[CONF_API_SECRET_KEY],
                            CONF_API_AUTH_KEY: validated[CONF_API_AUTH_KEY],
                            CONF_MODEL: probe.identity.model,
                        },
                        reason="reauth_successful",
                    )
        return self.async_show_form(
            step_id="reauth_confirm",
            data_schema=vol.Schema(KEY_SCHEMA),
            errors=errors,
        )

    async def async_step_reconfigure(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Update network routing and the declared secondary relay."""
        entry = self._get_reconfigure_entry()
        errors: dict[str, str] = {}
        supports_secondary = entry.data.get(CONF_MODEL) == MODEL_REMOOTIO_2
        if user_input is not None:
            validated, errors = _normalize_input(user_input, host=True)
            candidate = {**entry.data, **validated}
            if not supports_secondary:
                candidate[CONF_SECONDARY_RELAY] = False
            if not errors:
                try:
                    probe = await self._async_validate_existing(entry, candidate)
                    await self.async_set_unique_id(probe.identity.serial_number)
                    self._abort_if_unique_id_mismatch()
                except RemootioAuthenticationError:
                    errors["base"] = "invalid_auth"
                except RemootioIdentityError:
                    errors["base"] = "wrong_device"
                except RemootioConnectionError:
                    errors["base"] = "cannot_connect"
                except RemootioProtocolError:
                    errors["base"] = "invalid_response"
                else:
                    return self.async_update_reload_and_abort(
                        entry,
                        data_updates={
                            CONF_HOST: candidate[CONF_HOST],
                            CONF_PORT: candidate[CONF_PORT],
                            CONF_SECONDARY_RELAY: candidate[CONF_SECONDARY_RELAY],
                            CONF_MODEL: probe.identity.model,
                        },
                    )

        schema_fields: dict[vol.Marker, Any] = {
            vol.Required(CONF_HOST, default=entry.data[CONF_HOST]): str,
            vol.Required(CONF_PORT, default=entry.data[CONF_PORT]): vol.All(
                vol.Coerce(int), vol.Range(min=1, max=65535)
            ),
        }
        if supports_secondary:
            schema_fields[
                vol.Required(
                    CONF_SECONDARY_RELAY,
                    default=entry.data.get(CONF_SECONDARY_RELAY, False),
                )
            ] = bool
        schema = vol.Schema(schema_fields)
        return self.async_show_form(
            step_id="reconfigure", data_schema=schema, errors=errors
        )

    async def _async_validate_existing(
        self, entry: RemootioConfigEntry, candidate: dict[str, Any]
    ) -> ProbeResult:
        coordinator = getattr(entry, "runtime_data", None)
        if isinstance(coordinator, RemootioCoordinator):
            return await coordinator.async_validate_candidate(
                candidate[CONF_HOST],
                candidate[CONF_PORT],
                candidate[CONF_API_SECRET_KEY],
                candidate[CONF_API_AUTH_KEY],
            )
        return await self._async_probe(candidate, entry.unique_id)

    async def _async_probe(
        self, data: dict[str, Any], expected_serial: str | None = None
    ) -> ProbeResult:
        return await async_probe_device(
            async_get_clientsession(self.hass),
            data[CONF_HOST],
            data[CONF_API_SECRET_KEY],
            data[CONF_API_AUTH_KEY],
            port=data[CONF_PORT],
            expected_serial=expected_serial,
        )
