"""Constants for the Remootio integration."""

from __future__ import annotations

from typing import Final

from homeassistant.const import Platform

DOMAIN: Final = "remootio"

PLATFORMS: Final = [Platform.COVER, Platform.BUTTON]

CONF_API_SECRET_KEY: Final = "api_secret_key"
CONF_API_AUTH_KEY: Final = "api_auth_key"
CONF_SECONDARY_RELAY: Final = "secondary_relay"
CONF_SERIAL_NUMBER: Final = "serial_number"
CONF_MODEL: Final = "model"

DEFAULT_PORT: Final = 8080
DEFAULT_NAME: Final = "Remootio"

MODEL_REMOOTIO_1: Final = "remootio-1"
MODEL_REMOOTIO_2: Final = "remootio-2"
