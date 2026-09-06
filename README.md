# Remootio for Home Assistant

A local-only Home Assistant integration for Remootio controllers using the
official WebSocket API v3. It maintains the device's single allowed WebSocket
connection for commands, state queries, keepalives, and pushed events. No
Remootio cloud service is used.

## Status

The implementation and simulated automated test suite are complete. Physical
hardware validation has not been performed. Do not connect it to a controller
until the bounded read-only validation gate is explicitly opened; that first
session will send only `HELLO`, `AUTH`, and `QUERY`, never a relay action.

## Entities

- A status-sensor-equipped controller is exposed as a native garage cover.
  Opening and closing use Remootio's directional `OPEN` and `CLOSE` API actions.
  Remootio ultimately emits the same relay pulse expected by a conventional
  gate or garage-door opener.
- A controller that reports `no sensor` is exposed as a stateless primary
  trigger button. The integration never fabricates open or closed state.
- A secondary free relay is exposed as a stateless button only when the user
  explicitly confirms that output 2 is configured as a free relay. The v3 API
  does not provide a safe, read-only capability query.

Current state comes only from a successful `QUERY` response or an authoritative
`StateChange` event. Command responses are acknowledgements and are never used
to infer the resulting door state.

## Installation

### HACS custom repository

1. Add this repository to HACS as an **Integration** custom repository.
2. Install **Remootio**.
3. Restart Home Assistant.
4. In **Settings → Devices & services**, add **Remootio** or select a discovered
   `_remootio._tcp.local.` device.
5. Enter the 64-character API secret and API auth hexadecimal keys shown in the
   Remootio app.

The credentials are stored in the Home Assistant config entry. They are never
written to logs or diagnostics.

## Security and reliability

- Every encrypted frame is authenticated with HMAC-SHA256 using a constant-time
  comparison before AES-CBC decryption.
- Keys, base64, IVs, ciphertext, PKCS7 padding, JSON, and message fields are
  validated before use.
- Commands are acknowledged only by a response matching both action type and
  action ID. Rejection, timeout, malformed data, or disconnection becomes a
  visible Home Assistant action failure.
- Event replay is deduplicated, restart/counter reset is handled, and state is
  reconciled after authentication or an event gap.
- Entities become unavailable when connection health is lost while retaining
  the last authoritative state internally for recovery.

## Known limitations

- Remootio's API provides no read-only way to discover whether a Remootio 2 has
  output 2 configured as a free relay. This must be declared by the user.
- The protocol client is currently an isolated, Home Assistant-independent
  module inside the custom integration. A future Home Assistant Core submission
  would extract and publish it as an open-source Python package.
- Activity and history sensors are intentionally excluded from the initial
  release.

## Development

Home Assistant 2026.9.0 and Python 3.14.2 or newer are the initial baseline.

```bash
uv sync --group test
uv run --group test pytest
uv run --group test ruff check .
uv run --group test ruff format --check .
uv run --group test mypy
```

The Home Assistant-facing tests use `pytest-homeassistant-custom-component` and
its real Home Assistant fixtures. Protocol transport is simulated; no test in
the normal suite contacts or triggers a physical device.

## Protocol reference

[Official Remootio WebSocket API documentation](https://github.com/remootio/remootio-api-documentation)

## License

MIT
