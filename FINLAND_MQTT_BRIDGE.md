# Finland MQTT Observer Firmware

This build profile is for Finland MeshCore observer/repeater setups and defaults to a receive-first, regulation-friendly configuration.

## Default Firmware Settings

Finland observer builds produced with `build-finland-observer.sh` apply these defaults:

- Radio preset: EU Narrow style parameters
  - `frequency 869.6179809`
  - `bandwidth 62.5`
  - `sf 8`
  - `cr 8`
- Airtime factor (`af`): `9` (via `DEFAULT_AIRTIME_FACTOR=9`) to align with EU 868 MHz use 10% duty-cycle expectations.
- Device advert name: `FI MQTT Observer`
- Radio TX default: `off` (via `RADIO_RX_ONLY_DEFAULT=1`)

## Important TX Safety Behavior

This firmware will not transmit anything over LoRa until you explicitly enable TX:

```bash
set radio.tx on
```

If your RF chain is receive-only (for example LNA + filters with no safe TX path), keep TX disabled.

## Preserve Node Identity (Private Key)

If you are flashing a merged firmware, your node identity (private & public keys) will not survive the flash. To preserve the same node identity, save your current private key before flashing and restore it after flashing:

```bash
set prv.key <your_64_hex_char_private_key>
```

This keeps the same node identity/public key across migrations.

## First-Time Node Identity Setup

Set these node-specific values after flashing:

```bash
set name <your-node-name>
set lat <latitude>
set lon <longitude>
```

## MQTT Quick Setup (IATA / Origin)

Set an IATA/location code used by analyzer-style MQTT topics. For Finland use a suitable code such as `HEL`, `TMP`, or `JOE`:

```bash
set mqtt.iata HEL
```

`set name` is also used as MQTT origin on observer builds, so set it to the node/gateway name you want shown upstream.

## Operating Modes

### 1) Repeater + Observer (can forward and publish both directions)

Recommended settings:

```bash
set mqtt.rx on
set mqtt.tx on
set radio.tx on
```

Alternative TX uplink mode:

```bash
set mqtt.tx advert
```

Difference between `mqtt.tx on` and `mqtt.tx advert`:

- `mqtt.tx on`: publish all transmitted packets seen from this node (including repeated/forwarded traffic). This gives you both sides of repeater activity on MQTT.
- `mqtt.tx advert`: publish only this node's own advert transmissions, not general repeated TX traffic.

### 2) Silent Observer (maximum listening, no radio transmit)

For receive-only installs (for example LNA + filters) where TX is not wanted:

```bash
set mqtt.rx on
set mqtt.tx off
set radio.tx off
```

This keeps LoRa TX disabled while still reporting received mesh traffic to MQTT.

## Default MQTT Reporting Targets

Observer defaults are intended for Let's Mesh Analyzer targets. You can verify current presets with:

```bash
get mqtt1.preset
get mqtt2.preset
```

If you want packet delivery to CoreScope (`https://corescope.vaizki.fi/`), contact Vaizki on Discord for integration details.

For full MQTT command reference (slots/presets/custom brokers/status/raw/tx modes), see `MQTT_IMPLEMENTATION.md`.
