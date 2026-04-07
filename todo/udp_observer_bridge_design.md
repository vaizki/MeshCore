# UDP Observer Bridge Design (RP2040/nRF/ESP32 Friendly)

## Purpose

Define a lightweight, UDP-based observer uplink that can run on constrained MCUs (including RP2040 and nRF), with practical anti-abuse authentication and replay protection, while leaving MQTT/TLS complexity to a cloud-side UDP-to-MQTT gateway.

This design targets "prevent accidental or casual malicious injection" rather than nation-state adversaries.

## Why This Exists

- Current MQTT observer path is heavy on MCU RAM/flash, especially with TLS/WSS.
- RP2040/nRF builds are better served by a compact binary UDP uplink.
- Gateway-side translation to MQTT keeps firmware simple and portable.

## Design Decision: Epoch Source

Two approaches were considered:

1. Receiver wall-clock epoch (`floor(unix_time/300)`), sender tries to guess.
2. Boot-relative epoch (`floor(uptime_ms/300000)`), keyed with `boot_id`.

Selected approach: **boot-relative epoch**.

Reason:

- Works on MCUs with no RTC/NTP.
- Removes wall-clock dependency from packet authentication.
- Still rotates keys every 5 minutes.
- `boot_id` prevents key reuse across reboots.
- Simpler and more deterministic to implement/debug.

## Design Summary

- Transport: fire-and-forget UDP from node to gateway.
- Identity: Ed25519 status beacons signed with node identity key.
- Per-packet auth: HMAC tag on data packets.
- Replay/out-of-order handling: counter + sliding replay window on gateway.
- No trusted wall clock required on node.
- Epoch/key rotation is boot-relative using `boot_id` + `uptime_ms` buckets.

## Security Model

### In Scope

- Reject random forged packets from the public internet.
- Reject replays and duplicates.
- Tolerate packet loss and out-of-order UDP delivery.

### Out of Scope

- Confidentiality (payloads are not encrypted).
- Perfect forward secrecy.
- Active MITM with full key compromise.

## Key Materials

- `node_privkey` / `node_pubkey` (Ed25519 identity already used by MeshCore).
- `root_secret` (32-byte shared secret, per fleet or per node).
- `boot_id` (random 64-bit value generated at each boot).
- `counter` (monotonic 64-bit packet counter, per boot).

## Packet Types

- `STATUS` (`type=0x10`): signed with Ed25519.
- `DATA` (`type=0x20`): HMAC-authenticated.

## Canonical Encoding Rules

- All integers are big-endian.
- All signed/MACed bytes must be exactly identical on sender and receiver.
- No JSON in firmware packet path. Use compact binary.

## Wire Format

## Common Header (present in all packets)

- `version` (1 byte)
- `type` (1 byte)
- `node_pubkey` (32 bytes, Ed25519 public key)
- `boot_id` (8 bytes)
- `counter` (8 bytes)

## STATUS Packet

Payload fields:

- `uptime_ms` (8 bytes)
- `capability_flags` (4 bytes)
- `status_payload_len` (2 bytes)
- `status_payload` (variable, optional compact telemetry)

Authentication:

- `sig` (64 bytes Ed25519 signature over all bytes before `sig`).

Notes:

- `status_payload` can include firmware version, radio mode, queue stats, and optional diagnostics.
- Gateway may cache latest valid status per node.

## DATA Packet

Payload fields:

- `uptime_ms` (8 bytes)
- `mesh_packet_len` (2 bytes)
- `mesh_packet` (variable raw MeshCore packet bytes)

Authentication:

- `tag` (16 bytes truncated HMAC-SHA256)

`tag` is computed over the packet body (everything before `tag`) using `K(epoch_boot)`.

## Epoch/Key Derivation

Derived key function:

- `K(epoch_boot) = HMAC_SHA256(root_secret, "udp-obs-v1" || node_pubkey || boot_id || u32be(epoch_boot))`

Epoch length (boot-relative):

- 300 seconds (5 minutes).

Epoch definition:

- `epoch_boot = floor(uptime_ms / 300000)`.

Sender behavior:

- Sender computes one tag using `K(epoch_boot)`.
- Sender does not need RTC/NTP or any wall clock estimate.

Receiver verify order:

1. Parse `uptime_ms` from packet and compute `epoch_boot = floor(uptime_ms / 300000)`.
2. Verify `tag` using `K(epoch_boot)`.

## No-Wall-Clock Node Operation

Node does not need RTC/NTP:

- Use monotonic uptime and derive `epoch_boot` directly from it.
- Rotate key buckets every 300000 ms since boot.
- Security does not depend on wall clock at all.

## Replay and Out-of-Order Protection

Use per `(node_pubkey, boot_id)` replay state:

- `max_counter_seen` (u64)
- `bitmap` of width `W` counters (recommend `W=64` or `W=128`)

Algorithm:

- If `c > max_counter_seen`: advance window, set newest bit, accept.
- Else `delta = max_counter_seen - c`:
  - if `delta >= W`: reject as too old
  - if bit already set: reject as duplicate/replay
  - else set bit and accept (valid out-of-order packet)

This tolerates loss and out-of-order while still blocking replay duplicates.

## Sender Pseudocode

```python
VERSION = 1
TYPE_STATUS = 0x10
TYPE_DATA = 0x20

def derive_key(root_secret, node_pubkey, boot_id, epoch_boot_u32):
    return HMAC_SHA256(
        root_secret,
        b"udp-obs-v1" + node_pubkey + u64be(boot_id) + u32be(epoch_boot_u32)
    )

def build_status(node_pubkey, boot_id, counter, uptime_ms, flags, status_payload):
    body = (
        u8(VERSION) +
        u8(TYPE_STATUS) +
        node_pubkey +
        u64be(boot_id) +
        u64be(counter) +
        u64be(uptime_ms) +
        u32be(flags) +
        u16be(len(status_payload)) +
        status_payload
    )
    sig = ED25519_SIGN(node_privkey, body)  # 64 bytes
    return body + sig

def build_data(node_pubkey, boot_id, counter, mesh_packet):
    uptime = uptime_ms()
    epoch_boot = uptime // 300000
    body = (
        u8(VERSION) +
        u8(TYPE_DATA) +
        node_pubkey +
        u64be(boot_id) +
        u64be(counter) +
        u64be(uptime) +
        u16be(len(mesh_packet)) +
        mesh_packet
    )

    k = derive_key(root_secret, node_pubkey, boot_id, epoch_boot)
    tag = HMAC_SHA256(k, body)[:16]
    return body + tag

def send_loop():
    # boot
    boot_id = random_u64()
    counter = 0

    # status on boot
    udp_send(build_status(node_pubkey, boot_id, counter, uptime_ms(), flags(), b""))
    counter += 1

    while True:
        if every_5_minutes():
            udp_send(build_status(node_pubkey, boot_id, counter, uptime_ms(), flags(), compact_status()))
            counter += 1

        pkt = next_mesh_packet_or_none()
        if pkt is not None:
            udp_send(build_data(node_pubkey, boot_id, counter, pkt))
            counter += 1
```

## Receiver Pseudocode

```python
WINDOW = 128

def verify_status(pkt):
    body, sig = pkt[:-64], pkt[-64:]
    fields = parse_status_body(body)
    node_pubkey = fields.node_pubkey

    if not ED25519_VERIFY(node_pubkey, body, sig):
        return reject("bad signature")

    rs = replay_state(node_pubkey, fields.boot_id)
    if not replay_accept(rs, fields.counter, WINDOW):
        return reject("replay/duplicate")

    cache_status(fields)
    return accept()

def verify_data(pkt):
    body, tag = split_data_packet(pkt)  # last 16 bytes is one tag
    fields = parse_data_body(body)
    node_pubkey = fields.node_pubkey

    rs = replay_state(node_pubkey, fields.boot_id)
    if not replay_accept(rs, fields.counter, WINDOW):
        return reject("replay/duplicate")

    epoch_boot = fields.uptime_ms // 300000
    root = root_secret_for(node_pubkey)

    k = derive_key(root, node_pubkey, fields.boot_id, epoch_boot)
    expected = HMAC_SHA256(k, body)[:16]
    if not consteq(expected, tag):
        return reject("bad mac")

    mqtt_publish(transform_mesh_packet_to_mqtt(fields.mesh_packet))
    return accept()

def replay_accept(state, c, W):
    if c > state.max_counter:
        shift = c - state.max_counter
        state.bitmap = shift_left_and_zero_fill(state.bitmap, shift, W)
        state.bitmap[0] = 1
        state.max_counter = c
        return True

    delta = state.max_counter - c
    if delta >= W:
        return False
    if state.bitmap[delta] == 1:
        return False
    state.bitmap[delta] = 1
    return True
```

## Recommended Defaults

- Epoch size: 300 seconds.
- HMAC tag length: 16 bytes.
- Replay window `W`: 128.
- STATUS interval: 300 seconds.
- STATUS on boot: immediate.

## Failure Modes and Behavior

- Lost UDP packet: tolerated; packet is simply missing.
- Out-of-order packet: accepted if within replay window and MAC valid.
- Duplicate packet: rejected by replay bitmap.
- Node reboot: `boot_id` changes, replay state starts fresh for new boot.
- Gateway restart: replay cache loss can allow limited duplicate replays until state rebuild (mitigate with short persistence).

## MQTT Timestamping Strategy

Requirement: MQTT events should be wall-clock timestamped, but raw UDP receive time alone is not ideal because it includes transport/scheduling delay.

Recommended model: publish **multiple timestamps** and estimate radio event wall-clock using node monotonic time.

### Include These Time Fields in UDP Payload

- `uptime_ms`: node monotonic uptime at packet creation.
- Optional `rx_uptime_ms`: node uptime when radio packet was received (preferred for observer use).
- `counter`, `boot_id`, `node_pubkey`: for ordering and mapping.

### Gateway Time Anchoring

Maintain per `(node_pubkey, boot_id)` anchor:

- On each valid STATUS or DATA packet, record:
  - `anchor_gateway_wallclock_ms` (gateway wall clock now)
  - `anchor_node_uptime_ms` (packet uptime field)

Compute offset estimate:

- `offset_ms = anchor_gateway_wallclock_ms - anchor_node_uptime_ms`

Estimated radio wall-clock for a DATA packet:

- If `rx_uptime_ms` available: `radio_wallclock_est = rx_uptime_ms + offset_ms`
- Else fallback: `radio_wallclock_est = uptime_ms + offset_ms`

### Publish to MQTT (Do Not Hide Uncertainty)

Include:

- `gateway_rx_time` (actual UDP arrival wall clock)
- `radio_time_est` (estimated event time from uptime offset)
- `time_source` (`estimated_from_uptime` or `gateway_rx_fallback`)
- `time_uncertainty_ms` (best-effort estimate)

### Uncertainty / Drift Handling

- Use smoothing (EWMA) on `offset_ms` updates to reduce jitter.
- Cap backward jumps in `radio_time_est` (monotonic guard per node).
- Reset anchor on `boot_id` change.
- If no anchor yet, use `gateway_rx_time` and mark fallback source.

### Is There a Better Way Than UDP Arrival Time?

Yes:

- Best practical option in no-RTC systems is the **hybrid above**: wall-clock anchored by gateway, event timing from node monotonic uptime.
- Pure gateway receive time is acceptable fallback but less accurate.
- Full accuracy would require reliable synchronized time on node (NTP/PTP/GNSS), which this design intentionally avoids for portability.

## MQTT Output Compatibility (Current MeshCore Schema)

Goal: UDP-to-MQTT gateway must match current MeshCore observer JSON shape so existing consumers continue working without changes.

### Compatibility Rules

- Do not rename or remove existing keys.
- Do not change existing key types.
- Additive extension fields are allowed.
- Extensions must not be required for existing consumers.

### STATUS Payload Contract

Required root keys:

- `status` (string, usually `"online"`)
- `timestamp` (string, ISO-like format: `YYYY-MM-DDTHH:MM:SS.000000`)
- `origin` (string)
- `origin_id` (string, 64-char hex public key)
- `model` (string)
- `firmware_version` (string)
- `radio` (string, compact csv-like format, e.g. `"869.617981,62.5,8,8"`)
- `client_version` (string)

Optional nested key:

- `stats` (object), with optional numeric fields:
  - `battery_mv`
  - `uptime_secs`
  - `errors`
  - `queue_len`
  - `noise_floor`
  - `tx_air_secs`
  - `rx_air_secs`
  - `recv_errors`

### PACKETS Payload Contract

Required keys:

- `origin` (string)
- `origin_id` (string, 64-char hex public key)
- `timestamp` (string, ISO-like format: `YYYY-MM-DDTHH:MM:SS.000000`)
- `type` (string, must be `"PACKET"`)
- `direction` (string, `"rx"` or `"tx"`)
- `time` (string, `HH:MM:SS`)
- `date` (string, `DD/MM/YYYY`)
- `len` (string, numeric content)
- `packet_type` (string, numeric content)
- `route` (string, typically `F`, `D`, `T`, or `U`)
- `payload_len` (string, numeric content)
- `raw` (string, uppercase hex packet bytes)
- `hash` (string, uppercase hex packet hash)

Conditionally required for RX direction:

- `SNR` (string, numeric content with one decimal place)
- `RSSI` (string, numeric content)

Optional:

- `path` (string), when route/path metadata is available

### Type Parity Requirements

To match current MeshCore analyzer payload behavior, these fields must remain strings even though they represent numbers:

- `len`
- `packet_type`
- `payload_len`
- `SNR`
- `RSSI`

### Timestamp Behavior Parity

Current behavior should be preserved unless intentionally changed:

- `timestamp`: formatted in local timezone context.
- `time` and `date`: formatted in UTC context.

If this behavior is later unified/simplified, treat it as a versioned output change and communicate to downstream consumers.

## Key Management Notes

- Do not send `root_secret` over network.
- Prefer per-node `root_secret` if feasible; per-fleet key is simpler but broader blast radius.
- Rotate root keys operationally (manual/managed), independent of epoch derivation.

## Implementation Notes for MeshCore

- Keep this as a new lightweight bridge implementation (do not overload MQTT bridge).
- Reuse existing MeshCore Ed25519 identity signing for STATUS.
- Reuse existing SHA256/HMAC primitives for DATA MAC.
- Keep MCU-side allocations fixed-size and bounded.

## Test Plan

- Unit tests:
  - canonical encoding/decoding roundtrip
  - signature verify pass/fail
  - MAC pass/fail for single boot-relative epoch
  - replay window behavior for in-order, out-of-order, duplicate, too-old

- Integration tests:
  - packet loss simulation
  - packet reordering simulation
  - node reboot (`boot_id` change)
  - gateway restart with replay cache persistence on/off

- Performance tests:
  - packets/sec on RP2040 and nRF with realistic burst traffic
  - CPU time for STATUS signing and DATA HMAC
  - memory usage high-water marks

## Future Enhancements

- Optional ACK channel for high-value packets only.
- Optional compression for mesh payload in UDP body.
- Optional per-node secret rotation protocol (if needed later).
