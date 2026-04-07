#include "UDPObserverBridge.h"

#ifdef WITH_UDP_OBSERVER_BRIDGE

#include <Arduino.h>
#include <SHA256.h>
#include <stdio.h>
#include <string.h>

#if defined(ESP_PLATFORM)
#include <WiFi.h>
#include <WiFiUdp.h>
static WiFiUDP s_udp;
#endif

#if defined(NRF52_PLATFORM) && defined(ETHERNET_ENABLED)
#include <Dns.h>
#include <EthernetUdp.h>
#include <RAK13800_W5100S.h>
static EthernetUDP s_eth_udp;
static bool s_eth_udp_begun = false;
static DNSClient s_eth_dns;
static bool s_eth_dns_ready = false;

static bool eth_resolve_udp_host(const char* host, IPAddress& ip_out) {
  if (!host || host[0] == '\0') return false;
  if (ip_out.fromString(host)) return true;
  if (Ethernet.dnsServerIP() == IPAddress(0, 0, 0, 0)) return false;
  if (!s_eth_dns_ready) {
    s_eth_dns.begin(Ethernet.dnsServerIP());
    s_eth_dns_ready = true;
  }
  return s_eth_dns.getHostByName(host, ip_out) == 1;
}
#endif

#if defined(UDP_DEBUG) && defined(ARDUINO)
#include <Arduino.h>
#define UDP_LOG(...) \
  do { \
    if (Serial.availableForWrite() > 0) Serial.printf("UDP: " __VA_ARGS__); \
  } while (0)
#else
#define UDP_LOG(...) \
  do { \
  } while (0)
#endif

static const uint8_t UDP_VERSION = 1;
static const uint8_t UDP_TYPE_STATUS = 0x10;
static const uint8_t UDP_TYPE_DATA = 0x20;

static void write_u16be(uint8_t* p, uint16_t v) {
  p[0] = (uint8_t)(v >> 8);
  p[1] = (uint8_t)(v);
}

static void write_u32be(uint8_t* p, uint32_t v) {
  p[0] = (uint8_t)(v >> 24);
  p[1] = (uint8_t)(v >> 16);
  p[2] = (uint8_t)(v >> 8);
  p[3] = (uint8_t)(v);
}

static void write_u64be(uint8_t* p, uint64_t v) {
  for (int i = 0; i < 8; i++) {
    p[i] = (uint8_t)(v >> (56 - i * 8));
  }
}

UDPObserverBridge::UDPObserverBridge(NodePrefs* prefs, mesh::PacketManager* mgr, mesh::RTCClock* rtc,
                                     mesh::LocalIdentity* identity)
    : BridgeBase(prefs, mgr, rtc),
      _identity(identity),
      _dispatcher(nullptr),
      _radio(nullptr),
      _board(nullptr),
      _ms(nullptr),
      _boot_id(0),
      _counter(0),
      _last_status_ms(0),
      _wifi_warned(false) {
  _device_id[0] = '\0';
  strncpy(_firmware_version, "unknown", sizeof(_firmware_version) - 1);
  _firmware_version[sizeof(_firmware_version) - 1] = '\0';
  strncpy(_board_model, "unknown", sizeof(_board_model) - 1);
  _board_model[sizeof(_board_model) - 1] = '\0';
  strncpy(_build_date, "unknown", sizeof(_build_date) - 1);
  _build_date[sizeof(_build_date) - 1] = '\0';

  uint32_t r1 = (uint32_t)random(0x7fffffff);
  uint32_t r2 = (uint32_t)random(0x7fffffff);
  _boot_id = ((uint64_t)r1 << 32) ^ ((uint64_t)r2) ^ ((uint64_t)millis() << 17);
}

void UDPObserverBridge::setDeviceID(const char* device_id) {
  if (!device_id) return;
  strncpy(_device_id, device_id, sizeof(_device_id) - 1);
  _device_id[sizeof(_device_id) - 1] = '\0';
}

void UDPObserverBridge::setFirmwareVersion(const char* v) {
  if (!v) return;
  strncpy(_firmware_version, v, sizeof(_firmware_version) - 1);
  _firmware_version[sizeof(_firmware_version) - 1] = '\0';
}

void UDPObserverBridge::setBoardModel(const char* m) {
  if (!m) return;
  strncpy(_board_model, m, sizeof(_board_model) - 1);
  _board_model[sizeof(_board_model) - 1] = '\0';
}

void UDPObserverBridge::setBuildDate(const char* d) {
  if (!d) return;
  strncpy(_build_date, d, sizeof(_build_date) - 1);
  _build_date[sizeof(_build_date) - 1] = '\0';
}

void UDPObserverBridge::setStatsSources(mesh::Dispatcher* dispatcher, mesh::Radio* radio, mesh::MainBoard* board,
                                        mesh::MillisecondClock* ms) {
  _dispatcher = dispatcher;
  _radio = radio;
  _board = board;
  _ms = ms;
}

void UDPObserverBridge::storeRawRadioData(const uint8_t* raw_data, int len, float snr, float rssi) {
  (void)raw_data;
  (void)len;
  (void)snr;
  (void)rssi;
}

bool UDPObserverBridge::rootSecretBytes(uint8_t out[32]) const {
  if (strlen(_prefs->udp_root_secret_hex) != 64) return false;
  return mesh::Utils::fromHex(out, 32, _prefs->udp_root_secret_hex);
}

void UDPObserverBridge::deriveEpochKey(uint32_t epoch_boot, uint8_t key_out[32]) const {
  uint8_t root[32];
  if (!rootSecretBytes(root)) {
    memset(key_out, 0, 32);
    return;
  }
  const char label[] = "udp-obs-v1";
  SHA256 sha;
  sha.resetHMAC(root, 32);
  sha.update(label, 10);
  sha.update(_identity->pub_key, 32);
  uint8_t be_boot[8];
  write_u64be(be_boot, _boot_id);
  sha.update(be_boot, 8);
  uint8_t ebe[4];
  write_u32be(ebe, epoch_boot);
  sha.update(ebe, 4);
  sha.finalizeHMAC(root, 32, key_out, 32);
}

void UDPObserverBridge::fillStatusPayload(char* out, size_t out_sz) const {
  char radio[72];
  snprintf(radio, sizeof(radio), "%.6f,%.1f,%d,%d", (double)_prefs->freq, (double)_prefs->bw, (int)_prefs->sf,
           (int)_prefs->cr);
  snprintf(out, out_sz, "%s|%s|%s", _firmware_version, _board_model, radio);
}

bool UDPObserverBridge::buildStatusPacket(uint8_t* out, size_t out_sz, size_t* out_len) {
  if (!out || !out_len) return false;

  char status_text[200];
  fillStatusPayload(status_text, sizeof(status_text));
  uint16_t splen = (uint16_t)strlen(status_text);
  if (splen > 65535) return false;

  size_t body_len = 1 + 1 + 32 + 8 + 8 + 8 + 4 + 2 + splen;
  if (body_len + 64 > out_sz) return false;

  uint8_t* b = out;
  size_t o = 0;
  b[o++] = UDP_VERSION;
  b[o++] = UDP_TYPE_STATUS;
  memcpy(b + o, _identity->pub_key, 32);
  o += 32;
  write_u64be(b + o, _boot_id);
  o += 8;
  uint64_t c = _counter++;
  write_u64be(b + o, c);
  o += 8;
  uint64_t uptime = (uint64_t)millis();
  write_u64be(b + o, uptime);
  o += 8;
  write_u32be(b + o, 0);
  o += 4;
  write_u16be(b + o, splen);
  o += 2;
  memcpy(b + o, status_text, splen);
  o += splen;

  uint8_t sig[64];
  _identity->sign(sig, b, (int)o);
  memcpy(b + o, sig, 64);
  o += 64;
  *out_len = o;
  return true;
}

bool UDPObserverBridge::buildDataPacket(const uint8_t* mesh_raw, uint16_t mesh_len, uint8_t* out, size_t out_sz,
                                        size_t* out_len) {
  if (!mesh_raw || !out || !out_len) return false;
  uint8_t root_chk[32];
  if (!rootSecretBytes(root_chk)) return false;

  size_t body_len = 1 + 1 + 32 + 8 + 8 + 8 + 2 + mesh_len;
  if (body_len + 16 > out_sz) return false;

  uint8_t* b = out;
  size_t o = 0;
  b[o++] = UDP_VERSION;
  b[o++] = UDP_TYPE_DATA;
  memcpy(b + o, _identity->pub_key, 32);
  o += 32;
  write_u64be(b + o, _boot_id);
  o += 8;
  uint64_t c = _counter++;
  write_u64be(b + o, c);
  o += 8;
  uint64_t uptime = (uint64_t)millis();
  write_u64be(b + o, uptime);
  o += 8;
  write_u16be(b + o, mesh_len);
  o += 2;
  memcpy(b + o, mesh_raw, mesh_len);
  o += mesh_len;

  uint32_t epoch_boot = (uint32_t)(uptime / 300000ULL);
  uint8_t k[32];
  deriveEpochKey(epoch_boot, k);

  SHA256 sha;
  sha.resetHMAC(k, 32);
  sha.update(b, o);
  uint8_t mac[32];
  sha.finalizeHMAC(k, 32, mac, 32);
  memcpy(b + o, mac, 16);
  o += 16;
  *out_len = o;
  return true;
}

bool UDPObserverBridge::sendBuffer(const uint8_t* data, size_t len) {
  if (!data || len == 0) return false;
  if (_prefs->udp_gw_host[0] == '\0' || _prefs->udp_gw_port == 0) {
    UDP_LOG("no udp gateway (set udp.host / udp.port)\n");
    return false;
  }

#if defined(ESP_PLATFORM)
  if (WiFi.status() != WL_CONNECTED) {
    if (!_wifi_warned) {
      UDP_LOG("WiFi not connected\n");
      _wifi_warned = true;
    }
    return false;
  }
  _wifi_warned = false;

  IPAddress ip;
  if (!WiFi.hostByName(_prefs->udp_gw_host, ip)) {
    UDP_LOG("hostByName failed: %s\n", _prefs->udp_gw_host);
    return false;
  }

  s_udp.beginPacket(ip, _prefs->udp_gw_port);
  size_t w = s_udp.write(data, len);
  if (!s_udp.endPacket() || w != len) {
    UDP_LOG("UDP send failed\n");
    return false;
  }
  return true;
#elif defined(NRF52_PLATFORM) && defined(ETHERNET_ENABLED)
  if (Ethernet.localIP() == IPAddress(0, 0, 0, 0)) {
    if (!_wifi_warned) {
      UDP_LOG("Ethernet has no IP yet (wait for DHCP)\n");
      _wifi_warned = true;
    }
    return false;
  }
  if (Ethernet.linkStatus() != LinkON) {
    if (!_wifi_warned) {
      UDP_LOG("Ethernet link down\n");
      _wifi_warned = true;
    }
    return false;
  }
  _wifi_warned = false;

  if (!s_eth_udp_begun) {
    if (!s_eth_udp.begin(0)) {
      UDP_LOG("EthernetUDP begin failed\n");
      return false;
    }
    s_eth_udp_begun = true;
  }

  IPAddress ip;
  if (!eth_resolve_udp_host(_prefs->udp_gw_host, ip)) {
    UDP_LOG("UDP host resolve failed: %s\n", _prefs->udp_gw_host);
    return false;
  }

  s_eth_udp.beginPacket(ip, _prefs->udp_gw_port);
  size_t w = s_eth_udp.write(data, len);
  if (!s_eth_udp.endPacket() || w != len) {
    UDP_LOG("UDP send failed\n");
    return false;
  }
  return true;
#else
  (void)data;
  (void)len;
  if (!_wifi_warned) {
    UDP_LOG("UDP send: no network transport on this build\n");
    _wifi_warned = true;
  }
  return false;
#endif
}

void UDPObserverBridge::maybeSendStatus(unsigned long now_ms) {
  if (!_prefs->mqtt_status_enabled) return;
  if (_prefs->udp_gw_host[0] == '\0' || _prefs->udp_gw_port == 0) return;

  uint32_t interval = _prefs->mqtt_status_interval;
  if (interval < 60000) interval = 60000;

  if (_last_status_ms != 0 && (now_ms - _last_status_ms) < interval) return;

  uint8_t buf[384];
  size_t pkt_len = 0;
  if (!buildStatusPacket(buf, sizeof(buf), &pkt_len)) return;
  if (sendBuffer(buf, pkt_len)) {
    _last_status_ms = now_ms;
  }
}

void UDPObserverBridge::begin() {
#if defined(ESP_PLATFORM)
  WiFi.mode(WIFI_STA);
  WiFi.setAutoReconnect(true);
  if (strlen(_prefs->wifi_ssid) > 0) {
    WiFi.begin(_prefs->wifi_ssid, _prefs->wifi_password);
  }
  s_udp.begin(0);
#elif defined(NRF52_PLATFORM) && defined(ETHERNET_ENABLED)
  s_eth_udp_begun = false;
  s_eth_dns_ready = false;
#endif
  _initialized = true;
}

void UDPObserverBridge::end() {
  _initialized = false;
}

void UDPObserverBridge::loop() {
  if (!_initialized) return;
  maybeSendStatus(millis());
}

void UDPObserverBridge::onPacketReceived(mesh::Packet* packet) {
  if (!_initialized || !_prefs->mqtt_packets_enabled || !_prefs->mqtt_rx_enabled) return;
  if (_prefs->udp_gw_host[0] == '\0' || _prefs->udp_gw_port == 0) return;

  uint8_t raw[512];
  uint8_t rlen = packet->writeTo(raw);
  if (rlen == 0) return;

  uint8_t buf[640];
  size_t pkt_len = 0;
  if (!buildDataPacket(raw, rlen, buf, sizeof(buf), &pkt_len)) return;
  sendBuffer(buf, pkt_len);
}

void UDPObserverBridge::sendPacket(mesh::Packet* packet) {
  if (!_initialized || !_prefs->mqtt_packets_enabled) return;
  uint8_t tx_mode = _prefs->mqtt_tx_enabled;
  if (tx_mode == 0) return;

  if (tx_mode == 2) {
    if (packet->getPayloadType() != PAYLOAD_TYPE_ADVERT) return;
    if (packet->payload_len < PUB_KEY_SIZE) return;
    if (!_identity || memcmp(_identity->pub_key, packet->payload, PUB_KEY_SIZE) != 0) return;
  }

  if (_prefs->udp_gw_host[0] == '\0' || _prefs->udp_gw_port == 0) return;

  uint8_t raw[512];
  uint8_t rlen = packet->writeTo(raw);
  if (rlen == 0) return;

  uint8_t buf[640];
  size_t pkt_len = 0;
  if (!buildDataPacket(raw, rlen, buf, sizeof(buf), &pkt_len)) return;
  sendBuffer(buf, pkt_len);
}

#endif
