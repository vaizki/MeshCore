#pragma once

#include "helpers/bridges/BridgeBase.h"
#include <MeshCore.h>

#ifdef WITH_UDP_OBSERVER_BRIDGE

/**
 * Lightweight UDP uplink for observer telemetry (signed STATUS + HMAC DATA).
 * See todo/udp_observer_bridge_design.md. Transports: ESP32 WiFi UDP; RAK4631 +
 * RAK13800 Ethernet (W5100S) when ETHERNET_ENABLED is set.
 */
class UDPObserverBridge : public BridgeBase {
  mesh::LocalIdentity* _identity;
  mesh::Dispatcher* _dispatcher;
  mesh::Radio* _radio;
  mesh::MainBoard* _board;
  mesh::MillisecondClock* _ms;

  char _device_id[65];
  char _firmware_version[48];
  char _board_model[48];
  char _build_date[32];

  uint64_t _boot_id;
  uint64_t _counter;

  unsigned long _last_status_ms;
  bool _wifi_warned;

  void fillStatusPayload(char* out, size_t out_sz) const;
  bool buildStatusPacket(uint8_t* out, size_t out_sz, size_t* out_len);
  bool buildDataPacket(const uint8_t* mesh_raw, uint16_t mesh_len, uint8_t* out, size_t out_sz,
                       size_t* out_len);
  bool sendBuffer(const uint8_t* data, size_t len);
  void maybeSendStatus(unsigned long now_ms);
  void deriveEpochKey(uint32_t epoch_boot, uint8_t key_out[32]) const;
  bool rootSecretBytes(uint8_t out[32]) const;

public:
  UDPObserverBridge(NodePrefs* prefs, mesh::PacketManager* mgr, mesh::RTCClock* rtc,
                    mesh::LocalIdentity* identity);

  void begin() override;
  void end() override;
  void loop() override;
  void onPacketReceived(mesh::Packet* packet) override;
  void sendPacket(mesh::Packet* packet) override;

  void setDeviceID(const char* device_id);
  void setFirmwareVersion(const char* v);
  void setBoardModel(const char* m);
  void setBuildDate(const char* d);
  void storeRawRadioData(const uint8_t* raw_data, int len, float snr, float rssi);
  void setStatsSources(mesh::Dispatcher* dispatcher, mesh::Radio* radio, mesh::MainBoard* board,
                       mesh::MillisecondClock* ms);
  int getQueueSize() const { return 0; }
};

#endif
