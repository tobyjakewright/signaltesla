/*
 * Pure helpers for the WCH BLE Analyzer Pro USB command protocol.
 *
 * The AA81 layout is taken from the vendor's BleAnalyzer64.exe v1.53.  This
 * module deliberately has no libusb dependency, which keeps the command bytes
 * deterministic and unit-testable on a machine without the analyzer attached.
 */

#ifndef WCH_PROTOCOL_H
#define WCH_PROTOCOL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define WCH_BLE_CONFIG_PAYLOAD_SIZE 25u
#define WCH_BLE_CONFIG_FRAME_SIZE   29u
#define WCH_SCAN_TRIGGER_FRAME_SIZE  4u

typedef enum {
    WCH_BLE_PHY_1M = 0,
    WCH_BLE_PHY_2M = 1,
    WCH_BLE_PHY_CODED_S8 = 2,
    WCH_BLE_PHY_CODED_S2 = 3
} wch_ble_phy_t;

typedef struct {
    uint8_t channel;                 /* Primary advertising channel 37/38/39. */
    wch_ble_phy_t phy;
    uint8_t initiator_filter[6];     /* InitA, on-air (least-significant octet first). */
    uint8_t advertiser_filter[6];    /* AdvA, on-air (least-significant octet first). */
} wch_ble_monitor_config_t;

/* Build AA 81 19 00 + the vendor's 25-byte BLE-monitor payload. */
bool wch_build_ble_monitor_frame(const wch_ble_monitor_config_t *config,
                                 uint8_t out[WCH_BLE_CONFIG_FRAME_SIZE]);

/* Build the vendor application's capture-stop update: AA81 p0=01,p1=00. */
void wch_build_capture_stop_frame(uint8_t out[WCH_BLE_CONFIG_FRAME_SIZE]);

/* Build the unconditional AA A1 00 00 command used after AA81. */
void wch_build_scan_trigger_frame(uint8_t out[WCH_SCAN_TRIGGER_FRAME_SIZE]);

const char *wch_ble_phy_name(wch_ble_phy_t phy);

#endif /* WCH_PROTOCOL_H */
