#include "wch_protocol.h"

#include <string.h>

#define WCH_MAGIC              UINT8_C(0xAA)
#define WCH_CMD_BLE_CONFIG     UINT8_C(0x81)
#define WCH_CMD_SCAN_TRIGGER   UINT8_C(0xA1)
#define WCH_MODE_BLE_MONITOR   UINT8_C(0x01)

/* AA81 payload field-valid/update bits. */
#define WCH_CFG_MODE_VALID       UINT8_C(0x01)
#define WCH_CFG_CHANNEL_VALID    UINT8_C(0x02)
#define WCH_CFG_RESERVED_VALID   UINT8_C(0x04)
#define WCH_CFG_INITA_VALID      UINT8_C(0x08)
#define WCH_CFG_AA_VALID         UINT8_C(0x10)
#define WCH_CFG_CRCINIT_VALID    UINT8_C(0x20)
#define WCH_CFG_PHY_VALID        UINT8_C(0x40)
#define WCH_CFG_ADVA_VALID       UINT8_C(0x80)

bool wch_build_ble_monitor_frame(const wch_ble_monitor_config_t *config,
                                 uint8_t out[WCH_BLE_CONFIG_FRAME_SIZE])
{
    static const uint8_t advertising_access_address[4] = {
        UINT8_C(0xD6), UINT8_C(0xBE), UINT8_C(0x89), UINT8_C(0x8E)
    };
    static const uint8_t advertising_crc_init[3] = {
        UINT8_C(0x55), UINT8_C(0x55), UINT8_C(0x55)
    };

    if (!config || !out ||
            (config->channel != 37 && config->channel != 38 &&
             config->channel != 39) ||
            config->phy < WCH_BLE_PHY_1M ||
            config->phy > WCH_BLE_PHY_CODED_S2)
        return false;

    memset(out, 0, WCH_BLE_CONFIG_FRAME_SIZE);
    out[0] = WCH_MAGIC;
    out[1] = WCH_CMD_BLE_CONFIG;
    out[2] = (uint8_t)WCH_BLE_CONFIG_PAYLOAD_SIZE;
    out[3] = 0;

    /* Enabled BLE-monitor configuration with every supplied field valid. */
    out[4] = WCH_CFG_MODE_VALID | WCH_CFG_CHANNEL_VALID |
             WCH_CFG_RESERVED_VALID | WCH_CFG_INITA_VALID |
             WCH_CFG_AA_VALID | WCH_CFG_CRCINIT_VALID |
             WCH_CFG_PHY_VALID | WCH_CFG_ADVA_VALID;
    out[5] = WCH_MODE_BLE_MONITOR;
    out[6] = config->channel;
    /* payload bytes 3-4 are reserved and stay zero. */
    memcpy(out + 9, config->initiator_filter,
           sizeof(config->initiator_filter));
    memcpy(out + 15, advertising_access_address,
           sizeof(advertising_access_address));
    memcpy(out + 19, advertising_crc_init, sizeof(advertising_crc_init));
    out[22] = (uint8_t)(UINT8_C(0x10) << (unsigned int)config->phy);
    memcpy(out + 23, config->advertiser_filter,
           sizeof(config->advertiser_filter));
    return true;
}

void wch_build_capture_stop_frame(uint8_t out[WCH_BLE_CONFIG_FRAME_SIZE])
{
    if (!out)
        return;
    memset(out, 0, WCH_BLE_CONFIG_FRAME_SIZE);
    out[0] = WCH_MAGIC;
    out[1] = WCH_CMD_BLE_CONFIG;
    out[2] = (uint8_t)WCH_BLE_CONFIG_PAYLOAD_SIZE;
    out[4] = WCH_CFG_MODE_VALID;
    /* payload byte 1 (mode) remains zero: capture disabled. */
}

void wch_build_scan_trigger_frame(uint8_t out[WCH_SCAN_TRIGGER_FRAME_SIZE])
{
    if (!out)
        return;
    out[0] = WCH_MAGIC;
    out[1] = WCH_CMD_SCAN_TRIGGER;
    out[2] = 0;
    out[3] = 0;
}

const char *wch_ble_phy_name(wch_ble_phy_t phy)
{
    switch (phy) {
    case WCH_BLE_PHY_1M:       return "LE 1M";
    case WCH_BLE_PHY_2M:       return "LE 2M";
    case WCH_BLE_PHY_CODED_S8: return "LE Coded S=8";
    case WCH_BLE_PHY_CODED_S2: return "LE Coded S=2";
    default:                   return "unknown";
    }
}
