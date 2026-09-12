#include "../wch_protocol.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static void test_unfiltered_1m_channel_37(void)
{
    const uint8_t expected[WCH_BLE_CONFIG_FRAME_SIZE] = {
        0xAA, 0x81, 0x19, 0x00,
        0xFF, 0x01, 0x25, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xD6, 0xBE, 0x89, 0x8E,
        0x55, 0x55, 0x55,
        0x10,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    wch_ble_monitor_config_t config;
    uint8_t frame[WCH_BLE_CONFIG_FRAME_SIZE];

    memset(&config, 0, sizeof(config));
    config.channel = 37;
    config.phy = WCH_BLE_PHY_1M;
    assert(wch_build_ble_monitor_frame(&config, frame));
    assert(memcmp(frame, expected, sizeof(expected)) == 0);
}

static void test_filters_and_phy_encoding(void)
{
    const uint8_t initiator[6] = {0x4C, 0x6E, 0xAD, 0x88, 0x1E, 0x20};
    const uint8_t advertiser[6] = {0x01, 0x1D, 0x1A, 0x26, 0x3B, 0x38};
    wch_ble_monitor_config_t config;
    uint8_t frame[WCH_BLE_CONFIG_FRAME_SIZE];

    memset(&config, 0, sizeof(config));
    config.channel = 39;
    config.phy = WCH_BLE_PHY_CODED_S2;
    memcpy(config.initiator_filter, initiator, sizeof(initiator));
    memcpy(config.advertiser_filter, advertiser, sizeof(advertiser));
    assert(wch_build_ble_monitor_frame(&config, frame));
    assert(frame[4] == 0xFF);
    assert(frame[5] == 0x01);
    assert(frame[6] == 39);
    assert(memcmp(frame + 9, initiator, sizeof(initiator)) == 0);
    assert(frame[22] == 0x80);
    assert(memcmp(frame + 23, advertiser, sizeof(advertiser)) == 0);
}

static void test_stop_and_trigger(void)
{
    uint8_t stop[WCH_BLE_CONFIG_FRAME_SIZE];
    uint8_t trigger[WCH_SCAN_TRIGGER_FRAME_SIZE];
    const uint8_t expected_trigger[WCH_SCAN_TRIGGER_FRAME_SIZE] = {
        0xAA, 0xA1, 0x00, 0x00
    };

    wch_build_capture_stop_frame(stop);
    assert(stop[0] == 0xAA && stop[1] == 0x81 && stop[2] == 0x19);
    assert(stop[4] == 0x01 && stop[5] == 0x00);
    for (size_t i = 6; i < sizeof(stop); i++)
        assert(stop[i] == 0);

    wch_build_scan_trigger_frame(trigger);
    assert(memcmp(trigger, expected_trigger, sizeof(trigger)) == 0);
}

static void test_rejects_invalid_values(void)
{
    wch_ble_monitor_config_t config;
    uint8_t frame[WCH_BLE_CONFIG_FRAME_SIZE];

    memset(&config, 0, sizeof(config));
    config.channel = 36;
    assert(!wch_build_ble_monitor_frame(&config, frame));
    config.channel = 37;
    config.phy = (wch_ble_phy_t)4;
    assert(!wch_build_ble_monitor_frame(&config, frame));
}

int main(void)
{
    test_unfiltered_1m_channel_37();
    test_filters_and_phy_encoding();
    test_stop_and_trigger();
    test_rejects_invalid_values();
    puts("WCH protocol vectors: PASS");
    return 0;
}
