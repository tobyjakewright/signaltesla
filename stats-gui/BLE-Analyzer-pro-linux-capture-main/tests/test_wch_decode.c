#include "../wch_ble_analyzer.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    wch_pkt_hdr_t headers[10];
    uint8_t pdus[10][64];
    int lengths[10];
    int count;
} capture_t;

static void collect(const wch_pkt_hdr_t *header,
                    const uint8_t *pdu,
                    int pdu_len,
                    void *user)
{
    capture_t *capture = user;
    assert(capture->count < 10);
    capture->headers[capture->count] = *header;
    capture->lengths[capture->count] = pdu_len;
    assert(pdu_len <= (int)sizeof(capture->pdus[0]));
    memcpy(capture->pdus[capture->count], pdu, (size_t)pdu_len);
    capture->count++;
}

static size_t append_frame(uint8_t *out,
                           uint32_t timestamp,
                           uint8_t raw_channel,
                           uint8_t error_marker,
                           int8_t rssi,
                           uint8_t header0,
                           const uint8_t *payload,
                           uint8_t payload_len)
{
    uint16_t device_len = (uint16_t)(12u + payload_len);
    size_t frame_len = 4u + device_len;
    memset(out, 0, frame_len);
    out[0] = 0x55;
    out[1] = 0x10;
    out[2] = (uint8_t)device_len;
    out[3] = (uint8_t)(device_len >> 8);
    out[4] = (uint8_t)timestamp;
    out[5] = (uint8_t)(timestamp >> 8);
    out[6] = (uint8_t)(timestamp >> 16);
    out[7] = (uint8_t)(timestamp >> 24);
    out[8] = raw_channel;
    out[9] = error_marker;
    out[12] = (uint8_t)rssi;
    out[14] = header0;
    out[15] = payload_len;
    memcpy(out + 16, payload, payload_len);
    return frame_len;
}

static void test_connect_then_native_data(void)
{
    /* Official BLE_Connect.blemn CONNECT_IND example. */
    static const uint8_t connect_payload[34] = {
        0x4C, 0x6E, 0xAD, 0x88, 0x1E, 0x20,
        0x01, 0x1D, 0x1A, 0x26, 0x3B, 0x38,
        0x3F, 0x86, 0x07, 0x69,
        0x20, 0xA1, 0x01,
        0x01, 0x02, 0x00, 0x0C, 0x00, 0x00, 0x00, 0x90, 0x01,
        0x00, 0xD8, 0xFF, 0xFF, 0x1F,
        0x30
    };
    static const uint8_t feature_request[9] = {
        0x08, 0xFF, 0x59, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    static const uint8_t feature_response[9] = {
        0x09, 0xFF, 0x59, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    static const uint8_t empty_payload[1] = {0};

    uint8_t transfer[256];
    size_t used = 0;
    used += append_frame(transfer + used, 1880330, 37, 0, -50,
                         0x25, connect_payload, sizeof(connect_payload));
    used += append_frame(transfer + used, 1884494, 0x10, 0, -51,
                         0x03, feature_request, sizeof(feature_request));
    used += append_frame(transfer + used, 1884550, 0x10, 0, -49,
                         0x07, feature_response, sizeof(feature_response));
    /* Bit 7 in the raw channel is event phase metadata, not channel 128. */
    used += append_frame(transfer + used, 1899493, 0xA0, 0, -48,
                         0x01, empty_payload, 0);

    wch_device_t device;
    capture_t capture;
    memset(&device, 0, sizeof(device));
    memset(&capture, 0, sizeof(capture));
    device.configured_phy = WCH_BLE_PHY_1M;

    assert(wch_decode_transfer(&device, transfer, (int)used,
                               collect, &capture) == 4);
    assert(capture.count == 4);

    assert(capture.headers[0].link_layer == WCH_LINK_ADVERTISING);
    assert(capture.headers[0].pkt_type == PKT_CONNECT_IND);
    assert(capture.headers[0].access_addr == BLE_ADV_ACCESS_ADDRESS);
    assert(memcmp(capture.headers[0].crc, "\xC6\x15\x5C", 3) == 0);
    assert(device.connection_active);
    assert(device.connection.access_address == UINT32_C(0x6907863F));

    assert(capture.headers[1].link_layer == WCH_LINK_DATA);
    assert(capture.headers[1].channel_index == 16);
    assert(capture.headers[1].rssi == -51);
    assert(capture.headers[1].access_addr == UINT32_C(0x6907863F));
    assert(capture.headers[1].crc_init == UINT32_C(0x01A120));
    assert(capture.headers[1].pkt_type == 3);
    assert(capture.headers[1].direction ==
           WCH_DIRECTION_INITIATOR_TO_ADVERTISER);
    assert(memcmp(capture.headers[1].src_addr, connect_payload, 6) == 0);
    assert(memcmp(capture.headers[1].dst_addr,
                  connect_payload + 6, 6) == 0);
    assert(strcmp(wch_data_pdu_name(capture.headers[1].pkt_type,
                                    capture.pdus[1], capture.lengths[1]),
                  "LL_FEATURE_REQ") == 0);
    assert(memcmp(capture.headers[1].initiator_addr,
                  connect_payload, 6) == 0);
    assert(memcmp(capture.headers[1].advertiser_addr,
                  connect_payload + 6, 6) == 0);

    assert(capture.headers[2].direction ==
           WCH_DIRECTION_ADVERTISER_TO_INITIATOR);
    assert(memcmp(capture.headers[2].src_addr,
                  connect_payload + 6, 6) == 0);
    assert(strcmp(wch_data_pdu_name(capture.headers[2].pkt_type,
                                    capture.pdus[2], capture.lengths[2]),
                  "LL_FEATURE_RSP") == 0);

    assert(capture.headers[3].raw_channel == 0xA0);
    assert(capture.headers[3].channel_index == 32);
    assert(capture.headers[3].link_layer == WCH_LINK_DATA);
    assert(capture.headers[3].pkt_type == 1);
    assert(capture.headers[3].direction ==
           WCH_DIRECTION_INITIATOR_TO_ADVERTISER);
    assert(strcmp(wch_data_pdu_name(capture.headers[3].pkt_type,
                                    capture.pdus[3], capture.lengths[3]),
                  "LL_EMPTY") == 0);
}

static void test_error_marker_is_not_direction(void)
{
    uint8_t transfer[64];
    static const uint8_t payload[1] = {0};
    size_t used = append_frame(transfer, 1, 37, 1, -40, 0x00,
                               payload, sizeof(payload));
    wch_device_t device;
    capture_t capture;
    memset(&device, 0, sizeof(device));
    memset(&capture, 0, sizeof(capture));
    assert(wch_decode_transfer(&device, transfer, (int)used,
                               collect, &capture) == 0);
    assert(capture.count == 0);
    assert(device.err_count == 1);
}

static void test_ltk_decryption_pipeline(void)
{
    static const uint8_t ltk[16] = {
        0x4C, 0x68, 0x38, 0x41, 0x39, 0xF5, 0x74, 0xD8,
        0x36, 0xBC, 0xF3, 0x4E, 0x9D, 0xFB, 0x01, 0xBF
    };
    static const uint8_t connect_payload[34] = {
        0x4C, 0x6E, 0xAD, 0x88, 0x1E, 0x20,
        0x01, 0x1D, 0x1A, 0x26, 0x3B, 0x38,
        0x3F, 0x86, 0x07, 0x69,
        0x20, 0xA1, 0x01,
        0x01, 0x02, 0x00, 0x0C, 0x00, 0x00, 0x00, 0x90, 0x01,
        0x00, 0xD8, 0xFF, 0xFF, 0x1F,
        0x30
    };
    static const uint8_t skdm_wire[8] = {
        0x13, 0x02, 0xF1, 0xE0, 0xDF, 0xCE, 0xBD, 0xAC
    };
    static const uint8_t skds_wire[8] = {
        0x79, 0x68, 0x57, 0x46, 0x35, 0x24, 0x13, 0x02
    };
    static const uint8_t iv[8] = {
        0x24, 0xAB, 0xDC, 0xBA, 0xBE, 0xBA, 0xAF, 0xDE
    };

    uint8_t enc_req[23] = {0};
    enc_req[0] = 0x03;
    memcpy(enc_req + 11, skdm_wire, sizeof(skdm_wire));
    memcpy(enc_req + 19, iv, 4);

    uint8_t enc_rsp[13] = {0};
    enc_rsp[0] = 0x04;
    memcpy(enc_rsp + 1, skds_wire, sizeof(skds_wire));
    memcpy(enc_rsp + 9, iv + 4, 4);

    static const uint8_t start_enc_req[1] = {0x05};
    static const uint8_t encrypted_payload[5] = {
        0xA3, 0x4C, 0x13, 0xA4, 0x15
    };
    static const uint8_t encrypted_pdu[7] = {
        0x03, 0x05, 0xA3, 0x4C, 0x13, 0xA4, 0x15
    };

    uint8_t transfer[512];
    size_t used = 0;
    used += append_frame(transfer + used, 100, 37, 0, -50,
                         0x25, connect_payload, sizeof(connect_payload));
    used += append_frame(transfer + used, 200, 0x10, 0, -49,
                         0x03, enc_req, sizeof(enc_req));
    used += append_frame(transfer + used, 210, 0x10, 0, -48,
                         0x07, enc_rsp, sizeof(enc_rsp));
    used += append_frame(transfer + used, 300, 0xA0, 0, -47,
                         0x03, start_enc_req, sizeof(start_enc_req));
    used += append_frame(transfer + used, 310, 0xA0, 0, -46,
                         0x03, encrypted_payload,
                         sizeof(encrypted_payload));

    wch_device_t device;
    capture_t capture;
    memset(&device, 0, sizeof(device));
    memset(&capture, 0, sizeof(capture));
    device.configured_phy = WCH_BLE_PHY_1M;
    ble_crypto_set_ltk(&device.crypto, ltk);

    assert(wch_decode_transfer(&device, transfer, (int)used,
                               collect, &capture) == 5);
    assert(capture.count == 5);
    assert(device.crypto.session_key_ready);
    assert(device.crypto.encryption_active);

    const wch_pkt_hdr_t *decrypted = &capture.headers[4];
    assert(decrypted->link_layer == WCH_LINK_DATA);
    assert(decrypted->encrypted);
    assert(decrypted->decrypted);
    assert(decrypted->mic_checked);
    assert(decrypted->mic_valid);
    assert(decrypted->packet_counter_valid);
    assert(decrypted->packet_counter == 0);
    assert(!decrypted->retransmission);
    assert(decrypted->direction ==
           WCH_DIRECTION_ADVERTISER_TO_INITIATOR);
    assert(capture.lengths[4] == 3);
    assert(memcmp(capture.pdus[4], "\x03\x01\x06", 3) == 0);
    assert(strcmp(wch_data_pdu_name(decrypted->pkt_type,
                                    capture.pdus[4], capture.lengths[4]),
                  "LL_START_ENC_RSP") == 0);

    uint8_t raw_crc[3];
    uint8_t plaintext_crc[3];
    ble_crc24(encrypted_pdu, sizeof(encrypted_pdu),
              UINT32_C(0x01A120), raw_crc);
    ble_crc24(capture.pdus[4], (size_t)capture.lengths[4],
              UINT32_C(0x01A120), plaintext_crc);
    assert(memcmp(decrypted->crc, raw_crc, sizeof(raw_crc)) == 0);
    assert(memcmp(decrypted->crc, plaintext_crc, sizeof(plaintext_crc)) != 0);
}

int main(void)
{
    test_connect_then_native_data();
    test_error_marker_is_not_direction();
    test_ltk_decryption_pipeline();
    puts("WCH receive decoder vectors: PASS");
    return 0;
}
