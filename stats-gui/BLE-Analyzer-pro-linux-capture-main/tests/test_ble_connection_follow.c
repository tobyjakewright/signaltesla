#include "../ble_connection_follow.h"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

static unsigned int failures;

#define CHECK_TRUE(expr)                                                     \
    do {                                                                     \
        if (!(expr)) {                                                       \
            fprintf(stderr, "%s:%d: check failed: %s\n",                   \
                    __FILE__, __LINE__, #expr);                              \
            failures++;                                                      \
        }                                                                    \
    } while (0)

#define CHECK_U64(actual, expected)                                          \
    do {                                                                     \
        uint64_t check_actual = (uint64_t)(actual);                          \
        uint64_t check_expected = (uint64_t)(expected);                      \
        if (check_actual != check_expected) {                                \
            fprintf(stderr, "%s:%d: got %" PRIu64 ", expected %" PRIu64    \
                    " (%s)\n", __FILE__, __LINE__, check_actual,            \
                    check_expected, #actual);                                \
            failures++;                                                      \
        }                                                                    \
    } while (0)

static void write_le16(uint8_t *p, uint16_t value)
{
    p[0] = (uint8_t)value;
    p[1] = (uint8_t)(value >> 8);
}

static void make_connect_ind(uint8_t pdu[BLE_CONNECT_IND_PDU_LEN])
{
    memset(pdu, 0, BLE_CONNECT_IND_PDU_LEN);
    pdu[0] = 0xE5; /* CONNECT_IND, ChSel=1, TxAdd=1, RxAdd=1. */
    pdu[1] = BLE_CONNECT_IND_PAYLOAD_LEN;

    for (uint8_t i = 0; i < 6; i++) {
        pdu[2 + i] = (uint8_t)(i + 1);
        pdu[8 + i] = (uint8_t)(0x11 + i);
    }

    uint8_t *ll_data = pdu + 14;
    ll_data[0] = 0xD6;
    ll_data[1] = 0xBE;
    ll_data[2] = 0x89;
    ll_data[3] = 0x12;
    ll_data[4] = 0x12;
    ll_data[5] = 0x34;
    ll_data[6] = 0x56;
    ll_data[7] = 2;
    write_le16(ll_data + 8, 3);
    write_le16(ll_data + 10, 24);
    write_le16(ll_data + 12, 0);
    write_le16(ll_data + 14, 500);
    memset(ll_data + 16, 0xFF, 4);
    ll_data[20] = 0x1F;
    ll_data[21] = 0xE5; /* SCA=7, hop=5. */
}

static void test_parse_and_timing(void)
{
    uint8_t pdu[BLE_CONNECT_IND_PDU_LEN];
    ble_conn_params_t params;
    uint64_t start_us;
    uint64_t end_us;
    uint8_t aa_le[4];
    uint8_t crc_le[3];

    make_connect_ind(pdu);
    CHECK_U64(ble_conn_parse_connect_ind(pdu, sizeof(pdu), &params),
              BLE_CONN_OK);
    CHECK_TRUE(params.initiator_address_random);
    CHECK_TRUE(params.advertiser_address_random);
    CHECK_U64(params.access_address, UINT32_C(0x1289BED6));
    CHECK_U64(params.crc_init, UINT32_C(0x563412));
    CHECK_U64(params.win_size_units, 2);
    CHECK_U64(params.win_offset_units, 3);
    CHECK_U64(params.interval_units, 24);
    CHECK_U64(params.used_channel_count, 37);
    CHECK_U64(params.hop_increment, 5);
    CHECK_U64(params.sleep_clock_accuracy, 7);
    CHECK_TRUE(params.connect_ind_chsel);
    CHECK_TRUE(!params.channel_algorithm_resolved);
    CHECK_U64(params.channel_algorithm, BLE_CSA_2);
    CHECK_U64(ble_conn_sca_max_ppm(params.sleep_clock_accuracy), 20);

    CHECK_U64(ble_conn_initial_window_us(&params, UINT64_C(100000),
                                         &start_us, &end_us), BLE_CONN_OK);
    CHECK_U64(start_us, 105000);
    CHECK_U64(end_us, 107500);

    ble_conn_access_address_le(&params, aa_le);
    ble_conn_crc_init_le(&params, crc_le);
    CHECK_TRUE(memcmp(aa_le, "\xD6\xBE\x89\x12", sizeof(aa_le)) == 0);
    CHECK_TRUE(memcmp(crc_le, "\x12\x34\x56", sizeof(crc_le)) == 0);
}

static void check_csa2_vector(const uint8_t map[BLE_CHANNEL_MAP_SIZE],
                              uint16_t event_counter,
                              uint16_t expected_prn,
                              uint8_t expected_channel)
{
    uint8_t channel = UINT8_MAX;
    CHECK_U64(ble_csa2_prn_e(BLE_ADV_ACCESS_ADDRESS, event_counter),
              expected_prn);
    CHECK_U64(ble_csa2_channel(map, BLE_ADV_ACCESS_ADDRESS, event_counter,
                               &channel), BLE_CONN_OK);
    CHECK_U64(channel, expected_channel);
}

static void test_csa2_sig_vectors(void)
{
    /* Bluetooth Core, Vol 6, Part C, Section 3. */
    static const uint8_t all_channels[BLE_CHANNEL_MAP_SIZE] = {
        0xFF, 0xFF, 0xFF, 0xFF, 0x1F
    };
    static const uint8_t nine_channels[BLE_CHANNEL_MAP_SIZE] = {
        0x00, 0x06, 0xE0, 0x00, 0x1E
    };
    static const uint8_t three_channels[BLE_CHANNEL_MAP_SIZE] = {
        0x06, 0x01, 0x00, 0x00, 0x00
    };
    static const uint16_t prn_all[] = {56857, 1685, 38301, 27475};
    static const uint8_t channel_all[] = {25, 20, 6, 21};
    static const uint16_t prn_nine[] = {10975, 5490, 46970};
    static const uint8_t channel_nine[] = {23, 9, 34};
    static const uint16_t prn_three[] = {8628, 34748, 22072};
    static const uint8_t channel_three[] = {1, 2, 2};

    CHECK_U64(ble_csa2_channel_identifier(BLE_ADV_ACCESS_ADDRESS), 0x305F);
    for (uint16_t event = 0; event < 4; event++) {
        check_csa2_vector(all_channels, event, prn_all[event],
                          channel_all[event]);
    }
    for (uint16_t i = 0; i < 3; i++) {
        check_csa2_vector(nine_channels, (uint16_t)(6 + i), prn_nine[i],
                          channel_nine[i]);
        check_csa2_vector(three_channels, (uint16_t)(11 + i), prn_three[i],
                          channel_three[i]);
    }
}

static void test_csa1_selection_and_counter_wrap(void)
{
    static const uint8_t all_channels[BLE_CHANNEL_MAP_SIZE] = {
        0xFF, 0xFF, 0xFF, 0xFF, 0x1F
    };
    static const uint8_t sparse_channels[BLE_CHANNEL_MAP_SIZE] = {
        0x06, 0x01, 0x00, 0x00, 0x00
    };
    static const uint8_t all_expected[] = {5, 10, 15, 20, 25, 30, 35, 3};
    static const uint8_t sparse_expected[] = {8, 2, 1, 8, 2, 1, 8, 1};

    for (uint64_t event = 0; event < 8; event++) {
        uint8_t channel;
        CHECK_U64(ble_csa1_channel(all_channels, 5, event, &channel),
                  BLE_CONN_OK);
        CHECK_U64(channel, all_expected[event]);
        CHECK_U64(ble_csa1_channel(sparse_channels, 5, event, &channel),
                  BLE_CONN_OK);
        CHECK_U64(channel, sparse_expected[event]);
    }

    /* CSA#1 state must not reset merely because connEventCounter wraps. */
    uint8_t before_wrap;
    uint8_t after_wrap;
    CHECK_U64(ble_csa1_channel(all_channels, 5, UINT64_C(65535),
                               &before_wrap), BLE_CONN_OK);
    CHECK_U64(ble_csa1_channel(all_channels, 5, UINT64_C(65536),
                               &after_wrap), BLE_CONN_OK);
    CHECK_U64(before_wrap, 8);
    CHECK_U64(after_wrap, 13);
}

static void test_whitening_sig_vector(void)
{
    /* First 64 channel-0 bits from Core Vol 6, Part C, Section 4.1,
     * packed LSB-first because BLE transmits each octet LSB-first. */
    static const uint8_t expected[8] = {
        0x40, 0xB2, 0xBC, 0xC3, 0x1F, 0x37, 0x4A, 0x5F
    };
    uint8_t sequence[sizeof(expected)] = {0};

    CHECK_U64(ble_whitening_iv(0), 0x40);
    CHECK_U64(ble_whitening_iv(37), 0x65);
    CHECK_U64(ble_whiten(sequence, sizeof(sequence), 0), BLE_CONN_OK);
    CHECK_TRUE(memcmp(sequence, expected, sizeof(expected)) == 0);

    /* XOR is its own inverse. */
    CHECK_U64(ble_whiten(sequence, sizeof(sequence), 0), BLE_CONN_OK);
    for (size_t i = 0; i < sizeof(sequence); i++)
        CHECK_U64(sequence[i], 0);
}

static void test_crc_vector(void)
{
    /* Official WCH BLE_Connect.blemn advertising record, checked against the
     * Bluetooth Link Layer CRC polynomial and CRCInit 0x555555. */
    static const uint8_t pdu[] = {
        0x20, 0x0D, 0x02, 0x02, 0x03, 0xE4, 0xC2, 0x84,
        0x02, 0x01, 0x06, 0x03, 0x02, 0xE0, 0xFF
    };
    static const uint8_t expected[] = {0x8E, 0xD2, 0x7F};
    uint8_t actual[3] = {0};

    ble_crc24(pdu, sizeof(pdu), UINT32_C(0x555555), actual);
    CHECK_TRUE(memcmp(actual, expected, sizeof(expected)) == 0);
}

static void test_radio_event(void)
{
    uint8_t pdu[BLE_CONNECT_IND_PDU_LEN];
    ble_conn_params_t params;
    ble_conn_radio_event_t event;

    make_connect_ind(pdu);
    CHECK_U64(ble_conn_parse_connect_ind(pdu, sizeof(pdu), &params),
              BLE_CONN_OK);
    CHECK_U64(ble_conn_make_radio_event(&params, 3, UINT64_C(106000),
                                        250, 400, &event),
              BLE_CONN_ERR_CSA_UNRESOLVED);
    ble_conn_resolve_channel_algorithm(&params, true);
    CHECK_TRUE(params.channel_algorithm_resolved);
    CHECK_U64(params.channel_algorithm, BLE_CSA_2);
    CHECK_U64(ble_conn_make_radio_event(&params, 3, UINT64_C(106000),
                                        250, 400, &event), BLE_CONN_OK);
    CHECK_U64(event.event_ordinal, 3);
    CHECK_U64(event.event_counter, 3);
    CHECK_U64(event.nominal_anchor_us, 196000);
    CHECK_U64(event.listen_start_us, 195750);
    CHECK_U64(event.listen_end_us, 196400);
    CHECK_U64(event.frequency_mhz,
              ble_data_channel_frequency_mhz(event.data_channel));
    CHECK_U64(event.whitening_iv, ble_whitening_iv(event.data_channel));
    CHECK_U64(event.access_address, params.access_address);
    CHECK_U64(event.crc_init, params.crc_init);
}

static void test_invalid_inputs(void)
{
    uint8_t pdu[BLE_CONNECT_IND_PDU_LEN];
    ble_conn_params_t params;

    make_connect_ind(pdu);
    CHECK_U64(ble_conn_parse_connect_ind(pdu, sizeof(pdu) - 1, &params),
              BLE_CONN_ERR_TRUNCATED);

    make_connect_ind(pdu);
    pdu[0] = 0x00;
    CHECK_U64(ble_conn_parse_connect_ind(pdu, sizeof(pdu), &params),
              BLE_CONN_ERR_PDU_TYPE);

    make_connect_ind(pdu);
    memset(pdu + 30, 0, 5);
    pdu[30] = 1;
    CHECK_U64(ble_conn_parse_connect_ind(pdu, sizeof(pdu), &params),
              BLE_CONN_ERR_CHANNEL_MAP);

    make_connect_ind(pdu);
    pdu[35] = 0xE4;
    CHECK_U64(ble_conn_parse_connect_ind(pdu, sizeof(pdu), &params),
              BLE_CONN_ERR_HOP);

    CHECK_U64(ble_whiten(NULL, 1, 0), BLE_CONN_ERR_ARGUMENT);
    CHECK_U64(ble_whiten(NULL, 0, 40), BLE_CONN_ERR_ARGUMENT);
}

int main(void)
{
    test_parse_and_timing();
    test_csa2_sig_vectors();
    test_csa1_selection_and_counter_wrap();
    test_whitening_sig_vector();
    test_crc_vector();
    test_radio_event();
    test_invalid_inputs();

    if (failures != 0) {
        fprintf(stderr, "%u BLE connection-following checks failed\n", failures);
        return 1;
    }
    puts("BLE connection-following vectors: PASS");
    return 0;
}
