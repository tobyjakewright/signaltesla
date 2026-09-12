#include "ble_connection_follow.h"

#include <limits.h>
#include <string.h>

#define BLE_UNIT_1250_US UINT64_C(1250)

static uint16_t read_le16(const uint8_t *p)
{
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

static uint32_t read_le24(const uint8_t *p)
{
    return (uint32_t)p[0]
         | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16);
}

static uint32_t read_le32(const uint8_t *p)
{
    return (uint32_t)p[0]
         | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16)
         | ((uint32_t)p[3] << 24);
}

static uint8_t reverse_bits8(uint8_t value)
{
    value = (uint8_t)(((value & UINT8_C(0x55)) << 1)
                    | ((value >> 1) & UINT8_C(0x55)));
    value = (uint8_t)(((value & UINT8_C(0x33)) << 2)
                    | ((value >> 2) & UINT8_C(0x33)));
    return (uint8_t)((value << 4) | (value >> 4));
}

static uint16_t csa2_permute(uint16_t value)
{
    return (uint16_t)((uint16_t)reverse_bits8((uint8_t)value)
         | ((uint16_t)reverse_bits8((uint8_t)(value >> 8)) << 8));
}

static uint16_t csa2_mam(uint16_t a, uint16_t b)
{
    return (uint16_t)(UINT32_C(17) * a + b);
}

static uint8_t build_remapping_table(
    const uint8_t channel_map[BLE_CHANNEL_MAP_SIZE],
    uint8_t table[BLE_DATA_CHANNEL_COUNT])
{
    uint8_t count = 0;

    if (!channel_map)
        return 0;

    for (uint8_t channel = 0; channel < BLE_DATA_CHANNEL_COUNT; channel++) {
        if (ble_conn_channel_is_used(channel_map, channel))
            table[count++] = channel;
    }
    return count;
}

static ble_conn_status_t validate_params(ble_conn_params_t *params)
{
    if (params->win_size_units < 1 || params->win_size_units > 8)
        return BLE_CONN_ERR_WINDOW;

    if (params->interval_units < 6 || params->interval_units > 3200)
        return BLE_CONN_ERR_INTERVAL;

    if (params->win_offset_units > params->interval_units ||
            params->win_size_units > params->interval_units - 1)
        return BLE_CONN_ERR_WINDOW;

    if (params->peripheral_latency > 499)
        return BLE_CONN_ERR_LATENCY;

    if (params->supervision_timeout_units < 10 ||
            params->supervision_timeout_units > 3200)
        return BLE_CONN_ERR_TIMEOUT;

    uint64_t timeout_us = (uint64_t)params->supervision_timeout_units
                        * UINT64_C(10000);
    uint64_t minimum_timeout_us =
        ((uint64_t)params->peripheral_latency + 1u)
        * (uint64_t)params->interval_units
        * BLE_UNIT_1250_US * 2u;
    if (timeout_us <= minimum_timeout_us)
        return BLE_CONN_ERR_TIMEOUT;

    if ((params->channel_map[4] & UINT8_C(0xE0)) != 0)
        return BLE_CONN_ERR_CHANNEL_MAP;

    params->used_channel_count = build_remapping_table(
        params->channel_map, params->used_channels);
    if (params->used_channel_count < 2)
        return BLE_CONN_ERR_CHANNEL_MAP;

    if (params->hop_increment < 5 || params->hop_increment > 16)
        return BLE_CONN_ERR_HOP;

    return BLE_CONN_OK;
}

ble_conn_status_t ble_conn_parse_connect_ind(const uint8_t *pdu,
                                             size_t pdu_len,
                                             ble_conn_params_t *out)
{
    if (!pdu || !out)
        return BLE_CONN_ERR_ARGUMENT;
    if (pdu_len < 2)
        return BLE_CONN_ERR_TRUNCATED;
    if ((pdu[0] & UINT8_C(0x0F)) != UINT8_C(0x05))
        return BLE_CONN_ERR_PDU_TYPE;

    uint8_t payload_len = pdu[1] & UINT8_C(0x3F);
    if (payload_len != BLE_CONNECT_IND_PAYLOAD_LEN)
        return BLE_CONN_ERR_PDU_LENGTH;
    if (pdu_len < (size_t)payload_len + 2u)
        return BLE_CONN_ERR_TRUNCATED;

    ble_conn_params_t params;
    memset(&params, 0, sizeof(params));

    const uint8_t *payload = pdu + 2;
    const uint8_t *ll_data = payload + 12;

    memcpy(params.initiator_address, payload, 6);
    memcpy(params.advertiser_address, payload + 6, 6);
    params.initiator_address_random = (pdu[0] & UINT8_C(0x40)) != 0;
    params.advertiser_address_random = (pdu[0] & UINT8_C(0x80)) != 0;
    params.access_address = read_le32(ll_data);
    params.crc_init = read_le24(ll_data + 4);
    params.win_size_units = ll_data[7];
    params.win_offset_units = read_le16(ll_data + 8);
    params.interval_units = read_le16(ll_data + 10);
    params.peripheral_latency = read_le16(ll_data + 12);
    params.supervision_timeout_units = read_le16(ll_data + 14);
    memcpy(params.channel_map, ll_data + 16, BLE_CHANNEL_MAP_SIZE);
    params.hop_increment = ll_data[21] & UINT8_C(0x1F);
    params.sleep_clock_accuracy = (ll_data[21] >> 5) & UINT8_C(0x07);
    params.connect_ind_chsel = (pdu[0] & UINT8_C(0x20)) != 0;
    params.channel_algorithm = params.connect_ind_chsel
                             ? BLE_CSA_2 : BLE_CSA_1;
    /* If CONNECT_IND says CSA#1, the advertiser's bit cannot change that
     * outcome.  A set bit requires the triggering advertisement as the
     * second input to the negotiation rule in Vol 6, Part B, 4.5. */
    params.channel_algorithm_resolved = !params.connect_ind_chsel;

    ble_conn_status_t status = validate_params(&params);
    if (status != BLE_CONN_OK)
        return status;

    *out = params;
    return BLE_CONN_OK;
}

void ble_conn_resolve_channel_algorithm(ble_conn_params_t *params,
                                        bool advertiser_chsel)
{
    if (!params)
        return;
    params->advertiser_chsel_known = true;
    params->advertiser_chsel = advertiser_chsel;
    params->channel_algorithm = params->connect_ind_chsel && advertiser_chsel
                              ? BLE_CSA_2 : BLE_CSA_1;
    params->channel_algorithm_resolved = true;
}

const char *ble_conn_status_string(ble_conn_status_t status)
{
    switch (status) {
    case BLE_CONN_OK:              return "ok";
    case BLE_CONN_ERR_ARGUMENT:    return "invalid argument";
    case BLE_CONN_ERR_TRUNCATED:   return "truncated CONNECT_IND";
    case BLE_CONN_ERR_PDU_TYPE:    return "PDU is not CONNECT_IND";
    case BLE_CONN_ERR_PDU_LENGTH:  return "invalid CONNECT_IND length";
    case BLE_CONN_ERR_WINDOW:      return "invalid transmit window";
    case BLE_CONN_ERR_INTERVAL:    return "invalid connection interval";
    case BLE_CONN_ERR_LATENCY:     return "invalid peripheral latency";
    case BLE_CONN_ERR_TIMEOUT:     return "invalid supervision timeout";
    case BLE_CONN_ERR_CHANNEL_MAP: return "invalid channel map";
    case BLE_CONN_ERR_HOP:         return "invalid hop increment";
    case BLE_CONN_ERR_OVERFLOW:    return "timestamp overflow";
    case BLE_CONN_ERR_CSA_UNRESOLVED:
        return "advertiser ChSel is required to resolve the channel algorithm";
    default:                       return "unknown connection error";
    }
}

bool ble_conn_channel_is_used(const uint8_t channel_map[BLE_CHANNEL_MAP_SIZE],
                              uint8_t channel)
{
    if (!channel_map || channel >= BLE_DATA_CHANNEL_COUNT)
        return false;
    return (channel_map[channel / 8u] & (uint8_t)(1u << (channel % 8u))) != 0;
}

ble_conn_status_t ble_csa1_channel(
    const uint8_t channel_map[BLE_CHANNEL_MAP_SIZE],
    uint8_t hop_increment,
    uint64_t event_ordinal,
    uint8_t *channel_out)
{
    uint8_t table[BLE_DATA_CHANNEL_COUNT];
    uint8_t used_count;

    if (!channel_map || !channel_out)
        return BLE_CONN_ERR_ARGUMENT;
    if (hop_increment < 5 || hop_increment > 16)
        return BLE_CONN_ERR_HOP;

    used_count = build_remapping_table(channel_map, table);
    if (used_count < 2)
        return BLE_CONN_ERR_CHANNEL_MAP;

    /* lastUnmappedChannel is zero before the first event.  Reduce before
     * multiplication so this remains safe for any uint64_t ordinal. */
    uint8_t event_step = (uint8_t)(((event_ordinal % 37u) + 1u) % 37u);
    uint8_t unmapped = (uint8_t)((event_step * hop_increment) % 37u);
    if (ble_conn_channel_is_used(channel_map, unmapped)) {
        *channel_out = unmapped;
    } else {
        *channel_out = table[unmapped % used_count];
    }
    return BLE_CONN_OK;
}

uint16_t ble_csa2_channel_identifier(uint32_t access_address)
{
    return (uint16_t)((access_address >> 16) ^ access_address);
}

uint16_t ble_csa2_prn_e(uint32_t access_address, uint16_t event_counter)
{
    uint16_t channel_id = ble_csa2_channel_identifier(access_address);
    uint16_t prn = event_counter ^ channel_id;

    for (unsigned int round = 0; round < 3; round++) {
        prn = csa2_permute(prn);
        prn = csa2_mam(prn, channel_id);
    }
    return prn ^ channel_id;
}

ble_conn_status_t ble_csa2_channel(
    const uint8_t channel_map[BLE_CHANNEL_MAP_SIZE],
    uint32_t access_address,
    uint16_t event_counter,
    uint8_t *channel_out)
{
    uint8_t table[BLE_DATA_CHANNEL_COUNT];
    uint8_t used_count;

    if (!channel_map || !channel_out)
        return BLE_CONN_ERR_ARGUMENT;
    used_count = build_remapping_table(channel_map, table);
    if (used_count < 2)
        return BLE_CONN_ERR_CHANNEL_MAP;

    uint16_t prn_e = ble_csa2_prn_e(access_address, event_counter);
    uint8_t unmapped = (uint8_t)(prn_e % 37u);
    if (ble_conn_channel_is_used(channel_map, unmapped)) {
        *channel_out = unmapped;
    } else {
        /* floor(N * prn_e / 2^16), with a wide intermediate. */
        uint8_t remapping_index =
            (uint8_t)(((uint32_t)used_count * prn_e) >> 16);
        *channel_out = table[remapping_index];
    }
    return BLE_CONN_OK;
}

ble_conn_status_t ble_conn_channel_for_event(const ble_conn_params_t *params,
                                             uint64_t event_ordinal,
                                             uint8_t *channel_out)
{
    if (!params || !channel_out)
        return BLE_CONN_ERR_ARGUMENT;
    if (!params->channel_algorithm_resolved)
        return BLE_CONN_ERR_CSA_UNRESOLVED;
    if (params->channel_algorithm == BLE_CSA_1) {
        return ble_csa1_channel(params->channel_map, params->hop_increment,
                                event_ordinal, channel_out);
    }
    if (params->channel_algorithm == BLE_CSA_2) {
        return ble_csa2_channel(params->channel_map, params->access_address,
                                (uint16_t)event_ordinal, channel_out);
    }
    return BLE_CONN_ERR_ARGUMENT;
}

ble_conn_status_t ble_conn_initial_window_us(const ble_conn_params_t *params,
                                             uint64_t connect_ind_end_us,
                                             uint64_t *start_us,
                                             uint64_t *end_us)
{
    if (!params || !start_us || !end_us)
        return BLE_CONN_ERR_ARGUMENT;

    uint64_t offset_us = (UINT64_C(1) + params->win_offset_units)
                       * BLE_UNIT_1250_US;
    uint64_t size_us = (uint64_t)params->win_size_units * BLE_UNIT_1250_US;
    if (connect_ind_end_us > UINT64_MAX - offset_us)
        return BLE_CONN_ERR_OVERFLOW;
    uint64_t start = connect_ind_end_us + offset_us;
    if (start > UINT64_MAX - size_us)
        return BLE_CONN_ERR_OVERFLOW;

    *start_us = start;
    *end_us = start + size_us;
    return BLE_CONN_OK;
}

ble_conn_status_t ble_conn_make_radio_event(
    const ble_conn_params_t *params,
    uint64_t event_ordinal,
    uint64_t first_anchor_us,
    uint64_t early_guard_us,
    uint64_t late_guard_us,
    ble_conn_radio_event_t *out)
{
    if (!params || !out)
        return BLE_CONN_ERR_ARGUMENT;

    uint64_t interval_us = (uint64_t)params->interval_units * BLE_UNIT_1250_US;
    if (event_ordinal != 0 &&
            interval_us > (UINT64_MAX - first_anchor_us) / event_ordinal)
        return BLE_CONN_ERR_OVERFLOW;
    uint64_t anchor_us = first_anchor_us + event_ordinal * interval_us;
    if (anchor_us > UINT64_MAX - late_guard_us)
        return BLE_CONN_ERR_OVERFLOW;

    uint8_t channel;
    ble_conn_status_t status = ble_conn_channel_for_event(
        params, event_ordinal, &channel);
    if (status != BLE_CONN_OK)
        return status;

    memset(out, 0, sizeof(*out));
    out->event_ordinal = event_ordinal;
    out->event_counter = (uint16_t)event_ordinal;
    out->data_channel = channel;
    out->frequency_mhz = ble_data_channel_frequency_mhz(channel);
    out->whitening_iv = ble_whitening_iv(channel);
    out->access_address = params->access_address;
    out->crc_init = params->crc_init;
    out->nominal_anchor_us = anchor_us;
    out->listen_start_us = anchor_us > early_guard_us
                         ? anchor_us - early_guard_us : 0;
    out->listen_end_us = anchor_us + late_guard_us;
    return BLE_CONN_OK;
}

uint16_t ble_data_channel_frequency_mhz(uint8_t data_channel)
{
    if (data_channel >= BLE_DATA_CHANNEL_COUNT)
        return 0;
    return data_channel <= 10
         ? (uint16_t)(2404u + 2u * data_channel)
         : (uint16_t)(2406u + 2u * data_channel);
}

uint8_t ble_whitening_iv(uint8_t channel)
{
    if (channel > 39)
        return 0;
    return (uint8_t)(UINT8_C(0x40) | channel);
}

ble_conn_status_t ble_whiten(uint8_t *data, size_t len, uint8_t channel)
{
    if ((!data && len != 0) || channel > 39)
        return BLE_CONN_ERR_ARGUMENT;

    uint8_t lfsr = ble_whitening_iv(channel);
    for (size_t octet = 0; octet < len; octet++) {
        for (uint8_t bit_index = 0; bit_index < 8; bit_index++) {
            uint8_t whitening_bit = lfsr & UINT8_C(0x01);
            if (whitening_bit != 0)
                data[octet] ^= (uint8_t)(1u << bit_index);
            lfsr >>= 1;
            if (whitening_bit != 0)
                lfsr ^= UINT8_C(0x44);
        }
    }
    return BLE_CONN_OK;
}

void ble_crc24(const uint8_t *pdu,
               size_t pdu_len,
               uint32_t crc_init,
               uint8_t out[3])
{
    if (!out)
        return;

    uint32_t state = (uint32_t)reverse_bits8((uint8_t)crc_init)
                   | ((uint32_t)reverse_bits8((uint8_t)(crc_init >> 8)) << 8)
                   | ((uint32_t)reverse_bits8((uint8_t)(crc_init >> 16)) << 16);

    if (!pdu && pdu_len != 0) {
        memset(out, 0, 3);
        return;
    }

    for (size_t octet = 0; octet < pdu_len; octet++) {
        uint8_t data = pdu[octet];
        for (uint8_t bit = 0; bit < 8; bit++, data >>= 1) {
            uint32_t feedback = (state ^ data) & UINT32_C(1);
            state >>= 1;
            if (feedback != 0)
                state ^= UINT32_C(0xDA6000);
        }
    }

    out[0] = (uint8_t)state;
    out[1] = (uint8_t)(state >> 8);
    out[2] = (uint8_t)(state >> 16);
}

uint16_t ble_conn_sca_max_ppm(uint8_t sca)
{
    static const uint16_t max_ppm[8] = {
        500, 250, 150, 100, 75, 50, 30, 20
    };
    return sca < 8 ? max_ppm[sca] : 0;
}

void ble_conn_access_address_le(const ble_conn_params_t *params,
                                uint8_t out[4])
{
    if (!params || !out)
        return;
    out[0] = (uint8_t)params->access_address;
    out[1] = (uint8_t)(params->access_address >> 8);
    out[2] = (uint8_t)(params->access_address >> 16);
    out[3] = (uint8_t)(params->access_address >> 24);
}

void ble_conn_crc_init_le(const ble_conn_params_t *params, uint8_t out[3])
{
    if (!params || !out)
        return;
    out[0] = (uint8_t)params->crc_init;
    out[1] = (uint8_t)(params->crc_init >> 8);
    out[2] = (uint8_t)(params->crc_init >> 16);
}
