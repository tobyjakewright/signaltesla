/*
 * Bluetooth LE connection-following primitives.
 *
 * This module is intentionally independent of libusb and the WCH command
 * protocol.  It turns a captured legacy CONNECT_IND PDU into deterministic
 * radio/timing inputs, but does not claim that a particular receiver can be
 * retuned quickly enough to follow them.
 *
 * Algorithm reference: Bluetooth Core Specification, Vol 6, Part B,
 * Sections 2.3.3.1, 4.5.3, and 4.5.8.2/4.5.8.3.
 */

#ifndef BLE_CONNECTION_FOLLOW_H
#define BLE_CONNECTION_FOLLOW_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define BLE_DATA_CHANNEL_COUNT       37u
#define BLE_CHANNEL_MAP_SIZE          5u
#define BLE_CONNECT_IND_PAYLOAD_LEN  34u
#define BLE_CONNECT_IND_PDU_LEN      36u
#define BLE_ADV_ACCESS_ADDRESS UINT32_C(0x8E89BED6)

typedef enum {
    BLE_CONN_OK = 0,
    BLE_CONN_ERR_ARGUMENT = -1,
    BLE_CONN_ERR_TRUNCATED = -2,
    BLE_CONN_ERR_PDU_TYPE = -3,
    BLE_CONN_ERR_PDU_LENGTH = -4,
    BLE_CONN_ERR_WINDOW = -5,
    BLE_CONN_ERR_INTERVAL = -6,
    BLE_CONN_ERR_LATENCY = -7,
    BLE_CONN_ERR_TIMEOUT = -8,
    BLE_CONN_ERR_CHANNEL_MAP = -9,
    BLE_CONN_ERR_HOP = -10,
    BLE_CONN_ERR_OVERFLOW = -11,
    BLE_CONN_ERR_CSA_UNRESOLVED = -12
} ble_conn_status_t;

typedef enum {
    BLE_CSA_1 = 1,
    BLE_CSA_2 = 2
} ble_channel_algorithm_t;

typedef struct {
    uint8_t initiator_address[6]; /* On-air little-endian address order. */
    uint8_t advertiser_address[6];
    bool initiator_address_random;
    bool advertiser_address_random;

    uint32_t access_address;
    uint32_t crc_init;            /* Lower 24 bits are significant. */
    uint8_t win_size_units;       /* 1.25 ms units. */
    uint16_t win_offset_units;    /* 1.25 ms units. */
    uint16_t interval_units;      /* 1.25 ms units. */
    uint16_t peripheral_latency;
    uint16_t supervision_timeout_units; /* 10 ms units. */
    uint8_t channel_map[BLE_CHANNEL_MAP_SIZE];
    uint8_t used_channels[BLE_DATA_CHANNEL_COUNT];
    uint8_t used_channel_count;
    uint8_t hop_increment;
    uint8_t sleep_clock_accuracy;
    bool connect_ind_chsel;
    bool advertiser_chsel_known;
    bool advertiser_chsel;
    bool channel_algorithm_resolved;
    ble_channel_algorithm_t channel_algorithm;
} ble_conn_params_t;

typedef struct {
    uint64_t event_ordinal; /* Events since the first event; never truncated. */
    uint16_t event_counter; /* event_ordinal modulo 65536. */
    uint8_t data_channel;
    uint16_t frequency_mhz;
    uint8_t whitening_iv;
    uint32_t access_address;
    uint32_t crc_init;
    uint64_t nominal_anchor_us;
    uint64_t listen_start_us;
    uint64_t listen_end_us;
} ble_conn_radio_event_t;

/* Parse and validate a complete, de-whitened CONNECT_IND LL PDU.  The input
 * starts at the two-octet advertising PDU header and excludes AA and CRC. */
ble_conn_status_t ble_conn_parse_connect_ind(const uint8_t *pdu,
                                             size_t pdu_len,
                                             ble_conn_params_t *out);

/* CSA selection depends on ChSel from both CONNECT_IND and the advertising
 * PDU it answered.  CONNECT_IND ChSel=0 resolves to CSA#1 immediately;
 * ChSel=1 remains unresolved until this function receives the advertiser's
 * ChSel bit. */
void ble_conn_resolve_channel_algorithm(ble_conn_params_t *params,
                                        bool advertiser_chsel);

const char *ble_conn_status_string(ble_conn_status_t status);

bool ble_conn_channel_is_used(const uint8_t channel_map[BLE_CHANNEL_MAP_SIZE],
                              uint8_t channel);

/* CSA#1 uses event_ordinal rather than the 16-bit event counter so that the
 * sequence remains correct when the counter wraps. */
ble_conn_status_t ble_csa1_channel(
    const uint8_t channel_map[BLE_CHANNEL_MAP_SIZE],
    uint8_t hop_increment,
    uint64_t event_ordinal,
    uint8_t *channel_out);

uint16_t ble_csa2_channel_identifier(uint32_t access_address);
uint16_t ble_csa2_prn_e(uint32_t access_address, uint16_t event_counter);

ble_conn_status_t ble_csa2_channel(
    const uint8_t channel_map[BLE_CHANNEL_MAP_SIZE],
    uint32_t access_address,
    uint16_t event_counter,
    uint8_t *channel_out);

ble_conn_status_t ble_conn_channel_for_event(const ble_conn_params_t *params,
                                             uint64_t event_ordinal,
                                             uint8_t *channel_out);

/* Legacy CONNECT_IND first transmit window, measured from the end of the
 * CONNECT_IND packet.  The 1.25 ms transmitWindowDelay is included. */
ble_conn_status_t ble_conn_initial_window_us(const ble_conn_params_t *params,
                                             uint64_t connect_ind_end_us,
                                             uint64_t *start_us,
                                             uint64_t *end_us);

/* Build radio inputs for an event after event zero's anchor has been learned.
 * Guard values are supplied by the caller because receiver/local-clock error
 * is platform specific. */
ble_conn_status_t ble_conn_make_radio_event(
    const ble_conn_params_t *params,
    uint64_t event_ordinal,
    uint64_t first_anchor_us,
    uint64_t early_guard_us,
    uint64_t late_guard_us,
    ble_conn_radio_event_t *out);

uint16_t ble_data_channel_frequency_mhz(uint8_t data_channel);
uint8_t ble_whitening_iv(uint8_t channel);

/* Whitening and de-whitening are the same XOR operation. */
ble_conn_status_t ble_whiten(uint8_t *data, size_t len, uint8_t channel);

/* Reconstruct the three CRC octets stripped by the WCH radio.  The input is
 * the complete de-whitened two-octet LL header plus payload. */
void ble_crc24(const uint8_t *pdu,
               size_t pdu_len,
               uint32_t crc_init,
               uint8_t out[3]);

uint16_t ble_conn_sca_max_ppm(uint8_t sca);

/* Explicit wire-order helpers for a hardware configuration command. */
void ble_conn_access_address_le(const ble_conn_params_t *params,
                                uint8_t out[4]);
void ble_conn_crc_init_le(const ble_conn_params_t *params, uint8_t out[3]);

#endif /* BLE_CONNECTION_FOLLOW_H */
