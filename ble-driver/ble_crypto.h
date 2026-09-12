/*
 * Bluetooth Low Energy link-layer encryption helpers.
 *
 * This module implements the LE legacy/AES-CCM packet format used after an
 * LL_ENC_REQ / LL_ENC_RSP / LL_START_ENC_REQ exchange.  It deliberately does
 * not obtain keys: callers must supply the 128-bit LTK for a device they own
 * or are authorised to test.
 */

#ifndef BLE_CRYPTO_H
#define BLE_CRYPTO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define BLE_CRYPTO_KEY_SIZE       16u
#define BLE_CRYPTO_IV_SIZE         8u
#define BLE_CRYPTO_MIC_SIZE        4u
#define BLE_CRYPTO_COUNTER_LIMIT  UINT64_C(0x8000000000)
#define BLE_CRYPTO_COUNTER_WINDOW 50u

/* The CCM nonce direction bit is set for Central -> Peripheral packets. */
typedef enum {
    BLE_CRYPTO_PERIPHERAL_TO_CENTRAL = 0,
    BLE_CRYPTO_CENTRAL_TO_PERIPHERAL = 1
} ble_crypto_direction_t;

typedef enum {
    BLE_CRYPTO_CONTROL_NONE = 0,
    BLE_CRYPTO_CONTROL_ENC_REQ,
    BLE_CRYPTO_CONTROL_ENC_RSP,
    BLE_CRYPTO_CONTROL_START_ENC_REQ,
    BLE_CRYPTO_CONTROL_START_ENC_RSP,
    BLE_CRYPTO_CONTROL_PAUSE_ENC
} ble_crypto_control_t;

typedef struct {
    bool decrypted;
    bool mic_valid;
    bool retransmission;
    ble_crypto_direction_t direction;
    uint64_t packet_counter;
} ble_crypto_result_t;

typedef struct {
    bool has_ltk;
    bool have_enc_req;
    bool have_enc_rsp;
    bool session_key_ready;
    bool encryption_active;
    uint8_t ltk[BLE_CRYPTO_KEY_SIZE];
    uint8_t skdm_wire[8];
    uint8_t skds_wire[8];
    uint8_t iv[BLE_CRYPTO_IV_SIZE];
    uint8_t session_key[BLE_CRYPTO_KEY_SIZE];
    uint64_t next_counter[2];
} ble_crypto_state_t;

/* Parse exactly 32 hexadecimal characters, in the usual displayed key byte
 * order.  For example, "4C683841...01BF" yields bytes 4c,68,38,41,...,01,bf. */
bool ble_crypto_parse_ltk_hex(const char *text,
                              uint8_t key[BLE_CRYPTO_KEY_SIZE]);

void ble_crypto_state_init(ble_crypto_state_t *state);

/* Set or replace the LTK and clear all per-connection encryption state. */
void ble_crypto_set_ltk(ble_crypto_state_t *state,
                        const uint8_t key[BLE_CRYPTO_KEY_SIZE]);

/* Preserve the configured LTK while clearing SKD/IV/counters. */
void ble_crypto_reset_connection(ble_crypto_state_t *state);

/* Pure primitives, exposed for deterministic vectors and other capture
 * front ends.  skdm_wire/skds_wire and iv use byte order seen in LL PDUs. */
bool ble_crypto_derive_session_key(
    const uint8_t ltk[BLE_CRYPTO_KEY_SIZE],
    const uint8_t skdm_wire[8],
    const uint8_t skds_wire[8],
    uint8_t session_key[BLE_CRYPTO_KEY_SIZE]);

bool ble_crypto_ccm_decrypt(
    const uint8_t session_key[BLE_CRYPTO_KEY_SIZE],
    const uint8_t iv[BLE_CRYPTO_IV_SIZE],
    ble_crypto_direction_t direction,
    uint64_t packet_counter,
    uint8_t header0,
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    const uint8_t mic[BLE_CRYPTO_MIC_SIZE],
    uint8_t *plaintext);

/* Observe a complete, already-plaintext LL PDU ([header0][length][payload]).
 * Recognised control PDUs update the SKD, IV and encryption state. */
ble_crypto_control_t ble_crypto_observe_control(
    ble_crypto_state_t *state,
    const uint8_t *pdu,
    size_t pdu_len);

/* Authenticate and decrypt a complete encrypted LL PDU.  Direction and the
 * 39-bit per-direction packet counter are resolved by MIC validation.  Each
 * direction searches its expected counter through expected+49, followed by
 * expected-1 for a retransmission.  On success the output is a normal LL PDU
 * with the four-byte MIC removed and its length byte adjusted. */
bool ble_crypto_decrypt_pdu(
    ble_crypto_state_t *state,
    const uint8_t *encrypted_pdu,
    size_t encrypted_pdu_len,
    uint8_t *plaintext_pdu,
    size_t plaintext_capacity,
    size_t *plaintext_pdu_len,
    ble_crypto_result_t *result);

#endif /* BLE_CRYPTO_H */
