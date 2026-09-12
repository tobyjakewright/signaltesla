#include "../ble_crypto.h"

#include <assert.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>

static const uint8_t LTK[16] = {
    0x4C, 0x68, 0x38, 0x41, 0x39, 0xF5, 0x74, 0xD8,
    0x36, 0xBC, 0xF3, 0x4E, 0x9D, 0xFB, 0x01, 0xBF
};

/* These are the octets as transmitted in LL_ENC_REQ/LL_ENC_RSP.  Crackle's
 * test vector prints the individually reversed halves instead. */
static const uint8_t SKDM_WIRE[8] = {
    0x13, 0x02, 0xF1, 0xE0, 0xDF, 0xCE, 0xBD, 0xAC
};
static const uint8_t SKDS_WIRE[8] = {
    0x79, 0x68, 0x57, 0x46, 0x35, 0x24, 0x13, 0x02
};
static const uint8_t SESSION_KEY[16] = {
    0x99, 0xAD, 0x1B, 0x52, 0x26, 0xA3, 0x7E, 0x3E,
    0x05, 0x8E, 0x3B, 0x8E, 0x27, 0xC2, 0xC6, 0x66
};
static const uint8_t IV[8] = {
    0x24, 0xAB, 0xDC, 0xBA, 0xBE, 0xBA, 0xAF, 0xDE
};

static void build_nonce(uint64_t counter,
                        ble_crypto_direction_t direction,
                        uint8_t nonce[13])
{
    for (size_t i = 0; i < 5; i++) {
        nonce[i] = (uint8_t)counter;
        counter >>= 8;
    }
    nonce[4] &= 0x7F;
    if (direction == BLE_CRYPTO_CENTRAL_TO_PERIPHERAL)
        nonce[4] |= 0x80;
    memcpy(nonce + 5, IV, sizeof(IV));
}

/* Test-only encryption counterpart, used to exercise lost-packet recovery at
 * a non-zero counter.  The production path intentionally exposes decryption
 * only. */
static void encrypt_vector(ble_crypto_direction_t direction,
                           uint64_t counter,
                           uint8_t header0,
                           const uint8_t *plaintext,
                           size_t plaintext_len,
                           uint8_t *ciphertext,
                           uint8_t mic[4])
{
    uint8_t nonce[13];
    build_nonce(counter, direction, nonce);
    uint8_t aad = header0 & 0xE3;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    assert(ctx != NULL);
    int output_len = 0;
    int final_len = 0;
    assert(EVP_EncryptInit_ex(ctx, EVP_aes_128_ccm(), NULL, NULL, NULL) == 1);
    assert(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN,
                               (int)sizeof(nonce), NULL) == 1);
    assert(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, 4, NULL) == 1);
    assert(EVP_EncryptInit_ex(ctx, NULL, NULL, SESSION_KEY, nonce) == 1);
    assert(EVP_EncryptUpdate(ctx, NULL, &output_len, NULL,
                             (int)plaintext_len) == 1);
    assert(EVP_EncryptUpdate(ctx, NULL, &output_len, &aad, 1) == 1);
    assert(EVP_EncryptUpdate(ctx, ciphertext, &output_len, plaintext,
                             (int)plaintext_len) == 1);
    assert(output_len == (int)plaintext_len);
    assert(EVP_EncryptFinal_ex(ctx, ciphertext + output_len, &final_len) == 1);
    assert(final_len == 0);
    assert(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_GET_TAG, 4, mic) == 1);
    EVP_CIPHER_CTX_free(ctx);
}

static void test_ltk_parser(void)
{
    uint8_t parsed[16];
    assert(ble_crypto_parse_ltk_hex(
        "4C68384139F574D836BCF34E9DFB01BF", parsed));
    assert(memcmp(parsed, LTK, sizeof(parsed)) == 0);
    assert(ble_crypto_parse_ltk_hex(
        "4c68384139f574d836bcf34e9dfb01bf", parsed));
    assert(!ble_crypto_parse_ltk_hex(
        "4C68384139F574D836BCF34E9DFB01", parsed));
    assert(!ble_crypto_parse_ltk_hex(
        "4C68384139F574D836BCF34E9DFB01XZ", parsed));
}

static void test_crackle_session_key(void)
{
    uint8_t actual[16];
    assert(ble_crypto_derive_session_key(LTK, SKDM_WIRE, SKDS_WIRE,
                                         actual));
    assert(memcmp(actual, SESSION_KEY, sizeof(actual)) == 0);
}

static void test_crackle_ccm_vectors(void)
{
    static const uint8_t slave_ciphertext[1] = {0xA3};
    static const uint8_t slave_mic[4] = {0x4C, 0x13, 0xA4, 0x15};
    static const uint8_t master_ciphertext[1] = {0x9F};
    static const uint8_t master_mic[4] = {0xCD, 0xA7, 0xF4, 0x48};
    uint8_t plaintext[1] = {0};

    assert(ble_crypto_ccm_decrypt(
        SESSION_KEY, IV, BLE_CRYPTO_PERIPHERAL_TO_CENTRAL, 0, 0x03,
        slave_ciphertext, sizeof(slave_ciphertext), slave_mic, plaintext));
    assert(plaintext[0] == 0x06);

    plaintext[0] = 0;
    assert(ble_crypto_ccm_decrypt(
        SESSION_KEY, IV, BLE_CRYPTO_CENTRAL_TO_PERIPHERAL, 0, 0x03,
        master_ciphertext, sizeof(master_ciphertext), master_mic, plaintext));
    assert(plaintext[0] == 0x06);

    uint8_t bad_mic[4];
    memcpy(bad_mic, slave_mic, sizeof(bad_mic));
    bad_mic[0] ^= 1;
    assert(!ble_crypto_ccm_decrypt(
        SESSION_KEY, IV, BLE_CRYPTO_PERIPHERAL_TO_CENTRAL, 0, 0x03,
        slave_ciphertext, sizeof(slave_ciphertext), bad_mic, plaintext));
}

static void build_encryption_control_pdus(uint8_t enc_req[25],
                                          uint8_t enc_rsp[15],
                                          uint8_t start_req[3])
{
    memset(enc_req, 0, 25);
    enc_req[0] = 0x03;
    enc_req[1] = 23;
    enc_req[2] = 0x03;
    memcpy(enc_req + 13, SKDM_WIRE, sizeof(SKDM_WIRE));
    memcpy(enc_req + 21, IV, 4);

    memset(enc_rsp, 0, 15);
    enc_rsp[0] = 0x07;
    enc_rsp[1] = 13;
    enc_rsp[2] = 0x04;
    memcpy(enc_rsp + 3, SKDS_WIRE, sizeof(SKDS_WIRE));
    memcpy(enc_rsp + 11, IV + 4, 4);

    start_req[0] = 0x03;
    start_req[1] = 1;
    start_req[2] = 0x05;
}

static void test_control_state_and_counter_recovery(void)
{
    ble_crypto_state_t state;
    uint8_t enc_req[25], enc_rsp[15], start_req[3];
    build_encryption_control_pdus(enc_req, enc_rsp, start_req);

    ble_crypto_state_init(&state);
    ble_crypto_set_ltk(&state, LTK);
    assert(state.has_ltk);
    assert(ble_crypto_observe_control(&state, enc_req, sizeof(enc_req)) ==
           BLE_CRYPTO_CONTROL_ENC_REQ);
    assert(ble_crypto_observe_control(&state, enc_rsp, sizeof(enc_rsp)) ==
           BLE_CRYPTO_CONTROL_ENC_RSP);
    assert(state.session_key_ready);
    assert(memcmp(state.session_key, SESSION_KEY, sizeof(SESSION_KEY)) == 0);
    assert(memcmp(state.iv, IV, sizeof(IV)) == 0);
    assert(ble_crypto_observe_control(&state, start_req, sizeof(start_req)) ==
           BLE_CRYPTO_CONTROL_START_ENC_REQ);
    assert(state.encryption_active);

    static const uint8_t slave_packet[7] = {
        0x03, 0x05, 0xA3, 0x4C, 0x13, 0xA4, 0x15
    };
    static const uint8_t master_packet[7] = {
        0x03, 0x05, 0x9F, 0xCD, 0xA7, 0xF4, 0x48
    };
    uint8_t output[260];
    size_t output_len = 0;
    ble_crypto_result_t result;

    assert(ble_crypto_decrypt_pdu(&state, slave_packet,
                                  sizeof(slave_packet), output,
                                  sizeof(output), &output_len, &result));
    assert(output_len == 3);
    assert(memcmp(output, "\x03\x01\x06", 3) == 0);
    assert(result.direction == BLE_CRYPTO_PERIPHERAL_TO_CENTRAL);
    assert(result.packet_counter == 0);
    assert(!result.retransmission);
    assert(state.next_counter[BLE_CRYPTO_PERIPHERAL_TO_CENTRAL] == 1);

    assert(ble_crypto_decrypt_pdu(&state, master_packet,
                                  sizeof(master_packet), output,
                                  sizeof(output), &output_len, &result));
    assert(result.direction == BLE_CRYPTO_CENTRAL_TO_PERIPHERAL);
    assert(result.packet_counter == 0);
    assert(state.next_counter[BLE_CRYPTO_CENTRAL_TO_PERIPHERAL] == 1);

    /* The same authenticated packet is recognised as a retransmission of
     * expected-1 and must not advance that direction's counter. */
    assert(ble_crypto_decrypt_pdu(&state, master_packet,
                                  sizeof(master_packet), output,
                                  sizeof(output), &output_len, &result));
    assert(result.direction == BLE_CRYPTO_CENTRAL_TO_PERIPHERAL);
    assert(result.packet_counter == 0);
    assert(result.retransmission);
    assert(state.next_counter[BLE_CRYPTO_CENTRAL_TO_PERIPHERAL] == 1);

    /* Counter 7 authenticates inside the +49 recovery window after six
     * deliberately missed packets. */
    static const uint8_t lost_plaintext[3] = {0x02, 0x13, 0x37};
    uint8_t gap_packet[2 + sizeof(lost_plaintext) + 4];
    gap_packet[0] = 0x0A;
    gap_packet[1] = (uint8_t)(sizeof(lost_plaintext) + 4);
    encrypt_vector(BLE_CRYPTO_CENTRAL_TO_PERIPHERAL, 7,
                   gap_packet[0], lost_plaintext, sizeof(lost_plaintext),
                   gap_packet + 2, gap_packet + 2 + sizeof(lost_plaintext));
    assert(ble_crypto_decrypt_pdu(&state, gap_packet, sizeof(gap_packet),
                                  output, sizeof(output), &output_len,
                                  &result));
    assert(result.direction == BLE_CRYPTO_CENTRAL_TO_PERIPHERAL);
    assert(result.packet_counter == 7);
    assert(!result.retransmission);
    assert(state.next_counter[BLE_CRYPTO_CENTRAL_TO_PERIPHERAL] == 8);
    assert(output_len == 2 + sizeof(lost_plaintext));
    assert(memcmp(output + 2, lost_plaintext, sizeof(lost_plaintext)) == 0);

    /* Encrypted empty data PDUs carry only a MIC and occur frequently. */
    uint8_t empty_packet[6] = {0x01, 0x04, 0, 0, 0, 0};
    static const uint8_t empty_plaintext = 0;
    encrypt_vector(BLE_CRYPTO_PERIPHERAL_TO_CENTRAL, 1,
                   empty_packet[0], &empty_plaintext, 0,
                   empty_packet + 2, empty_packet + 2);
    assert(ble_crypto_decrypt_pdu(&state, empty_packet,
                                  sizeof(empty_packet), output,
                                  sizeof(output), &output_len, &result));
    assert(result.direction == BLE_CRYPTO_PERIPHERAL_TO_CENTRAL);
    assert(result.packet_counter == 1);
    assert(output_len == 2);
    assert(output[0] == 0x01 && output[1] == 0x00);

    /* A new connection reset retains the configured LTK only. */
    ble_crypto_reset_connection(&state);
    assert(state.has_ltk);
    assert(memcmp(state.ltk, LTK, sizeof(LTK)) == 0);
    assert(!state.have_enc_req);
    assert(!state.session_key_ready);
    assert(!state.encryption_active);
}

static void test_encrypted_state_without_key(void)
{
    ble_crypto_state_t state;
    uint8_t enc_req[25], enc_rsp[15], start_req[3];
    build_encryption_control_pdus(enc_req, enc_rsp, start_req);
    ble_crypto_state_init(&state);
    assert(ble_crypto_observe_control(&state, enc_req, sizeof(enc_req)) ==
           BLE_CRYPTO_CONTROL_ENC_REQ);
    assert(ble_crypto_observe_control(&state, enc_rsp, sizeof(enc_rsp)) ==
           BLE_CRYPTO_CONTROL_ENC_RSP);
    assert(!state.session_key_ready);
    assert(ble_crypto_observe_control(&state, start_req, sizeof(start_req)) ==
           BLE_CRYPTO_CONTROL_START_ENC_REQ);
    assert(state.encryption_active);
}

int main(void)
{
    test_ltk_parser();
    test_crackle_session_key();
    test_crackle_ccm_vectors();
    test_control_state_and_counter_recovery();
    test_encrypted_state_without_key();
    puts("BLE LTK/AES-CCM vectors: PASS");
    return 0;
}
