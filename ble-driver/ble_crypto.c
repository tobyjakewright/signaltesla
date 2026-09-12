#include "ble_crypto.h"

#include <limits.h>
#include <openssl/evp.h>
#include <string.h>

/* LL control opcodes used by the encryption procedure. */
#define LL_ENC_REQ        UINT8_C(0x03)
#define LL_ENC_RSP        UINT8_C(0x04)
#define LL_START_ENC_REQ  UINT8_C(0x05)
#define LL_START_ENC_RSP  UINT8_C(0x06)
#define LL_TERMINATE_IND  UINT8_C(0x02)
#define LL_PAUSE_ENC_REQ  UINT8_C(0x0A)
#define LL_PAUSE_ENC_RSP  UINT8_C(0x0B)

static int hex_nibble(char value)
{
    if (value >= '0' && value <= '9')
        return value - '0';
    if (value >= 'a' && value <= 'f')
        return value - 'a' + 10;
    if (value >= 'A' && value <= 'F')
        return value - 'A' + 10;
    return -1;
}

bool ble_crypto_parse_ltk_hex(const char *text,
                              uint8_t key[BLE_CRYPTO_KEY_SIZE])
{
    if (!text || !key || strlen(text) != BLE_CRYPTO_KEY_SIZE * 2u)
        return false;

    uint8_t parsed[BLE_CRYPTO_KEY_SIZE];
    for (size_t i = 0; i < BLE_CRYPTO_KEY_SIZE; i++) {
        int high = hex_nibble(text[i * 2u]);
        int low = hex_nibble(text[i * 2u + 1u]);
        if (high < 0 || low < 0)
            return false;
        parsed[i] = (uint8_t)(((unsigned int)high << 4) |
                              (unsigned int)low);
    }
    memcpy(key, parsed, sizeof(parsed));
    return true;
}

void ble_crypto_state_init(ble_crypto_state_t *state)
{
    if (state)
        memset(state, 0, sizeof(*state));
}

void ble_crypto_reset_connection(ble_crypto_state_t *state)
{
    if (!state)
        return;

    bool has_ltk = state->has_ltk;
    uint8_t ltk[BLE_CRYPTO_KEY_SIZE];
    memcpy(ltk, state->ltk, sizeof(ltk));
    memset(state, 0, sizeof(*state));
    if (has_ltk) {
        memcpy(state->ltk, ltk, sizeof(state->ltk));
        state->has_ltk = true;
    }
    /* Avoid retaining an extra key copy on the stack. */
    memset(ltk, 0, sizeof(ltk));
}

void ble_crypto_set_ltk(ble_crypto_state_t *state,
                        const uint8_t key[BLE_CRYPTO_KEY_SIZE])
{
    if (!state || !key)
        return;
    uint8_t key_copy[BLE_CRYPTO_KEY_SIZE];
    memcpy(key_copy, key, sizeof(key_copy));
    memset(state, 0, sizeof(*state));
    memcpy(state->ltk, key_copy, BLE_CRYPTO_KEY_SIZE);
    state->has_ltk = true;
    memset(key_copy, 0, sizeof(key_copy));
}

bool ble_crypto_derive_session_key(
    const uint8_t ltk[BLE_CRYPTO_KEY_SIZE],
    const uint8_t skdm_wire[8],
    const uint8_t skds_wire[8],
    uint8_t session_key[BLE_CRYPTO_KEY_SIZE])
{
    if (!ltk || !skdm_wire || !skds_wire || !session_key)
        return false;

    /* The controller transmits each SKD half least-significant octet first.
     * AES takes the combined 128-bit value most-significant octet first:
     * reverse(SKDs_wire) || reverse(SKDm_wire). */
    uint8_t skd[BLE_CRYPTO_KEY_SIZE];
    for (size_t i = 0; i < 8; i++) {
        skd[i] = skds_wire[7u - i];
        skd[8u + i] = skdm_wire[7u - i];
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        memset(skd, 0, sizeof(skd));
        return false;
    }

    int produced = 0;
    int final_len = 0;
    bool ok = EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, ltk, NULL) == 1
           && EVP_CIPHER_CTX_set_padding(ctx, 0) == 1
           && EVP_EncryptUpdate(ctx, session_key, &produced,
                                skd, (int)sizeof(skd)) == 1
           && produced == (int)BLE_CRYPTO_KEY_SIZE
           && EVP_EncryptFinal_ex(ctx, session_key + produced, &final_len) == 1
           && final_len == 0;

    EVP_CIPHER_CTX_free(ctx);
    memset(skd, 0, sizeof(skd));
    if (!ok)
        memset(session_key, 0, BLE_CRYPTO_KEY_SIZE);
    return ok;
}

bool ble_crypto_ccm_decrypt(
    const uint8_t session_key[BLE_CRYPTO_KEY_SIZE],
    const uint8_t iv[BLE_CRYPTO_IV_SIZE],
    ble_crypto_direction_t direction,
    uint64_t packet_counter,
    uint8_t header0,
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    const uint8_t mic[BLE_CRYPTO_MIC_SIZE],
    uint8_t *plaintext)
{
    if (!session_key || !iv || !mic ||
            (ciphertext_len != 0u && (!ciphertext || !plaintext)) ||
            ciphertext_len > (size_t)INT_MAX ||
            packet_counter >= BLE_CRYPTO_COUNTER_LIMIT ||
            (direction != BLE_CRYPTO_PERIPHERAL_TO_CENTRAL &&
             direction != BLE_CRYPTO_CENTRAL_TO_PERIPHERAL))
        return false;

    uint8_t nonce[13];
    uint64_t counter = packet_counter;
    for (size_t i = 0; i < 5; i++) {
        nonce[i] = (uint8_t)counter;
        counter >>= 8;
    }
    nonce[4] &= UINT8_C(0x7F);
    if (direction == BLE_CRYPTO_CENTRAL_TO_PERIPHERAL)
        nonce[4] |= UINT8_C(0x80);
    memcpy(nonce + 5, iv, BLE_CRYPTO_IV_SIZE);

    /* NESN, SN and MD change on retransmission and are excluded from AAD. */
    uint8_t aad = header0 & UINT8_C(0xE3);
    uint8_t zero_length_dummy = 0;
    uint8_t *output = ciphertext_len == 0u ? &zero_length_dummy : plaintext;
    static const uint8_t empty_input = 0;
    const uint8_t *input = ciphertext_len == 0u ? &empty_input : ciphertext;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return false;

    int out_len = 0;
    bool ok = EVP_DecryptInit_ex(ctx, EVP_aes_128_ccm(), NULL, NULL, NULL) == 1
           && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN,
                                  (int)sizeof(nonce), NULL) == 1
           && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG,
                                  (int)BLE_CRYPTO_MIC_SIZE,
                                  (void *)(uintptr_t)mic) == 1
           && EVP_DecryptInit_ex(ctx, NULL, NULL, session_key, nonce) == 1
           && EVP_DecryptUpdate(ctx, NULL, &out_len, NULL,
                                (int)ciphertext_len) == 1
           && EVP_DecryptUpdate(ctx, NULL, &out_len, &aad, 1) == 1
           && EVP_DecryptUpdate(ctx, output, &out_len, input,
                                (int)ciphertext_len) == 1
           && out_len == (int)ciphertext_len;

    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

static bool derive_if_ready(ble_crypto_state_t *state)
{
    if (!state || !state->has_ltk || !state->have_enc_req ||
            !state->have_enc_rsp)
        return false;

    state->session_key_ready = ble_crypto_derive_session_key(
        state->ltk, state->skdm_wire, state->skds_wire,
        state->session_key);
    if (state->session_key_ready) {
        state->next_counter[BLE_CRYPTO_PERIPHERAL_TO_CENTRAL] = 0;
        state->next_counter[BLE_CRYPTO_CENTRAL_TO_PERIPHERAL] = 0;
    }
    return state->session_key_ready;
}

ble_crypto_control_t ble_crypto_observe_control(
    ble_crypto_state_t *state,
    const uint8_t *pdu,
    size_t pdu_len)
{
    if (!state || !pdu || pdu_len < 3u || (pdu[0] & UINT8_C(0x03)) != 3u)
        return BLE_CRYPTO_CONTROL_NONE;

    size_t declared = pdu[1];
    if (declared < 1u || pdu_len < declared + 2u)
        return BLE_CRYPTO_CONTROL_NONE;

    switch (pdu[2]) {
    case LL_ENC_REQ:
        /* opcode + RAND(8) + EDIV(2) + SKDm(8) + IVm(4) */
        if (declared < 23u)
            return BLE_CRYPTO_CONTROL_NONE;
        /* A new encryption request begins a fresh session but keeps the LTK. */
        state->have_enc_req = false;
        state->have_enc_rsp = false;
        state->session_key_ready = false;
        state->encryption_active = false;
        memset(state->session_key, 0, sizeof(state->session_key));
        memset(state->skds_wire, 0, sizeof(state->skds_wire));
        memset(state->iv + 4, 0, 4);
        state->next_counter[0] = 0;
        state->next_counter[1] = 0;
        memcpy(state->skdm_wire, pdu + 13, sizeof(state->skdm_wire));
        memcpy(state->iv, pdu + 21, 4);
        state->have_enc_req = true;
        return BLE_CRYPTO_CONTROL_ENC_REQ;

    case LL_ENC_RSP:
        /* opcode + SKDs(8) + IVs(4) */
        if (declared < 13u)
            return BLE_CRYPTO_CONTROL_NONE;
        memcpy(state->skds_wire, pdu + 3, sizeof(state->skds_wire));
        memcpy(state->iv + 4, pdu + 11, 4);
        state->have_enc_rsp = true;
        (void)derive_if_ready(state);
        return BLE_CRYPTO_CONTROL_ENC_RSP;

    case LL_START_ENC_REQ:
        /* The link becomes encrypted after this plaintext request even when
         * no LTK was configured.  session_key_ready separately controls
         * whether the host can authenticate/decrypt subsequent packets. */
        state->encryption_active = true;
        return BLE_CRYPTO_CONTROL_START_ENC_REQ;

    case LL_START_ENC_RSP:
        return BLE_CRYPTO_CONTROL_START_ENC_RSP;

    case LL_PAUSE_ENC_REQ:
        /* The response to the request is still protected. */
        return BLE_CRYPTO_CONTROL_PAUSE_ENC;

    case LL_PAUSE_ENC_RSP:
        state->encryption_active = false;
        return BLE_CRYPTO_CONTROL_PAUSE_ENC;

    case LL_TERMINATE_IND:
        state->encryption_active = false;
        return BLE_CRYPTO_CONTROL_NONE;

    default:
        return BLE_CRYPTO_CONTROL_NONE;
    }
}

static bool try_counter(const ble_crypto_state_t *state,
                        ble_crypto_direction_t direction,
                        uint64_t packet_counter,
                        uint8_t header0,
                        const uint8_t *ciphertext,
                        size_t ciphertext_len,
                        const uint8_t mic[BLE_CRYPTO_MIC_SIZE],
                        uint8_t *plaintext)
{
    return ble_crypto_ccm_decrypt(state->session_key, state->iv, direction,
                                  packet_counter, header0, ciphertext,
                                  ciphertext_len, mic, plaintext);
}

static bool finish_decrypt(ble_crypto_state_t *state,
                           ble_crypto_direction_t direction,
                           uint64_t packet_counter,
                           bool retransmission,
                           uint8_t header0,
                           const uint8_t *plaintext,
                           size_t plaintext_len,
                           uint8_t *plaintext_pdu,
                           size_t *plaintext_pdu_len,
                           ble_crypto_result_t *result)
{
    plaintext_pdu[0] = header0;
    plaintext_pdu[1] = (uint8_t)plaintext_len;
    if (plaintext_len != 0u)
        memcpy(plaintext_pdu + 2, plaintext, plaintext_len);
    *plaintext_pdu_len = plaintext_len + 2u;

    if (!retransmission)
        state->next_counter[direction] = packet_counter + 1u;

    if (result) {
        result->decrypted = true;
        result->mic_valid = true;
        result->retransmission = retransmission;
        result->direction = direction;
        result->packet_counter = packet_counter;
    }
    return true;
}

bool ble_crypto_decrypt_pdu(
    ble_crypto_state_t *state,
    const uint8_t *encrypted_pdu,
    size_t encrypted_pdu_len,
    uint8_t *plaintext_pdu,
    size_t plaintext_capacity,
    size_t *plaintext_pdu_len,
    ble_crypto_result_t *result)
{
    if (result)
        memset(result, 0, sizeof(*result));
    if (plaintext_pdu_len)
        *plaintext_pdu_len = 0;

    if (!state || !state->session_key_ready || !state->encryption_active ||
            !encrypted_pdu || encrypted_pdu_len < 2u || !plaintext_pdu ||
            !plaintext_pdu_len)
        return false;

    size_t encrypted_payload_len = encrypted_pdu[1];
    if (encrypted_payload_len < BLE_CRYPTO_MIC_SIZE ||
            encrypted_pdu_len < encrypted_payload_len + 2u)
        return false;

    size_t ciphertext_len = encrypted_payload_len - BLE_CRYPTO_MIC_SIZE;
    if (plaintext_capacity < ciphertext_len + 2u)
        return false;

    const uint8_t *ciphertext = encrypted_pdu + 2;
    const uint8_t *mic = ciphertext + ciphertext_len;
    uint8_t plaintext[UINT8_MAX + 1u];

    /* Search forward first so packet loss does not desynchronise the stream.
     * Alternate direction at each distance so neither side is preferred. */
    for (uint64_t distance = 0; distance < BLE_CRYPTO_COUNTER_WINDOW;
         distance++) {
        for (unsigned int raw_direction = 0; raw_direction < 2u;
             raw_direction++) {
            ble_crypto_direction_t direction =
                (ble_crypto_direction_t)raw_direction;
            uint64_t expected = state->next_counter[direction];
            if (expected >= BLE_CRYPTO_COUNTER_LIMIT ||
                    distance >= BLE_CRYPTO_COUNTER_LIMIT - expected)
                continue;
            uint64_t candidate = expected + distance;
            if (try_counter(state, direction, candidate, encrypted_pdu[0],
                            ciphertext, ciphertext_len, mic, plaintext)) {
                return finish_decrypt(state, direction, candidate, false,
                                      encrypted_pdu[0], plaintext,
                                      ciphertext_len, plaintext_pdu,
                                      plaintext_pdu_len, result);
            }
        }
    }

    /* A repeated packet reuses the previous counter.  Do not advance the
     * expected counter when its MIC authenticates. */
    for (unsigned int raw_direction = 0; raw_direction < 2u;
         raw_direction++) {
        ble_crypto_direction_t direction =
            (ble_crypto_direction_t)raw_direction;
        uint64_t expected = state->next_counter[direction];
        if (expected == 0u)
            continue;
        uint64_t candidate = expected - 1u;
        if (try_counter(state, direction, candidate, encrypted_pdu[0],
                        ciphertext, ciphertext_len, mic, plaintext)) {
            return finish_decrypt(state, direction, candidate, true,
                                  encrypted_pdu[0], plaintext, ciphertext_len,
                                  plaintext_pdu, plaintext_pdu_len, result);
        }
    }

    return false;
}
