/*
 * WCH BLE Analyzer Pro – Linux libusb driver implementation
 *
 * Protocol confirmed by reverse-engineering BleAnalyzer64.exe:
 *
 *   Command format (EP 0x02, Bulk OUT):
 *     [0xAA][CMD][len_lo][len_hi][payload…]
 *
 *   Init sequence (state=3, firmware already loaded):
 *     1. AA 84 13 00 [00 00 00 00] "BLEAnalyzer&IAP"  → EP 0x82: 33 32
 *     2. AA 81 19 00 [25-byte BLE config payload]      → starts BLE streaming
 *     3. AA A1 00 00                                   → status echo + scan
 *
 *   Data frame format (received on EP 0x82, one per USB transfer):
 *     Byte 0:    0x55 (magic)
 *     Byte 1:    0x10 (data packet) | 0x01 (status echo)
 *     Byte 2-3:  payload_len (LE uint16)
 *     Payload:
 *       [0-3]  timestamp_us (LE uint32, μs from device boot)
 *       [4]    channel/event (low six bits channel; bit 7 event phase)
 *       [5]    RF/CRC error marker (zero accepted; non-zero dropped)
 *       [6-7]  reserved
 *       [8]    rssi (signed int8, dBm)
 *       [9]    reserved
 *       [10]   pdu_hdr0 (BLE LL PDU header byte 0)
 *       [11]   pdu_payload_len (includes MIC if encrypted; excludes CRC)
 *       [12+]  advertising/data/control payload or ciphertext + MIC
 */

#include "wch_ble_analyzer.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── Protocol constants ─────────────────────────────────────────────────── */

#define WCH_MAGIC        0xAA   /* command magic byte */
#define CMD_IDENTIFY     0x84   /* identify/arm */

/* "BLEAnalyzer&IAP" – 15-byte ASCII string used in the identify command */
static const uint8_t IAP_STR[15] = {
    'B','L','E','A','n','a','l','y','z','e','r','&','I','A','P'
};

/* Device frame magic bytes */
#define FRAME_MAGIC      0x55
#define FRAME_TYPE_DATA  0x10
#define FRAME_TYPE_STS   0x01   /* status / config echo */

/* Metadata ends with the PDU length byte. Anonymous ADV_EXT_IND packets do
 * not necessarily contain a six-byte advertiser address. */
#define MIN_DATA_PAYLOAD 12

/* ── Internal helpers ───────────────────────────────────────────────────── */

static int bulk_write(wch_device_t *dev, const uint8_t *buf, int len)
{
    int xfer = 0;
    int r = libusb_bulk_transfer(dev->handle, EP_BULK_OUT,
                                 (uint8_t *)buf, len, &xfer, 1000);
    if (r != 0)
        return r;
    return xfer == len ? 0 : LIBUSB_ERROR_IO;
}

static int bulk_read(wch_device_t *dev, uint8_t *buf, int len,
                     int *got, int timeout_ms)
{
    *got = 0;
    unsigned int timeout = timeout_ms > 0 ? (unsigned int)timeout_ms : 0u;
    return libusb_bulk_transfer(dev->handle, EP_BULK_IN,
                                buf, len, got, timeout);
}

/* ── wch_init ────────────────────────────────────────────────────────────── */

int wch_init(libusb_context **ctx_out)
{
    return libusb_init(ctx_out);
}

/* ── wch_exit ────────────────────────────────────────────────────────────── */

void wch_exit(libusb_context *ctx)
{
    libusb_exit(ctx);
}

/* ── wch_find_devices ────────────────────────────────────────────────────── */

int wch_find_devices(libusb_context *ctx, wch_device_t devs[MAX_MCU_DEVICES])
{
    libusb_device **list;
    ssize_t cnt = libusb_get_device_list(ctx, &list);
    if (cnt < 0)
        return (int)cnt;

    int found = 0;
    for (ssize_t i = 0; i < cnt && found < MAX_MCU_DEVICES; i++) {
        struct libusb_device_descriptor desc;
        if (libusb_get_device_descriptor(list[i], &desc) != 0)
            continue;
        if (desc.idVendor  != WCH_VID ||
            desc.idProduct != WCH_PID_BLE_MCU)
            continue;

        memset(&devs[found], 0, sizeof(wch_device_t));
        devs[found].ctx     = ctx;
        devs[found].bus     = libusb_get_bus_number(list[i]);
        devs[found].addr    = libusb_get_device_address(list[i]);
        devs[found].is_open = false;
        found++;
    }

    libusb_free_device_list(list, 1);
    return found;
}

/* ── wch_open_device ─────────────────────────────────────────────────────── */

int wch_open_device(wch_device_t *dev)
{
    libusb_device **list;
    ssize_t cnt = libusb_get_device_list(dev->ctx, &list);
    if (cnt < 0)
        return (int)cnt;

    libusb_device *target = NULL;
    for (ssize_t i = 0; i < cnt; i++) {
        if (libusb_get_bus_number(list[i])     == dev->bus &&
            libusb_get_device_address(list[i]) == dev->addr) {
            target = list[i];
            break;
        }
    }

    if (!target) {
        libusb_free_device_list(list, 1);
        return LIBUSB_ERROR_NO_DEVICE;
    }

    int r = libusb_open(target, &dev->handle);
    libusb_free_device_list(list, 1);
    if (r != 0)
        return r;

    libusb_set_auto_detach_kernel_driver(dev->handle, 1);

    r = libusb_claim_interface(dev->handle, 0);
    if (r != 0) {
        libusb_close(dev->handle);
        dev->handle = NULL;
        return r;
    }

    dev->is_open    = true;
    dev->rx_count   = 0;
    dev->err_count  = 0;
    dev->ts_prev_us = 0;
    dev->ts_hi_us   = 0;
    dev->ts_prev_extended_us = 0;
    dev->pkt_seq    = 0;
    dev->configured_phy = WCH_BLE_PHY_1M;
    dev->connection_active = false;
    dev->connection_generation = 0;
    memset(&dev->connection, 0, sizeof(dev->connection));
    dev->previous_event_phase = UINT8_MAX;
    dev->direction_state = 0;
    dev->previous_nesn = 0;
    dev->previous_sn = 1;
    dev->rx_carry_len = 0;
    ble_crypto_state_init(&dev->crypto);
    return 0;
}

/* ── wch_close_device ────────────────────────────────────────────────────── */

void wch_close_device(wch_device_t *dev)
{
    if (!dev->is_open)
        return;
    libusb_release_interface(dev->handle, 0);
    libusb_close(dev->handle);
    dev->handle  = NULL;
    dev->is_open = false;
    ble_crypto_state_init(&dev->crypto);
}

/* ── wch_start_capture ───────────────────────────────────────────────────── */

/*
 * Confirmed init sequence for state=3 (firmware already loaded):
 *
 *   Step 1 – AA 84: identify / arm
 *     Frame: AA 84 13 00  [00 00 00 00]  "BLEAnalyzer&IAP"
 *     Response on EP 0x82: 33 32  (non-zero byte 0 → firmware present, state=3)
 *
 *   Step 2 – AA 81: BLE monitor config
 *     Frame: AA 81 19 00  [25-byte payload]
 *     Payload: [0]=0xFF (valid mask) [1]=0x01 (BLE monitor mode)
 *              [2]=channel [18]=PHY selector, plus AA/CRCInit and filters
 *     Sending this makes the device start streaming captured BLE packets.
 *     Its queued data is left for the normal packet loop.
 *
 *   Step 3 – AA A1: start-scan trigger
 *     Frame: AA A1 00 00
 *     Device sends a 29-byte status echo, then continues streaming.
 */
int wch_start_capture(wch_device_t *dev, const wch_capture_config_t *cfg)
{
    uint8_t frame[64];
    uint8_t trigger[WCH_SCAN_TRIGGER_FRAME_SIZE];
    uint8_t resp[64];
    int     got, r;

    if (!dev || !cfg ||
            (cfg->ble_channel != 37 && cfg->ble_channel != 38 &&
             cfg->ble_channel != 39) ||
            cfg->phy < WCH_BLE_PHY_1M ||
            cfg->phy > WCH_BLE_PHY_CODED_S2)
        return LIBUSB_ERROR_INVALID_PARAM;

    /* ── Step 1: AA 84 identify ─────────────────────────────────── */
    memset(frame, 0, sizeof(frame));
    frame[0] = WCH_MAGIC;
    frame[1] = CMD_IDENTIFY;
    frame[2] = 0x13;            /* payload len = 19 = 4 + 15 */
    frame[3] = 0x00;
    /* bytes [4..7] = 4-byte device ID (zeros works) */
    memcpy(frame + 8, IAP_STR, sizeof(IAP_STR));

    r = bulk_write(dev, frame, 4 + 4 + 15);
    if (r != 0)
        return r;

    /* Read response: expect 2 bytes (e.g. 33 32) indicating firmware present */
    r = bulk_read(dev, resp, sizeof(resp), &got, 2000);
    if (r != 0) {
        fprintf(stderr, "[wch bus=%d addr=%d] AA84 read error: %s\n",
                dev->bus, dev->addr, libusb_error_name(r));
        return r;
    }
    if (got < 1 || resp[0] == 0) {
        fprintf(stderr,
                "[wch bus=%d addr=%d] AA84 identify did not confirm firmware\n",
                dev->bus, dev->addr);
        return LIBUSB_ERROR_IO;
    }
    fprintf(stderr, "[wch bus=%d addr=%d] AA84 response[0]=0x%02X "
                    "(firmware present, state=3)\n",
            dev->bus, dev->addr, resp[0]);

    /* ── Step 2: AA 81 BLE monitor config ───────────────────────── */
    memset(frame, 0, sizeof(frame));
    wch_ble_monitor_config_t monitor;
    memset(&monitor, 0, sizeof(monitor));
    monitor.channel = cfg->ble_channel;
    monitor.phy = cfg->phy;
    memcpy(monitor.initiator_filter, cfg->initiator_filter,
           sizeof(monitor.initiator_filter));
    memcpy(monitor.advertiser_filter, cfg->advertiser_filter,
           sizeof(monitor.advertiser_filter));
    if (!wch_build_ble_monitor_frame(&monitor, frame))
        return LIBUSB_ERROR_INVALID_PARAM;

    r = bulk_write(dev, frame, (int)WCH_BLE_CONFIG_FRAME_SIZE);
    if (r != 0)
        return r;

    /* ── Step 3: AA A1 start-scan trigger ───────────────────────── */
    wch_build_scan_trigger_frame(trigger);
    r = bulk_write(dev, trigger, (int)sizeof(trigger));
    if (r != 0)
        return r;

    dev->configured_phy = cfg->phy;
    dev->connection_active = false;
    memset(&dev->connection, 0, sizeof(dev->connection));
    dev->previous_event_phase = UINT8_MAX;
    dev->direction_state = 0;
    dev->previous_nesn = 0;
    dev->previous_sn = 1;
    dev->rx_carry_len = 0;
    ble_crypto_state_init(&dev->crypto);
    if (cfg->has_ltk)
        ble_crypto_set_ltk(&dev->crypto, cfg->ltk);

    /* The normal packet loop drains and skips the queued status echo. */
    return 0;
}

/* ── wch_stop_capture ────────────────────────────────────────────────────── */

int wch_stop_capture(wch_device_t *dev)
{
    uint8_t frame[WCH_BLE_CONFIG_FRAME_SIZE];
    uint8_t trigger[WCH_SCAN_TRIGGER_FRAME_SIZE];

    if (!dev || !dev->is_open)
        return LIBUSB_ERROR_INVALID_PARAM;

    wch_build_capture_stop_frame(frame);
    int r = bulk_write(dev, frame, (int)sizeof(frame));
    if (r != 0)
        return r;
    wch_build_scan_trigger_frame(trigger);
    r = bulk_write(dev, trigger, (int)sizeof(trigger));
    if (r == 0) {
        dev->connection_active = false;
        dev->crypto.encryption_active = false;
    }
    return r;
}

/* ── wch_read_packets ────────────────────────────────────────────────────── */

/*
 * Reads one USB bulk transfer from EP 0x82 and decodes all device frames
 * found in the buffer.
 *
 * Device frame format:
 *   [0x55][type][len_lo][len_hi][payload…]
 *
 * type=0x10: BLE data packet – decoded and reported via callback.
 * type=0x01: status echo     – silently skipped.
 * other:     resync one byte.
 *
 * Returns number of decoded packets (≥0) or negative libusb error.
 * LIBUSB_ERROR_TIMEOUT is treated as 0 (normal when no packets arrive).
 */
int wch_read_packets(wch_device_t    *dev,
                     uint8_t         *buf,
                     wch_packet_cb_t  cb,
                     void            *user_ctx,
                     int              timeout_ms)
{
    if (!dev || !buf || dev->rx_carry_len > sizeof(dev->rx_carry) ||
            dev->rx_carry_len >= BULK_TRANSFER_SIZE)
        return LIBUSB_ERROR_INVALID_PARAM;

    size_t carry_len = dev->rx_carry_len;
    if (carry_len != 0)
        memcpy(buf, dev->rx_carry, carry_len);

    int xfer = 0;
    unsigned int timeout = timeout_ms > 0 ? (unsigned int)timeout_ms : 0u;
    int r = libusb_bulk_transfer(dev->handle, EP_BULK_IN,
                                 buf + carry_len,
                                 BULK_TRANSFER_SIZE - (int)carry_len,
                                 &xfer, timeout);
    if (r == LIBUSB_ERROR_TIMEOUT)
        return 0;
    if (r != 0)
        return r;

    int total = (int)carry_len + xfer;
    int complete = 0;
    while (complete + 4 <= total) {
        if (buf[complete] != FRAME_MAGIC) {
            complete++;
            continue;
        }
        uint16_t payload_len = (uint16_t)(
            (uint16_t)buf[complete + 2]
            | (uint16_t)((uint16_t)buf[complete + 3] << 8));
        if (payload_len > WCH_MAX_FRAME_PAYLOAD) {
            complete++;
            continue;
        }
        int frame_len = 4 + (int)payload_len;
        if (complete + frame_len > total)
            break;
        complete += frame_len;
    }

    int decoded = wch_decode_transfer(dev, buf, complete, cb, user_ctx);
    size_t trailing = (size_t)(total - complete);
    if (trailing > sizeof(dev->rx_carry)) {
        dev->rx_carry_len = 0;
        return LIBUSB_ERROR_OVERFLOW;
    }
    if (trailing != 0)
        memmove(dev->rx_carry, buf + complete, trailing);
    dev->rx_carry_len = trailing;
    return decoded;
}

/* The CH582F receive record does not contain a direction flag.  This is the
 * exact state machine used by the official v1.53 host: channel bit 7 marks an
 * event phase, while NESN/SN disambiguate packets inside the same event. */
static uint8_t classify_data_packet(wch_device_t *dev,
                                    uint8_t raw_channel,
                                    uint8_t header0,
                                    uint8_t *sequence_class)
{
    uint8_t nesn = (header0 >> 2) & UINT8_C(1);
    uint8_t sn = (header0 >> 3) & UINT8_C(1);
    uint8_t packet_class;

    if (dev->previous_sn != nesn) {
        packet_class = dev->previous_nesn != sn ? 1 : 0;
    } else if (dev->previous_nesn == nesn) {
        packet_class = dev->previous_sn == sn ? 2 : 3;
    } else {
        packet_class = 3;
    }

    uint8_t event_phase = raw_channel & UINT8_C(0x80);
    uint8_t reverse_direction;
    if (event_phase != dev->previous_event_phase) {
        reverse_direction = 0;
        dev->direction_state = nesn != sn ? 1 : 0;
    } else {
        reverse_direction = dev->direction_state ^ (nesn != sn ? 1 : 0);
    }

    dev->previous_event_phase = event_phase;
    dev->previous_nesn = nesn;
    dev->previous_sn = sn;
    if (sequence_class)
        *sequence_class = packet_class;

    return reverse_direction != 0
         ? WCH_DIRECTION_ADVERTISER_TO_INITIATOR
         : WCH_DIRECTION_INITIATOR_TO_ADVERTISER;
}

int wch_decode_transfer(wch_device_t    *dev,
                        const uint8_t   *buf,
                        int              transfer_len,
                        wch_packet_cb_t  cb,
                        void            *user_ctx)
{
    if (!dev || !buf || transfer_len < 4)
        return 0;

    int decoded = 0;
    int offset  = 0;

    while (offset + 4 <= transfer_len) {
        if (buf[offset] != FRAME_MAGIC) {
            offset++;
            continue;
        }

        uint8_t  ftype      = buf[offset + 1];
        uint16_t plen       = (uint16_t)(
            (uint16_t)buf[offset + 2]
            | (uint16_t)((uint16_t)buf[offset + 3] << 8));
        if (plen > WCH_MAX_FRAME_PAYLOAD) {
            offset++;
            continue;
        }
        int      frame_size = 4 + (int)plen;

        if (offset + frame_size > transfer_len)
            break;   /* truncated frame – wait for more data */

        /* Status echo: skip silently */
        if (ftype == FRAME_TYPE_STS) {
            offset += frame_size;
            dev->err_count++;
            continue;
        }

        /* Unknown type: skip */
        if (ftype != FRAME_TYPE_DATA) {
            offset++;
            continue;
        }

        /* Data frame: need at least MIN_DATA_PAYLOAD bytes of payload */
        if (plen < MIN_DATA_PAYLOAD) {
            offset += frame_size;
            continue;
        }

        /* Raw payload byte 5 is the firmware's CRC/error marker.  The vendor
         * host drops non-zero records and labels them as RF/CRC errors. */
        if (buf[offset + 9] != 0) {
            offset += frame_size;
            dev->err_count++;
            continue;
        }

        const uint8_t *p = buf + offset + 4;  /* payload start */

        uint8_t  raw_channel  = p[4];
        uint8_t  channel      = raw_channel & UINT8_C(0x3F);
        if (channel > 39) {
            offset += frame_size;
            continue;
        }

        uint32_t ts32         = (uint32_t)p[0] | ((uint32_t)p[1] << 8)
                              | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
        uint8_t  flags        = p[5];
        int8_t   rssi         = (int8_t)p[8];
        uint8_t  pdu_hdr0     = p[10];
        uint8_t  pdu_plen     = p[11];

        /* Full de-whitened LL PDU: header, length, and payload. */
        const uint8_t *pdu = p + 10;
        int pdu_len = 2 + (int)pdu_plen;
        int avail = (int)plen - 10;
        if (pdu_len > avail)
            pdu_len = avail;
        const uint8_t *callback_pdu = pdu;
        int callback_pdu_len = pdu_len;
        uint8_t decrypted_pdu[UINT8_MAX + 2u];

        bool is_data = channel < 37 && dev->connection_active;
        uint8_t pkt_type_ble = is_data
                             ? (pdu_hdr0 & UINT8_C(0x03))
                             : (pdu_hdr0 & UINT8_C(0x0F));

        /* Extend 32-bit device timestamp to 64-bit */
        if (dev->pkt_seq != 0 && ts32 < dev->ts_prev_us)
            dev->ts_hi_us += UINT64_C(0x100000000);
        uint64_t ts64 = dev->ts_hi_us | ts32;
        uint64_t dt = dev->pkt_seq == 0
                    ? 0 : ts64 - dev->ts_prev_extended_us;
        dev->ts_prev_us = ts32;
        dev->ts_prev_extended_us = ts64;

        /* Build wch_pkt_hdr_t */
        wch_pkt_hdr_t hdr;
        memset(&hdr, 0, sizeof(hdr));
        hdr.rssi         = rssi;
        hdr.pkt_type     = pkt_type_ble;
        hdr.direction    = WCH_DIRECTION_UNKNOWN;
        hdr.link_layer   = is_data ? WCH_LINK_DATA : WCH_LINK_ADVERTISING;
        hdr.raw_channel  = raw_channel;
        hdr.device_flags = flags;
        hdr.phy           = (uint8_t)dev->configured_phy;
        hdr.access_addr  = BLE_ADV_ACCESS_ADDRESS;
        hdr.crc_init     = UINT32_C(0x555555);
        hdr.channel_index = channel;
        hdr.timestamp_us = ts64;
        hdr.interval_us  = dt;
        hdr.pkt_index    = dev->pkt_seq++;

        if (is_data) {
            if (dev->connection_active) {
                hdr.access_addr = dev->connection.access_address;
                hdr.crc_init = dev->connection.crc_init;
                memcpy(hdr.initiator_addr, dev->connection.initiator_address, 6);
                memcpy(hdr.advertiser_addr, dev->connection.advertiser_address, 6);
                hdr.direction = classify_data_packet(dev, raw_channel,
                                                     pdu_hdr0,
                                                     &hdr.sequence_class);
                if (hdr.direction == WCH_DIRECTION_INITIATOR_TO_ADVERTISER) {
                    memcpy(hdr.src_addr, hdr.initiator_addr, 6);
                    memcpy(hdr.dst_addr, hdr.advertiser_addr, 6);
                } else {
                    memcpy(hdr.src_addr, hdr.advertiser_addr, 6);
                    memcpy(hdr.dst_addr, hdr.initiator_addr, 6);
                }
            }
        } else {
            /* Decode only addresses whose positions are defined by this
             * advertising PDU type. ADV_EXT_IND does not begin with AdvA. */
            const uint8_t *adv_payload = pdu + 2;
            int adv_avail = pdu_len - 2;
            if (adv_avail > (int)pdu_plen)
                adv_avail = (int)pdu_plen;

            if (pkt_type_ble <= PKT_ADV_SCAN_IND) {
                if (adv_avail >= 6)
                    memcpy(hdr.src_addr, adv_payload, 6);
                if ((pkt_type_ble == PKT_ADV_DIRECT_IND ||
                     pkt_type_ble == PKT_SCAN_REQ ||
                     pkt_type_ble == PKT_CONNECT_IND) && adv_avail >= 12)
                    memcpy(hdr.dst_addr, adv_payload + 6, 6);
            } else if (pkt_type_ble == PKT_ADV_EXT_IND && adv_avail >= 2 &&
                       (adv_payload[0] & 0x3F) >= 1) {
                uint8_t ext_len   = adv_payload[0] & 0x3F;
                uint8_t ext_flags = adv_payload[1];
                int ext_end = 1 + (int)ext_len;
                if (ext_end > adv_avail)
                    ext_end = adv_avail;
                int cursor = 2;
                if (ext_flags & 0x01) {
                    if (cursor + 6 <= ext_end)
                        memcpy(hdr.src_addr, adv_payload + cursor, 6);
                    cursor += 6;
                }
                if (ext_flags & 0x02) {
                    if (cursor + 6 <= ext_end)
                        memcpy(hdr.dst_addr, adv_payload + cursor, 6);
                }
            }

            if (pkt_type_ble == PKT_CONNECT_IND) {
                ble_conn_params_t connection;
                ble_conn_status_t status = ble_conn_parse_connect_ind(
                    pdu, (size_t)pdu_len, &connection);
                if (status == BLE_CONN_OK) {
                    dev->connection = connection;
                    dev->connection_active = true;
                    dev->connection_generation++;
                    dev->previous_event_phase = UINT8_MAX;
                    dev->direction_state = 0;
                    dev->previous_nesn = 0;
                    dev->previous_sn = 1;
                    ble_crypto_reset_connection(&dev->crypto);
                    memcpy(hdr.initiator_addr, connection.initiator_address, 6);
                    memcpy(hdr.advertiser_addr, connection.advertiser_address, 6);
                }
            }
        }

        /* The USB record omits the on-air CRC.  Reconstruct it over the exact
         * captured PDU before any AES-CCM replacement so a decrypted PCAP
         * still retains the checksum associated with the encrypted bytes. */
        ble_crc24(pdu, (size_t)pdu_len, hdr.crc_init, hdr.crc);

        if (is_data) {
            bool on_air_encrypted = dev->crypto.encryption_active;
            if (on_air_encrypted) {
                hdr.encrypted = 1;
                if (dev->crypto.session_key_ready) {
                    size_t plaintext_len = 0;
                    ble_crypto_result_t crypto_result;
                    hdr.mic_checked = 1;
                    if (ble_crypto_decrypt_pdu(
                            &dev->crypto, pdu, (size_t)pdu_len,
                            decrypted_pdu, sizeof(decrypted_pdu),
                            &plaintext_len, &crypto_result)) {
                        hdr.decrypted = 1;
                        hdr.mic_valid = crypto_result.mic_valid ? 1 : 0;
                        hdr.retransmission =
                            crypto_result.retransmission ? 1 : 0;
                        hdr.packet_counter_valid = 1;
                        hdr.packet_counter = crypto_result.packet_counter;
                        callback_pdu = decrypted_pdu;
                        callback_pdu_len = (int)plaintext_len;

                        /* MIC validation is authoritative for direction and
                         * also protects the plaintext used by the UI/PCAP. */
                        hdr.direction = crypto_result.direction ==
                                BLE_CRYPTO_CENTRAL_TO_PERIPHERAL
                                      ? WCH_DIRECTION_INITIATOR_TO_ADVERTISER
                                      : WCH_DIRECTION_ADVERTISER_TO_INITIATOR;
                        if (hdr.direction ==
                                WCH_DIRECTION_INITIATOR_TO_ADVERTISER) {
                            memcpy(hdr.src_addr, hdr.initiator_addr, 6);
                            memcpy(hdr.dst_addr, hdr.advertiser_addr, 6);
                        } else {
                            memcpy(hdr.src_addr, hdr.advertiser_addr, 6);
                            memcpy(hdr.dst_addr, hdr.initiator_addr, 6);
                        }

                        (void)ble_crypto_observe_control(
                            &dev->crypto, callback_pdu,
                            (size_t)callback_pdu_len);
                    }
                }
            } else {
                /* LL_ENC_REQ/RSP and LL_START_ENC_REQ are still plaintext.
                 * Observing them derives the session key and starts the CCM
                 * counter state for the next packet. */
                (void)ble_crypto_observe_control(&dev->crypto, pdu,
                                                 (size_t)pdu_len);
            }
        }

        dev->rx_count++;
        if (cb)
            cb(&hdr, callback_pdu, callback_pdu_len, user_ctx);

        decoded++;
        offset += frame_size;
    }

    return decoded;
}

/* ── Utility ──────────────────────────────────────────────────────────────── */

const char *wch_pkt_type_name(uint8_t pkt_type)
{
    switch (pkt_type) {
    case PKT_ADV_IND:                 return "ADV_IND";
    case PKT_ADV_DIRECT_IND:          return "ADV_DIRECT_IND";
    case PKT_ADV_NONCONN_IND:         return "ADV_NONCONN_IND";
    case PKT_SCAN_REQ:                return "SCAN_REQ";
    case PKT_SCAN_RSP:                return "SCAN_RSP";
    case PKT_CONNECT_IND:             return "CONNECT_IND";
    case PKT_ADV_SCAN_IND:            return "ADV_SCAN_IND";
    case PKT_ADV_EXT_IND:             return "ADV_EXT_IND";
    case PKT_CRC_ERR:                 return "CRC_ERR";
    case PKT_MISS:                    return "PKT_MISS";
    case PKT_LL_EMPTY:                return "LL_EMPTY";
    default: {
        static char buf[8];
        snprintf(buf, sizeof(buf), "0x%02X", pkt_type);
        return buf;
    }
    }
}

const char *wch_data_pdu_name(uint8_t llid,
                              const uint8_t *pdu,
                              int pdu_len)
{
    if (llid == 1)
        return pdu_len <= 2 || (pdu && pdu[1] == 0)
             ? "LL_EMPTY" : "LL_CONTINUATION";
    if (llid == 2)
        return "LL_DATA";
    if (llid != 3 || !pdu || pdu_len < 3)
        return "LL_RESERVED";

    switch (pdu[2]) {
    case 0x00: return "LL_CONNECTION_UPDATE_IND";
    case 0x01: return "LL_CHANNEL_MAP_IND";
    case 0x02: return "LL_TERMINATE_IND";
    case 0x03: return "LL_ENC_REQ";
    case 0x04: return "LL_ENC_RSP";
    case 0x05: return "LL_START_ENC_REQ";
    case 0x06: return "LL_START_ENC_RSP";
    case 0x07: return "LL_UNKNOWN_RSP";
    case 0x08: return "LL_FEATURE_REQ";
    case 0x09: return "LL_FEATURE_RSP";
    case 0x0A: return "LL_PAUSE_ENC_REQ";
    case 0x0B: return "LL_PAUSE_ENC_RSP";
    case 0x0C: return "LL_VERSION_IND";
    case 0x0D: return "LL_REJECT_IND";
    case 0x0E: return "LL_PERIPHERAL_FEATURE_REQ";
    case 0x0F: return "LL_CONNECTION_PARAM_REQ";
    case 0x10: return "LL_CONNECTION_PARAM_RSP";
    case 0x11: return "LL_REJECT_EXT_IND";
    case 0x12: return "LL_PING_REQ";
    case 0x13: return "LL_PING_RSP";
    case 0x14: return "LL_LENGTH_REQ";
    case 0x15: return "LL_LENGTH_RSP";
    case 0x16: return "LL_PHY_REQ";
    case 0x17: return "LL_PHY_RSP";
    case 0x18: return "LL_PHY_UPDATE_IND";
    case 0x19: return "LL_MIN_USED_CHANNELS_IND";
    case 0x1A: return "LL_CTE_REQ";
    case 0x1B: return "LL_CTE_RSP";
    case 0x1C: return "LL_PERIODIC_SYNC_IND";
    case 0x1D: return "LL_CLOCK_ACCURACY_REQ";
    case 0x1E: return "LL_CLOCK_ACCURACY_RSP";
    case 0x1F: return "LL_CIS_REQ";
    case 0x20: return "LL_CIS_RSP";
    case 0x21: return "LL_CIS_IND";
    case 0x22: return "LL_CIS_TERMINATE_IND";
    case 0x23: return "LL_POWER_CONTROL_REQ";
    case 0x24: return "LL_POWER_CONTROL_RSP";
    case 0x25: return "LL_POWER_CHANGE_IND";
    default:   return "LL_CONTROL";
    }
}

void wch_mac_to_str(const uint8_t mac[6], char out[18])
{
    snprintf(out, 18, "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[5], mac[4], mac[3], mac[2], mac[1], mac[0]);
}

void wch_print_packet(const wch_pkt_hdr_t *hdr,
                      const uint8_t       *pdu,
                      int                  pdu_len)
{
    char src[18], dst[18];
    wch_mac_to_str(hdr->src_addr, src);
    wch_mac_to_str(hdr->dst_addr, dst);

    const char *packet_name = hdr->encrypted && !hdr->decrypted
                            ? "LL_ENCRYPTED"
                            : (hdr->link_layer == WCH_LINK_DATA
                               ? wch_data_pdu_name(hdr->pkt_type, pdu, pdu_len)
                               : wch_pkt_type_name(hdr->pkt_type));

    printf("[%12llu us] ch%02u  %-28s  rssi %4d dBm  AA %08X  %s",
           (unsigned long long)hdr->timestamp_us,
           hdr->channel_index,
           packet_name,
           (int)hdr->rssi,
           hdr->access_addr,
           src);

    if (hdr->link_layer == WCH_LINK_DATA ||
            hdr->pkt_type == PKT_SCAN_REQ ||
            hdr->pkt_type == PKT_CONNECT_IND)
        printf("→%s", dst);

    if (hdr->decrypted)
        printf("  AES-CCM ok ctr=%llu%s",
               (unsigned long long)hdr->packet_counter,
               hdr->retransmission ? " retransmission" : "");
    else if (hdr->encrypted)
        printf("  encrypted%s", hdr->mic_checked ? " MIC-failed" : "");

    if (pdu && pdu_len > 0) {
        int show = (pdu_len < 24) ? pdu_len : 24;
        printf("  PDU[%d]:", pdu_len);
        for (int i = 0; i < show; i++)
            printf(" %02x", pdu[i]);
        if (pdu_len > show)
            printf(" ...");
    }
    putchar('\n');
}
