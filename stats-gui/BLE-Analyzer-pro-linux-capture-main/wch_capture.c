/*
 * wch_capture – CLI BLE packet capture tool for the WCH BLE Analyzer Pro
 *
 * _POSIX_C_SOURCE 200112L is required for sigaction(2) under -std=c11.
 */
#define _POSIX_C_SOURCE 200112L

/*
 *
 * Usage:
 *   wch_capture [OPTIONS]
 *
 * Options:
 *   -v            Verbose: print every packet to stdout
 *   -J            Emit one machine-readable JSON object per packet to stdout
 *   -w FILE.pcap  Write captured packets to a PCAP file
 *   -p PHY        LE 1M, 2M, Coded S8, or Coded S2
 *   -c CHAN       0=all advertising channels, or pin to 37/38/39
 *   -i/-a MAC     Optional initiator/advertiser filters
 *   -k LTK        Optional known 128-bit key for live AES-CCM decryption
 *   -V            Print the machine-readable driver capability marker
 *   -h            Show this help
 *
 * Signals:
 *   SIGINT / SIGTERM   Stop capture and exit cleanly.
 *
 * PCAP output uses DLT_BLUETOOTH_LE_LL_WITH_PHDR (256), which Wireshark
 * decodes natively.  The pseudo-header is 10 bytes:
 *
 *   uint8_t  rf_channel          (0-39)
 *   int8_t   signal_power        (RSSI dBm, or 0x80 = invalid)
 *   int8_t   noise_power         (0x80 = invalid)
 *   uint8_t  access_address_offenses
 *   uint32_t reference_access_address (LE)
 *   uint16_t flags               (LE)
 *
 * Flags bit assignments (Wireshark packet-btle.h):
 *   bit 0: DEWHITENED      – data already de-whitened by hardware (MUST be 1)
 *   bit 1: SIGPOWER_VALID  – signal_power field is valid
 *   bit 2: NOISE_VALID     – noise_power field is valid
 *   0x0008: DECRYPTED      – payload was decrypted
 *   0x0010: REF_AA_VALID   – reference_access_address is valid
 *   0x0400: CRC_CHECKED    – reconstructed CRC was checked by hardware
 *   0x0800: CRC_VALID      – hardware accepted this packet
 *   0x1000: MIC_CHECKED    – set only after host AES-CCM verification
 *   0x2000: MIC_VALID      – set only after host AES-CCM verification
 */

#include "wch_ble_analyzer.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <signal.h>
#include <getopt.h>
#include <errno.h>
#include <time.h>

/* ── BLE channel → RF channel conversion ────────────────────────────────── */

/*
 * DLT_BLUETOOTH_LE_LL_WITH_PHDR rf_channel field is the PHYSICAL RF channel
 * index where 0 = 2402 MHz, 1 = 2404 MHz, ..., n = 2402+2n MHz.
 * This is NOT the same as the BLE logical channel index (0-39):
 *   BLE ch 37 → RF ch  0  (2402 MHz, advertising)
 *   BLE ch 38 → RF ch 12  (2426 MHz, advertising)
 *   BLE ch 39 → RF ch 39  (2480 MHz, advertising)
 *   BLE ch  0 → RF ch  1  (2404 MHz, data)
 *   BLE ch 1-10 → RF ch 2-11
 *   BLE ch 11-36 → RF ch 13-38
 */
static uint8_t ble_ch_to_rf_ch(uint8_t ch)
{
    if (ch == 37) return 0;
    if (ch == 38) return 12;
    if (ch == 39) return 39;
    if (ch <= 10) return ch + 1;
    return ch + 2;
}

/* ── PCAP file format ───────────────────────────────────────────────────── */

#define PCAP_MAGIC        0xa1b2c3d4u
#define PCAP_VERSION_MAJ  2
#define PCAP_VERSION_MIN  4
#define PCAP_SNAPLEN      65535
#define PCAP_DLT_BLE_LL_WITH_PHDR  256   /* Wireshark DLT for BLE LL + phdr */

#pragma pack(push, 1)
typedef struct {
    uint32_t magic;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t  thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;
} pcap_file_hdr_t;

typedef struct {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
} pcap_rec_hdr_t;

/* DLT_BLUETOOTH_LE_LL_WITH_PHDR pseudo-header (10 bytes) */
typedef struct {
    uint8_t  rf_channel;
    int8_t   signal_power;
    int8_t   noise_power;
    uint8_t  access_address_offenses;
    uint32_t reference_access_address;
    uint16_t flags;
} ble_phdr_t;
#pragma pack(pop)

/* ── Globals ────────────────────────────────────────────────────────────── */

static volatile sig_atomic_t g_stop = 0;

static void sig_handler(int sig)
{
    (void)sig;
    g_stop = 1;
}

static FILE    *g_pcap_file   = NULL;
static bool     g_verbose     = false;
static bool     g_json        = false;
static uint64_t g_pkt_count   = 0;

typedef struct {
    int mcu_index;
    int usb_bus;
    int usb_address;
} packet_context_t;

/* ── PCAP helpers ───────────────────────────────────────────────────────── */

static bool pcap_open(const char *path)
{
    g_pcap_file = fopen(path, "wb");
    if (!g_pcap_file) {
        perror(path);
        return false;
    }

    pcap_file_hdr_t fh = {
        .magic         = PCAP_MAGIC,
        .version_major = PCAP_VERSION_MAJ,
        .version_minor = PCAP_VERSION_MIN,
        .thiszone      = 0,
        .sigfigs       = 0,
        .snaplen       = PCAP_SNAPLEN,
        .network       = PCAP_DLT_BLE_LL_WITH_PHDR,
    };
    fwrite(&fh, sizeof(fh), 1, g_pcap_file);
    fflush(g_pcap_file);
    return true;
}

static void pcap_write_packet(const wch_pkt_hdr_t *hdr,
                              const uint8_t       *pdu,
                              int                  pdu_len)
{
    if (!g_pcap_file)
        return;

    /*
     * Build the BLE LL pseudo-header.
     * DEWHITENED (0x0001) MUST be set: the CH582F hardware de-whitens all
     * received PDUs before sending them over USB.  Without this bit Wireshark
     * would try to re-apply whitening, producing garbled PDU type fields.
     * SIGPOWER_VALID (0x0002): RSSI from device is always valid.
     * REF_AA_VALID   (0x0010): reference_access_address is supplied for both
     * advertising and followed connection packets.
     */
    uint16_t flags = 0x0001   /* DEWHITENED         */
                   | 0x0002   /* SIGPOWER_VALID     */
                   | 0x0010   /* REF_AA_VALID       */
                   | 0x0400   /* CRC_CHECKED        */
                   | 0x0800;  /* CRC_VALID          */
    if (hdr->decrypted)
        flags |= 0x0008;      /* DECRYPTED           */
    if (hdr->mic_checked)
        flags |= 0x1000;      /* MIC_CHECKED         */
    if (hdr->mic_valid)
        flags |= 0x2000;      /* MIC_VALID           */

    ble_phdr_t ph = {
        .rf_channel               = ble_ch_to_rf_ch(hdr->channel_index),
        .signal_power             = (int8_t)hdr->rssi,
        .noise_power              = (int8_t)0x80,   /* unknown */
        .access_address_offenses  = 0,
        .reference_access_address = hdr->access_addr,
        .flags                    = flags,
    };

    /*
     * Use wall-clock time for pcap timestamps so that packets from all three
     * MCUs have monotonically increasing, comparable timestamps.  The device's
     * own 32-bit μs clock (hdr->timestamp_us) is per-MCU-boot and cannot be
     * compared across devices without synchronisation.
     */
    struct timespec now;
    clock_gettime(CLOCK_REALTIME, &now);
    uint32_t ts_sec  = (uint32_t)now.tv_sec;
    uint32_t ts_usec = (uint32_t)(now.tv_nsec / 1000);

    /*
     * Per pcap-linktype(7) for LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR (256),
     * the packet data after the 10-byte PHDR is:
     *   [Access Address 4 B] [BLE LL PDU 2+N B] [CRC 3 B]
     * Wireshark uses the Access Address to determine advertising vs. data
     * channel and routes to the correct dissector.
     */
    uint32_t aa_le = hdr->access_addr;  /* already LE uint32 */

    size_t pdu_size = pdu_len > 0 ? (size_t)pdu_len : 0u;
    uint32_t data_len = (uint32_t)(sizeof(ph) + 4u + pdu_size + 3u);

    pcap_rec_hdr_t rh = {
        .ts_sec   = ts_sec,
        .ts_usec  = ts_usec,
        .incl_len = data_len,
        .orig_len = data_len,
    };

    fwrite(&rh,    sizeof(rh),  1, g_pcap_file);
    fwrite(&ph,    sizeof(ph),  1, g_pcap_file);
    fwrite(&aa_le, 4,           1, g_pcap_file);  /* access address */
    if (pdu && pdu_size > 0u)
        fwrite(pdu, 1, pdu_size, g_pcap_file);    /* BLE LL PDU     */
    fwrite(hdr->crc, 3, 1, g_pcap_file);          /* host-reconstructed on-air CRC */
    fflush(g_pcap_file);                          /* ensure each complete record hits disk */
}

/* Emit a deliberately small, stable JSON-lines record for application use.
 * All strings are generated locally from fixed-format hexadecimal values, so
 * no general-purpose JSON escaping is needed here. */
static void json_write_packet(const wch_pkt_hdr_t *hdr,
                              const uint8_t       *pdu,
                              int                  pdu_len,
                              const packet_context_t *packet_ctx)
{
    if (!g_json)
        return;

    struct timespec now;
    clock_gettime(CLOCK_REALTIME, &now);
    uint64_t host_us = (uint64_t)now.tv_sec * UINT64_C(1000000)
                     + (uint64_t)(now.tv_nsec / 1000);

    char src[18], dst[18], initiator[18], advertiser[18];
    wch_mac_to_str(hdr->src_addr, src);
    wch_mac_to_str(hdr->dst_addr, dst);
    wch_mac_to_str(hdr->initiator_addr, initiator);
    wch_mac_to_str(hdr->advertiser_addr, advertiser);

    const char *packet_name = hdr->encrypted && !hdr->decrypted
                            ? "LL_ENCRYPTED"
                            : (hdr->link_layer == WCH_LINK_DATA
                               ? wch_data_pdu_name(hdr->pkt_type, pdu, pdu_len)
                               : wch_pkt_type_name(hdr->pkt_type));
    const char *link_name = hdr->link_layer == WCH_LINK_DATA
                          ? "data" : "advertising";
    const char *direction_name = "unknown";
    if (hdr->direction == WCH_DIRECTION_INITIATOR_TO_ADVERTISER)
        direction_name = "initiator_to_advertiser";
    else if (hdr->direction == WCH_DIRECTION_ADVERTISER_TO_INITIATOR)
        direction_name = "advertiser_to_initiator";
    const char *decrypt_status = !hdr->encrypted ? "not_encrypted"
                               : hdr->decrypted ? "decrypted"
                               : hdr->mic_checked ? "mic_failed"
                               : "unavailable";

    printf("{\"host_timestamp\":%lld.%06ld,"
           "\"host_timestamp_us\":%llu,"
           "\"device_timestamp_us\":%llu,"
           "\"mcu_index\":%d,"
           "\"usb_bus\":%d,"
           "\"usb_address\":%d,"
           "\"channel\":%u,"
           "\"raw_channel\":%u,"
           "\"device_flags\":%u,"
           "\"link_layer\":\"%s\","
           "\"phy\":\"%s\","
           "\"type_code\":%u,"
           "\"type_name\":\"%s\","
           "\"rssi\":%d,"
           "\"access_address\":\"%08X\","
           "\"crc_init\":\"%06X\","
           "\"crc\":\"%02X%02X%02X\","
           "\"crc_reconstructed\":true,"
           "\"sequence_class\":%u,"
           "\"encrypted\":%s,"
           "\"decrypted\":%s,"
           "\"mic_checked\":%s,"
           "\"mic_valid\":%s,"
           "\"decrypt_status\":\"%s\","
           "\"retransmission\":%s,"
           "\"src\":\"%s\","
           "\"dst\":",
           (long long)now.tv_sec, now.tv_nsec / 1000,
           (unsigned long long)host_us,
           (unsigned long long)hdr->timestamp_us,
           packet_ctx ? packet_ctx->mcu_index : -1,
           packet_ctx ? packet_ctx->usb_bus : -1,
           packet_ctx ? packet_ctx->usb_address : -1,
           hdr->channel_index,
           hdr->raw_channel,
           hdr->device_flags,
           link_name,
           wch_ble_phy_name((wch_ble_phy_t)hdr->phy),
           hdr->pkt_type,
           packet_name,
           (int)hdr->rssi,
           hdr->access_addr,
           hdr->crc_init,
           hdr->crc[0], hdr->crc[1], hdr->crc[2],
           hdr->sequence_class,
           hdr->encrypted ? "true" : "false",
           hdr->decrypted ? "true" : "false",
           hdr->mic_checked ? "true" : "false",
           hdr->mic_checked ? (hdr->mic_valid ? "true" : "false") : "null",
           decrypt_status,
           hdr->retransmission ? "true" : "false",
           src);

    bool has_dst = false;
    for (int i = 0; i < 6; i++) {
        if (hdr->dst_addr[i] != 0) {
            has_dst = true;
            break;
        }
    }
    if (has_dst)
        printf("\"%s\"", dst);
    else
        fputs("null", stdout);

    printf(",\"direction\":%u,\"direction_name\":\"%s\","
           "\"initiator\":\"%s\",\"advertiser\":\"%s\","
           "\"packet_counter\":",
           hdr->direction, direction_name, initiator, advertiser);
    if (hdr->packet_counter_valid)
        printf("%llu", (unsigned long long)hdr->packet_counter);
    else
        fputs("null", stdout);
    fputs(",\"pdu_hex\":\"", stdout);
    for (int i = 0; pdu && i < pdu_len; i++)
        printf("%02X", pdu[i]);
    fputs("\"}\n", stdout);
    fflush(stdout);
}

/* ── Packet callback ────────────────────────────────────────────────────── */

static void on_packet(const wch_pkt_hdr_t *hdr,
                      const uint8_t       *pdu,
                      int                  pdu_len,
                      void                *ctx)
{
    g_pkt_count++;

    /* JSON mode keeps stdout machine-readable; -v remains available when
     * JSON mode is not selected. */
    if (g_verbose && !g_json)
        wch_print_packet(hdr, pdu, pdu_len);

    json_write_packet(hdr, pdu, pdu_len, (const packet_context_t *)ctx);
    pcap_write_packet(hdr, pdu, pdu_len);
}

/* ── MAC address parsing ─────────────────────────────────────────────────── */

/* ── Usage ───────────────────────────────────────────────────────────────── */

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

/* Convert AA:BB:CC:DD:EE:FF display order to BLE on-air byte order. */
static bool parse_mac_wire_order(const char *text, uint8_t out[6])
{
    if (!text || !out || strlen(text) != 17)
        return false;

    uint8_t display[6];
    for (size_t i = 0; i < 6; i++) {
        size_t offset = i * 3;
        int high = hex_nibble(text[offset]);
        int low = hex_nibble(text[offset + 1]);
        if (high < 0 || low < 0)
            return false;
        if (i < 5 && text[offset + 2] != ':' && text[offset + 2] != '-')
            return false;
        display[i] = (uint8_t)(((unsigned int)high << 4) | (unsigned int)low);
    }
    for (size_t i = 0; i < 6; i++)
        out[i] = display[5 - i];
    return true;
}

static bool parse_phy(const char *text, wch_ble_phy_t *phy)
{
    if (!text || !phy)
        return false;
    if (strcmp(text, "1") == 0 || strcmp(text, "1M") == 0 ||
            strcmp(text, "1m") == 0) {
        *phy = WCH_BLE_PHY_1M;
        return true;
    }
    if (strcmp(text, "2") == 0 || strcmp(text, "2M") == 0 ||
            strcmp(text, "2m") == 0) {
        *phy = WCH_BLE_PHY_2M;
        return true;
    }
    if (strcmp(text, "S8") == 0 || strcmp(text, "s8") == 0 ||
            strcmp(text, "coded-s8") == 0) {
        *phy = WCH_BLE_PHY_CODED_S8;
        return true;
    }
    if (strcmp(text, "S2") == 0 || strcmp(text, "s2") == 0 ||
            strcmp(text, "coded-s2") == 0) {
        *phy = WCH_BLE_PHY_CODED_S2;
        return true;
    }
    return false;
}

static void usage(const char *prog)
{
    fprintf(stderr,
        "WCH BLE Analyzer PRO Linux Capture tool by Xecaz 2026!\n\n"
        "Usage: %s [OPTIONS]\n"
        "\n"
        "Options:\n"
        "  -v            Print packets to stdout\n"
        "  -J            JSON Lines to stdout (one complete PDU per line)\n"
        "  -w FILE.pcap  Write PCAP (DLT 256, BLE LL + phdr)\n"
        "  -p PHY        1, 2, S8, or S2 (default: 1M)\n"
        "  -c CHAN       0=ch37/38/39 (one per MCU), or pin 37, 38, or 39\n"
        "  -i MAC        Follow this initiator/central (optional)\n"
        "  -a MAC        Follow this advertiser/peripheral (optional)\n"
        "  -k LTK        Decrypt with a 128-bit LTK (exactly 32 hex digits)\n"
        "  -V            Print driver version/capabilities\n"
        "  -h            Show this help\n"
        "\n"
        "Firmware follows a captured CONNECT_IND across data channels 0-36.\n"
        "LTK decryption is live after LL_ENC_REQ/RSP; LE Secure Connections\n"
        "keys must be supplied as an LTK. Passkey derivation is not supported.\n"
        "\n"
        "Capture stops on SIGINT (Ctrl+C) or SIGTERM.\n",
        prog);
}

/* ── main ────────────────────────────────────────────────────────────────── */

int main(int argc, char *argv[])
{
    wch_capture_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.phy = WCH_BLE_PHY_1M;

    const char *pcap_path = NULL;
    int         opt;

    while ((opt = getopt(argc, argv, "vJw:p:i:a:k:K:2c:A:C:W:hV")) != -1) {
        switch (opt) {
        case 'v':
            g_verbose = true;
            break;
        case 'J':
            g_json = true;
            break;
        case 'w':
            pcap_path = optarg;
            break;
        case 'p':
            if (!parse_phy(optarg, &cfg.phy)) {
                fprintf(stderr, "PHY must be 1, 2, S8, or S2.\n");
                return 1;
            }
            break;
        case 'c': {
            char *end = NULL;
            errno = 0;
            long v = strtol(optarg, &end, 10);
            if (errno != 0 || !end || end == optarg || *end != '\0' ||
                    (v != 0 && v != 37 && v != 38 && v != 39)) {
                fprintf(stderr, "BLE channel must be 0 (all), 37, 38, or 39.\n");
                return 1;
            }
            cfg.ble_channel = (uint8_t)v;
            break;
        }
        case 'i':
            if (!parse_mac_wire_order(optarg, cfg.initiator_filter)) {
                fprintf(stderr, "Initiator MAC must use AA:BB:CC:DD:EE:FF form.\n");
                return 1;
            }
            break;
        case 'a':
            if (!parse_mac_wire_order(optarg, cfg.advertiser_filter)) {
                fprintf(stderr, "Advertiser MAC must use AA:BB:CC:DD:EE:FF form.\n");
                return 1;
            }
            break;
        case 'k':
            if (!ble_crypto_parse_ltk_hex(optarg, cfg.ltk)) {
                fprintf(stderr,
                        "LTK must be exactly 32 hexadecimal digits.\n");
                return 1;
            }
            cfg.has_ltk = true;
            break;
        case 'K':
            fprintf(stderr,
                    "Passkey derivation is not supported; supply the LTK with -k.\n");
            return 1;
        case 'V':
            puts("wch_capture 2.0 wirelessboss-native-follow-v1 ltk-aes-ccm aa81-v1.53");
            return 0;
        case '2': case 'A': case 'C': case 'W':
            fprintf(stderr, "Option -%c is not implemented by the proven Linux driver.\n", opt);
            return 1;
        case 'h':
        default:
            usage(argv[0]);
            return opt == 'h' ? 0 : 1;
        }
    }

    if (!g_verbose && !g_json && !pcap_path) {
        fprintf(stderr, "Nothing to do – use -v, -J and/or -w FILE.pcap\n");
        usage(argv[0]);
        return 1;
    }
    if (cfg.has_ltk)
        fprintf(stderr, "Live AES-CCM decryption enabled with supplied LTK.\n");

    /* Set up signal handlers */
    struct sigaction sa = { .sa_handler = sig_handler };
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    /* Initialise libusb */
    libusb_context *ctx = NULL;
    int r = wch_init(&ctx);
    if (r != 0) {
        fprintf(stderr, "libusb_init: %s\n", libusb_error_name(r));
        return 1;
    }

    /* Find MCU devices */
    wch_device_t devs[MAX_MCU_DEVICES];
    int ndev = wch_find_devices(ctx, devs);
    if (ndev <= 0) {
        fprintf(stderr, "No WCH BLE Analyzer MCUs found "
                "(VID 0x%04X / PID 0x%04X).\n"
                "Check USB connection and udev rules.\n",
                WCH_VID, WCH_PID_BLE_MCU);
        wch_exit(ctx);
        return 1;
    }
    fprintf(stderr, "Found %d MCU device(s).\n", ndev);

    /* Open all found devices */
    int opened = 0;
    for (int i = 0; i < ndev; i++) {
        r = wch_open_device(&devs[i]);
        if (r != 0) {
            fprintf(stderr, "open bus=%d addr=%d: %s\n",
                    devs[i].bus, devs[i].addr, libusb_error_name(r));
        } else {
            fprintf(stderr, "Opened bus=%d addr=%d\n",
                    devs[i].bus, devs[i].addr);
            opened++;
        }
    }
    if (opened == 0) {
        fprintf(stderr, "Could not open any device.\n");
        wch_exit(ctx);
        return 1;
    }

    /* Open PCAP output file */
    if (pcap_path && !pcap_open(pcap_path)) {
        for (int i = 0; i < ndev; i++)
            wch_close_device(&devs[i]);
        wch_exit(ctx);
        return 1;
    }

    /*
     * Send start command to all open devices.
     *
     * Channel assignment for BLE monitor mode:
     *   The hardware has 3 independent CH582F MCUs, one per BLE advertising
     *   channel (37 / 38 / 39).  Assign a different channel to each MCU so
     *   all three advertising channels are captured simultaneously.
     *   Confirmed by RE of BleAnalyzer64.exe (AA81 payload byte [2] = channel).
     */
    static const uint8_t adv_ch[3] = {37, 38, 39};
    int auto_channel_slot = 0;
    int started = 0;
    int exit_status = 0;
    bool capture_started[MAX_MCU_DEVICES] = {false};

    for (int i = 0; i < ndev; i++) {
        if (!devs[i].is_open)
            continue;

        wch_capture_config_t dev_cfg = cfg;
        /* Auto-assign by successfully opened radio, so a failed USB function
         * does not leave an avoidable gap at the start of channel coverage. */
        if (cfg.ble_channel == 0)
            dev_cfg.ble_channel = adv_ch[auto_channel_slot % 3];

        r = wch_start_capture(&devs[i], &dev_cfg);
        if (r != 0)
            fprintf(stderr, "start_capture bus=%d addr=%d: %s\n",
                    devs[i].bus, devs[i].addr, libusb_error_name(r));
        else {
            capture_started[i] = true;
            started++;
            fprintf(stderr, "  MCU %d (bus=%d addr=%d): BLE ch%d\n",
                    i, devs[i].bus, devs[i].addr, dev_cfg.ble_channel ? dev_cfg.ble_channel : 37);
        }
        if (r == 0 && cfg.ble_channel == 0)
            auto_channel_slot++;
    }
    fprintf(stderr, "Started %d MCU radio(s).\n", started);
    if (started == 0) {
        fprintf(stderr, "No analyzer radio completed its capture start sequence.\n");
        exit_status = 1;
        g_stop = 1;
    }

    /* Allocate bulk read buffers – one per device */
    uint8_t *bufs[MAX_MCU_DEVICES] = {0};
    packet_context_t packet_ctx[MAX_MCU_DEVICES];
    for (int i = 0; i < ndev; i++) {
        bufs[i] = NULL;
        packet_ctx[i].mcu_index  = i;
        packet_ctx[i].usb_bus    = devs[i].bus;
        packet_ctx[i].usb_address = devs[i].addr;
        if (devs[i].is_open && capture_started[i]) {
            bufs[i] = malloc(BULK_TRANSFER_SIZE);
            if (!bufs[i]) {
                fprintf(stderr, "Out of memory\n");
                exit_status = 1;
                g_stop = 1;
                break;
            }
        }
    }

    fprintf(stderr, "Capturing… press Ctrl+C to stop.\n");

    /*
     * Main capture loop.
     *
     * Strategy: drain each MCU's USB buffer completely before moving on.
     * This prevents the artificial 1:1:1 channel ratio caused by reading
     * exactly one bulk transfer per MCU per loop iteration.
     *
     * DRAIN_POLL_MS: short timeout used to drain buffered packets quickly.
     *   Returning 0 (timeout) means the MCU's kernel buffer is empty.
     *
     * IDLE_WAIT_MS: longer timeout used when all MCUs are quiet to avoid
     *   busy-looping while still waking up promptly when traffic arrives.
     */
#define DRAIN_POLL_MS  5    /* quick drain: check for already-buffered data  */
#define IDLE_WAIT_MS   100  /* idle wait: block until traffic arrives (per MCU) */
#define MAX_CONSECUTIVE_READ_ERRORS 5

    unsigned int consecutive_read_errors[MAX_MCU_DEVICES] = {0};

    while (!g_stop) {
        bool any_data = false;

        /* Phase 1: drain each MCU until its buffer is empty */
        for (int i = 0; i < ndev && !g_stop; i++) {
            if (!devs[i].is_open || !capture_started[i] || !bufs[i])
                continue;
            for (;;) {
                int n = wch_read_packets(&devs[i], bufs[i], on_packet,
                                         &packet_ctx[i],
                                         DRAIN_POLL_MS);
                if (n > 0) {
                    consecutive_read_errors[i] = 0;
                    any_data = true;
                    continue;
                }
                if (n == 0)
                    consecutive_read_errors[i] = 0;
                if (n < 0) {
                    consecutive_read_errors[i]++;
                    fprintf(stderr,
                            "read error bus=%d addr=%d (%u/%u): %s\n",
                            devs[i].bus, devs[i].addr,
                            consecutive_read_errors[i],
                            MAX_CONSECUTIVE_READ_ERRORS,
                            libusb_error_name(n));
                    if (n == LIBUSB_ERROR_NO_DEVICE) {
                        fprintf(stderr, "Analyzer disconnected; stopping capture.\n");
                        exit_status = 1;
                        g_stop = 1;
                    } else if (consecutive_read_errors[i] >=
                               MAX_CONSECUTIVE_READ_ERRORS) {
                        capture_started[i] = false;
                        started--;
                        exit_status = 1;
                        fprintf(stderr,
                                "Disabled MCU %d (bus=%d addr=%d) after persistent "
                                "USB read errors.\n",
                                i, devs[i].bus, devs[i].addr);
                        fprintf(stderr, "Active %d MCU radio(s).\n", started);
                        if (started == 0) {
                            fprintf(stderr,
                                    "No analyzer radios remain active; stopping capture.\n");
                            g_stop = 1;
                        }
                    } else {
                        /* Most libusb errors return immediately.  Back off so
                         * a persistent error cannot turn this into a hot loop. */
                        struct timespec retry = { .tv_sec = 0,
                                                  .tv_nsec = 100000000L };
                        nanosleep(&retry, NULL);
                    }
                }
                break;  /* n == 0 → timeout, buffer empty */
            }
        }

        /* Phase 2: when all MCUs are idle, do a longer blocking wait
         * on each MCU to reduce CPU usage until traffic resumes. */
        if (!any_data && !g_stop) {
            for (int i = 0; i < ndev && !g_stop; i++) {
                if (!devs[i].is_open || !capture_started[i] || !bufs[i])
                    continue;
                int n = wch_read_packets(&devs[i], bufs[i], on_packet,
                                         &packet_ctx[i], IDLE_WAIT_MS);
                if (n >= 0)
                    consecutive_read_errors[i] = 0;
                if (n < 0) {
                    consecutive_read_errors[i]++;
                    fprintf(stderr,
                            "read error bus=%d addr=%d (%u/%u): %s\n",
                            devs[i].bus, devs[i].addr,
                            consecutive_read_errors[i],
                            MAX_CONSECUTIVE_READ_ERRORS,
                            libusb_error_name(n));
                    if (n == LIBUSB_ERROR_NO_DEVICE) {
                        fprintf(stderr, "Analyzer disconnected; stopping capture.\n");
                        exit_status = 1;
                        g_stop = 1;
                    } else if (consecutive_read_errors[i] >=
                               MAX_CONSECUTIVE_READ_ERRORS) {
                        capture_started[i] = false;
                        started--;
                        exit_status = 1;
                        fprintf(stderr,
                                "Disabled MCU %d (bus=%d addr=%d) after persistent "
                                "USB read errors.\n",
                                i, devs[i].bus, devs[i].addr);
                        fprintf(stderr, "Active %d MCU radio(s).\n", started);
                        if (started == 0) {
                            fprintf(stderr,
                                    "No analyzer radios remain active; stopping capture.\n");
                            g_stop = 1;
                        }
                    } else {
                        struct timespec retry = { .tv_sec = 0,
                                                  .tv_nsec = 100000000L };
                        nanosleep(&retry, NULL);
                    }
                }
            }
        }
    }

    /* Stop and clean up */
    fprintf(stderr, "\nStopping capture (%llu packets)…\n",
            (unsigned long long)g_pkt_count);

    for (int i = 0; i < ndev; i++) {
        if (!devs[i].is_open)
            continue;
        if (capture_started[i])
            wch_stop_capture(&devs[i]);
        fprintf(stderr, "  bus=%d addr=%d: rx=%llu err=%llu\n",
                devs[i].bus, devs[i].addr,
                (unsigned long long)devs[i].rx_count,
                (unsigned long long)devs[i].err_count);
        wch_close_device(&devs[i]);
        free(bufs[i]);
    }

    if (g_pcap_file) {
        fflush(g_pcap_file);
        fclose(g_pcap_file);
        fprintf(stderr, "PCAP written to %s\n", pcap_path);
    }

    wch_exit(ctx);
    return exit_status;
}
