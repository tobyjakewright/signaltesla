/*
 * WCH BLE Analyzer Pro - Linux libusb driver
 *
 * Hardware: 3x CH582F BLE 5.1 RISC-V MCUs + CH334 USB 2.0 hub
 * USB IDs:  VID 0x1A86 / PID 0x8009 (WinChipHead / wch.cn)
 *           VID 0x1A86 / PID 0x8091 (CH334 hub, handled by kernel hub driver)
 *
 * USB descriptor (per CH582F MCU):
 *   Interface 0: Class 0xFF (Vendor Specific), SubClass 0x80, Protocol 0x55
 *   EP 0x81: Interrupt IN,  64 bytes  – (not used; I/O error in practice)
 *   EP 0x82: Bulk IN,       64 bytes  – captured BLE packet stream
 *   EP 0x02: Bulk OUT,      64 bytes  – host → device commands
 *
 * Three CH582F devices appear as three independent USB devices through the
 * CH334 hub.  All three MCUs receive the same init sequence and stream
 * BLE packets, normally with one MCU assigned to each primary advertising
 * channel (37/38/39).  Each MCU firmware can follow a CONNECT_IND natively
 * onto the connection's hopping data channels 0-36.
 *
 * ── CONFIRMED command protocol (EP 0x02, Bulk OUT) ──────────────────────────
 *   Frame format: [0xAA][CMD][len_lo][len_hi][payload…]
 *
 *   AA 84 13 00  [4-byte device-ID, use zeros]  "BLEAnalyzer&IAP"
 *       Identify / arm.  Response on EP 0x82: 0x33 0x32 means firmware
 *       already loaded (state=3).  State machine does NOT send AA 86 in
 *       this case.
 *
 *   AA 81 19 00  [25-byte payload]
 *       BLE monitor config.  Payload:
 *         [0]     = 0xFF (all configuration fields valid + enabled)
 *         [1]     = 0x01 (BLE monitor mode; this is not the PHY)
 *         [2]     = advertising channel 37, 38 or 39
 *         [3-4]   = zero/reserved
 *         [5-10]  = optional InitA filter, BLE wire order
 *         [11-14] = D6 BE 89 8E (advertising Access Address, wire order)
 *         [15-17] = 55 55 55 (advertising CRCInit)
 *         [18]    = 10/20/40/80 (1M/2M/Coded S8/Coded S2)
 *         [19-24] = optional AdvA filter, BLE wire order
 *       Sending this starts packet streaming on EP 0x82 immediately.
 *
 *   AA A1 00 00
 *       Start-scan trigger.  Device sends a 29-byte status echo then
 *       continues streaming BLE packets on EP 0x82.
 *
 *   AA 85  [firmware upload chunks – only needed when device has no firmware]
 *   AA 86  [configure after firmware upload – NOT sent in normal operation]
 *
 * ── Packet format received on EP 0x82 ───────────────────────────────────────
 *   Each USB transfer carries one device frame:
 *
 *   Byte  Size  Field
 *   ────  ────  ─────
 *      0     1  0x55  (frame magic)
 *      1     1  0x10  (data packet type; 0x01 = status echo, others: skip)
 *      2     2  payload_len  (LE uint16, number of bytes that follow)
 *   --- payload (payload_len bytes) ---
 *      4     4  timestamp_us  (LE uint32, microseconds from device boot)
 *      8     1  channel/event (low 6 bits BLE channel 0-39; bit7 event phase)
 *      9     1  error marker  (zero valid; nonzero RF/CRC error)
 *     10     2  reserved
 *     12     1  rssi          (signed int8, dBm)
 *     13     1  reserved
 *     14     1  pdu_hdr0      (advertising PDU header or data-channel header)
 *     15     1  pdu_payload_len (includes the 4-byte MIC while encrypted;
 *                              never includes the stripped 3-byte CRC)
 *     16     N  PDU payload   (advertising/data/control or ciphertext+MIC)
 *
 *   The full reconstructed BLE LL PDU for pcap output:
 *     [pdu_hdr0][pdu_payload_len][payload_16+…]   (2 + pdu_payload_len bytes)
 *
 * Command protocol (EP 0x02, Bulk OUT) – CONFIRMED via RE of BleAnalyzer64.exe
 */

#ifndef WCH_BLE_ANALYZER_H
#define WCH_BLE_ANALYZER_H

#include <stdint.h>
#include <stdbool.h>
#include <libusb.h>

#include "ble_connection_follow.h"
#include "ble_crypto.h"
#include "wch_protocol.h"

/* ── USB IDs ─────────────────────────────────────────────────────────────── */
#define WCH_VID              0x1A86
#define WCH_PID_BLE_MCU      0x8009   /* CH582F BLE MCU */
#define WCH_PID_HUB          0x8091   /* CH334 USB hub  */

/* ── Endpoints ───────────────────────────────────────────────────────────── */
#define EP_INTERRUPT_IN      0x81   /* EP1 IN  – interrupt, 64 B, status/events */
#define EP_BULK_IN           0x82   /* EP2 IN  – bulk,      64 B, BLE packets   */
#define EP_BULK_OUT          0x02   /* EP2 OUT – bulk,      64 B, commands       */
#define EP_MAX_PACKET_SIZE   64

/* Bulk transfer sizes (from Windows driver analysis) */
#define BULK_TRANSFER_SIZE   0x2800   /* 10240 bytes – driver's default read size */
#define WCH_MAX_FRAME_PAYLOAD 512
#define BULK_READ_TIMEOUT_MS 1000
#define INT_READ_TIMEOUT_MS  200

/* Maximum CH582F devices in the product (hub has 4 ports, 3 used) */
#define MAX_MCU_DEVICES      3

/* ── Packet type codes (pkt_type field) ─────────────────────────────────── */
/* Advertisement / Scan */
#define PKT_ADV_IND                      0x00
#define PKT_ADV_DIRECT_IND               0x01
#define PKT_ADV_NONCONN_IND              0x02
#define PKT_SCAN_REQ                     0x03
#define PKT_SCAN_RSP                     0x04
#define PKT_CONNECT_IND                  0x05
#define PKT_ADV_SCAN_IND                 0x06
#define PKT_ADV_EXT_IND                  0x07
/* 0x08-0x0F are reserved in the advertising physical-channel header. */
/* Error / status */
#define PKT_CRC_ERR                      0xFE
#define PKT_MISS                         0xFD
#define PKT_LL_EMPTY                     0xFC

/* ── Link-layer and direction metadata ──────────────────────────────────── */
typedef enum {
    WCH_LINK_ADVERTISING = 0,
    WCH_LINK_DATA = 1,
    WCH_LINK_UNKNOWN = 2
} wch_link_layer_t;

typedef enum {
    WCH_DIRECTION_UNKNOWN = 0,
    WCH_DIRECTION_INITIATOR_TO_ADVERTISER = 1,
    WCH_DIRECTION_ADVERTISER_TO_INITIATOR = 2
} wch_packet_direction_t;

/* ── PHY modes (used in start command) ──────────────────────────────────── */

/* ── Capture modes ───────────────────────────────────────────────────────── */

/*
 * Decoded per-packet metadata header (internal representation, NOT the
 * on-wire device format).  wch_read_packets() fills this from the actual
 * device frame and passes it to the user callback together with the raw
 * BLE LL PDU bytes.
 */
#pragma pack(push, 1)
typedef struct {
    int8_t   rssi;            /* Signed RSSI in dBm            */
    uint8_t  pkt_type;        /* advertising type or data LLID */
    uint8_t  direction;       /* wch_packet_direction_t        */
    uint8_t  link_layer;      /* wch_link_layer_t              */
    uint8_t  raw_channel;     /* firmware channel byte before masking */
    uint8_t  device_flags;    /* accepted error marker (zero)  */
    uint8_t  phy;             /* wch_ble_phy_t                  */
    uint8_t  crc[3];          /* Reconstructed on-air CRC bytes */
    uint8_t  sequence_class;  /* Vendor-compatible SN/NESN class */
    uint8_t  encrypted;       /* On-air payload included a four-byte MIC */
    uint8_t  decrypted;       /* Callback PDU is authenticated plaintext */
    uint8_t  mic_checked;     /* AES-CCM authentication was attempted */
    uint8_t  mic_valid;       /* AES-CCM MIC authenticated successfully */
    uint8_t  retransmission;  /* Reused the previous direction counter */
    uint8_t  packet_counter_valid;
    uint32_t access_addr;     /* BLE Access Address (host value) */
    uint32_t crc_init;        /* active 24-bit CRCInit          */
    uint8_t  src_addr[6];     /* transmitter when direction known */
    uint8_t  dst_addr[6];     /* receiver when direction known */
    uint8_t  initiator_addr[6];
    uint8_t  advertiser_addr[6];
    uint64_t pkt_index;       /* Per-device sequence number    */
    uint64_t timestamp_us;    /* Timestamp in μs               */
    uint64_t interval_us;     /* Δt since previous packet (μs) */
    uint64_t packet_counter;  /* 39-bit CCM counter when MIC-valid */
    uint8_t  channel_index;   /* BLE channel 0-39              */
} wch_pkt_hdr_t;
#pragma pack(pop)

/* ── Configuration for start command ────────────────────────────────────── */
typedef struct {
    uint8_t ble_channel;        /* primary advertising channel 37/38/39 */
    wch_ble_phy_t phy;
    uint8_t initiator_filter[6]; /* wire order; all-zero is wildcard */
    uint8_t advertiser_filter[6];/* wire order; all-zero is wildcard */
    bool has_ltk;               /* enable live AES-CCM decryption */
    uint8_t ltk[BLE_CRYPTO_KEY_SIZE];
} wch_capture_config_t;

/* ── Per-device handle ───────────────────────────────────────────────────── */
typedef struct {
    libusb_context       *ctx;        /* libusb context (set by wch_find_devices) */
    libusb_device_handle *handle;
    int                   bus;
    int                   addr;
    bool                  is_open;
    uint64_t              rx_count;   /* Good packets received   */
    uint64_t              err_count;  /* Status/unknown frames   */
    /* Timestamp extension (device provides 32-bit μs; we extend to 64-bit) */
    uint32_t              ts_prev_us; /* Previous 32-bit timestamp */
    uint64_t              ts_hi_us;   /* High 32 bits accumulated  */
    uint64_t              ts_prev_extended_us;
    uint64_t              pkt_seq;    /* Monotonic sequence number */
    wch_ble_phy_t         configured_phy;
    bool                  connection_active;
    uint64_t              connection_generation;
    ble_conn_params_t     connection;
    uint8_t               previous_event_phase;
    uint8_t               direction_state;
    uint8_t               previous_nesn;
    uint8_t               previous_sn;
    ble_crypto_state_t     crypto;
    uint8_t               rx_carry[WCH_MAX_FRAME_PAYLOAD + 4];
    size_t                rx_carry_len;
} wch_device_t;

/* ── Callback prototype ───────────────────────────────────────────────────── */
/*
 * Called for every complete packet received from the device.
 *   hdr      – pointer to decoded capture and encryption metadata
 *   pdu      – pointer to the raw BLE PDU bytes (after the header)
 *   pdu_len  – length of pdu in bytes
 *   user_ctx – opaque pointer passed to wch_start_capture()
 */
typedef void (*wch_packet_cb_t)(const wch_pkt_hdr_t *hdr,
                                const uint8_t       *pdu,
                                int                  pdu_len,
                                void                *user_ctx);

/* ── Public API ──────────────────────────────────────────────────────────── */

/**
 * Initialise libusb context.  Must be called once before any other function.
 * Returns 0 on success, negative libusb error code on failure.
 */
int  wch_init(libusb_context **ctx_out);

/**
 * Scan the bus for connected WCH BLE Analyzer MCUs.
 * Fills @devs[0..MAX_MCU_DEVICES-1] and returns the number found (0–3).
 */
int  wch_find_devices(libusb_context *ctx, wch_device_t devs[MAX_MCU_DEVICES]);

/**
 * Open a single MCU device, detach any kernel driver, claim interface 0.
 * Returns 0 on success.
 */
int  wch_open_device(wch_device_t *dev);

/**
 * Send the capture start sequence to one MCU.
 * Sequence: AA84 (identify) → AA81 (BLE config) → AA A1 (start scan).
 * Returns 0 on success, negative libusb error on failure.
 */
int  wch_start_capture(wch_device_t *dev, const wch_capture_config_t *cfg);

/**
 * Prepare to stop capture. No stop command is known; this is intentionally a
 * no-op and the caller must immediately close the USB interface.
 */
int  wch_stop_capture(wch_device_t *dev);

/**
 * Read and decode one bulk-IN transfer from EP 0x82.
 * Parses device frames: [0x55][0x10][len16][payload…]
 * Calls @cb for each BLE data frame (type 0x10).  Status frames (type 0x01)
 * and unknown frames are silently discarded.
 * buf must be caller-allocated with at least BULK_TRANSFER_SIZE bytes.
 *
 * @timeout_ms: libusb transfer timeout in milliseconds.
 *   Use BULK_READ_TIMEOUT_MS (1000) for normal blocking reads.
 *   Use 0 for a non-blocking poll (returns immediately if no data).
 *
 * Returns the number of packets decoded (≥0), or a negative libusb error.
 * LIBUSB_ERROR_TIMEOUT (returned as 0) is normal when no packets arrive.
 */
int  wch_read_packets(wch_device_t    *dev,
                      uint8_t         *buf,      /* caller-allocated, ≥BULK_TRANSFER_SIZE */
                      wch_packet_cb_t  cb,
                      void            *user_ctx,
                      int              timeout_ms);

/* Decode a complete bulk-IN byte buffer.  Exposed for deterministic parser
 * tests; normal callers should use wch_read_packets(). */
int  wch_decode_transfer(wch_device_t    *dev,
                         const uint8_t   *buf,
                         int              transfer_len,
                         wch_packet_cb_t  cb,
                         void            *user_ctx);

/**
 * Release interface and close the device handle.
 */
void wch_close_device(wch_device_t *dev);

/**
 * Tear down libusb context.
 */
void wch_exit(libusb_context *ctx);

/* ── Utility ──────────────────────────────────────────────────────────────── */
const char *wch_pkt_type_name(uint8_t pkt_type);
const char *wch_data_pdu_name(uint8_t llid,
                              const uint8_t *pdu,
                              int pdu_len);
void        wch_print_packet(const wch_pkt_hdr_t *hdr,
                              const uint8_t       *pdu,
                              int                  pdu_len);
void        wch_mac_to_str(const uint8_t mac[6], char out[18]);

#endif /* WCH_BLE_ANALYZER_H */
