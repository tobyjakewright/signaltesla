# WCH Analyzer v1.53 protocol notes

These fields were recovered from the official `BleAnalyzer64.exe` bundled in
`WCH_BLEAnalyzer.zip` v1.53 and cross-checked against the official
`BLE_Connect.blemn` and `BLE_Pair.blemn` examples. They supersede hypotheses
in the historical `RE_PROCESS.md` log.

## Capture configuration

The host sends `AA 81 19 00`, followed by 25 payload bytes:

| Payload | Meaning |
|---|---|
| 0 | field-valid/enable mask; `FF` for a complete running BLE configuration |
| 1 | mode: `01` BLE monitor, `02` custom 2.4 GHz, `00` stop |
| 2 | primary advertising channel: 37, 38 or 39 |
| 3-4 | reserved/zero |
| 5-10 | optional InitA filter, BLE on-air octet order |
| 11-14 | Access Address, normally `D6 BE 89 8E` |
| 15-17 | CRCInit, normally `55 55 55` |
| 18 | PHY: `10` 1M, `20` 2M, `40` Coded S8, `80` Coded S2 |
| 19-24 | optional AdvA filter, BLE on-air octet order |

`AA A1 00 00` follows every update. The normal all-channel configuration sends
the same fields to three radios, with channels 37, 38 and 39 respectively.
Conventional MAC display order must be reversed for the filter fields.

## Receive record

Each EP82 frame begins `55 10 len16`. Its payload is:

| Payload | Meaning |
|---|---|
| 0-3 | 32-bit device timestamp in microseconds |
| 4 | low six bits BLE logical channel; bit 7 connection-event phase |
| 5 | hardware receive/error marker; zero means accepted |
| 6-7 | reserved/unknown |
| 8 | signed RSSI dBm |
| 9 | reserved/unknown |
| 10 | BLE LL header byte 0 |
| 11 | BLE LL payload length |
| 12… | BLE LL payload; on-air CRC octets are stripped |

Connected records do not repeat the Access Address. The host parses the
captured `CONNECT_IND` and retains its Access Address, CRCInit and peers for
subsequent data-channel records. Direction is reconstructed from raw-channel
bit 7 and the data-header NESN/SN state, as implemented in
`wch_ble_analyzer.c`.

## Native following and encryption

No event-by-event hop command is sent. The analyzer firmware itself follows a
captured `CONNECT_IND`; the official example changes from primary channel 37
to data channels 16, 32, 11 and onward using the connection parameters.

LTKs remain host-side. `LL_ENC_REQ` supplies SKDm and IVm;
`LL_ENC_RSP` supplies SKDs and IVs. The host derives the session key with
AES-128, maintains separate 39-bit direction counters, and authenticates each
encrypted packet with its four-byte AES-CCM MIC. A known LTK can decrypt a
reconnection. Passive LE Secure Connections key recovery is not available
from public packets and a passkey alone.

Primary package source:
[WCH BLE Analyzer download](https://www.wch-ic.com/downloads/WCH_BLEAnalyzer_zip.html).
