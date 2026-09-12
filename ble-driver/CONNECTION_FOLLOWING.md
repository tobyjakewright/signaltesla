# BLE connection-following core

`ble_connection_follow.c` is the radio-independent scheduling core for
following a legacy `CONNECT_IND`. It is deliberately separated from libusb so
the protocol math can be verified before sending unproven commands to the WCH
firmware.

Implemented and tested:

- strict decoding of the 34-byte `CONNECT_IND` payload;
- connection Access Address and 24-bit CRCInit in explicit little-endian form;
- first transmit-window timing, connection interval and event anchor timing;
- channel-map validation and ascending remapping table construction;
- Channel Selection Algorithm #1, including correct behavior when the 16-bit
  connection event counter wraps;
- Channel Selection Algorithm #2, including permutation, MAM, PRN generation,
  channel remapping and 16-bit event-counter wrap;
- data-channel frequency and whitening-IV generation;
- BLE whitening/de-whitening; and
- radio-event records containing channel, frequency, whitening input, Access
  Address, CRCInit, event counter and guarded listen window.

The CSA#2 tests use the Bluetooth SIG sample data for all 37 channels, a
9-channel map, and a 3-channel map. The whitening test uses the SIG's first 64
channel-0 whitening bits. Run them with:

```sh
make test
```

## ChSel detail

The channel algorithm is not safely determined from `CONNECT_IND` alone. If
the `CONNECT_IND` ChSel bit is zero, the connection uses CSA#1. If it is one,
the ChSel bit of the advertising PDU it answered is also required; CSA#2 is
used only when both are one. Consequently, the parser marks a set
`CONNECT_IND` ChSel as unresolved until
`ble_conn_resolve_channel_algorithm()` is called with the triggering
advertisement's bit.

## Hardware integration

The official v1.53 Windows program and its bundled `BLE_Connect.blemn` trace
resolve the earlier uncertainty: connection hopping is firmware-native. The
host configures three radios on primary channels 37/38/39 with the same BLE
monitor mode, PHY and optional InitA/AdvA filters. A radio which receives a
`CONNECT_IND` follows the resulting connection internally; the host does not
send hop parameters or issue event-by-event retune commands.

The Linux receive path therefore parses `CONNECT_IND` once to retain the
dynamic Access Address, CRCInit and peer addresses, then accepts the firmware's
packets on logical channels 0-36. Raw channel bit 7 is connection-event phase
metadata. The exact official NESN/SN state machine reconstructs direction.

The independent CSA/timing routines remain valuable for validation and future
hardware work, but they are deliberately not used to race the firmware with
host-timed USB retunes.

## Encryption

Following and decryption are separate. A known LTK plus captured
`LL_ENC_REQ`/`LL_ENC_RSP` yields the session key, IV and AES-CCM state. The
Linux driver decrypts live, verifies the four-byte MIC, and marks plaintext in
the DLT 256 pseudo-header so Wireshark does not try to interpret ciphertext.
The LTK never leaves the host process.

Legacy pairing can sometimes yield an STK when the complete exchange and TK
are known. LE Secure Connections cannot be passively recovered from a passkey
and public radio traffic because the ECDH secret is missing; use an LTK exported
from one endpoint for those connections.

## Primary references

- [Bluetooth Core Specification, Vol 6 Part B](https://www.bluetooth.com/wp-content/uploads/Files/Specification/HTML/Core-60/out/en/low-energy-controller/link-layer-specification.html), especially Sections 2.3.3.1, 4.5.1, 4.5.3, and 4.5.8.
- [Bluetooth Core Specification, Vol 6 Part C sample data](https://www.bluetooth.com/wp-content/uploads/Files/Specification/HTML/Core_v6.3/out/en/low-energy-controller/sample-data.html), Sections 3 and 4.1.
- [WCH CH58x BLE/RF software reference](https://www.wch.cn/uploads/file/20230316/1678936172282320.pdf), which documents configurable RF Access Address, CRCInit, and channel inputs.
- [WCH BLE Analyzer Pro package page](https://www.wch-ic.com/downloads/WCH_BLEAnalyzer_zip.html), whose published claim is simultaneous listening on primary channels 37, 38, and 39.
