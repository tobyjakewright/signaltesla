# WCH BLE Analyzer Pro — Linux Driver

> WinChipHead forgot to ship a Linux driver.
> We forgot to ask permission.

A reverse-engineered libusb-1.0 driver for the **WCH BLE Analyzer Pro** — a $30 USB
BLE 5.1 sniffer built around three CH582F RISC-V MCUs and a CH334 hub. Each MCU
starts on its own primary advertising channel (37/38/39). When it receives a
`CONNECT_IND`, the analyzer firmware follows that connection natively across
data channels 0-36. Output is a standard PCAP that Wireshark opens without a
plugin.

---

## Hardware

```
┌─────────────────────────────────────┐
│         WCH BLE Analyzer Pro        │
│                                     │
│  [CH582F ch37]  VID 0x1A86          │
│  [CH582F ch38]  PID 0x8009  × 3     │
│  [CH582F ch39]                      │
│  [CH334 hub  ]  PID 0x8091          │
└─────────────────────────────────────┘
```

The device shows up as three independent USB devices through the hub.  The Windows app
knows this.  Now Linux does too.

---

## Requirements

```bash
sudo apt install build-essential pkg-config libusb-1.0-0-dev libssl-dev
```

---

## Build & install

```bash
cd linux-driver
make
sudo make install          # installs binary + udev rule
sudo udevadm control --reload-rules && sudo udevadm trigger
```

---

## Usage

```bash
# Capture to file and watch live
sudo ./wch_capture -v -w capture.pcap

# Capture to PCAP and emit one JSON object per packet for WirelessBOSS
sudo ./wch_capture -J -w capture.pcap

# Open in Wireshark
wireshark capture.pcap

# Pin all MCUs to channel 37
sudo ./wch_capture -w capture.pcap -c 37

# Follow connections involving one peripheral and decrypt with a known LTK
sudo ./wch_capture -J -w watch.pcap -a AA:BB:CC:DD:EE:FF \
  -k 00112233445566778899AABBCCDDEEFF
```

After installing the udev rule you can drop `sudo`.

```
Options:
  -v            Print packets to stdout
  -J            JSON Lines to stdout (one complete PDU per line)
  -w FILE.pcap  Write PCAP (DLT 256, BLE LL + phdr)
  -p PHY        1, 2, S8, or S2 (default: 1M)
  -c CHAN       0=ch37/38/39 (one per MCU), or pin 37, 38, or 39
  -i MAC        Optional initiator/central filter
  -a MAC        Optional advertiser/peripheral filter
  -k LTK        Optional 128-bit LTK (32 hexadecimal digits)
  -h            Show this help
```

JSON mode includes host/device timestamps, MCU and USB identity, channel,
link-layer type, PHY, RSSI, dynamic Access Address, initiator/peripheral
addresses, reconstructed direction, encryption status, and the complete PDU.
Output is flushed after every packet so a supervising application can consume
it live.

---

## How it works

The CH582F speaks a simple vendor protocol over USB bulk transfers:

```
Host  →  AA 84 ...          identify / check firmware
Device → 33 32              firmware present, let's go
Host  →  AA 81 ... ch ...   BLE monitor config (channel, PHY, peer filters)
Host  →  AA A1              start scan
Device → 55 10 ...          BLE packets, forever
```

Packets arrive as `[0x55][0x10][len16][payload]` frames.  The driver decodes them,
reconstructs the BLE LL PDU, and writes a `LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR` pcap
record.  Wireshark takes it from there.

**CRC note:** The CH582F validates the received CRC and strips its octets before
USB delivery. The driver reconstructs the deterministic BLE CRC-24 from the
complete PDU and active CRCInit, writes those octets to PCAP, and marks the
packet checked/valid only because the hardware error marker was zero. These are
reconstructed bytes, not separately sampled RF bytes.

Current protocol contract: [`OFFICIAL_PROTOCOL_NOTES.md`](OFFICIAL_PROTOCOL_NOTES.md).
The chronological experiment log remains in [`RE_PROCESS.md`](RE_PROCESS.md).

---

## Verified support and limitations

**Implemented from the official v1.53 host protocol:** simultaneous monitoring
of primary channels 37/38/39; LE 1M, 2M and Coded S8/S2 configuration; InitA
and AdvA filters; firmware-native legacy `CONNECT_IND` following on data
channels 0-36; dynamic Access Address/CRCInit tracking; Link Layer control PDU
naming; and host-side AES-CCM decryption when the user supplies the connection's
LTK.

Blank MAC filters follow any connection captured by an available radio. MAC
filters are optional and transmitted in BLE on-air byte order after converting
the conventional `AA:BB:CC:DD:EE:FF` input. The LTK stays in the Linux process;
it is never sent to the analyzer.

The analyzer remains passive: it does not connect to devices, query GATT, or
inject BLE traffic. `ADV_EXT_IND`/`AuxPtr` can be decoded, but this driver does
not yet follow secondary extended-advertising payloads. A known LTK can decrypt
a reconnection. Passive LE Secure Connections key recovery from a passkey or
public over-the-air values is not possible; export the LTK from an endpoint.
Custom 2.4 GHz mode remains outside this integration.

The radio-independent connection scheduler is implemented in
`ble_connection_follow.c`: it parses CONNECT_IND, calculates CSA#1/CSA#2,
remaps channel maps, reconstructs CRC-24, and supplies deterministic timing and
radio values. The production capture path lets the analyzer firmware perform
the actual hopping and uses the parsed connection state to label the returned
packets. `make test` checks the protocol, receive decoder, BLE algorithms, and
crypto against deterministic vectors; see
[`CONNECTION_FOLLOWING.md`](CONNECTION_FOLLOWING.md).

---

## License

Do whatever you want, i am happy if anyone get any use for it.
