# switch-wifi-bridge [![Build Status](https://cloud.drone.io/api/badges/wafuu-chan/switch-wifi-bridge/status.svg)](https://cloud.drone.io/wafuu-chan/switch-wifi-bridge)
Play Switch games with only local wireless mode, online!

### Project abandoned

nl80211/mac80211 don't expose enough features in userspace to be able to do this effectively in userspace. Would need per-driver modifications to support the required features which is well outside of expectations of a normal user.

Needs WLAN driver to ACK packets destined to spoofed MAC addresses. The `active` flag in monitor mode can do this, but support for it is non-existant and most WLAN cards don't support more than one MAC address at a time.
Doing this in software in userspace is far too slow for slower devices as SIFS intervals are measured in microseconds (Raspberry Pi takes ~1ms between receiving the packet to sending the ACK due to packet decoding time and userspace<>kernelspace overhead)

# Requirements
- A Linux PC. This will NOT work in Windows or macOS due to driver support.
- libpcap 1.x+ (on Debian based systems, this may be labeled as libpcap-0.8 even if it's 1.x+)
- **A WiFi adapter with monitor mode and packet injection support**

# Running
TBD
