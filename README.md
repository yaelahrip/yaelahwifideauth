# YaelahDeauth

![banner](https://i.imgur.com/EVyW4Qf.png) <!-- optional: your own ASCII or image banner -->

## 🔥 Super Wi-Fi Deauth/Research Tool

**YaelahDeauth** is a multi-purpose wireless security and pentesting toolkit focused on Wi-Fi deauthentication, auditing, and network research.  
It is designed for education, CTFs, internal red-teaming, and research into wireless security.

- **Author:** [yaelahrip](https://github.com/yaelahrip)
- **Special thanks:** [ARXHR007](https://github.com/arxhr007) & ChatGPT

---

## 🛠️ Features

- **Cross-platform**: Works on Linux (full features) and Windows (demo mode)
- **Menu-driven UI**: Interactive terminal menu for beginners or manual use
- **Batch/CLI Mode**: Scriptable/automation-friendly with full argument support
- **Ethics and Safety**: Usage warnings, confirmations, dry-run/testing modes, rate limiting, interface restoration
- **Access Point (AP) Scanner**: Channel and region aware, lists BSSID, SSID, signal, crypto, vendor
- **Client Scanner**: Scan for connected clients, with vendor info
- **Deauth Attack**: Targeted or broadcast deauthentication (Linux only, requires compatible card)
- **Dry-Run**: Simulate attacks without sending real packets
- **Session Logging**: Export scan and attack logs (JSON/CSV)
- **MAC Vendor Lookup**: Recognize device types by manufacturer
- **Progress Bars**: Visual feedback on slow/long operations
- **Advanced Stubs**: PMKID/Handshake capture, Beacon/probe flood, Web dashboard (for future expansion)
- **Failsafe**: Auto-restore network interface mode on exit or error

---

## ⚙️ Supported Platforms

- **Linux:** Full functionality (recommended). Needs root and compatible wireless adapter.
- **Windows:** DEMO ONLY (menus, logging, dry-run; real attacks and scanning are *not* possible due to OS limitations).
- **MacOS:** Basic support (some advanced attacks/monitor mode may not be available).

---

## 🚀 Installation

**Python 3.7+ required.**

1. **Clone this repo:**
    ```bash
    git clone https://github.com/yaelahrip/YaelahDeauth.git
    cd YaelahDeauth
    ```

2. **Install dependencies:**
    ```bash
    pip install psutil scapy mac-vendor-lookup rich flask
    ```

3. **(Linux only) Ensure your system has:**
    - `ifconfig`, `iwconfig` (part of `net-tools` and `wireless-tools`)
    - `systemctl` (for managing NetworkManager)

4. **(Linux only) Run as root:**
    ```bash
    sudo python3 yaelahdeauth.py
    ```

5. **(Windows) Just run:**
    ```bash
    python yaelahdeauth.py
    ```
    > Will run in DEMO mode (no real packet attacks).

---

## 🕹️ Usage

### **Interactive Menu Mode** (default)
Just run (with root on Linux):
```bash
sudo python3 yaelahdeauth.py




# Scan Wi-Fi and export results
sudo python3 yaelahdeauth.py --cli --scan_wifi --export json

# Scan clients on AP
sudo python3 yaelahdeauth.py --cli --scan_clients --ap AA:BB:CC:DD:EE:FF --export csv

# Deauth a client (Linux only, will NOT work on Windows)
sudo python3 yaelahdeauth.py --cli --deauth --ap AA:BB:CC:DD:EE:FF --client 11:22:33:44:55:66 --count 100

# Deauth all clients (broadcast) on an AP
sudo python3 yaelahdeauth.py --cli --deauth_all --ap AA:BB:CC:DD:EE:FF --count 500



| Feature        | Linux | Windows (Demo)         |
| -------------- | ----- | ---------------------- |
| Menu UI        | ✅     | ✅                      |
| CLI/batch      | ✅     | ✅                      |
| AP scan        | ✅     | demo only              |
| Client scan    | ✅     | demo only              |
| Deauth         | ✅     | demo (no real packets) |
| Export log     | ✅     | ✅                      |
| Vendor lookup  | ✅     | ✅                      |
| Progress bar   | ✅     | ✅                      |
| Restore iface  | ✅     | -                      |
| Advanced stubs | ✅     | ✅                      |


⚠️ Disclaimer

This tool is provided strictly for authorized testing, research, learning, and CTF/education use only.
Do not use on networks you do not own or have explicit permission to audit. Unauthorized use is illegal and unethical.
By using YaelahDeauth, you agree to take full responsibility for your actions.


📝 Credits

Author: yaelahrip
Special thanks: ARXHR007
Framework: Based on Scapy, mac-vendor-lookup, Rich, and Flask.



💬 Questions / Bugs / Contributions

Open an issue for bug reports or feature requests.
PRs are welcome!
