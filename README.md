# Net-Guardian

![C++17](https://img.shields.io/badge/C%2B%2B-17-00d2ff?style=for-the-badge&logo=cplusplus&logoColor=white)
![Wireshark](https://img.shields.io/badge/Wireshark-PCAP%20v2.4-00ff66?style=for-the-badge&logo=wireshark&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-a855f7?style=for-the-badge)

High-speed **C++17** network traffic monitor and **Deep Packet Inspection (DPI)** analyzer built for seamless interoperability with **Wireshark `.pcap`** captures. Dissects Ethernet II, IPv4, TCP, UDP, ICMP, DNS, and HTTP flows while flagging defensive security anomalies in milliseconds with zero third-party runtime dependencies.

---

## Key Capabilities

- **Native Wireshark PCAP v2.4 Engine:** Parses standard little-endian and big-endian `.pcap` captures directly in portable C++17 (no external library setup required).
- **Multi-Layer Dissection & Filtering:** Inspects Ethernet II, IPv4, TCP flags (`SYN/ACK/PSH/FIN/RST`), UDP, ICMP, ARP, DNS QNAME labels, and HTTP request headers with `--proto`, `--ip`, and `--port` filters.
- **Defensive DPI & IDS Heuristics:**
  - `IDS-SYN-SWEEP`: Detects horizontal/vertical TCP SYN port sweeps across multiple ports.
  - `DPI-HTTP-BASIC-AUTH`: Flags unencrypted HTTP Basic Authorization credentials.
  - `DPI-CLEARTEXT-TELNET` / `DPI-CLEARTEXT-FTP`: Identifies legacy cleartext management & transfer protocols.
  - `DPI-DNS-TUNNEL-HEURISTIC`: Flags anomalously long DNS subdomain labels associated with DNS tunneling / DGA traffic.
- **Built-in Demo PCAP Generator & JSON Telemetry:** Generate a valid Wireshark-openable sample capture (`--generate-demo`) and export structured JSON reports (`--json`).

---

## Build & Run

### Using g++ (Linux / macOS / Windows MinGW)

```bash
git clone https://github.com/RC-JESTOR/Net-Guardian.git
cd Net-Guardian

# Compile
g++ -std=c++17 -O2 -Wall -Wextra -Iinclude src/main.cpp src/pcap_reader.cpp src/packet_parser.cpp src/dpi_engine.cpp -o net_guardian

# Analyze the included Wireshark sample capture
./net_guardian --pcap samples/demo_traffic.pcap --verbose --json report.json
```

### Using CMake

```bash
cmake -S . -B build
cmake --build build
./build/net_guardian --pcap samples/demo_traffic.pcap --verbose
```

---

## Project Structure

```text
Net-Guardian/
├── CMakeLists.txt
├── Makefile
├── include/
│   ├── pcap_reader.hpp    # Wireshark PCAP v2.4 binary reader & demo writer
│   ├── packet_parser.hpp  # L2/L3/L4/L7 protocol dissection structs
│   └── dpi_engine.hpp     # Defensive DPI rules, flow stats & JSON exporter
├── src/
│   ├── pcap_reader.cpp
│   ├── packet_parser.cpp
│   ├── dpi_engine.cpp
│   └── main.cpp
└── samples/
    └── demo_traffic.pcap  # Openable directly in Wireshark!
```

---

## Author

**Navida Sathsindu Wijesooriya (RC-JESTOR)**  
Cyber Security & IT Graduate | National CTF Finalist & Top Performer  
[GitHub](https://github.com/RC-JESTOR) • [LinkedIn](https://www.linkedin.com/in/navida-wijesooriya)
