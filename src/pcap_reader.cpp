#include "pcap_reader.hpp"

#include <cstring>
#include <fstream>
#include <sstream>

namespace netguardian {

namespace {

uint16_t swap16(uint16_t v) { return static_cast<uint16_t>((v >> 8) | (v << 8)); }
uint32_t swap32(uint32_t v) {
    return ((v & 0x000000FFu) << 24) |
           ((v & 0x0000FF00u) << 8)  |
           ((v & 0x00FF0000u) >> 8)  |
           ((v & 0xFF000000u) >> 24);
}

void push16BE(std::vector<uint8_t>& buf, uint16_t v) {
    buf.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
    buf.push_back(static_cast<uint8_t>(v & 0xFF));
}

void push32BE(std::vector<uint8_t>& buf, uint32_t v) {
    buf.push_back(static_cast<uint8_t>((v >> 24) & 0xFF));
    buf.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
    buf.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
    buf.push_back(static_cast<uint8_t>(v & 0xFF));
}

std::vector<uint8_t> buildIpv4Packet(uint8_t proto,
                                     const uint8_t src_ip[4],
                                     const uint8_t dst_ip[4],
                                     const std::vector<uint8_t>& l4_payload) {
    std::vector<uint8_t> frame;
    const uint8_t dst_mac[6] = {0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e};
    const uint8_t src_mac[6] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    frame.insert(frame.end(), dst_mac, dst_mac + 6);
    frame.insert(frame.end(), src_mac, src_mac + 6);
    push16BE(frame, 0x0800);

    const uint16_t total_len = static_cast<uint16_t>(20 + l4_payload.size());
    frame.push_back(0x45);
    frame.push_back(0x00);
    push16BE(frame, total_len);
    push16BE(frame, 0x1234);
    push16BE(frame, 0x4000);
    frame.push_back(64);
    frame.push_back(proto);
    push16BE(frame, 0x0000);
    frame.insert(frame.end(), src_ip, src_ip + 4);
    frame.insert(frame.end(), dst_ip, dst_ip + 4);

    frame.insert(frame.end(), l4_payload.begin(), l4_payload.end());
    return frame;
}

std::vector<uint8_t> buildTcpSegment(uint16_t src_port,
                                     uint16_t dst_port,
                                     uint8_t flags,
                                     const std::string& payload_str) {
    std::vector<uint8_t> tcp;
    push16BE(tcp, src_port);
    push16BE(tcp, dst_port);
    push32BE(tcp, 1000);
    push32BE(tcp, 0);
    tcp.push_back(0x50);
    tcp.push_back(flags);
    push16BE(tcp, 65535);
    push16BE(tcp, 0);
    push16BE(tcp, 0);
    tcp.insert(tcp.end(), payload_str.begin(), payload_str.end());
    return tcp;
}

std::vector<uint8_t> buildUdpDnsQuery(uint16_t src_port, const std::string& domain) {
    std::vector<uint8_t> dns;
    push16BE(dns, 0x4242);
    push16BE(dns, 0x0100);
    push16BE(dns, 1);
    push16BE(dns, 0);
    push16BE(dns, 0);
    push16BE(dns, 0);

    std::stringstream ss(domain);
    std::string label;
    while (std::getline(ss, label, '.')) {
        if (label.empty()) continue;
        dns.push_back(static_cast<uint8_t>(label.size() & 0x3F));
        dns.insert(dns.end(), label.begin(), label.end());
    }
    dns.push_back(0x00);
    push16BE(dns, 1);
    push16BE(dns, 1);

    std::vector<uint8_t> udp;
    push16BE(udp, src_port);
    push16BE(udp, 53);
    push16BE(udp, static_cast<uint16_t>(8 + dns.size()));
    push16BE(udp, 0);
    udp.insert(udp.end(), dns.begin(), dns.end());
    return udp;
}

} // namespace

bool PcapReader::readFile(const std::string& path,
                          PcapGlobalHeader& header,
                          std::vector<PcapPacketRecord>& records,
                          std::string& error_out) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        error_out = "Unable to open PCAP file: " + path;
        return false;
    }

    in.read(reinterpret_cast<char*>(&header), sizeof(PcapGlobalHeader));
    if (!in) {
        error_out = "Truncated PCAP global header.";
        return false;
    }

    bool swapped = false;
    if (header.magic_number == 0xa1b2c3d4u || header.magic_number == 0xa1b23c4du) {
        swapped = false;
    } else if (header.magic_number == 0xd4c3b2a1u || header.magic_number == 0x4d3cb2a1u) {
        swapped = true;
        header.version_major = swap16(header.version_major);
        header.version_minor = swap16(header.version_minor);
        header.snaplen = swap32(header.snaplen);
        header.network = swap32(header.network);
    } else {
        error_out = "Unrecognized PCAP magic number (expected Wireshark PCAP v2.4 format).";
        return false;
    }

    records.clear();
    while (true) {
        uint32_t rec_hdr[4] = {0, 0, 0, 0};
        in.read(reinterpret_cast<char*>(rec_hdr), sizeof(rec_hdr));
        if (in.gcount() == 0) break;
        if (in.gcount() != static_cast<std::streamsize>(sizeof(rec_hdr))) {
            error_out = "Truncated packet record header in PCAP stream.";
            return false;
        }

        PcapPacketRecord rec;
        rec.ts_sec   = swapped ? swap32(rec_hdr[0]) : rec_hdr[0];
        rec.ts_usec  = swapped ? swap32(rec_hdr[1]) : rec_hdr[1];
        rec.incl_len = swapped ? swap32(rec_hdr[2]) : rec_hdr[2];
        rec.orig_len = swapped ? swap32(rec_hdr[3]) : rec_hdr[3];

        if (rec.incl_len > 65535 * 4) {
            error_out = "Implausible packet length in PCAP file.";
            return false;
        }

        rec.data.resize(rec.incl_len);
        if (rec.incl_len > 0) {
            in.read(reinterpret_cast<char*>(rec.data.data()), rec.incl_len);
            if (in.gcount() != static_cast<std::streamsize>(rec.incl_len)) {
                error_out = "Truncated packet payload in PCAP stream.";
                return false;
            }
        }
        records.push_back(std::move(rec));
    }
    return true;
}

bool PcapReader::writeDemoPcap(const std::string& path, std::string& error_out) {
    std::ofstream out(path, std::ios::binary);
    if (!out) {
        error_out = "Unable to create demo PCAP file: " + path;
        return false;
    }

    PcapGlobalHeader gh{};
    gh.magic_number = 0xa1b2c3d4u;
    gh.version_major = 2;
    gh.version_minor = 4;
    gh.thiszone = 0;
    gh.sigfigs = 0;
    gh.snaplen = 65535;
    gh.network = 1;
    out.write(reinterpret_cast<const char*>(&gh), sizeof(gh));

    uint32_t ts = 1764000000u;
    auto emit = [&](const std::vector<uint8_t>& frame) {
        uint32_t rec_hdr[4] = {
            ts++,
            125000u,
            static_cast<uint32_t>(frame.size()),
            static_cast<uint32_t>(frame.size())
        };
        out.write(reinterpret_cast<const char*>(rec_hdr), sizeof(rec_hdr));
        out.write(reinterpret_cast<const char*>(frame.data()), frame.size());
    };

    const uint8_t client[4]  = {192, 168, 1, 15};
    const uint8_t server[4]  = {10, 0, 0, 80};
    const uint8_t scanner[4] = {192, 168, 1, 99};
    const uint8_t dns_srv[4] = {8, 8, 8, 8};

    // 1. Normal HTTP traffic
    emit(buildIpv4Packet(6, client, server,
         buildTcpSegment(51000, 80, 0x18, "GET /index.html HTTP/1.1\r\nHost: demo.local\r\n\r\n")));

    // 2. Cleartext HTTP Basic Authorization header (triggers defensive DPI warning)
    emit(buildIpv4Packet(6, client, server,
         buildTcpSegment(51002, 80, 0x18, "GET /admin HTTP/1.1\r\nHost: demo.local\r\nAuthorization: Basic YWRtaW46ZGVtbw==\r\n\r\n")));

    // 3. Cleartext Telnet session attempt (port 23 warning)
    emit(buildIpv4Packet(6, client, server, buildTcpSegment(51010, 23, 0x02, "")));

    // 4. Normal DNS lookup + High-length anomalous DNS label heuristic
    emit(buildIpv4Packet(17, client, dns_srv, buildUdpDnsQuery(53001, "swinburne.edu.au")));
    emit(buildIpv4Packet(17, scanner, dns_srv,
         buildUdpDnsQuery(53002, "a8f91c2b7e401d9a8b7c6d5e4f3a2b1c9900aabbccddeeff.telemetry-check.example")));

    // 5. Simulated TCP SYN sweep across multiple ports (triggers defensive IDS heuristic)
    const uint16_t sweep_ports[] = {21, 22, 25, 80, 443, 445, 3306, 8080};
    for (uint16_t p : sweep_ports) {
        emit(buildIpv4Packet(6, scanner, server, buildTcpSegment(44000 + p, p, 0x02, "")));
    }

    return true;
}

} // namespace netguardian
