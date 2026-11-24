#include "packet_parser.hpp"

#include <algorithm>
#include <cstdio>
#include <iomanip>
#include <sstream>

namespace netguardian {

namespace {

uint16_t read16BE(const std::vector<uint8_t>& b, size_t off) {
    return static_cast<uint16_t>((static_cast<uint16_t>(b[off]) << 8) | b[off + 1]);
}

std::string formatMac(const std::vector<uint8_t>& b, size_t off) {
    char buf[24];
    std::snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x",
                  b[off], b[off + 1], b[off + 2], b[off + 3], b[off + 4], b[off + 5]);
    return buf;
}

std::string formatIp(const std::vector<uint8_t>& b, size_t off) {
    char buf[20];
    std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u",
                  b[off], b[off + 1], b[off + 2], b[off + 3]);
    return buf;
}

std::string extractDnsQname(const std::vector<uint8_t>& payload) {
    if (payload.size() < 13) return "";
    size_t pos = 12;
    std::string out;
    while (pos < payload.size()) {
        uint8_t len = payload[pos++];
        if (len == 0) break;
        if ((len & 0xC0) != 0 || pos + len > payload.size()) break;
        if (!out.empty()) out.push_back('.');
        out.append(reinterpret_cast<const char*>(&payload[pos]), len);
        pos += len;
    }
    return out;
}

} // namespace

ParsedPacket PacketParser::parse(uint32_t index,
                                 uint32_t ts_sec,
                                 uint32_t ts_usec,
                                 const std::vector<uint8_t>& raw) {
    ParsedPacket pkt;
    pkt.index = index;
    pkt.ts_sec = ts_sec;
    pkt.ts_usec = ts_usec;
    pkt.length = static_cast<uint32_t>(raw.size());

    if (raw.size() < 14) return pkt;

    pkt.dst_mac = formatMac(raw, 0);
    pkt.src_mac = formatMac(raw, 6);
    pkt.ether_type = read16BE(raw, 12);

    if (pkt.ether_type == 0x0806) {
        pkt.app_proto = Protocol::ARP;
        pkt.app_summary = "ARP Frame";
        return pkt;
    }

    if (pkt.ether_type != 0x0800 || raw.size() < 34) {
        return pkt;
    }

    const size_t ip_off = 14;
    const uint8_t ihl = static_cast<uint8_t>((raw[ip_off] & 0x0F) * 4);
    if (ihl < 20 || raw.size() < ip_off + ihl) return pkt;

    pkt.has_ipv4 = true;
    pkt.ttl = raw[ip_off + 8];
    pkt.ip_proto = raw[ip_off + 9];
    pkt.src_ip = formatIp(raw, ip_off + 12);
    pkt.dst_ip = formatIp(raw, ip_off + 16);

    const size_t l4_off = ip_off + ihl;

    if (pkt.ip_proto == 1) {
        pkt.app_proto = Protocol::ICMP;
        pkt.app_summary = "ICMP Control Message";
        return pkt;
    }

    if (pkt.ip_proto == 6 && raw.size() >= l4_off + 20) {
        pkt.src_port = read16BE(raw, l4_off);
        pkt.dst_port = read16BE(raw, l4_off + 2);
        const uint8_t data_off = static_cast<uint8_t>(((raw[l4_off + 12] >> 4) & 0x0F) * 4);
        pkt.tcp_flags = raw[l4_off + 13];
        pkt.app_proto = Protocol::TCP;

        const size_t pay_off = l4_off + data_off;
        if (data_off >= 20 && pay_off < raw.size()) {
            pkt.payload.assign(raw.begin() + static_cast<std::ptrdiff_t>(pay_off), raw.end());
            std::string preview(pkt.payload.begin(),
                                pkt.payload.begin() + std::min<size_t>(pkt.payload.size(), 64));
            if (preview.rfind("GET ", 0) == 0 || preview.rfind("POST ", 0) == 0 ||
                preview.rfind("PUT ", 0) == 0 || preview.rfind("HEAD ", 0) == 0 ||
                preview.rfind("HTTP/", 0) == 0) {
                pkt.app_proto = Protocol::HTTP;
                size_t eol = preview.find("\r\n");
                pkt.app_summary = (eol == std::string::npos) ? preview : preview.substr(0, eol);
            } else if (pkt.dst_port == 443 || pkt.src_port == 443) {
                pkt.app_proto = Protocol::TLS;
                pkt.app_summary = "Encrypted TLS Stream";
            }
        } else if (pkt.dst_port == 443 || pkt.src_port == 443) {
            pkt.app_proto = Protocol::TLS;
            pkt.app_summary = "TLS Handshake";
        }
    } else if (pkt.ip_proto == 17 && raw.size() >= l4_off + 8) {
        pkt.src_port = read16BE(raw, l4_off);
        pkt.dst_port = read16BE(raw, l4_off + 2);
        pkt.app_proto = Protocol::UDP;

        const size_t pay_off = l4_off + 8;
        if (pay_off < raw.size()) {
            pkt.payload.assign(raw.begin() + static_cast<std::ptrdiff_t>(pay_off), raw.end());
        }
        if (pkt.dst_port == 53 || pkt.src_port == 53) {
            pkt.app_proto = Protocol::DNS;
            std::string qname = extractDnsQname(pkt.payload);
            pkt.app_summary = qname.empty() ? "DNS Packet" : ("DNS Query: " + qname);
        }
    }

    return pkt;
}

std::string PacketParser::protocolToString(Protocol p) {
    switch (p) {
        case Protocol::TCP:  return "TCP";
        case Protocol::UDP:  return "UDP";
        case Protocol::ICMP: return "ICMP";
        case Protocol::ARP:  return "ARP";
        case Protocol::DNS:  return "DNS";
        case Protocol::HTTP: return "HTTP";
        case Protocol::TLS:  return "TLS";
        default:             return "OTHER";
    }
}

std::string PacketParser::tcpFlagsToString(uint8_t flags) {
    std::string out;
    if (flags & 0x02) out += "SYN ";
    if (flags & 0x10) out += "ACK ";
    if (flags & 0x08) out += "PSH ";
    if (flags & 0x01) out += "FIN ";
    if (flags & 0x04) out += "RST ";
    if (!out.empty() && out.back() == ' ') out.pop_back();
    return out.empty() ? "-" : out;
}

} // namespace netguardian
