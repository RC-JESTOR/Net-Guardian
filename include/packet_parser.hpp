#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace netguardian {

enum class Protocol {
    UNKNOWN,
    TCP,
    UDP,
    ICMP,
    ARP,
    DNS,
    HTTP,
    TLS
};

struct ParsedPacket {
    uint32_t index = 0;
    uint32_t ts_sec = 0;
    uint32_t ts_usec = 0;
    uint32_t length = 0;

    std::string src_mac;
    std::string dst_mac;
    uint16_t ether_type = 0;

    bool has_ipv4 = false;
    std::string src_ip;
    std::string dst_ip;
    uint8_t ip_proto = 0;
    uint8_t ttl = 0;

    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    uint8_t tcp_flags = 0; // FIN=0x01, SYN=0x02, RST=0x04, PSH=0x08, ACK=0x10

    Protocol app_proto = Protocol::UNKNOWN;
    std::string app_summary;
    std::vector<uint8_t> payload;
};

class PacketParser {
public:
    static ParsedPacket parse(uint32_t index,
                              uint32_t ts_sec,
                              uint32_t ts_usec,
                              const std::vector<uint8_t>& raw);

    static std::string protocolToString(Protocol p);
    static std::string tcpFlagsToString(uint8_t flags);
};

} // namespace netguardian
