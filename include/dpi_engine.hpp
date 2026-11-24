#pragma once

#include "packet_parser.hpp"
#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace netguardian {

struct SecurityAlert {
    std::string severity; // HIGH, MEDIUM, LOW
    std::string rule_id;
    std::string title;
    std::string src_ip;
    std::string dst_ip;
    uint32_t packet_index;
    std::string detail;
};

struct FilterOptions {
    std::string protocol; // tcp, udp, icmp, dns, http, tls, arp
    std::string ip;
    uint16_t port = 0;
    bool verbose = false;
};

class DpiEngine {
public:
    void inspect(const ParsedPacket& pkt);
    void finalizeHeuristics();

    const std::vector<SecurityAlert>& alerts() const { return alerts_; }
    const std::map<std::string, uint64_t>& protocolCounts() const { return proto_counts_; }
    const std::map<std::string, uint64_t>& topTalkers() const { return talker_bytes_; }
    uint64_t totalPackets() const { return total_packets_; }
    uint64_t totalBytes() const { return total_bytes_; }

    void printSummary() const;
    bool exportJson(const std::string& path, const std::string& source_pcap) const;

    static bool matchesFilter(const ParsedPacket& pkt, const FilterOptions& filter);

private:
    uint64_t total_packets_ = 0;
    uint64_t total_bytes_ = 0;
    std::map<std::string, uint64_t> proto_counts_;
    std::map<std::string, uint64_t> talker_bytes_;
    std::map<std::string, std::set<uint16_t>> syn_targets_by_src_;
    std::vector<SecurityAlert> alerts_;

    void inspectHttpPayload(const ParsedPacket& pkt, const std::string& text);
    void inspectDnsPayload(const ParsedPacket& pkt);
    void inspectCleartextPorts(const ParsedPacket& pkt);
};

} // namespace netguardian
