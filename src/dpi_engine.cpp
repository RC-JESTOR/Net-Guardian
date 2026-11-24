#include "dpi_engine.hpp"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>

namespace netguardian {

namespace {

std::string toLower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

std::string jsonEscape(const std::string& in) {
    std::string out;
    out.reserve(in.size() + 8);
    for (char c : in) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:   out.push_back(c); break;
        }
    }
    return out;
}

} // namespace

bool DpiEngine::matchesFilter(const ParsedPacket& pkt, const FilterOptions& filter) {
    if (!filter.protocol.empty()) {
        if (toLower(PacketParser::protocolToString(pkt.app_proto)) != toLower(filter.protocol)) {
            return false;
        }
    }
    if (!filter.ip.empty()) {
        if (pkt.src_ip != filter.ip && pkt.dst_ip != filter.ip) {
            return false;
        }
    }
    if (filter.port != 0) {
        if (pkt.src_port != filter.port && pkt.dst_port != filter.port) {
            return false;
        }
    }
    return true;
}

void DpiEngine::inspect(const ParsedPacket& pkt) {
    total_packets_++;
    total_bytes_ += pkt.length;

    const std::string proto_name = PacketParser::protocolToString(pkt.app_proto);
    proto_counts_[proto_name]++;

    if (pkt.has_ipv4) {
        talker_bytes_[pkt.src_ip] += pkt.length;
    }

    if (pkt.ip_proto == 6 && (pkt.tcp_flags & 0x02) && !(pkt.tcp_flags & 0x10)) {
        syn_targets_by_src_[pkt.src_ip].insert(pkt.dst_port);
    }

    inspectCleartextPorts(pkt);

    if (pkt.app_proto == Protocol::HTTP && !pkt.payload.empty()) {
        std::string text(pkt.payload.begin(), pkt.payload.end());
        inspectHttpPayload(pkt, text);
    } else if (pkt.app_proto == Protocol::DNS) {
        inspectDnsPayload(pkt);
    }
}

void DpiEngine::inspectCleartextPorts(const ParsedPacket& pkt) {
    if (pkt.ip_proto != 6) return;
    if (pkt.dst_port == 23) {
        alerts_.push_back({
            "MEDIUM", "DPI-CLEARTEXT-TELNET", "Unencrypted Telnet Traffic Detected",
            pkt.src_ip, pkt.dst_ip, pkt.index,
            "TCP connection targeting port 23 (Telnet). Migrate remote management to SSH (port 22)."
        });
    } else if (pkt.dst_port == 21 && (pkt.tcp_flags & 0x02)) {
        alerts_.push_back({
            "LOW", "DPI-CLEARTEXT-FTP", "Cleartext FTP Control Channel Observed",
            pkt.src_ip, pkt.dst_ip, pkt.index,
            "TCP SYN targeting port 21 (FTP). Prefer SFTP or FTPS for credential protection."
        });
    }
}

void DpiEngine::inspectHttpPayload(const ParsedPacket& pkt, const std::string& text) {
    std::string lower = toLower(text);
    if (lower.find("authorization: basic ") != std::string::npos) {
        alerts_.push_back({
            "HIGH", "DPI-HTTP-BASIC-AUTH", "Cleartext HTTP Basic Authentication Detected",
            pkt.src_ip, pkt.dst_ip, pkt.index,
            "Unencrypted HTTP request carries an Authorization: Basic header. Enforce HTTPS/TLS."
        });
    }
    if (lower.find("union select") != std::string::npos ||
        lower.find("<script") != std::string::npos ||
        lower.find("../") != std::string::npos) {
        alerts_.push_back({
            "HIGH", "DPI-HTTP-ANOMALY", "Suspicious Web Signature in HTTP Traffic",
            pkt.src_ip, pkt.dst_ip, pkt.index,
            "Detected potential anomaly signature inside HTTP payload (" + pkt.app_summary + ")."
        });
    }
}

void DpiEngine::inspectDnsPayload(const ParsedPacket& pkt) {
    const std::string prefix = "DNS Query: ";
    if (pkt.app_summary.rfind(prefix, 0) != 0) return;
    std::string domain = pkt.app_summary.substr(prefix.size());

    size_t dot = domain.find('.');
    std::string first_label = (dot == std::string::npos) ? domain : domain.substr(0, dot);
    if (first_label.size() >= 36) {
        alerts_.push_back({
            "MEDIUM", "DPI-DNS-TUNNEL-HEURISTIC", "Anomalously Long DNS Subdomain Label",
            pkt.src_ip, pkt.dst_ip, pkt.index,
            "First DNS label length is " + std::to_string(first_label.size()) +
            " chars (" + domain + "), indicative of potential DNS tunneling or DGA telemetry."
        });
    }
}

void DpiEngine::finalizeHeuristics() {
    for (const auto& kv : syn_targets_by_src_) {
        if (kv.second.size() >= 6) {
            alerts_.push_back({
                "HIGH", "IDS-SYN-SWEEP", "Horizontal/Vertical TCP SYN Port Sweep Detected",
                kv.first, "multiple-ports", 0,
                "Host " + kv.first + " initiated SYN probes across " +
                std::to_string(kv.second.size()) + " distinct destination ports."
            });
        }
    }
}

void DpiEngine::printSummary() const {
    std::cout << "\n========================================================================\n";
    std::cout << "  NET-GUARDIAN // DEEP PACKET INSPECTION & TELEMETRY SUMMARY\n";
    std::cout << "========================================================================\n";
    std::cout << "  Packets Analyzed : " << total_packets_ << "\n";
    std::cout << "  Total Bytes      : " << total_bytes_ << " bytes\n";
    std::cout << "  Protocol Breakdown:\n";
    for (const auto& kv : proto_counts_) {
        std::cout << "    - " << std::left << std::setw(8) << kv.first << ": " << kv.second << " pkt(s)\n";
    }
    std::cout << "  Top Talkers (by source bytes):\n";
    for (const auto& kv : talker_bytes_) {
        std::cout << "    - " << std::left << std::setw(16) << kv.first << ": " << kv.second << " bytes\n";
    }
    std::cout << "------------------------------------------------------------------------\n";
    std::cout << "  Security Alerts  : " << alerts_.size() << "\n";
    for (size_t i = 0; i < alerts_.size(); ++i) {
        const auto& a = alerts_[i];
        std::cout << "  [" << (i + 1) << "] [" << a.severity << "] " << a.rule_id << " -- " << a.title << "\n";
        std::cout << "      Flow   : " << a.src_ip << " -> " << a.dst_ip;
        if (a.packet_index > 0) std::cout << " (pkt #" << a.packet_index << ")";
        std::cout << "\n      Detail : " << a.detail << "\n";
    }
    std::cout << "========================================================================\n\n";
}

bool DpiEngine::exportJson(const std::string& path, const std::string& source_pcap) const {
    std::ofstream out(path);
    if (!out) return false;

    out << "{\n";
    out << "  \"tool\": \"Net-Guardian v1.0.0\",\n";
    out << "  \"author\": \"Navida Wijesuriya (RC-JESTOR)\",\n";
    out << "  \"source_pcap\": \"" << jsonEscape(source_pcap) << "\",\n";
    out << "  \"total_packets\": " << total_packets_ << ",\n";
    out << "  \"total_bytes\": " << total_bytes_ << ",\n";
    out << "  \"protocols\": {\n";
    size_t idx = 0;
    for (const auto& kv : proto_counts_) {
        out << "    \"" << jsonEscape(kv.first) << "\": " << kv.second
            << (++idx < proto_counts_.size() ? "," : "") << "\n";
    }
    out << "  },\n";
    out << "  \"alerts\": [\n";
    for (size_t i = 0; i < alerts_.size(); ++i) {
        const auto& a = alerts_[i];
        out << "    {\n";
        out << "      \"severity\": \"" << jsonEscape(a.severity) << "\",\n";
        out << "      \"rule_id\": \"" << jsonEscape(a.rule_id) << "\",\n";
        out << "      \"title\": \"" << jsonEscape(a.title) << "\",\n";
        out << "      \"src_ip\": \"" << jsonEscape(a.src_ip) << "\",\n";
        out << "      \"dst_ip\": \"" << jsonEscape(a.dst_ip) << "\",\n";
        out << "      \"packet_index\": " << a.packet_index << ",\n";
        out << "      \"detail\": \"" << jsonEscape(a.detail) << "\"\n";
        out << "    }" << (i + 1 < alerts_.size() ? "," : "") << "\n";
    }
    out << "  ]\n";
    out << "}\n";
    return true;
}

} // namespace netguardian
