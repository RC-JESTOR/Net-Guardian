#include "dpi_engine.hpp"
#include "packet_parser.hpp"
#include "pcap_reader.hpp"

#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

using namespace netguardian;

static void printUsage() {
    std::cout << "Net-Guardian v1.0.0 -- C++17 PCAP & Deep Packet Inspection Analyzer\n"
              << "Usage:\n"
              << "  net_guardian --pcap <file.pcap> [--proto tcp|udp|http|dns|tls|icmp] [--ip <addr>] [--port <num>] [--verbose] [--json <out.json>]\n"
              << "  net_guardian --generate-demo <output.pcap>\n";
}

int main(int argc, char* argv[]) {
    std::string pcap_path;
    std::string demo_out;
    std::string json_out;
    FilterOptions filter;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if ((arg == "--pcap" || arg == "-r") && i + 1 < argc) {
            pcap_path = argv[++i];
        } else if (arg == "--generate-demo" && i + 1 < argc) {
            demo_out = argv[++i];
        } else if (arg == "--proto" && i + 1 < argc) {
            filter.protocol = argv[++i];
        } else if (arg == "--ip" && i + 1 < argc) {
            filter.ip = argv[++i];
        } else if (arg == "--port" && i + 1 < argc) {
            filter.port = static_cast<uint16_t>(std::atoi(argv[++i]));
        } else if (arg == "--json" && i + 1 < argc) {
            json_out = argv[++i];
        } else if (arg == "--verbose" || arg == "-v") {
            filter.verbose = true;
        } else if (arg == "--help" || arg == "-h") {
            printUsage();
            return 0;
        }
    }

    if (!demo_out.empty()) {
        std::string err;
        if (!PcapReader::writeDemoPcap(demo_out, err)) {
            std::cerr << "[!] " << err << "\n";
            return 1;
        }
        std::cout << "[+] Generated Wireshark-compatible demo PCAP -> " << demo_out << "\n";
        if (pcap_path.empty()) return 0;
    }

    if (pcap_path.empty()) {
        printUsage();
        return 1;
    }

    PcapGlobalHeader gh{};
    std::vector<PcapPacketRecord> records;
    std::string err;
    if (!PcapReader::readFile(pcap_path, gh, records, err)) {
        std::cerr << "[!] " << err << "\n";
        return 1;
    }

    DpiEngine engine;
    uint32_t idx = 0;

    for (const auto& rec : records) {
        idx++;
        ParsedPacket pkt = PacketParser::parse(idx, rec.ts_sec, rec.ts_usec, rec.data);
        if (!DpiEngine::matchesFilter(pkt, filter)) continue;

        engine.inspect(pkt);

        if (filter.verbose) {
            std::cout << "#" << std::setw(3) << pkt.index << " ["
                      << std::setw(5) << PacketParser::protocolToString(pkt.app_proto) << "] "
                      << pkt.src_ip << ":" << pkt.src_port << " -> "
                      << pkt.dst_ip << ":" << pkt.dst_port
                      << " (" << pkt.length << "B)";
            if (pkt.ip_proto == 6) {
                std::cout << " [" << PacketParser::tcpFlagsToString(pkt.tcp_flags) << "]";
            }
            if (!pkt.app_summary.empty()) {
                std::cout << " | " << pkt.app_summary;
            }
            std::cout << "\n";
        }
    }

    engine.finalizeHeuristics();
    engine.printSummary();

    if (!json_out.empty()) {
        if (engine.exportJson(json_out, pcap_path)) {
            std::cout << "[+] JSON telemetry report exported -> " << json_out << "\n";
        } else {
            std::cerr << "[!] Failed to write JSON report to " << json_out << "\n";
        }
    }

    return 0;
}
