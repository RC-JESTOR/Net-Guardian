#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace netguardian {

struct PcapGlobalHeader {
    uint32_t magic_number;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t  thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network; // 1 = LINKTYPE_ETHERNET
};

struct PcapPacketRecord {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
    std::vector<uint8_t> data;
};

class PcapReader {
public:
    static bool readFile(const std::string& path,
                         PcapGlobalHeader& header,
                         std::vector<PcapPacketRecord>& records,
                         std::string& error_out);

    static bool writeDemoPcap(const std::string& path, std::string& error_out);
};

} // namespace netguardian
