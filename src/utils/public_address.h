#pragma once
#include <cstdint>

inline bool publicIPv4(std::uint32_t ip) {
    const auto range = [ip](std::uint32_t base, unsigned int bits) {
        const auto mask = UINT32_MAX << (32 - bits);
        return (ip & mask) == base;
    };
    return !(range(0x00000000, 8) || range(0x0a000000, 8) || range(0x64400000, 10) ||
             range(0x7f000000, 8) || range(0xa9fe0000, 16) || range(0xac100000, 12) ||
             range(0xc0000000, 24) || range(0xc0000200, 24) || range(0xc0a80000, 16) ||
             range(0xc6120000, 15) || range(0xc6336400, 24) || range(0xcb007100, 24) ||
             range(0xe0000000, 3));
}

inline bool publicIPv6(const unsigned char *ip) {
    bool mapped = true;
    for (int i = 0; i < 10; ++i) mapped = mapped && ip[i] == 0;
    if (mapped && ip[10] == 0xff && ip[11] == 0xff)
        return publicIPv4((std::uint32_t(ip[12]) << 24) | (std::uint32_t(ip[13]) << 16) |
                          (std::uint32_t(ip[14]) << 8) | ip[15]);
    return (ip[0] & 0xe0) == 0x20 &&
           !(ip[0] == 0x20 && ip[1] == 0x01 && ip[2] == 0x0d && ip[3] == 0xb8);
}
