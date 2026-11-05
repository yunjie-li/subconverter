#include "utils/public_address.h"
#include <cassert>
#include <initializer_list>
int main() {
    assert(publicIPv4(0x08080808));
    assert(publicIPv4(0x01010101));
    for (auto ip : {0x00000000U, 0x0a000001U, 0x7f000001U, 0xa9fea9feU, 0xac110002U,
                    0xc0a80101U, 0x64400001U, 0xe0000001U, 0xffffffffU}) assert(!publicIPv4(ip));
    unsigned char ipv6[16] = {0};
    assert(!publicIPv6(ipv6)); ipv6[15] = 1; assert(!publicIPv6(ipv6));
    ipv6[0] = 0x26; ipv6[1] = 6; ipv6[2] = 0x47; ipv6[3] = 0; assert(publicIPv6(ipv6));
    ipv6[0] = 0xfc; assert(!publicIPv6(ipv6));
    for (auto &byte : ipv6) byte = 0;
    ipv6[10] = ipv6[11] = 0xff; ipv6[12] = 127; ipv6[15] = 1; assert(!publicIPv6(ipv6));
    ipv6[12] = ipv6[13] = ipv6[14] = ipv6[15] = 8; assert(publicIPv6(ipv6));
}
