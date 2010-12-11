#include <util.hh>
#include <cstdio>

using namespace Util;

void Util::hex_dump(uint8_t const *mem, std::size_t length, std::string &o)
{
    o.reserve(length * 2 + // One pair of digits per byte.
              length - 1);   // Spaces separating bytes.

    char tmps[3];
    for (std::size_t i = 0; i < length; ++i) {
        std::sprintf(tmps, "%02x", static_cast<unsigned>(mem[i]));
        o.append(tmps);
        if (i + 1 < length)
            o.push_back(' ');
    }
}

void Util::debug_hex_print(uint8_t const *mem, std::size_t length, unsigned lineLength, unsigned dotInterval)
{
    std::printf("-----\n");
    for (std::size_t i = 0; i < length; ++i) {
        std::printf("%02x", static_cast<unsigned>(mem[i]));
        if (lineLength != 0 && i != 0 && (i+1) % lineLength == 0)
            std::printf("\n");
        else if (dotInterval != 0 && i != 0 && (i+1) % dotInterval == 0 && i + 1 < length)
            std::printf(" . ");
        else printf(" ");
    }
    std::printf("\n-----\n\n");
}
