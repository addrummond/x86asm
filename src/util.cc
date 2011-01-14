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

void Util::debug_hex_print(uint8_t const *mem, std::size_t length, unsigned line_length, unsigned dot_interval, std::size_t highlight_start, std::size_t highlight_end)
{
    // Slight bug here -- can't highlight from position 0 (but this wouldn't be useful anyway).

#define OPEN_CHAR "<"
#define CLOSE_CHAR ">"

    std::printf("-----\n");
    if (highlight_start != highlight_end)
        std::printf(" ");
    for (std::size_t i = 0; i < length; ++i) {
        std::printf("%02x", static_cast<unsigned>(mem[i]));
        if (line_length != 0 && i != 0 && (i+1) % line_length == 0) {
            if (highlight_start == highlight_end)
                std::printf("\n");
            else if (highlight_start == i + 1)
                std::printf("\n" OPEN_CHAR);
            else if (highlight_end == i + 1)
                std::printf(CLOSE_CHAR "\n ");
            else
                std::printf("\n ");
        }
        else if (dot_interval != 0 && i != 0 && (i+1) % dot_interval == 0 && i + 1 < length) {
            if (highlight_start == highlight_end)
                std::printf(" . ");
            else if (highlight_start == i + 1)
                std::printf(" ." OPEN_CHAR);
            else if (highlight_end == i + 1)
                std::printf(CLOSE_CHAR ". ");
            else
                std::printf(" . ");
        }
        else {
            if (highlight_start == highlight_end)
                std::printf(" ");
            else if (highlight_start == i + 1)
                std::printf(OPEN_CHAR);
            else if (highlight_end == i + 1)
                std::printf(CLOSE_CHAR);
            else
                std::printf(" ");
        }
    }
    std::printf("\n-----\n\n");

#undef OPEN_CHAR
#undef CLOSE_CHAR
}
