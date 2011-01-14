// Taken from http://blogs.msdn.com/b/abhinaba/archive/2008/10/27/c-c-compile-time-asserts.aspx
#ifndef UTIL_HH
#define UTIL_HH

#include <cstddef>
#include <string>
#include <cstdlib>

namespace static_assert
{
    template <bool> struct STATIC_ASSERT_FAILURE;
    template <> struct STATIC_ASSERT_FAILURE<true> { enum { value = 1 }; };

    template<int x> struct static_assert_test{};
}

#define COMPILE_ASSERT(x) \
    typedef ::static_assert::static_assert_test<\
        sizeof(::static_assert::STATIC_ASSERT_FAILURE< (bool)( x ) >)>\
            _static_assert_typedef_

namespace Util {

void hex_dump(uint8_t const *mem, std::size_t length, std::string &o);
    void debug_hex_print(uint8_t const *mem,
                         std::size_t length,
                         unsigned lineLength=16,
                         unsigned dotInterval = 4,
                         std::size_t highlight_start=0,
                         std::size_t highlight_end=0);

}

#endif
