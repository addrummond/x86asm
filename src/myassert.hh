#ifndef MYASSERT_HH
#define MYASSERT_HH

#ifndef DEBUG
#undef assert
#define assert(x)
#else
#include <cassert>
#endif

#endif
