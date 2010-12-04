// [Slightly modified version of code taken from LLVM; see mremap.cc]

#ifndef MREMAP_HH
#define MREMAP_HH

/* Some BSD systems still use MAP_ANON instead of MAP_ANONYMOUS.  */

#ifndef MAP_ANONYMOUS
# define MAP_ANONYMOUS MAP_ANON
#endif

extern void *mremap (void *, size_t, size_t, int, ...);

#endif
