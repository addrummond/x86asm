// [Slightly modified version of a file taken from LLVM.]

/* mremap.c -- version of mremap for gold.  */

/* Copyright 2009 Free Software Foundation, Inc.
   Written by Ian Lance Taylor <iant@google.com>.

   This file is part of gold.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston,
   MA 02110-1301, USA.  */

#include <cstddef>
#include <cstring>
#include <sys/types.h>
#include <sys/mman.h>
#include <mremap.hh>

using namespace std;

/* This file implements mremap for systems which don't have it.  The
   gold code requires support for mmap.  However, there are systems
   which have mmap but not mremap.  This is not a general replacement
   for mremap; it only supports the features which are required for
   gold.  In particular, we assume that the MREMAP_MAYMOVE flag is
   set.  */

extern void *mremap (void *, size_t, size_t, int, ...);

void *mremap (void *old_address, size_t old_size, size_t new_size, int flags, ...)
{
  void *ret;

  ret = mmap (0, new_size, flags, // ALEX: This used to be just (PROT_READ | PROT_WRITE)
              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (ret == MAP_FAILED)
    return ret;
  memcpy (ret, old_address,
          old_size < new_size ? old_size : new_size);
  (void) munmap (old_address, old_size);
  return ret;
}

