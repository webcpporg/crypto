// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// A stand-in for Valgrind's <valgrind/memcheck.h>, for declassify_compile_test.cpp alone: the one
// client request crypto's headers name under WEBCPP_CRYPTO_DETAIL_CT_VALGRIND, which reads both
// its arguments, so that every lane compiles the marks the constant-time lane alone runs.

#ifndef WEBCPP_TEST_CRYPTO_SUPPORT_VALGRIND_STUB_MEMCHECK_H
#define WEBCPP_TEST_CRYPTO_SUPPORT_VALGRIND_STUB_MEMCHECK_H

/** Reads the address and the size, as Valgrind's request does, and marks nothing. */
#define VALGRIND_MAKE_MEM_DEFINED(address, size) \
    (static_cast<void>(address), static_cast<void>(size), 0)

#endif  // WEBCPP_TEST_CRYPTO_SUPPORT_VALGRIND_STUB_MEMCHECK_H
