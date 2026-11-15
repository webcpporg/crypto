// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

#ifndef WEBCPP_CRYPTO_DETAIL_DECLASSIFY_HPP
#define WEBCPP_CRYPTO_DETAIL_DECLASSIFY_HPP

#include <webcpp/crypto/config.hpp>

/**
 * Marks a value derived from secrets as public, where webcpp's code branches on it by design:
 * the verdict of a tag's check. Nothing in a program's build; a constant-time test defines
 * WEBCPP_CRYPTO_DETAIL_CT_VALGRIND or WEBCPP_CRYPTO_DETAIL_CT_MSAN, and the mark is then
 * Valgrind's or MemorySanitizer's, so that the checker reports every other branch on a
 * secret and not this one (Task 20, spec section 8.3).
 *
 * Tip: the object marked is never const, so the branch that follows reads it again after the
 * mark instead of a register the compiler kept from before it (BoringSSL's practice, n1).
 */
#ifdef WEBCPP_CRYPTO_DETAIL_CT_VALGRIND
#include <valgrind/memcheck.h>
#define WEBCPP_CRYPTO_DETAIL_DECLASSIFY(address, size) \
    static_cast<void>(VALGRIND_MAKE_MEM_DEFINED((address), (size)))
#elif defined(WEBCPP_CRYPTO_DETAIL_CT_MSAN)
#include <sanitizer/msan_interface.h>
#define WEBCPP_CRYPTO_DETAIL_DECLASSIFY(address, size) __msan_unpoison((address), (size))
#else
#define WEBCPP_CRYPTO_DETAIL_DECLASSIFY(address, size) static_cast<void>(0)
#endif

#endif  // WEBCPP_CRYPTO_DETAIL_DECLASSIFY_HPP
