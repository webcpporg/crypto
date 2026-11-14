/* Copyright (c) 2026 WebCpp.org
 *
 * Distributed under the Boost Software License, Version 1.0. (See
 * accompanying file LICENSE_1_0.txt or copy at
 * https://www.boost.org/LICENSE_1_0.txt)
 *
 * The link-time canaries of webcpp::crypto's backends, readable as C and C++. A backend's
 * header reads its canary inside every function that calls the C library, and webcpp's
 * src/canary_<name>.c, which /third_party//<name> compiles with the library's own flags,
 * defines it, so that a program linked without that library, or with one of another
 * commit or configuration, fails to link with the canary's name:
 *
 *     webcpp_crypto_<name>_<commit7>_<configuration>__add_third_party_<name>_to_your_link
 *
 * On MSVC the same three facts also reach the linker as #pragma detect_mismatch. */
#ifndef WEBCPP_CRYPTO_DETAIL_CANARY_H
#define WEBCPP_CRYPTO_DETAIL_CANARY_H

/* The commit each library is pinned at, its first seven hex digits, which the CI compares
 * with `git -C third_party/libs/<name> rev-parse --short=7 HEAD`. A test of the canary
 * gives another through WEBCPP_CRYPTO_<NAME>_CANARY_COMMIT. */
#ifdef WEBCPP_CRYPTO_BEARSSL_CANARY_COMMIT
#define WEBCPP_CRYPTO_BEARSSL_COMMIT WEBCPP_CRYPTO_BEARSSL_CANARY_COMMIT
#else
#define WEBCPP_CRYPTO_BEARSSL_COMMIT 7bea48e
#endif

#ifdef WEBCPP_CRYPTO_CTAES_CANARY_COMMIT
#define WEBCPP_CRYPTO_CTAES_COMMIT WEBCPP_CRYPTO_CTAES_CANARY_COMMIT
#else
#define WEBCPP_CRYPTO_CTAES_COMMIT 9be056a
#endif

#define WEBCPP_CRYPTO_DETAIL_CANARY_I(name, commit, configuration) \
    webcpp_crypto_##name##_##commit##_##configuration##__add_third_party_##name##_to_your_link
#define WEBCPP_CRYPTO_DETAIL_CANARY(name, commit, configuration) \
    WEBCPP_CRYPTO_DETAIL_CANARY_I(name, commit, configuration)
#define WEBCPP_CRYPTO_DETAIL_STRING_I(x) #x
#define WEBCPP_CRYPTO_DETAIL_STRING(x) WEBCPP_CRYPTO_DETAIL_STRING_I(x)
#define WEBCPP_CRYPTO_DETAIL_MISMATCH_VALUE(name, commit, configuration) \
    #name "-" WEBCPP_CRYPTO_DETAIL_STRING(commit) "-" WEBCPP_CRYPTO_DETAIL_STRING(configuration)

#endif
