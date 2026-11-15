// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

/**
 The backend BearSSL: BearSSL's own C code, built from its sources by
 `/third_party//bearssl`. It serves `gcm<aes128/192/256<backends::bearssl>>`, and has no
 block cipher.

 @see "The backends", in the guide.
*/
#ifndef WEBCPP_CRYPTO_BACKENDS_BEARSSL_HPP
#define WEBCPP_CRYPTO_BACKENDS_BEARSSL_HPP

#include <webcpp/crypto/config.hpp>

// The first of BearSSL's three layers (spec section 4.3): a program that uses BearSSL
// without linking it stops here, with the line to write.
#ifndef WEBCPP_CRYPTO_HAS_BEARSSL
// clang-format off
#if defined(WEBCPP_CRYPTO_DETAIL_NONE_LINKED) && defined(WEBCPP_CRYPTO_WEBASSEMBLY)
#error "webcpp::crypto: no backend is linked. On WebAssembly the backend is BearSSL: in the program's Jamfile, add /third_party//bearssl beside /webcpp/crypto//crypto, as in: exe app : app.cpp /webcpp/crypto//crypto /third_party//bearssl ; (without b2: define WEBCPP_CRYPTO_HAS_BEARSSL=1 and link BearSSL built with webcpp's src/canary_bearssl.c)"
#elif defined(WEBCPP_CRYPTO_DETAIL_NONE_LINKED)
#error "webcpp::crypto: no backend is linked. In the program's Jamfile, add /webcpp/crypto//openssl (OpenSSL built from source) or /third_party//bearssl (built from source) beside /webcpp/crypto//crypto, as in: exe app : app.cpp /webcpp/crypto//crypto /webcpp/crypto//openssl ; (without b2: define WEBCPP_CRYPTO_HAS_OPENSSL=1 and link libcrypto, or define WEBCPP_CRYPTO_HAS_BEARSSL=1 and link BearSSL built with webcpp's src/canary_bearssl.c)"
#else
#error "webcpp::crypto: the backend BearSSL is used and not linked. In the program's Jamfile, add /third_party//bearssl beside /webcpp/crypto//crypto, or, with /webcpp/crypto//openssl linked, select OpenSSL with <define>WEBCPP_CRYPTO_DEFAULT_BACKEND_OPENSSL. (without b2: define WEBCPP_CRYPTO_HAS_BEARSSL=1 and link BearSSL built with webcpp's src/canary_bearssl.c)"
#endif
// clang-format on
#else

#include <webcpp/crypto/detail/canary.h>
#include <webcpp/crypto/detail/engines.hpp>

#include <bearssl.h>

#include <string_view>

// The configuration the canary names: BearSSL's seeder as third_party/Jamfile builds it.
#ifdef WEBCPP_CRYPTO_BEARSSL_CANARY_CONFIGURATION
#define WEBCPP_CRYPTO_DETAIL_BEARSSL_CONFIGURATION WEBCPP_CRYPTO_BEARSSL_CANARY_CONFIGURATION
#elif defined(_WIN32)
#define WEBCPP_CRYPTO_DETAIL_BEARSSL_CONFIGURATION noseeder
#else
#define WEBCPP_CRYPTO_DETAIL_BEARSSL_CONFIGURATION getentropy  // lint-world: a canary's name
#endif
// The second layer: the canary's symbol, which src/canary_bearssl.c defines in the library,
// read by every function that calls BearSSL; the third, on MSVC, the linker's comparison of
// the same three facts.
#define WEBCPP_CRYPTO_DETAIL_BEARSSL_CANARY                            \
    WEBCPP_CRYPTO_DETAIL_CANARY(bearssl, WEBCPP_CRYPTO_BEARSSL_COMMIT, \
                                WEBCPP_CRYPTO_DETAIL_BEARSSL_CONFIGURATION)

#ifdef _MSC_VER
#pragma detect_mismatch(                                                       \
    "webcpp_crypto_backend_bearssl",                                           \
    WEBCPP_CRYPTO_DETAIL_MISMATCH_VALUE(bearssl, WEBCPP_CRYPTO_BEARSSL_COMMIT, \
                                        WEBCPP_CRYPTO_DETAIL_BEARSSL_CONFIGURATION))
#endif

extern "C" const char WEBCPP_CRYPTO_DETAIL_BEARSSL_CANARY;

namespace webcpp::crypto::backends {

/** The backend BearSSL (spec section 3.2). */
struct bearssl {
    /** The backend's name, which the examples print. */
    static constexpr std::string_view name = "bearssl";
};

}  // namespace webcpp::crypto::backends

#endif  // WEBCPP_CRYPTO_HAS_BEARSSL
#endif  // WEBCPP_CRYPTO_BACKENDS_BEARSSL_HPP
