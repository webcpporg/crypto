// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

/**
 The configuration of webcpp::crypto, which each of its headers includes first:
 whether it is built without exceptions, whether the target is WebAssembly, the
 backends the build links and the default backend.

 @see "Using webcpp::crypto in your Jamfile", in the guide.
*/
#ifndef WEBCPP_CRYPTO_CONFIG_HPP
#define WEBCPP_CRYPTO_CONFIG_HPP

#include <webcpp/config.hpp>

// MrDocs parses crypto natively, as a build with exceptions does, where neither
// macro is defined: these definitions, each undone at once, are the ones the
// reference lists. WEBCPP_CRYPTO_HAS_OPENSSL stays when the reference's build
// defines it, linking OpenSSL to read the backend headers (doc/Jamfile).
#ifdef __MRDOCS__
/**
 Defined when webcpp::crypto is built without exceptions: when webcpp has none (the
 compiler has none, or the developer defined `WEBCPP_NO_EXCEPTIONS` for every webcpp
 library), or when the developer defines it alone.

 Every operation reports its errors as values whether or not it is defined. The random
 device's `operator()`, whose failure could not be reported, is declared only when it is
 not defined.

 @see "Exceptions", in the guide.
*/
#define WEBCPP_CRYPTO_NO_EXCEPTIONS
#undef WEBCPP_CRYPTO_NO_EXCEPTIONS
/** Defined on the WebAssembly targets, wasip2, wasip3 and Emscripten. */
#define WEBCPP_CRYPTO_WEBASSEMBLY 1
#undef WEBCPP_CRYPTO_WEBASSEMBLY
#ifdef WEBCPP_CRYPTO_HAS_BEARSSL
/** Defined while config.hpp reads a reference's build that links BearSSL (doc/Jamfile). */
#define WEBCPP_CRYPTO_DETAIL_REFERENCE_LINKS_BEARSSL
#endif
/**
 Defined by `/third_party//bearssl` when the program links BearSSL; a program built without
 b2 defines it to 1 itself.
*/
#define WEBCPP_CRYPTO_HAS_BEARSSL 1
#ifndef WEBCPP_CRYPTO_DETAIL_REFERENCE_LINKS_BEARSSL
#undef WEBCPP_CRYPTO_HAS_BEARSSL
#endif
#undef WEBCPP_CRYPTO_DETAIL_REFERENCE_LINKS_BEARSSL
#ifdef WEBCPP_CRYPTO_HAS_OPENSSL
/** Defined while config.hpp reads a reference's build that links OpenSSL (doc/Jamfile). */
#define WEBCPP_CRYPTO_DETAIL_REFERENCE_LINKS_OPENSSL
#endif
/**
 Defined by `/webcpp/crypto//openssl` when the program links OpenSSL; a program built without
 b2 defines it to 1 itself. Refused on Emscripten, where OpenSSL is not built.
*/
#define WEBCPP_CRYPTO_HAS_OPENSSL 1
#ifndef WEBCPP_CRYPTO_DETAIL_REFERENCE_LINKS_OPENSSL
#undef WEBCPP_CRYPTO_HAS_OPENSSL
#endif
#undef WEBCPP_CRYPTO_DETAIL_REFERENCE_LINKS_OPENSSL
/**
 Defined by a program to make BearSSL the default backend, on every target, when OpenSSL
 is linked as well.
*/
#define WEBCPP_CRYPTO_DEFAULT_BACKEND_BEARSSL
#undef WEBCPP_CRYPTO_DEFAULT_BACKEND_BEARSSL
/**
 Defined by a program to make OpenSSL the default backend, which on wasip2 and wasip3 it is
 not without it. Refused on Emscripten, and together with
 `WEBCPP_CRYPTO_DEFAULT_BACKEND_BEARSSL`.
*/
#define WEBCPP_CRYPTO_DEFAULT_BACKEND_OPENSSL
#undef WEBCPP_CRYPTO_DEFAULT_BACKEND_OPENSSL
#endif

#if !defined(WEBCPP_HAS_EXCEPTIONS) && !defined(WEBCPP_CRYPTO_NO_EXCEPTIONS)
#define WEBCPP_CRYPTO_NO_EXCEPTIONS
#endif

#if defined(WEBCPP_TARGET_WASIP2) || defined(WEBCPP_TARGET_WASIP3) || \
    defined(WEBCPP_TARGET_EMSCRIPTEN)
#define WEBCPP_CRYPTO_WEBASSEMBLY 1
#endif

// The refusals of impossible combinations (spec section 4.3). Clang and gcc go on after an
// #error, so the first error is the instruction; MSVC stops at it. OpenSSL is built for
// native, wasip2 and wasip3 (/webcpp/crypto//openssl), never for Emscripten; with b2,
// /webcpp/crypto//openssl stops an Emscripten build first, and these say it without b2.
// clang-format off
#if defined(WEBCPP_TARGET_EMSCRIPTEN) && defined(WEBCPP_CRYPTO_HAS_OPENSSL)
#error "webcpp::crypto: OpenSSL is not built for Emscripten. In the program's Jamfile, replace /webcpp/crypto//openssl with /third_party//bearssl."
#endif
#if defined(WEBCPP_TARGET_EMSCRIPTEN) && defined(WEBCPP_CRYPTO_DEFAULT_BACKEND_OPENSSL)
#error "webcpp::crypto: WEBCPP_CRYPTO_DEFAULT_BACKEND_OPENSSL selects OpenSSL, which is not built for Emscripten. Remove that define, or make it WEBCPP_CRYPTO_DEFAULT_BACKEND_BEARSSL."
#endif
#if defined(WEBCPP_CRYPTO_DEFAULT_BACKEND_OPENSSL) && defined(WEBCPP_CRYPTO_DEFAULT_BACKEND_BEARSSL)
#error "webcpp::crypto: both WEBCPP_CRYPTO_DEFAULT_BACKEND_OPENSSL and WEBCPP_CRYPTO_DEFAULT_BACKEND_BEARSSL are defined. Keep one."
#endif
// clang-format on

// The default backend of the AEADs (spec section 5): the one the program selects; else
// natively the first linked of OpenSSL, BearSSL; else BearSSL, whose header then says that
// no backend is linked when neither is, and that BearSSL is not linked when OpenSSL alone is
// (on WebAssembly, where the program selects OpenSSL with its define).
#ifdef WEBCPP_CRYPTO_DEFAULT_BACKEND_OPENSSL
/** Defined when OpenSSL is the default backend: the program selects it. */
#define WEBCPP_CRYPTO_DETAIL_DEFAULT_OPENSSL 1
#elif defined(WEBCPP_CRYPTO_DEFAULT_BACKEND_BEARSSL)
/** Defined when BearSSL is the default backend: the program selects it. */
#define WEBCPP_CRYPTO_DETAIL_DEFAULT_BEARSSL 1
#elif !defined(WEBCPP_CRYPTO_WEBASSEMBLY) && defined(WEBCPP_CRYPTO_HAS_OPENSSL)
/** Defined when OpenSSL is the default backend: natively, the first linked. */
#define WEBCPP_CRYPTO_DETAIL_DEFAULT_OPENSSL 1
#else
/** Defined when BearSSL is the default backend: on WebAssembly, or natively without OpenSSL. */
#define WEBCPP_CRYPTO_DETAIL_DEFAULT_BEARSSL 1
#if !defined(WEBCPP_CRYPTO_HAS_BEARSSL) && !defined(WEBCPP_CRYPTO_HAS_OPENSSL)
/** Defined when no backend is linked, which BearSSL's header then says. */
#define WEBCPP_CRYPTO_DETAIL_NONE_LINKED 1
#endif
#endif

namespace webcpp::crypto::backends {

/** BearSSL, built from its sources by `/third_party//bearssl`. */
struct bearssl;
/** OpenSSL 3.5, built from its pinned sources, named by `/webcpp/crypto//openssl`. */
struct openssl;
/** ctaes as Bitcoin Core ships it, built from its source by `/third_party//ctaes`. */
struct ctaes;
/** libsecp256k1, built from its sources by `/third_party//secp256k1`. */
struct secp256k1;

}  // namespace webcpp::crypto::backends

namespace webcpp::crypto {

#ifdef WEBCPP_CRYPTO_DETAIL_DEFAULT_OPENSSL
/** The backend of `ciphers::aes256<>`, `ciphers::gcm<aes256<>>` and `ciphers::aes256_gcm`, as
 * section 5 chooses it. */
using default_backend = backends::openssl;
#else
/** The backend of `ciphers::aes256<>`, `ciphers::gcm<aes256<>>` and `ciphers::aes256_gcm`, as
 * section 5 chooses it. */
using default_backend = backends::bearssl;
#endif

}  // namespace webcpp::crypto

#endif  // WEBCPP_CRYPTO_CONFIG_HPP
