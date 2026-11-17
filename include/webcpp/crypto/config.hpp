// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

/**
 The configuration of webcpp::crypto, which each of its headers includes first:
 whether it is built without exceptions, whether the target is WebAssembly, the
 backends the build links, and the refusal of version 0.1's defines that chose the
 default backend, which the target alone now chooses (`detail/defaults.hpp`).

 @see "Using webcpp::crypto in your Jamfile", in the guide.
*/
#ifndef WEBCPP_CRYPTO_CONFIG_HPP
#define WEBCPP_CRYPTO_CONFIG_HPP

#include <webcpp/config.hpp>

// MrDocs parses crypto natively, as a build with exceptions does, where neither
// macro is defined: these definitions, each undone at once, are the ones the
// reference lists. WEBCPP_CRYPTO_HAS_OPENSSL stays when the reference's build
// defines it, linking OpenSSL to read the backend headers (doc/Jamfile), and
// WEBCPP_CRYPTO_OPENSSL_MEMORY_RESOURCE stays, so that the reference lists the
// declarations of the memory option too.
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
#ifdef WEBCPP_CRYPTO_HAS_CTAES
/** Defined while config.hpp reads a reference's build that links ctaes (doc/Jamfile). */
#define WEBCPP_CRYPTO_DETAIL_REFERENCE_LINKS_CTAES
#endif
/**
 Defined by `/third_party//ctaes` when the program links ctaes; a program built without b2
 defines it to 1 itself, and compiles webcpp's `src/canary_ctaes.c` with ctaes.
*/
#define WEBCPP_CRYPTO_HAS_CTAES 1
#ifndef WEBCPP_CRYPTO_DETAIL_REFERENCE_LINKS_CTAES
#undef WEBCPP_CRYPTO_HAS_CTAES
#endif
#undef WEBCPP_CRYPTO_DETAIL_REFERENCE_LINKS_CTAES
#ifdef WEBCPP_CRYPTO_HAS_SODIUM
/** Defined while config.hpp reads a reference's build that links libsodium (doc/Jamfile). */
#define WEBCPP_CRYPTO_DETAIL_REFERENCE_LINKS_SODIUM
#endif
/**
 Defined by `/third_party//sodium` when the program links libsodium; a program built without
 b2 defines it to 1 itself, and links libsodium built with webcpp's `src/canary_sodium.c`.
*/
#define WEBCPP_CRYPTO_HAS_SODIUM 1
#ifndef WEBCPP_CRYPTO_DETAIL_REFERENCE_LINKS_SODIUM
#undef WEBCPP_CRYPTO_HAS_SODIUM
#endif
#undef WEBCPP_CRYPTO_DETAIL_REFERENCE_LINKS_SODIUM
#ifdef WEBCPP_CRYPTO_HAS_SECP256K1
/** Defined while config.hpp reads a reference's build that links libsecp256k1 (doc/Jamfile). */
#define WEBCPP_CRYPTO_DETAIL_REFERENCE_LINKS_SECP256K1
#endif
/**
 Defined by `/third_party//secp256k1` when the program links libsecp256k1; a program built
 without b2 defines it to 1 itself, and builds libsecp256k1 with webcpp's
 `src/canary_secp256k1.c`.
*/
#define WEBCPP_CRYPTO_HAS_SECP256K1 1
#ifndef WEBCPP_CRYPTO_DETAIL_REFERENCE_LINKS_SECP256K1
#undef WEBCPP_CRYPTO_HAS_SECP256K1
#endif
#undef WEBCPP_CRYPTO_DETAIL_REFERENCE_LINKS_SECP256K1
#ifdef WEBCPP_CRYPTO_SECP256K1_SMALL_TABLES
/** Defined while config.hpp reads a reference's build of libsecp256k1's small tables. */
#define WEBCPP_CRYPTO_DETAIL_REFERENCE_SMALL_TABLES
#endif
/**
 Defined by `/third_party//secp256k1` when libsecp256k1 is built with its small precomputed
 tables (`<webcpp-secp256k1-tables>small`, and Emscripten's default); a program built without
 b2 defines it to 1 itself when it builds libsecp256k1 with `ECMULT_WINDOW_SIZE=2` and
 `COMB_BLOCKS=2`, `COMB_TEETH=5`. The canary refuses a program and a library that disagree.
*/
#define WEBCPP_CRYPTO_SECP256K1_SMALL_TABLES 1
#ifndef WEBCPP_CRYPTO_DETAIL_REFERENCE_SMALL_TABLES
#undef WEBCPP_CRYPTO_SECP256K1_SMALL_TABLES
#endif
#undef WEBCPP_CRYPTO_DETAIL_REFERENCE_SMALL_TABLES
/**
 Defined by a native program, in its project's requirements beside `/webcpp/crypto//openssl`, to
 send every allocation of OpenSSL's in the process to a resource of the program's: the program
 then defines `openssl_memory_resource()` once and calls
 `backends::openssl::install_memory_functions()` as the first statement of `main`. Refused on
 every WebAssembly target, and natively without OpenSSL linked.

 @see "OpenSSL's allocations in your own memory resource", in the guide.
*/
#define WEBCPP_CRYPTO_OPENSSL_MEMORY_RESOURCE
#endif

#if !defined(WEBCPP_HAS_EXCEPTIONS) && !defined(WEBCPP_CRYPTO_NO_EXCEPTIONS)
#define WEBCPP_CRYPTO_NO_EXCEPTIONS
#endif

#if defined(WEBCPP_TARGET_WASIP2) || defined(WEBCPP_TARGET_WASIP3) || \
    defined(WEBCPP_TARGET_EMSCRIPTEN)
#define WEBCPP_CRYPTO_WEBASSEMBLY 1
#else
/** Defined on the native target, where no WebAssembly target is: the capability table's name. */
#define WEBCPP_CRYPTO_DETAIL_TARGET_NATIVE 1
#endif

// The refusals of impossible combinations. Clang and gcc go on after an
// #error, so the first error is the instruction; MSVC stops at it. OpenSSL is built for
// native, wasip2 and wasip3 (/webcpp/crypto//openssl), never for Emscripten; with b2,
// /webcpp/crypto//openssl stops an Emscripten build first, and these say it without b2.
// clang-format off
#if defined(WEBCPP_TARGET_EMSCRIPTEN) && defined(WEBCPP_CRYPTO_HAS_OPENSSL)
#error "webcpp::crypto: OpenSSL is not built for Emscripten. In the program's Jamfile, replace /webcpp/crypto//openssl with /third_party//bearssl."
#endif
// Version 0.1's two defines chose the default backend; the target alone chooses it now
// (design D32), and a define the build ignored would change which code a program runs.
#ifdef WEBCPP_CRYPTO_DEFAULT_BACKEND_BEARSSL
#error "webcpp::crypto: WEBCPP_CRYPTO_DEFAULT_BACKEND_BEARSSL no longer chooses a default. Write the backend in the type where the program wants it, as in ciphers::gcm<ciphers::aes256<backends::bearssl>>."
#endif
#ifdef WEBCPP_CRYPTO_DEFAULT_BACKEND_OPENSSL
#error "webcpp::crypto: WEBCPP_CRYPTO_DEFAULT_BACKEND_OPENSSL no longer chooses a default. Write the backend in the type where the program wants it, as in ciphers::gcm<ciphers::aes256<backends::openssl>>."
#endif
#if defined(WEBCPP_CRYPTO_OPENSSL_MEMORY_RESOURCE) && defined(WEBCPP_CRYPTO_WEBASSEMBLY)
#error "webcpp::crypto: WEBCPP_CRYPTO_OPENSSL_MEMORY_RESOURCE is an option of native programs, and this program is built for WebAssembly. Remove that define from the program's Jamfile."
#endif
#if defined(WEBCPP_CRYPTO_OPENSSL_MEMORY_RESOURCE) && !defined(WEBCPP_CRYPTO_WEBASSEMBLY) && \
    !defined(WEBCPP_CRYPTO_HAS_OPENSSL)
#error "webcpp::crypto: WEBCPP_CRYPTO_OPENSSL_MEMORY_RESOURCE routes OpenSSL's allocations, and OpenSSL is not linked. In the program's Jamfile, add /webcpp/crypto//openssl beside /webcpp/crypto//crypto, or remove that define. (without b2: define WEBCPP_CRYPTO_HAS_OPENSSL=1 and link libcrypto)"
#endif
// clang-format on

namespace webcpp::crypto::backends {

/** BearSSL, built from its sources by `/third_party//bearssl`. */
struct bearssl;
/** OpenSSL 3.5, built from its pinned sources, named by `/webcpp/crypto//openssl`. */
struct openssl;
/** ctaes as Bitcoin Core ships it, built from its source by `/third_party//ctaes`. */
struct ctaes;
/** libsecp256k1, built from its sources by `/third_party//secp256k1`. */
struct secp256k1;
/** libsodium 1.0.22, built from its sources by `/third_party//sodium`. */
struct sodium;

}  // namespace webcpp::crypto::backends

#endif  // WEBCPP_CRYPTO_CONFIG_HPP
