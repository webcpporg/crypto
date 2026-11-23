// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

/**
 The configuration of webcpp::crypto, which each of its headers includes first:
 whether it is built without exceptions, whether the target is WebAssembly, whether
 the build has threads, the backends the build links, and the refusal of version
 0.1's defines that chose the default backend, which the target alone now chooses
 (`detail/defaults.hpp`).

 @see "Using webcpp::crypto in your Jamfile", in the guide.
*/
#ifndef WEBCPP_CRYPTO_CONFIG_HPP
#define WEBCPP_CRYPTO_CONFIG_HPP

#include <webcpp/config.hpp>

// MrDocs parses crypto as a build with exceptions does: these definitions are the ones the
// reference lists. WEBCPP_CRYPTO_WEBASSEMBLY and WEBCPP_CRYPTO_HAS_THREADS, which this header sets
// from the target below, are undone at once. The macros a build sets are left as the build set them
// (push_macro and pop_macro keep the definition or its absence): WEBCPP_CRYPTO_NO_EXCEPTIONS,
// WEBCPP_CRYPTO_NO_THREADS, the libraries' WEBCPP_CRYPTO_HAS_<NAME>,
// WEBCPP_CRYPTO_SECP256K1_SMALL_TABLES and WEBCPP_CRYPTO_OPENSSL_MEMORY_RESOURCE. crypto's
// doc/Jamfile links every library and defines the memory option, so its reference reads each
// backend's header and the option's declarations, while the reference of a library that includes
// crypto reads only what that library's build sets (trystero's, for Emscripten's target, has no
// memory option for the refusals below to meet).
#ifdef __MRDOCS__
#pragma push_macro("WEBCPP_CRYPTO_NO_EXCEPTIONS")
#undef WEBCPP_CRYPTO_NO_EXCEPTIONS
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
#pragma pop_macro("WEBCPP_CRYPTO_NO_EXCEPTIONS")
/** Defined on the WebAssembly targets, wasip2, wasip3 and Emscripten. */
#define WEBCPP_CRYPTO_WEBASSEMBLY 1
#undef WEBCPP_CRYPTO_WEBASSEMBLY
/**
 Defined when the build has threads (design D23): natively when Boost.Config defines
 `BOOST_HAS_THREADS`, on Emscripten when the program is built with `-pthread` (b2's
 `threading=multi`), never on wasip2 or wasip3, and never when the program defines
 `WEBCPP_CRYPTO_NO_THREADS`. Only then do the heavy operations' `async_` variants run on
 another thread; without it, a program that calls one stops with the synchronous name to
 call instead.

 Natively Boost.Config defines `BOOST_HAS_THREADS` whatever b2's `threading` says on macOS,
 on Windows and with libstdc++ or libc++ on Linux, so that a native build has threads
 unless the program defines `WEBCPP_CRYPTO_NO_THREADS`.
*/
#define WEBCPP_CRYPTO_HAS_THREADS 1
#undef WEBCPP_CRYPTO_HAS_THREADS
#pragma push_macro("WEBCPP_CRYPTO_NO_THREADS")
#undef WEBCPP_CRYPTO_NO_THREADS
/**
 Defined by a program that wants no threads from webcpp::crypto: `WEBCPP_CRYPTO_HAS_THREADS`
 stays undefined, and the heavy operations' `async_` variants refuse to compile.
*/
#define WEBCPP_CRYPTO_NO_THREADS
#pragma pop_macro("WEBCPP_CRYPTO_NO_THREADS")
#pragma push_macro("WEBCPP_CRYPTO_HAS_BEARSSL")
#undef WEBCPP_CRYPTO_HAS_BEARSSL
/**
 Defined by `/third_party//bearssl` when the program links BearSSL; a program built without
 b2 defines it to 1 itself.
*/
#define WEBCPP_CRYPTO_HAS_BEARSSL 1
#pragma pop_macro("WEBCPP_CRYPTO_HAS_BEARSSL")
#pragma push_macro("WEBCPP_CRYPTO_HAS_OPENSSL")
#undef WEBCPP_CRYPTO_HAS_OPENSSL
/**
 Defined by `/webcpp/crypto//openssl` when the program links OpenSSL; a program built without
 b2 defines it to 1 itself. Refused on Emscripten, where OpenSSL is not built.
*/
#define WEBCPP_CRYPTO_HAS_OPENSSL 1
#pragma pop_macro("WEBCPP_CRYPTO_HAS_OPENSSL")
#pragma push_macro("WEBCPP_CRYPTO_HAS_CTAES")
#undef WEBCPP_CRYPTO_HAS_CTAES
/**
 Defined by `/third_party//ctaes` when the program links ctaes; a program built without b2
 defines it to 1 itself, and compiles webcpp's `src/canary_ctaes.c` with ctaes.
*/
#define WEBCPP_CRYPTO_HAS_CTAES 1
#pragma pop_macro("WEBCPP_CRYPTO_HAS_CTAES")
#pragma push_macro("WEBCPP_CRYPTO_HAS_SODIUM")
#undef WEBCPP_CRYPTO_HAS_SODIUM
/**
 Defined by `/third_party//sodium` when the program links libsodium; a program built without
 b2 defines it to 1 itself, and links libsodium built with webcpp's `src/canary_sodium.c`.
*/
#define WEBCPP_CRYPTO_HAS_SODIUM 1
#pragma pop_macro("WEBCPP_CRYPTO_HAS_SODIUM")
#pragma push_macro("WEBCPP_CRYPTO_HAS_SECP256K1")
#undef WEBCPP_CRYPTO_HAS_SECP256K1
/**
 Defined by `/third_party//secp256k1` when the program links libsecp256k1; a program built
 without b2 defines it to 1 itself, and builds libsecp256k1 with webcpp's
 `src/canary_secp256k1.c`.
*/
#define WEBCPP_CRYPTO_HAS_SECP256K1 1
#pragma pop_macro("WEBCPP_CRYPTO_HAS_SECP256K1")
#pragma push_macro("WEBCPP_CRYPTO_SECP256K1_SMALL_TABLES")
#undef WEBCPP_CRYPTO_SECP256K1_SMALL_TABLES
/**
 Defined by `/third_party//secp256k1` when libsecp256k1 is built with its small precomputed
 tables (`<webcpp-secp256k1-tables>small`, and Emscripten's default); a program built without
 b2 defines it to 1 itself when it builds libsecp256k1 with `ECMULT_WINDOW_SIZE=2` and
 `COMB_BLOCKS=2`, `COMB_TEETH=5`. The canary refuses a program and a library that disagree.
*/
#define WEBCPP_CRYPTO_SECP256K1_SMALL_TABLES 1
#pragma pop_macro("WEBCPP_CRYPTO_SECP256K1_SMALL_TABLES")
#pragma push_macro("WEBCPP_CRYPTO_OPENSSL_MEMORY_RESOURCE")
#undef WEBCPP_CRYPTO_OPENSSL_MEMORY_RESOURCE
/**
 Defined by a native program, in its project's requirements beside `/webcpp/crypto//openssl`, to
 send every allocation of OpenSSL's in the process to a resource of the program's: the program
 then defines `openssl_memory_resource()` once and calls
 `backends::openssl::install_memory_functions()` as the first statement of `main`. Refused on
 every WebAssembly target, and natively without OpenSSL linked.

 @see "OpenSSL's allocations in your own memory resource", in the guide.
*/
#define WEBCPP_CRYPTO_OPENSSL_MEMORY_RESOURCE
#pragma pop_macro("WEBCPP_CRYPTO_OPENSSL_MEMORY_RESOURCE")
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

// Threads (design D23): natively when Boost.Config sees threads, which it does whatever b2's
// threading says (so natively unless WEBCPP_CRYPTO_NO_THREADS), on Emscripten with -pthread,
// never on WASI.
#if !defined(WEBCPP_CRYPTO_NO_THREADS) && !defined(WEBCPP_TARGET_WASIP2) &&     \
    !defined(WEBCPP_TARGET_WASIP3) &&                                           \
    ((defined(WEBCPP_TARGET_EMSCRIPTEN) && defined(__EMSCRIPTEN_PTHREADS__)) || \
     (!defined(WEBCPP_TARGET_EMSCRIPTEN) && defined(BOOST_HAS_THREADS)))
/**
 Defined in a build with threads, where the heavy operations' `async_` variants exist (design
 D23): natively unless the program defines `WEBCPP_CRYPTO_NO_THREADS` (Boost.Config's
 `BOOST_HAS_THREADS`, which b2's `threading=single` leaves defined), on Emscripten with
 `-pthread`, never on WASI.
*/
#define WEBCPP_CRYPTO_HAS_THREADS 1
#endif

// The refusals of impossible combinations. Clang and gcc go on after an
// #error, so the first error is the instruction; MSVC stops at it. OpenSSL is built for
// native, wasip2 and wasip3 (/webcpp/crypto//openssl), never for Emscripten; with b2,
// /webcpp/crypto//openssl stops an Emscripten build first, and these say it without b2.
// A reference (MrDocs) describes the headers and builds no program, so none of them refuses it.
// clang-format off
#if !defined(__MRDOCS__) && defined(WEBCPP_TARGET_EMSCRIPTEN) && defined(WEBCPP_CRYPTO_HAS_OPENSSL)
#error "webcpp::crypto: OpenSSL is not built for Emscripten. In the program's Jamfile, replace /webcpp/crypto//openssl with /third_party//bearssl."
#endif
// Version 0.1's two defines chose the default backend; the target alone chooses it now
// (design D32), and a define the build ignored would change which code a program runs.
#if !defined(__MRDOCS__) && defined(WEBCPP_CRYPTO_DEFAULT_BACKEND_BEARSSL)
#error "webcpp::crypto: WEBCPP_CRYPTO_DEFAULT_BACKEND_BEARSSL no longer chooses a default. Write the backend in the type where the program wants it, as in ciphers::gcm<ciphers::aes256<backends::bearssl>>."
#endif
#if !defined(__MRDOCS__) && defined(WEBCPP_CRYPTO_DEFAULT_BACKEND_OPENSSL)
#error "webcpp::crypto: WEBCPP_CRYPTO_DEFAULT_BACKEND_OPENSSL no longer chooses a default. Write the backend in the type where the program wants it, as in ciphers::gcm<ciphers::aes256<backends::openssl>>."
#endif
#if !defined(__MRDOCS__) && defined(WEBCPP_CRYPTO_OPENSSL_MEMORY_RESOURCE) && \
    defined(WEBCPP_CRYPTO_WEBASSEMBLY)
#error "webcpp::crypto: WEBCPP_CRYPTO_OPENSSL_MEMORY_RESOURCE is an option of native programs, and this program is built for WebAssembly. Remove that define from the program's Jamfile."
#endif
#if !defined(__MRDOCS__) && defined(WEBCPP_CRYPTO_OPENSSL_MEMORY_RESOURCE) && \
    !defined(WEBCPP_CRYPTO_WEBASSEMBLY) && !defined(WEBCPP_CRYPTO_HAS_OPENSSL)
#error "webcpp::crypto: WEBCPP_CRYPTO_OPENSSL_MEMORY_RESOURCE routes OpenSSL's allocations, and OpenSSL is not linked. In the program's Jamfile, add /webcpp/crypto//openssl beside /webcpp/crypto//crypto, or remove that define. (without b2: define WEBCPP_CRYPTO_HAS_OPENSSL=1 and link libcrypto)"
#endif
// clang-format on

// The backends' tags. webcpp::hash has tags of the same names in webcpp::hash::backends, and a
// program that uses both libraries (signing.hpp's SHA-256 is webcpp::hash's) sees both:
// clang-tidy's bugprone-forward-declaration-namespace then takes a tag this translation unit does
// not use for a declaration in the wrong namespace. Each library names its own backends on
// purpose, so the tags hash shares are exempt: bearssl, openssl and sodium, as hash's config.hpp
// exempts its own.
namespace webcpp::crypto::backends {

/** BearSSL, built from its sources by `/third_party//bearssl`. */
struct bearssl;  // NOLINT(bugprone-forward-declaration-namespace)
/** OpenSSL 3.5, built from its pinned sources, named by `/webcpp/crypto//openssl`. */
struct openssl;  // NOLINT(bugprone-forward-declaration-namespace)
/** ctaes as Bitcoin Core ships it, built from its source by `/third_party//ctaes`. */
struct ctaes;
/** libsecp256k1, built from its sources by `/third_party//secp256k1`. */
struct secp256k1;
/** libsodium 1.0.22, built from its sources by `/third_party//sodium`. */
struct sodium;  // NOLINT(bugprone-forward-declaration-namespace)
/**
 The default backend of whichever family takes it: a name only, of no library, which each family
 resolves to its own default on the target (`default_backend_t<Family>`).

 `aes128`, `aes192` and `aes256` take it: `aes256<>` names the AES block cipher's default with it,
 and `gcm<aes256<>>` AES-GCM's. Any other use is refused as an unknown backend.
*/
struct family_default;

}  // namespace webcpp::crypto::backends

#endif  // WEBCPP_CRYPTO_CONFIG_HPP
