// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// No local name in a crypto header hides a program's global. MSVC warns, C4459, at a parameter
// or a local of a header's non-template function (inline code) that has the name of a global of
// the program ("declaration of 'timing' hides global declaration"), an error at /W4 /WX, and, where
// a function template is instantiated, at its locals (14.3 and 14.5, secure's user_globals test,
// which instantiates secure's); this test instantiates few templates, so the names that live only
// in templates are listed defensively, for a function that stops being a template. Clang and GCC
// never warn across namespaces, so the test is MSVC's, and natively it only compiles. A local takes
// two words, the role then the kind (`timing_scope`, `completion_token`, `signature_bytes`), which
// no program names a global.
//
// Every header of another library that a crypto header includes comes first, so that their own
// names are parsed before the globals exist; then a global of every one-word name a crypto
// header gave a local or a parameter until each took two words; then every public header.
//
// How the list was made: an aggregate translation unit of every header of include/, every
// backend and XKCP linked (secp256k1's Keccak-256 path), its AST dumped (clang -Xclang
// -ast-dump), each ParmVarDecl, VarDecl and BindingDecl inside a function of include/ whose name
// matches ^[a-z][a-z0-9]*$; again with WEBCPP_CRYPTO_OPENSSL_MEMORY_RESOURCE,
// WEBCPP_SECURE_TIMING_COVERED and WEBCPP_SECURE_TIMING_ENTERED, and without
// threads, for the code only they compile. The namespace-scope constants (`eddsa`, `schnorr`,
// `strict`, the generated tables' `supported` and `linked`) and the static data members (each
// backend's `name`, `overhead`) are not locals, and are left out: C4459 applies to neither;
// `size` (ed25519's `public_key::size`) and `order` (`p_curve_traits`) are static data members
// too, listed only because they were also locals.
//
// A name that the platform's C library already declares as a global (`encrypt`, <unistd.h>'s)
// cannot be a program's global there anyway: it is declared on MSVC alone.

#include <webcpp/crypto/config.hpp>
#include <webcpp/crypto/detail/windows.hpp>  // <windows.h> and <bcrypt.h> on Windows, alone

#include <webcpp/asio/append.hpp>
#include <webcpp/asio/associated_allocator.hpp>
#include <webcpp/asio/associated_cancellation_slot.hpp>
#include <webcpp/asio/associated_executor.hpp>
#include <webcpp/asio/async_result.hpp>
#include <webcpp/asio/bind_allocator.hpp>
#include <webcpp/asio/cancellation_type.hpp>
#include <webcpp/asio/dispatch.hpp>
#include <webcpp/asio/error.hpp>
#include <webcpp/asio/execution/allocator.hpp>
#include <webcpp/asio/executor_work_guard.hpp>
#include <webcpp/asio/post.hpp>
#include <webcpp/asio/query.hpp>
#include <webcpp/config.hpp>
#include <webcpp/hash/algorithms.hpp>
#include <webcpp/hash/keccak.hpp>

#include <boost/hash2/digest.hpp>
#include <boost/system/errc.hpp>
#include <boost/system/error_category.hpp>
#include <boost/system/error_code.hpp>
#include <boost/system/result.hpp>
#include <boost/system/system_error.hpp>
#include <boost/throw_exception.hpp>

#include <bearssl.h>
#include <ctaes.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/opensslv.h>
#include <secp256k1.h>
#include <secp256k1_ecdh.h>
#include <secp256k1_ellswift.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_musig.h>
#include <secp256k1_preallocated.h>
#include <secp256k1_recovery.h>
#include <secp256k1_schnorrsig.h>
#include <secp256k1_silentpayments.h>
#include <sodium/core.h>
#include <sodium/crypto_aead_chacha20poly1305.h>
#include <sodium/crypto_aead_xchacha20poly1305.h>
#include <sodium/crypto_box.h>
#include <sodium/crypto_box_curve25519xchacha20poly1305.h>
#include <sodium/crypto_kx.h>
#include <sodium/crypto_scalarmult_curve25519.h>
#include <sodium/crypto_secretbox.h>
#include <sodium/crypto_secretbox_xchacha20poly1305.h>
#include <sodium/crypto_sign_ed25519.h>
#include <sodium/utils.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <climits>
#include <compare>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <memory>
#include <memory_resource>
#include <new>
#include <optional>
#include <source_location>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <type_traits>
#include <utility>

#ifndef _WIN32
#include <sys/random.h>  // lint-world: getentropy's header, which detail/entropy.hpp includes
#endif
#if defined(__aarch64__) && defined(__APPLE__)
#include <sys/sysctl.h>  // lint-world: sysctlbyname's header, which detail/timing.hpp includes
#elif defined(__aarch64__) && defined(__linux__)
#include <sys/auxv.h>  // lint-world: getauxval's header, which detail/timing.hpp includes
#endif

// NOLINTBEGIN(readability-redundant-declaration): clang-tidy takes Boost.Variant2's dependent
// `mp_all<...>::value` for a declaration of `value`
extern int const accepted, address, aead, again, agreed, allocator, at, beforenm, begun, block,
    body, borrow, bound, bytes, c, characters, code, copy, count, data, decoded, decrypt, der,
    difference, digest, done, end, executor, expected, f, feature, file, first, from, guard,
    guarded, guards, half, handler, head, header, held, high, i, input, invoke, iv, job, key, keyed,
    label, last, length, line, lines, location, longest, m, made, message, moved, multiplied, nonce,
    nonzero, old, one, opened, opening, operation, order, other, out, output, peer, piece, pkcs8,
    point, policy, prefix, printable, put, r, ran, raw, ready, receive, returned, run, s, same,
    scalar, scheme, scratch, sealed, seed, separator, shared, signature, size, slot, spki, start,
    started, state, storage, tag, tail, taken, text, timing, to, token, transmit, type, value,
    verdict, view, visit, where, whole, wide, work, written;
#ifdef _MSC_VER
extern int const encrypt;
#endif
// NOLINTEND(readability-redundant-declaration)

#include <webcpp/crypto.hpp>
#include <webcpp/crypto/async.hpp>
#include <webcpp/crypto/backends/openssl.hpp>
#include <webcpp/crypto/backends/secp256k1.hpp>

int main() {
    return 0;
}
