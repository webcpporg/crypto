// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The constant-time paths that memcheck (ctgrind_test.cpp) and MemorySanitizer (msan_test.cpp)
// both check, written once against a checker's four primitives, so that the two checkers'
// coverage cannot diverge: a later family adds its path here. A checker is a type with
//
// - `static void mark_secret(std::span<std::uint8_t>)`: the bytes are secret from now on;
// - `static void mark_public(std::span<std::uint8_t const>)`: the bytes are public, as a public
//   key derived from a secret one is;
// - `static std::optional<bool> traced(std::span<std::uint8_t const>)`: whether the secret mark
//   reached some byte of these, so that the path that wrote them is traced; empty when the
//   checker could not read its own shadow, which every check here counts as a failure;
// - `static void verdict(bool const&)`: the verdict, whether a tag matched, must be public, the
//   checker reports it otherwise;
//
// and two facts about its shadow: `exact_subtraction`, whether the mark follows a subtraction's
// carry (memcheck's does, MemorySanitizer's approximation drops it, so that a constant-time
// reduction of a secret to one bit comes out public, msan_test.cpp says more), and
// `reads_destroyed`, whether a destroyed object's bytes can be read back (MemorySanitizer marks
// them by itself, -fsanitize-memory-use-after-dtor). A trace that the shadow cannot keep is not
// checked; the other checker checks it.

#ifndef WEBCPP_TEST_CRYPTO_CONSTANT_TIME_PATHS_HPP
#define WEBCPP_TEST_CRYPTO_CONSTANT_TIME_PATHS_HPP

#include <webcpp/crypto/backends/bearssl.hpp>
#include <webcpp/crypto/backends/ctaes.hpp>
#include <webcpp/crypto/backends/sodium.hpp>
#include <webcpp/crypto/ciphers/aes.hpp>
#include <webcpp/crypto/ciphers/chacha20_poly1305.hpp>
#include <webcpp/crypto/ciphers/secretbox.hpp>
#include <webcpp/crypto/curves/ed25519.hpp>
#include <webcpp/crypto/curves/x25519.hpp>
#include <webcpp/crypto/curves/x25519/kx.hpp>
#include <webcpp/crypto/detail/bytes.hpp>
#include <webcpp/crypto/equal.hpp>
#include <webcpp/crypto/hybrid/box.hpp>
#include <webcpp/crypto/secret.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <new>
#include <optional>
#include <span>
#include <utility>

namespace webcpp::test::constant_time {

namespace crypto = webcpp::crypto;
using crypto::backends::sodium;

/** The bytes of an object, for a checker's primitives. */
template <class T>
std::span<std::uint8_t const> bytes_of(T const& object) {
    return {reinterpret_cast<std::uint8_t const*>(&object), sizeof object};
}

/** Counts a failed check, with its name. */
inline int check(bool ok, char const* what) {
    if (!ok) {
        std::printf("FAILED: %s\n", what);
    }
    return ok ? 0 : 1;
}

/** Whether the checker read its shadow and the secret mark reached `bytes`. */
template <class Checker>
bool carries_mark(std::span<std::uint8_t const> bytes) {
    std::optional<bool> const traced = Checker::traced(bytes);
    return traced.has_value() && *traced;
}

/** Whether the checker read its shadow and the secret mark reached none of `bytes`. */
template <class Checker>
bool clear_of_mark(std::span<std::uint8_t const> bytes) {
    std::optional<bool> const traced = Checker::traced(bytes);
    return traced.has_value() && !*traced;
}

/** equal with both sides secret, its result marked public for the test's own branch. */
template <class Checker>
int equal_path() {
    std::array<std::uint8_t, 16> a{};
    std::array<std::uint8_t, 16> b{};
    Checker::mark_secret(a);
    Checker::mark_secret(b);
    // Not const: the mark changes the object in the checker's shadow, so it is read again.
    bool same = crypto::equal(a, b);  // NOLINT(misc-const-correctness)
    Checker::mark_public(bytes_of(same));
    return check(same, "equal");
}

/**
 * is_all_zero with its bytes secret. The bytes are undefined, not zero, so its result is
 * whatever they hold: only its being traced is checked, where the shadow follows a subtraction's
 * carry (its reduction is ((total - 1) >> 8) & 1).
 */
template <class Checker>
int all_zero() {
    std::array<std::uint8_t, 32> bytes{};
    Checker::mark_secret(bytes);
    bool const zero = crypto::detail::is_all_zero(bytes);
    if constexpr (Checker::exact_subtraction) {
        return check(carries_mark<Checker>(bytes_of(zero)), "is_all_zero");
    } else {
        return 0;
    }
}

/**
 * secret's wipe: a move, a move assignment and the destructor overwrite the bytes they leave
 * behind with constants, without a branch on them, so that the checker holds them public after.
 */
template <class Checker>
int secret_wipe() {
    using secret = crypto::secret<32>;
    alignas(secret) std::array<std::byte, sizeof(secret)> storage{};
    auto* const first = new (storage.data()) secret;
    std::ranges::fill(first->writable(), std::uint8_t{0x42});
    Checker::mark_secret(first->writable());
    secret moved(std::move(*first));
    bool const moved_from_wiped = clear_of_mark<Checker>(first->bytes());
    secret assigned;
    assigned = std::move(moved);
    bool const assigned_from_wiped =
        clear_of_mark<Checker>(moved.bytes());  // NOLINT(bugprone-use-after-move)
    bool const kept = carries_mark<Checker>(assigned.bytes());
    *first = std::move(assigned);
    first->~secret();
    bool destroyed_wiped = true;
    if constexpr (Checker::reads_destroyed) {
        destroyed_wiped = clear_of_mark<Checker>(
            {reinterpret_cast<std::uint8_t const*>(storage.data()), storage.size()});
    }
    return check(moved_from_wiped && assigned_from_wiped && kept && destroyed_wiped,
                 "secret's wipe");
}

/**
 * make, seal and open of an AEAD or a secret box with the key, the data and the tag secret: an
 * open of the message, then an open of no message under the same tag, which fails. Each verdict
 * must be public: the engine or the library marks it so, and only it.
 */
template <class Checker, class Aead>
int seal_and_open(char const* what) {
    std::array<std::uint8_t, 32> key{};
    std::array<std::uint8_t, Aead::iv_size> const iv{};
    std::array<std::uint8_t, 64> data{};
    key.fill(0x42);
    data.fill(0x17);
    Checker::mark_secret(key);
    Checker::mark_secret(data);
    auto made = Aead::make(key);
    auto tag = made->seal(iv, {}, data);
    int const failures =
        check(tag.has_value() && carries_mark<Checker>(data) && carries_mark<Checker>(*tag), what);
    Checker::mark_secret(*tag);
    auto const opened = made->open(iv, {}, data, *tag);
    bool const opened_verdict = opened.has_value();
    Checker::verdict(opened_verdict);
    auto const none = made->open(iv, {}, std::span<std::uint8_t>{}, *tag);
    bool const none_verdict = none.has_value();
    Checker::verdict(none_verdict);
    return failures + check(opened_verdict && !none_verdict, what);
}

/** make, encrypt and decrypt of ctaes with the key and the block secret. */
template <class Checker>
int ctaes_block() {
    std::array<std::uint8_t, 32> key{};
    std::array<std::uint8_t, 16> block{};
    key.fill(0x42);
    block.fill(0x17);
    Checker::mark_secret(key);
    Checker::mark_secret(block);
    auto made = crypto::ciphers::aes256<crypto::backends::ctaes>::make(key);
    bool const ok = made && made->encrypt(block) && made->decrypt(block);
    return check(ok && carries_mark<Checker>(block), "ctaes");
}

/** Ed25519 on libsodium: make and sign with the seed secret. */
template <class Checker>
int sodium_ed25519() {
    std::array<std::uint8_t, 32> seed{};
    std::array<std::uint8_t, 64> const message{};
    seed.fill(0x42);
    Checker::mark_secret(seed);
    auto const pair = crypto::curves::ed25519::basic_keypair<sodium>::make(seed);
    auto const signature = pair->sign(message);
    return check(signature.has_value() && carries_mark<Checker>(*signature),
                 "Ed25519 on libsodium");
}

/**
 * X25519 on libsodium: the public key and the agreement with the secret key secret, the peer's
 * public key public. Whether the shared secret is all zero is marked public where webcpp
 * branches on it, in the engine and in `agree`. The public key is checked traced where the
 * shadow follows a subtraction's carry: ref10's table lookup selects public points with masks
 * of the form ((x ^ y) - 1) >> 31.
 */
template <class Checker>
int sodium_x25519() {
    namespace x25519 = crypto::curves::x25519;
    std::array<std::uint8_t, 32> peer_secret{};
    peer_secret.fill(0x24);
    auto const peer = x25519::public_key<sodium>(peer_secret);
    std::array<std::uint8_t, 32> secret_key{};
    secret_key.fill(0x42);
    Checker::mark_secret(secret_key);
    auto const own = x25519::public_key<sodium>(secret_key);
    auto const shared = x25519::agree<sodium>(secret_key, *peer);
    bool own_traced = own.has_value();
    if constexpr (Checker::exact_subtraction) {
        own_traced = own_traced && carries_mark<Checker>(*own);
    }
    return check(own_traced, "X25519's public key on libsodium") +
           check(shared.has_value() && carries_mark<Checker>(shared->bytes()),
                 "X25519's agreement on libsodium");
}

/**
 * A box on libsodium: make with the secret key secret, then seal and open as an AEAD's. The
 * agreement's verdict is libsodium's own branch (sodium_verdicts.supp).
 */
template <class Checker, class Box>
int sodium_box(char const* what) {
    std::array<std::uint8_t, 32> peer_secret{};
    peer_secret.fill(0x24);
    auto const peer = crypto::curves::x25519::public_key<sodium>(peer_secret);
    std::array<std::uint8_t, 32> secret_key{};
    std::array<std::uint8_t, Box::iv_size> const iv{};
    std::array<std::uint8_t, 64> data{};
    secret_key.fill(0x42);
    data.fill(0x17);
    Checker::mark_secret(secret_key);
    Checker::mark_secret(data);
    auto made = Box::make(secret_key, *peer);
    auto tag = made->seal(iv, data);
    int const failures =
        check(tag.has_value() && carries_mark<Checker>(data) && carries_mark<Checker>(*tag), what);
    Checker::mark_secret(*tag);
    auto const opened = made->open(iv, data, *tag);
    bool const opened_verdict = opened.has_value();
    Checker::verdict(opened_verdict);
    return failures + check(opened_verdict, what);
}

/** kx on libsodium: both key pairs from secret seeds, both sides' session keys. */
template <class Checker>
int sodium_kx() {
    using keypair = crypto::curves::x25519::kx_keypair<sodium>;
    std::array<std::uint8_t, 32> client_seed{};
    std::array<std::uint8_t, 32> server_seed{};
    client_seed.fill(0x42);
    server_seed.fill(0x24);
    Checker::mark_secret(client_seed);
    Checker::mark_secret(server_seed);
    auto const client = keypair::make(client_seed);
    auto const server = keypair::make(server_seed);
    auto const client_key = *client->public_key();
    auto const server_key = *server->public_key();
    // The public keys are public: sent to the peer.
    Checker::mark_public(client_key);
    Checker::mark_public(server_key);
    auto const client_keys = client->client_session_keys(server_key);
    auto const server_keys = server->server_session_keys(client_key);
    return check(client_keys.has_value() && server_keys.has_value() &&
                     carries_mark<Checker>(client_keys->receive.bytes()) &&
                     carries_mark<Checker>(server_keys->transmit.bytes()),
                 "kx on libsodium");
}

/** Every path above, on the checker: the number of failed checks. */
template <class Checker>
int common_paths() {
    namespace ciphers = crypto::ciphers;
    return equal_path<Checker>() + all_zero<Checker>() + secret_wipe<Checker>() +
           ctaes_block<Checker>() +
           seal_and_open<Checker, ciphers::chacha20_poly1305<crypto::backends::bearssl>>(
               "BearSSL ChaCha") +
           sodium_ed25519<Checker>() + sodium_x25519<Checker>() +
           seal_and_open<Checker, ciphers::chacha20_poly1305<sodium>>(
               "ChaCha20-Poly1305 on libsodium") +
           seal_and_open<Checker, ciphers::chacha20_poly1305_original<sodium>>(
               "the original on libsodium") +
           seal_and_open<Checker, ciphers::xchacha20_poly1305<sodium>>(
               "XChaCha20-Poly1305 on libsodium") +
           seal_and_open<Checker, ciphers::secretbox<sodium>>("secretbox on libsodium") +
           seal_and_open<Checker, ciphers::secretbox_xchacha20poly1305<sodium>>(
               "its XChaCha20 twin") +
           sodium_box<Checker,
                      crypto::hybrid::basic_box<crypto::families::box_xsalsa20poly1305, sodium>>(
               "box on libsodium") +
           sodium_box<Checker,
                      crypto::hybrid::basic_box<crypto::families::box_xchacha20poly1305, sodium>>(
               "box_xchacha20poly1305 on libsodium") +
           sodium_kx<Checker>();
}

}  // namespace webcpp::test::constant_time

#endif  // WEBCPP_TEST_CRYPTO_CONSTANT_TIME_PATHS_HPP
