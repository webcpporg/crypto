// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// MemorySanitizer's poisoning (spec section 8.3): the keys, the seeds, the plaintext, the block
// and the tag are poisoned, and a branch or an index that depends on them, in webcpp's code,
// BearSSL's, ctaes's or libsodium's, all instrumented, ends the run with a report. The paths are
// ctgrind_test.cpp's but OpenSSL's: equal, is_all_zero and secret's wipe; BearSSL's AES-GCM and
// ChaCha20-Poly1305; ctaes's AES; and on libsodium Ed25519, X25519, the three ChaCha20-Poly1305
// AEADs, the two secret boxes, the two boxes and kx. Each path's output is checked to be
// poisoned too, where MemorySanitizer's shadow keeps it: the poison reaches it, so the path is
// traced.
//
// MemorySanitizer approximates a subtraction's shadow by its operands' without the carry, so the
// constant-time reduction to one bit, ((x - 1) >> 8) & 1 or ~(q | -q) >> 31, of a value whose low
// bits are poisoned comes out initialised (measured with clang 18, 2026-11-18). Every verdict
// here is computed that way, BearSSL's, libsodium's and is_all_zero's: MemorySanitizer reports
// no branch on one with or without its mark (a mutant without webcpp's marks passes), and
// memcheck, which propagates the carry, is the check of the marks.

#include <webcpp/crypto/backends/bearssl.hpp>
#include <webcpp/crypto/backends/ctaes.hpp>
#include <webcpp/crypto/backends/sodium.hpp>
#include <webcpp/crypto/ciphers/aes.hpp>
#include <webcpp/crypto/ciphers/chacha20_poly1305.hpp>
#include <webcpp/crypto/ciphers/gcm.hpp>
#include <webcpp/crypto/ciphers/secretbox.hpp>
#include <webcpp/crypto/curves/ed25519.hpp>
#include <webcpp/crypto/curves/x25519.hpp>
#include <webcpp/crypto/curves/x25519/kx.hpp>
#include <webcpp/crypto/detail/bytes.hpp>
#include <webcpp/crypto/equal.hpp>
#include <webcpp/crypto/hybrid/box.hpp>
#include <webcpp/crypto/secret.hpp>

#include <sanitizer/msan_interface.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <new>
#include <span>
#include <utility>

namespace {

namespace crypto = webcpp::crypto;
using crypto::backends::sodium;

/** Poisons bytes: they are secret. */
void mark_secret(std::span<std::uint8_t> bytes) {
    __msan_poison(bytes.data(), bytes.size());
}

/** Unpoisons bytes, as a public key derived from a secret one is public. */
void mark_public(std::span<std::uint8_t const> bytes) {
    __msan_unpoison(bytes.data(), bytes.size());
}

/** Whether some byte of `bytes` is poisoned: a path's output is, when the poison reached it. */
bool traced(std::span<std::uint8_t const> bytes) {
    return __msan_test_shadow(bytes.data(), bytes.size()) != -1;
}

/** Counts a failed check, with its name. */
int check(bool ok, char const* what) {
    if (!ok) {
        std::printf("FAILED: %s\n", what);
    }
    return ok ? 0 : 1;
}

/**
 * make, seal and open of BearSSL's AES-GCM with the key, the data and the tag poisoned. The
 * planted leak, a branch on a key byte, is here.
 */
int bearssl_gcm() {
    std::array<std::uint8_t, 32> key{};
    std::array<std::uint8_t, 12> const iv{};
    std::array<std::uint8_t, 64> data{};
    __msan_poison(key.data(), key.size());
    __msan_poison(data.data(), data.size());
#ifdef WEBCPP_TEST_CRYPTO_PLANTED_LEAK
    if (key[0] == 0) {  // the planted leak: MemorySanitizer must report it
        std::printf("planted\n");
    }
#endif
    auto made = crypto::ciphers::gcm<crypto::ciphers::aes256<crypto::backends::bearssl>>::make(key);
    auto tag = made->seal(iv, {}, data);
    __msan_poison(tag->data(), tag->size());
    // The verdict is declassified inside the engine (WEBCPP_CRYPTO_DETAIL_DECLASSIFY).
    auto const opened = made->open(iv, {}, data, *tag);
    // And the verdict is checked initialised here, the twin of ctgrind_test.cpp's check: an
    // optimiser may turn the engine's branch on it into a select, and neither the select nor
    // what main passes on and returns is reported (-fno-sanitize-memory-param-retval). The mark's
    // teeth are memcheck's all the same: without it this program passes too (measured with clang
    // 18, 2026-11-18), since MemorySanitizer approximates a subtraction's shadow by its operands'
    // without the carry, so that BearSSL's EQ0, ~(q | -q) >> 31, of an accumulated difference
    // whose low byte is poisoned comes out initialised.
    bool const verdict = opened.has_value();
    __msan_check_mem_is_initialized(&verdict, sizeof verdict);
    return check(verdict, "BearSSL GCM");
}

/**
 * make, seal and open of an AEAD or a secret box with the key, the data and the tag poisoned: an
 * open of the message, then an open of no message under the same tag, which fails. Each verdict
 * must be initialised: the engine or the library marks it public, and only it.
 */
template <class Aead>
int seal_and_open(char const* what) {
    std::array<std::uint8_t, 32> key{};
    std::array<std::uint8_t, Aead::iv_size> const iv{};
    std::array<std::uint8_t, 64> data{};
    key.fill(0x42);
    data.fill(0x17);
    mark_secret(key);
    mark_secret(data);
    auto made = Aead::make(key);
    auto tag = made->seal(iv, {}, data);
    int const failures = check(tag.has_value() && traced(data) && traced(*tag), what);
    mark_secret(*tag);
    auto const opened = made->open(iv, {}, data, *tag);
    bool const verdict = opened.has_value();
    __msan_check_mem_is_initialized(&verdict, sizeof verdict);
    auto const none = made->open(iv, {}, std::span<std::uint8_t>{}, *tag);
    bool const none_verdict = none.has_value();
    __msan_check_mem_is_initialized(&none_verdict, sizeof none_verdict);
    return failures + check(verdict && !none_verdict, what);
}

/** make, encrypt and decrypt of ctaes with the key and the block poisoned. */
int ctaes_block() {
    std::array<std::uint8_t, 32> key{};
    std::array<std::uint8_t, 16> block{};
    __msan_poison(key.data(), key.size());
    __msan_poison(block.data(), block.size());
    auto made = crypto::ciphers::aes256<crypto::backends::ctaes>::make(key);
    bool const ok = made && made->encrypt(block) && made->decrypt(block);
    return check(ok && traced(block), "ctaes");
}

/** Ed25519 on libsodium: make and sign with the seed poisoned. */
int sodium_ed25519() {
    std::array<std::uint8_t, 32> seed{};
    std::array<std::uint8_t, 64> const message{};
    seed.fill(0x42);
    mark_secret(seed);
    auto const pair = crypto::curves::ed25519::basic_keypair<sodium>::make(seed);
    auto const signature = pair->sign(message);
    return check(signature.has_value() && traced(*signature), "Ed25519 on libsodium");
}

/**
 * X25519 on libsodium: the public key and the agreement with the secret key poisoned, the peer's
 * public key public. Whether the shared secret is all zero is marked public where webcpp
 * branches on it, in the engine and in `agree`.
 */
int sodium_x25519() {
    namespace x25519 = crypto::curves::x25519;
    std::array<std::uint8_t, 32> peer_secret{};
    peer_secret.fill(0x24);
    auto const peer = x25519::public_key<sodium>(peer_secret);
    std::array<std::uint8_t, 32> secret_key{};
    secret_key.fill(0x42);
    mark_secret(secret_key);
    auto const own = x25519::public_key<sodium>(secret_key);
    auto const shared = x25519::agree<sodium>(secret_key, *peer);
    // The public key is not checked poisoned: ref10's table lookup selects public points with
    // masks of the form ((x ^ y) - 1) >> 31, which MemorySanitizer's carry-less approximation of
    // a subtraction counts initialised, so the point it selects comes out initialised (measured
    // with clang 18, 2026-11-18); ctgrind_test.cpp checks it traced.
    return check(own.has_value(), "X25519's public key on libsodium") +
           check(shared.has_value() && traced(shared->bytes()), "X25519's agreement on libsodium");
}

/** A box on libsodium: make with the secret key poisoned, then seal and open as an AEAD's. */
template <class Box>
int sodium_box(char const* what) {
    std::array<std::uint8_t, 32> peer_secret{};
    peer_secret.fill(0x24);
    auto const peer = crypto::curves::x25519::public_key<sodium>(peer_secret);
    std::array<std::uint8_t, 32> secret_key{};
    std::array<std::uint8_t, Box::iv_size> const iv{};
    std::array<std::uint8_t, 64> data{};
    secret_key.fill(0x42);
    data.fill(0x17);
    mark_secret(secret_key);
    mark_secret(data);
    auto made = Box::make(secret_key, *peer);
    auto tag = made->seal(iv, data);
    int const failures = check(tag.has_value() && traced(data) && traced(*tag), what);
    mark_secret(*tag);
    auto const opened = made->open(iv, data, *tag);
    bool const verdict = opened.has_value();
    __msan_check_mem_is_initialized(&verdict, sizeof verdict);
    return failures + check(verdict, what);
}

/**
 * kx on libsodium: both key pairs from poisoned seeds, both sides' session keys.
 */
int sodium_kx() {
    using keypair = crypto::curves::x25519::kx_keypair<sodium>;
    std::array<std::uint8_t, 32> client_seed{};
    std::array<std::uint8_t, 32> server_seed{};
    client_seed.fill(0x42);
    server_seed.fill(0x24);
    mark_secret(client_seed);
    mark_secret(server_seed);
    auto const client = keypair::make(client_seed);
    auto const server = keypair::make(server_seed);
    auto const client_key = *client->public_key();
    auto const server_key = *server->public_key();
    // The public keys are public: sent to the peer.
    mark_public(client_key);
    mark_public(server_key);
    auto const client_keys = client->client_session_keys(server_key);
    auto const server_keys = server->server_session_keys(client_key);
    return check(client_keys.has_value() && server_keys.has_value() &&
                     traced(client_keys->receive.bytes()) && traced(server_keys->transmit.bytes()),
                 "kx on libsodium");
}

/**
 * is_all_zero with its bytes poisoned. Its result is not checked poisoned: its reduction,
 * ((total - 1) >> 8) & 1, comes out initialised under MemorySanitizer's carry-less approximation
 * of a subtraction, as BearSSL's EQ0 does (bearssl_gcm above); ctgrind_test.cpp checks it traced.
 */
int all_zero() {
    std::array<std::uint8_t, 32> bytes{};
    mark_secret(bytes);
    static_cast<void>(crypto::detail::is_all_zero(bytes));
    return 0;
}

/**
 * secret's wipe: a move and a move assignment overwrite the bytes they leave behind with
 * constants, without a branch on them, so that they are initialised after; the destructor's wipe
 * is run for its branches only, since MemorySanitizer poisons a destroyed object
 * (-fsanitize-memory-use-after-dtor, on by default), and ctgrind_test.cpp checks its bytes.
 */
int secret_wipe() {
    using secret = crypto::secret<32>;
    alignas(secret) std::array<std::byte, sizeof(secret)> storage{};
    auto* const first = new (storage.data()) secret;
    std::ranges::fill(first->writable(), std::uint8_t{0x42});
    mark_secret(first->writable());
    secret moved(std::move(*first));
    bool const moved_from_wiped = !traced(first->bytes());
    secret assigned;
    assigned = std::move(moved);
    bool const assigned_from_wiped = !traced(moved.bytes());  // NOLINT(bugprone-use-after-move)
    bool const kept = traced(assigned.bytes());
    *first = std::move(assigned);
    first->~secret();
    return check(moved_from_wiped && assigned_from_wiped && kept, "secret's wipe");
}

}  // namespace

int main() {
    namespace ciphers = crypto::ciphers;
    std::array<std::uint8_t, 16> a{};
    std::array<std::uint8_t, 16> b{};
    __msan_poison(a.data(), a.size());
    __msan_poison(b.data(), b.size());
    bool same = crypto::equal(a, b);
    __msan_unpoison(&same, sizeof same);

    int const failures =
        check(same, "equal") + all_zero() + secret_wipe() + bearssl_gcm() + ctaes_block() +
        seal_and_open<ciphers::chacha20_poly1305<crypto::backends::bearssl>>("BearSSL ChaCha") +
        sodium_ed25519() + sodium_x25519() +
        seal_and_open<ciphers::chacha20_poly1305<sodium>>("ChaCha20-Poly1305 on libsodium") +
        seal_and_open<ciphers::chacha20_poly1305_original<sodium>>("the original on libsodium") +
        seal_and_open<ciphers::xchacha20_poly1305<sodium>>("XChaCha20-Poly1305 on libsodium") +
        seal_and_open<ciphers::secretbox<sodium>>("secretbox on libsodium") +
        seal_and_open<ciphers::secretbox_xchacha20poly1305<sodium>>("its XChaCha20 twin") +
        sodium_box<crypto::hybrid::basic_box<crypto::families::box_xsalsa20poly1305, sodium>>(
            "box on libsodium") +
        sodium_box<crypto::hybrid::basic_box<crypto::families::box_xchacha20poly1305, sodium>>(
            "box_xchacha20poly1305 on libsodium") +
        sodium_kx();
    std::printf("constant time under MemorySanitizer: %s\n", failures == 0 ? "ok" : "FAILED");
    return failures == 0 ? 0 : 1;
}
