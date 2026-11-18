// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// Under Valgrind's memcheck, the keys, the seeds, the plaintext, the block and the tag are marked
// undefined: a branch or a memory index that depends on them is an error, and the run fails
// (--error-exitcode). It covers equal, is_all_zero and secret's wipe; make, seal and open of
// BearSSL's AES-GCM and ChaCha20-Poly1305; make and seal of OpenSSL's two; make, encrypt and
// decrypt of ctaes's AES; and on libsodium Ed25519's make and sign, X25519's public key and
// agreement, the three ChaCha20-Poly1305 AEADs, the two secret boxes, the two boxes and kx.
// Each path's output is checked to be undefined too: the mark reaches it, so the path is traced.

#include <webcpp/crypto/backends/bearssl.hpp>
#include <webcpp/crypto/backends/ctaes.hpp>
#include <webcpp/crypto/backends/openssl.hpp>
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

#include <valgrind/memcheck.h>

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

/** Marks bytes secret: memcheck's undefined. */
void mark_secret(std::span<std::uint8_t> bytes) {
    VALGRIND_MAKE_MEM_UNDEFINED(bytes.data(), bytes.size());
}

/** Marks bytes public, as a public key derived from a secret one is. */
void mark_public(std::span<std::uint8_t const> bytes) {
    VALGRIND_MAKE_MEM_DEFINED(bytes.data(), bytes.size());
}

/**
 * Whether memcheck holds some bit of `bytes` undefined, read from its own shadow without an error:
 * a path's output is, when the secret mark reached it.
 */
bool traced(std::span<std::uint8_t const> bytes) {
    std::array<std::uint8_t, 64> bits{};
    std::size_t const size = (std::min)(bytes.size(), bits.size());
    if (VALGRIND_GET_VBITS(bytes.data(), bits.data(), size) != 1) {
        return false;
    }
    return std::any_of(bits.begin(), bits.begin() + static_cast<std::ptrdiff_t>(size),
                       [](std::uint8_t bit) { return bit != 0; });
}

/** Counts a failed check, with its name. */
int check(bool ok, char const* what) {
    if (!ok) {
        std::printf("FAILED: %s\n", what);
    }
    return ok ? 0 : 1;
}

/** make, seal and open of BearSSL with the key, the data and the tag secret. */
int bearssl_seal_and_open() {
    std::array<std::uint8_t, 32> key{};
    std::array<std::uint8_t, 12> const iv{};
    std::array<std::uint8_t, 64> data{};
    key.fill(0x42);
    data.fill(0x17);
    VALGRIND_MAKE_MEM_UNDEFINED(key.data(), key.size());
    VALGRIND_MAKE_MEM_UNDEFINED(data.data(), data.size());
#ifdef WEBCPP_TEST_CRYPTO_PLANTED_LEAK
    // The planted leak: a branch on a secret byte, which memcheck must report.
    if (key[0] == 0x42) {
        std::printf("planted\n");
    }
#endif
    auto made = crypto::ciphers::gcm<crypto::ciphers::aes256<crypto::backends::bearssl>>::make(key);
    auto tag = made->seal(iv, {}, data);
    VALGRIND_MAKE_MEM_UNDEFINED(tag->data(), tag->size());
    // The verdict is declassified inside the engine (WEBCPP_CRYPTO_DETAIL_DECLASSIFY).
    auto const opened = made->open(iv, {}, data, *tag);
    // And only because of that mark is the verdict defined: checked, since an optimiser may
    // turn the engine's branch on it into a select, which memcheck does not report.
    bool const verdict = opened.has_value();
    static_cast<void>(VALGRIND_CHECK_VALUE_IS_DEFINED(verdict));
    return verdict ? 0 : 1;
}

/**
 * make, seal and open of an AEAD or a secret box with the key, the data and the tag secret: an
 * open of the message, then an open of no message under the same tag, which fails. Each verdict
 * must be defined: the engine or the library marks it public, and only it.
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
    static_cast<void>(VALGRIND_CHECK_VALUE_IS_DEFINED(verdict));
    auto const none = made->open(iv, {}, std::span<std::uint8_t>{}, *tag);
    bool const none_verdict = none.has_value();
    static_cast<void>(VALGRIND_CHECK_VALUE_IS_DEFINED(none_verdict));
    return failures + check(verdict && !none_verdict, what);
}

/**
 * make and seal of OpenSSL with the key and the data secret. Its open is not checked with
 * secrets: OpenSSL branches on the tag's verdict inside EVP_DecryptFinal_ex, where webcpp
 * cannot declassify it; the documentation says so.
 */
template <class Aead>
int openssl_seal(char const* what) {
    std::array<std::uint8_t, 32> key{};
    std::array<std::uint8_t, Aead::iv_size> const iv{};
    std::array<std::uint8_t, 64> data{};
    key.fill(0x42);
    data.fill(0x17);
    mark_secret(key);
    mark_secret(data);
    auto made = Aead::make(key);
    auto const tag = made->seal(iv, {}, data);
    return check(tag.has_value() && traced(data), what);
}

/** make, encrypt and decrypt of ctaes with the key and the block secret. */
int ctaes_block() {
    std::array<std::uint8_t, 32> key{};
    std::array<std::uint8_t, 16> block{};
    key.fill(0x42);
    block.fill(0x17);
    VALGRIND_MAKE_MEM_UNDEFINED(key.data(), key.size());
    VALGRIND_MAKE_MEM_UNDEFINED(block.data(), block.size());
    auto made = crypto::ciphers::aes256<crypto::backends::ctaes>::make(key);
    bool const ok = made && made->encrypt(block) && made->decrypt(block);
    return ok ? 0 : 1;
}

/** Ed25519 on libsodium: make and sign with the seed secret. */
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
 * X25519 on libsodium: the public key and the agreement with the secret key secret, the peer's
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
    return check(own.has_value() && traced(*own), "X25519's public key on libsodium") +
           check(shared.has_value() && traced(shared->bytes()), "X25519's agreement on libsodium");
}

/** A box on libsodium: make with the secret key secret, then seal and open as an AEAD's. */
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
    // The agreement's verdict is libsodium's internal branch (sodium_verdicts.supp).
    auto made = Box::make(secret_key, *peer);
    auto tag = made->seal(iv, data);
    int const failures = check(tag.has_value() && traced(data) && traced(*tag), what);
    mark_secret(*tag);
    auto const opened = made->open(iv, data, *tag);
    bool const verdict = opened.has_value();
    static_cast<void>(VALGRIND_CHECK_VALUE_IS_DEFINED(verdict));
    return failures + check(verdict, what);
}

/** kx on libsodium: both key pairs from secret seeds, both sides' session keys. */
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

/** is_all_zero with its bytes secret, its result marked public for the test's own branch. */
int all_zero() {
    std::array<std::uint8_t, 32> bytes{};
    mark_secret(bytes);
    bool zero = crypto::detail::is_all_zero(bytes);
    bool const result_traced = traced({reinterpret_cast<std::uint8_t const*>(&zero), sizeof zero});
    VALGRIND_MAKE_MEM_DEFINED(&zero, sizeof zero);
    // The bytes are undefined, not zero: the result is whatever they hold, so only its being
    // traced is checked.
    return check(result_traced, "is_all_zero");
}

/**
 * secret's wipe: a move, a move assignment and the destructor overwrite the bytes they leave
 * behind with constants, without a branch on them, so that memcheck holds them defined after.
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
    bool const destroyed_wiped =
        !traced({reinterpret_cast<std::uint8_t const*>(storage.data()), storage.size()});
    return check(moved_from_wiped && assigned_from_wiped && kept && destroyed_wiped,
                 "secret's wipe");
}

}  // namespace

int main() {
    namespace ciphers = crypto::ciphers;
    std::array<std::uint8_t, 16> a{};
    std::array<std::uint8_t, 16> b{};
    VALGRIND_MAKE_MEM_UNDEFINED(a.data(), a.size());
    VALGRIND_MAKE_MEM_UNDEFINED(b.data(), b.size());
    bool equal = crypto::equal(a, b);
    VALGRIND_MAKE_MEM_DEFINED(&equal, sizeof equal);  // the test's own branch below
    int const failures =
        (equal ? 0 : 1) + all_zero() + secret_wipe() + bearssl_seal_and_open() +
        openssl_seal<ciphers::gcm<ciphers::aes256<crypto::backends::openssl>>>("OpenSSL GCM") +
        ctaes_block() +
        seal_and_open<ciphers::chacha20_poly1305<crypto::backends::bearssl>>("BearSSL ChaCha") +
        openssl_seal<ciphers::chacha20_poly1305<crypto::backends::openssl>>("OpenSSL ChaCha") +
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
    std::printf("constant time under memcheck: %s\n", failures == 0 ? "ok" : "FAILED");
    return failures;
}
