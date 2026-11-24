// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// crypto_kx, the box and the sealed box on a backend that has them but no X25519 (a stand-in,
// as the capability table would declare a later one) stop where each class is named, each with
// the one refusal that says it takes an X25519 key pair of its own backend, and with those
// errors alone: no engine's and no X25519's after them. The key pair and the public key are
// parameters, since making them would call X25519's engine.

// clang's -verify reads a directive from one comment line: wrapped, it checks nothing, so each
// whole text stays on one line.
// clang-format off
// expected-error@webcpp/crypto/key_exchange/kx.hpp:* {{webcpp::crypto: key_exchange::kx_keypair holds an X25519 key pair of its own backend, which has no X25519.}}
// expected-error@webcpp/crypto/public_key_encryption/box.hpp:* {{webcpp::crypto: public_key_encryption::basic_box takes an X25519 key pair of its own backend, which has no X25519.}}
// expected-error@webcpp/crypto/public_key_encryption/sealed_box.hpp:* {{webcpp::crypto: public_key_encryption::basic_sealed_box takes an X25519 key pair of its own backend, which has no X25519.}}
// clang-format on
#include <webcpp/crypto/curves/x25519.hpp>
#include <webcpp/crypto/detail/capabilities.hpp>
#include <webcpp/crypto/key_exchange/kx.hpp>
#include <webcpp/crypto/public_key_encryption/box.hpp>
#include <webcpp/crypto/public_key_encryption/sealed_box.hpp>

#include <array>
#include <cstdint>

namespace {

/** A backend that has crypto_kx, the box and the sealed box, and no X25519. */
struct without_x25519 {};

}  // namespace

namespace webcpp::crypto::detail {

/** The stand-in has crypto_kx. */
template <>
inline constexpr bool supported<families::kx, families::kx, without_x25519> = true;

/** The stand-in has the X25519-XSalsa20-Poly1305 box. */
template <>
inline constexpr bool
    supported<families::box_xsalsa20poly1305, families::box_xsalsa20poly1305, without_x25519> =
        true;

/** The stand-in has the sealed box. */
template <>
inline constexpr bool supported<families::sealed_box, families::sealed_box, without_x25519> = true;

}  // namespace webcpp::crypto::detail

namespace {

namespace crypto = webcpp::crypto;

/** Names the three on the stand-in, with a key pair and a public key of its own. */
bool named(crypto::curves::x25519::basic_keypair<without_x25519> const& own_keypair,
           crypto::curves::x25519::public_key const& peer_public_key) {
    std::array<std::uint8_t, 32> const seed{};
    std::array<std::uint8_t, 48> sealed{};
    return crypto::key_exchange::kx_keypair<without_x25519>::derive_from_seed(seed) &&
           crypto::public_key_encryption::basic_box<crypto::families::box_xsalsa20poly1305,
                                                    without_x25519>::from_keys(own_keypair,
                                                                               peer_public_key) &&
           crypto::public_key_encryption::basic_sealed_box<without_x25519>::seal(peer_public_key,
                                                                                 {}, sealed);
}

}  // namespace

// The function is compiled, which is the test; it is never run.
int main() {
    static_cast<void>(&named);
    return 0;
}
