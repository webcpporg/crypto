// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// Every curve's crypto::verify in one program: a 32-byte array is Ed25519's key under
// crypto::eddsa and BIP340's x-only key under crypto::schnorr, each call resolved to its curve's
// overload with no ambiguity and no catch-all, and each signature verifying under its own scheme
// alone; ECDSA takes each curve's key object and no bytes.

#include <webcpp/crypto/backends/bearssl.hpp>
#include <webcpp/crypto/backends/sodium.hpp>
#include <webcpp/crypto/curves/ed25519.hpp>
#include <webcpp/crypto/curves/p256.hpp>
#include <webcpp/crypto/curves/secp256k1.hpp>
#include <webcpp/crypto/error.hpp>
#include <webcpp/crypto/signing.hpp>
#include <webcpp/test/exit_status.hpp>

#include <boost/core/lightweight_test.hpp>

#include <array>
#include <cstdint>
#include <span>

namespace crypto = webcpp::crypto;

namespace {

using key_bytes = std::array<std::uint8_t, 32>;
using message_bytes = std::span<std::uint8_t const>;

// A 32-byte array is a key of eddsa and of schnorr, and of no other scheme.
static_assert(crypto::detail::has_verifier_v<crypto::eddsa_t, key_bytes>);
static_assert(crypto::detail::has_verifier_v<crypto::schnorr_t, key_bytes>);
static_assert(!crypto::detail::has_verifier_v<crypto::ecdsa_sha256_t, key_bytes>);
static_assert(crypto::can_verify<crypto::eddsa_t, message_bytes, key_bytes>);
static_assert(crypto::can_verify<crypto::schnorr_t, message_bytes, key_bytes>);
static_assert(!crypto::can_verify<crypto::ecdsa_sha256_t, message_bytes, key_bytes>);
// A span of a size known only at run time is Ed25519's key, whose size verify checks, and no
// x-only key.
static_assert(crypto::can_verify<crypto::eddsa_t, message_bytes, std::span<std::uint8_t const>>);
static_assert(!crypto::can_verify<crypto::schnorr_t, message_bytes, std::span<std::uint8_t const>>);
// ECDSA's key is each curve's object.
static_assert(crypto::can_verify<crypto::ecdsa_sha256_t, message_bytes,
                                 crypto::curves::secp256k1::public_key>);
static_assert(
    crypto::can_verify<crypto::ecdsa_sha256_t, message_bytes,
                       crypto::curves::p256::basic_public_key<crypto::backends::bearssl>>);

// Ed25519 and BIP340 signatures, each against its key held in a 32-byte array: each verifies
// under its own scheme and is refused under the other.
void byte_keys() {
    key_bytes seed{};
    seed.fill(0x42);
    std::array<std::uint8_t, 5> const message{'h', 'e', 'l', 'l', 'o'};
    auto const ed25519 = crypto::curves::ed25519::keypair::make(seed);
    auto const secp256k1 = crypto::curves::secp256k1::keypair::make(seed);
    if (!BOOST_TEST(ed25519.has_value()) || !BOOST_TEST(secp256k1.has_value())) {
        return;
    }
    key_bytes const ed25519_key = *ed25519->public_key();
    key_bytes const xonly_key = *secp256k1->xonly_public_key();
    auto const eddsa_signature = ed25519->sign(crypto::eddsa, message);
    auto const schnorr_signature = secp256k1->sign(crypto::schnorr, message);
    if (!BOOST_TEST(eddsa_signature.has_value()) || !BOOST_TEST(schnorr_signature.has_value())) {
        return;
    }
    BOOST_TEST(crypto::verify(crypto::eddsa, *eddsa_signature, message, ed25519_key).has_value());
    BOOST_TEST(crypto::verify(crypto::schnorr, *schnorr_signature, message, xonly_key).has_value());
    BOOST_TEST(crypto::verify(crypto::eddsa, *schnorr_signature, message, ed25519_key).error() ==
               crypto::error::invalid_signature);
    BOOST_TEST(crypto::verify(crypto::schnorr, *eddsa_signature, message, xonly_key).has_error());
}

}  // namespace

int main() {
    byte_keys();
    return webcpp::test::exit_status(boost::report_errors());
}
