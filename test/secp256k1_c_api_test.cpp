// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// A C module webcpp does not wrap, called and linked (spec section 2.8, "A C module not
// wrapped"): the recovery module's `secp256k1_ecdsa_sign_recoverable` and
// `secp256k1_ecdsa_recover`, and the ElligatorSwift module's `secp256k1_ellswift_create` and
// `secp256k1_ellswift_decode`, against `/third_party//secp256k1` and nothing else of webcpp's
// but the key pair, which names the public key they must agree with.

#include <webcpp/crypto/curves/secp256k1.hpp>
#include <webcpp/test/exit_status.hpp>

#include <boost/core/lightweight_test.hpp>

#include <secp256k1.h>
#include <secp256k1_ellswift.h>
#include <secp256k1_recovery.h>

#include <array>
#include <cstddef>
#include <cstdint>

namespace {

namespace secp = webcpp::crypto::curves::secp256k1;

using secret_key = std::array<std::uint8_t, 32>;
using compressed_key = std::array<std::uint8_t, 33>;

// A public key, serialised compressed, as the crypto library's key pair gives it.
compressed_key serialised(secp256k1_context const* context, secp256k1_pubkey const& key) {
    compressed_key out{};
    std::size_t size = out.size();
    BOOST_TEST_EQ(
        secp256k1_ec_pubkey_serialize(context, out.data(), &size, &key, SECP256K1_EC_COMPRESSED),
        1);
    BOOST_TEST_EQ(size, out.size());
    return out;
}

// Recovery: a recoverable signature of a hash, its compact form and recovery id, and the
// public key recovered from it, which is the key pair's; another hash recovers another key.
void recovery(secp256k1_context* context, secret_key const& secret,
              compressed_key const& expected) {
    std::array<std::uint8_t, 32> hash{};
    hash.fill(0x5a);
    secp256k1_ecdsa_recoverable_signature signature;
    BOOST_TEST_EQ(secp256k1_ecdsa_sign_recoverable(context, &signature, hash.data(), secret.data(),
                                                   nullptr, nullptr),
                  1);
    secp256k1_pubkey recovered;
    BOOST_TEST_EQ(secp256k1_ecdsa_recover(context, &recovered, &signature, hash.data()), 1);
    BOOST_TEST(serialised(context, recovered) == expected);

    std::array<std::uint8_t, 64> compact{};
    int id = -1;
    BOOST_TEST_EQ(secp256k1_ecdsa_recoverable_signature_serialize_compact(context, compact.data(),
                                                                          &id, &signature),
                  1);
    BOOST_TEST(id >= 0 && id <= 3);
    secp256k1_ecdsa_recoverable_signature parsed;
    BOOST_TEST_EQ(
        secp256k1_ecdsa_recoverable_signature_parse_compact(context, &parsed, compact.data(), id),
        1);
    secp256k1_pubkey again;
    BOOST_TEST_EQ(secp256k1_ecdsa_recover(context, &again, &parsed, hash.data()), 1);
    BOOST_TEST(serialised(context, again) == expected);

    hash.fill(0xa5);
    secp256k1_pubkey other;
    if (BOOST_TEST_EQ(secp256k1_ecdsa_recover(context, &other, &parsed, hash.data()), 1)) {
        BOOST_TEST(serialised(context, other) != expected);
    }
}

// ElligatorSwift: the 64-byte encoding of the public key of a secret decodes to that key.
void ellswift(secp256k1_context* context, secret_key const& secret,
              compressed_key const& expected) {
    std::array<std::uint8_t, 64> encoded{};
    std::array<std::uint8_t, 32> randomness{};
    randomness.fill(0x77);
    BOOST_TEST_EQ(
        secp256k1_ellswift_create(context, encoded.data(), secret.data(), randomness.data()), 1);
    secp256k1_pubkey decoded;
    BOOST_TEST_EQ(secp256k1_ellswift_decode(context, &decoded, encoded.data()), 1);
    BOOST_TEST(serialised(context, decoded) == expected);
}

}  // namespace

int main() {
    secret_key secret{};
    secret.fill(0x33);
    auto const key = secp::keypair::make(secret);
    if (!BOOST_TEST(key.has_value())) {
        return webcpp::test::exit_status(boost::report_errors());
    }
    auto const expected = key->public_key();
    if (!BOOST_TEST(expected.has_value())) {
        return webcpp::test::exit_status(boost::report_errors());
    }

    secp256k1_context* const context = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    if (!BOOST_TEST(context != nullptr)) {
        return webcpp::test::exit_status(boost::report_errors());
    }
    recovery(context, secret, *expected);
    ellswift(context, secret, *expected);
    secp256k1_context_destroy(context);
    return webcpp::test::exit_status(boost::report_errors());
}
