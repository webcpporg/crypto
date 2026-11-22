// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// libsecp256k1's C API stays reachable beside crypto's wrappers: the recovery module's
// `secp256k1_ecdsa_sign_recoverable` and `secp256k1_ecdsa_recover`, and the ElligatorSwift
// module's `secp256k1_ellswift_create` and `secp256k1_ellswift_decode`, called and linked
// against `/third_party//secp256k1`. What the C calls give is compared with the wrappers: the
// key the C API recovers with `recover`'s, and the key ElligatorSwift decodes with
// `public_key::make`'s; both with the key pair's.

#include <webcpp/crypto/curves/secp256k1.hpp>
#include <webcpp/crypto/signing.hpp>
#include <webcpp/test/exit_status.hpp>

#include <boost/core/lightweight_test.hpp>

#include <secp256k1.h>
#include <secp256k1_ellswift.h>
#include <secp256k1_recovery.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>

namespace {

namespace crypto = webcpp::crypto;
namespace secp = webcpp::crypto::curves::secp256k1;

using secret_key = std::array<std::uint8_t, 32>;
using compressed_key = std::array<std::uint8_t, 33>;

// A public key, serialised compressed, as the crypto library's key pair gives it.
compressed_key serialised(secp256k1_context const* context, secp256k1_pubkey const& key) {
    compressed_key out{};
    std::size_t size = out.size();
    // NOLINTNEXTLINE(bugprone-signed-bitwise): libsecp256k1's macro shifts a signed constant
    unsigned const flags = SECP256K1_EC_COMPRESSED;
    BOOST_TEST_EQ(secp256k1_ec_pubkey_serialize(context, out.data(), &size, &key, flags), 1);
    BOOST_TEST_EQ(size, out.size());
    return out;
}

// Recovery: a recoverable signature of a hash, its compact form and recovery id, and the
// public key recovered from it, which is the key pair's; another hash recovers another key.
void recovery(secp256k1_context const* context, secret_key const& secret,
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

    // The wrapper recovers the same key from the same 65 bytes, r, s and the id.
    std::array<std::uint8_t, secp::recoverable_signature_size> with_id{};
    std::ranges::copy(compact, with_id.begin());
    with_id[64] = static_cast<std::uint8_t>(id);
    auto const wrapped =
        secp::recover(crypto::ecdsa_sha256_recoverable, with_id, crypto::prehashed{hash});
    auto const expected_key = secp::public_key::make(expected);
    if (BOOST_TEST(wrapped && expected_key)) {
        BOOST_TEST(*wrapped == *expected_key);
        BOOST_TEST(wrapped->compressed() == serialised(context, again));
    }

    hash.fill(0xa5);
    secp256k1_pubkey other;
    if (BOOST_TEST_EQ(secp256k1_ecdsa_recover(context, &other, &parsed, hash.data()), 1)) {
        BOOST_TEST(serialised(context, other) != expected);
    }
}

// ElligatorSwift: the 64-byte encoding of the public key of a secret decodes to that key.
void ellswift(secp256k1_context const* context, secret_key const& secret,
              compressed_key const& expected) {
    std::array<std::uint8_t, 64> encoded{};
    std::array<std::uint8_t, 32> randomness{};
    randomness.fill(0x77);
    BOOST_TEST_EQ(
        secp256k1_ellswift_create(context, encoded.data(), secret.data(), randomness.data()), 1);
    secp256k1_pubkey decoded;
    BOOST_TEST_EQ(secp256k1_ellswift_decode(context, &decoded, encoded.data()), 1);
    BOOST_TEST(serialised(context, decoded) == expected);

    // The decoded point, serialised by the C API, parses with the wrapper to the key pair's key.
    auto const wrapped = secp::public_key::make(serialised(context, decoded));
    auto const expected_key = secp::public_key::make(expected);
    if (BOOST_TEST(wrapped && expected_key)) {
        BOOST_TEST(*wrapped == *expected_key);
    }
}

}  // namespace

int main() {
    secret_key secret{};
    secret.fill(0x33);
    auto const key = secp::keypair::make(secret);
    if (!BOOST_TEST(key.has_value())) {
        return webcpp::test::exit_status(boost::report_errors());
    }
    auto const public_key = key->public_key();
    if (!BOOST_TEST(public_key.has_value())) {
        return webcpp::test::exit_status(boost::report_errors());
    }
    compressed_key const expected = public_key->compressed();

    // NOLINTNEXTLINE(bugprone-signed-bitwise): libsecp256k1's macro shifts a signed constant
    secp256k1_context* const context = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    if (!BOOST_TEST(context != nullptr)) {
        return webcpp::test::exit_status(boost::report_errors());
    }
    recovery(context, secret, expected);
    ellswift(context, secret, expected);
    secp256k1_context_destroy(context);
    return webcpp::test::exit_status(boost::report_errors());
}
