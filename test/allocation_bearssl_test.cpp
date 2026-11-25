// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// On BearSSL nothing allocates (spec section 3.2): from_key, seal, open, the incremental seal,
// equal and random_device's fill, ChaCha20-Poly1305's from_key, seal, open (good and failed)
// and move, and P-256's key pair from_secret and generate, public key from_bytes and
// from_coordinates, sign(ecdsa_sha256, ...) and crypto::verify of a message and of a digest,
// to_der, from_der, normalize_low_s, is_low_s, agree, encode_spki, decode_spki, encode_pkcs8 and
// decode_pkcs8 make no call of operator new, nor of the C library's allocator where the target lets
// a program count it; a control proves the counter moves.

#include <webcpp/crypto/backends/bearssl.hpp>
#include <webcpp/crypto/ciphers/chacha20_poly1305.hpp>
#include <webcpp/crypto/curves/p256.hpp>
#include <webcpp/crypto/curves/p256/formats.hpp>
#include <webcpp/crypto/random_device.hpp>  // lint-world: a test
#include <webcpp/crypto/signing.hpp>
#include <webcpp/secure/constant_time_equal.hpp>
#include <webcpp/test/exit_status.hpp>

#include "support/counting.hpp"
#include "support/gcm_checks.hpp"
#include "support/p256_data.hpp"

#include <boost/core/lightweight_test.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <span>
#include <utility>

namespace {

// P-256's functions, each called once: the key pair's from_secret and generate, the public key's
// from_bytes and from_coordinates, ECDSA's eight (sign and verify each of a message and of a
// digest), ECDH's agree and the formats' four.
void p256_calls() {
    namespace crypto = webcpp::crypto;
    namespace p256 = crypto::curves::p256;
    namespace data = webcpp::test::p256;
    using keypair = p256::basic_keypair<crypto::backends::bearssl>;
    using public_key = p256::basic_public_key<crypto::backends::bearssl>;
    auto const pair = keypair::from_secret(data::rfc6979_scalar);
    BOOST_TEST(keypair::generate().has_value());
    std::span<std::uint8_t const, 65> const point(data::rfc6979_public);
    BOOST_TEST(public_key::from_bytes(point).has_value());
    BOOST_TEST(
        public_key::from_coordinates(point.subspan<1, 32>(), point.subspan<33, 32>()).has_value());
    std::array<std::uint8_t, p256::digest_size> digest{};
    digest.fill(0x5a);
    if (!BOOST_TEST(pair.has_value())) {
        return;
    }
    auto const signature = pair->sign(crypto::ecdsa_sha256, crypto::prehashed{digest});
    auto const of_message = pair->sign(crypto::ecdsa_sha256, digest);
    auto const key = public_key::from_bytes(point);
    if (!BOOST_TEST(signature.has_value()) || !BOOST_TEST(of_message.has_value()) ||
        !BOOST_TEST(key.has_value())) {
        return;
    }
    BOOST_TEST(crypto::verify(crypto::ecdsa_sha256, *signature, crypto::prehashed{digest}, *key)
                   .has_value());
    BOOST_TEST(crypto::verify(crypto::ecdsa_sha256, *of_message, digest, *key).has_value());
    std::array<std::uint8_t, p256::max_der_size> der{};
    auto const written = p256::to_der(*signature, der);
    if (BOOST_TEST(written.has_value())) {
        BOOST_TEST(p256::from_der(std::span(der).first(*written)).has_value());
    }
    BOOST_TEST(p256::normalize_low_s(*signature).has_value());
    BOOST_TEST(p256::is_low_s(*signature));
    BOOST_TEST(pair->agree(*key).has_value());
    std::array<std::uint8_t, p256::max_spki_size> spki{};
    std::array<std::uint8_t, p256::max_pkcs8_size> pkcs8{};
    BOOST_TEST(p256::encode_spki(*key, spki).has_value());
    BOOST_TEST(p256::decode_spki<crypto::backends::bearssl>(spki).has_value());
    BOOST_TEST(p256::encode_pkcs8(*pair, pkcs8).has_value());
    BOOST_TEST(p256::decode_pkcs8<crypto::backends::bearssl>(pkcs8).has_value());
}

}  // namespace

int main() {
    namespace crypto = webcpp::crypto;
    namespace secure = webcpp::secure;
    // The control: a malloc of the C library's moves the counter where it is counted.
    std::size_t const control = webcpp::test::allocations();
    void* volatile block = std::malloc(40);
    std::free(block);
    // A constant condition: `if constexpr`, which MSVC's C4127 (an error under /W4 /WX) leaves be.
    if constexpr (webcpp::test::c_allocations_counted) {
        BOOST_TEST_EQ(webcpp::test::allocations() - control, 1U);
    } else {
        BOOST_TEST_EQ(webcpp::test::allocations() - control, 0U);
        std::printf("the C library's allocations are not counted on this target\n");
    }
    std::array<std::uint8_t, 32> key{};
    std::array<std::uint8_t, 12> nonce{};
    std::array<std::uint8_t, 4096> data{};
    std::size_t const before = webcpp::test::allocations();
    {
        crypto::random_device device;  // lint-world: a test
        BOOST_TEST(device.fill(key).has_value());
        auto made =
            crypto::ciphers::gcm<crypto::ciphers::aes256<crypto::backends::bearssl>>::from_key(key);
        BOOST_TEST(made.has_value());
        auto const tag = made->seal(nonce, {}, data);
        BOOST_TEST(tag.has_value());
        BOOST_TEST(made->open(nonce, {}, data, *tag).has_value());
        BOOST_TEST(made->begin_seal(nonce, {}).has_value());
        BOOST_TEST(made->update(data).has_value());
        BOOST_TEST(made->result().has_value());
        auto const open_tag = made->seal(nonce, {}, data);
        BOOST_TEST(open_tag.has_value());
        BOOST_TEST(made->begin_open(nonce, {}).has_value());
        BOOST_TEST(made->authenticate(data).has_value());
        BOOST_TEST(made->verify(*open_tag).has_value());
        BOOST_TEST(made->decrypt(data).has_value());
        BOOST_TEST(made->end_open().has_value());
        BOOST_TEST(secure::constant_time_equal(*tag, *tag));
        using chacha = crypto::ciphers::chacha20_poly1305<crypto::backends::bearssl>;
        auto sealer = chacha::from_key(key);
        BOOST_TEST(sealer.has_value());
        auto const sealed = sealer->seal(nonce, nonce, data);
        BOOST_TEST(sealed.has_value());
        BOOST_TEST(sealer->open(nonce, nonce, data, *sealed).has_value());
        std::array<std::uint8_t, 16> const forged{};
        BOOST_TEST(sealer->open(nonce, nonce, data, forged).error() ==
                   crypto::error::authentication_failed);
        chacha const moved = std::move(*sealer);
        p256_calls();
    }
    BOOST_TEST_EQ(webcpp::test::allocations(), before);
    return webcpp::test::exit_status(boost::report_errors());
}
