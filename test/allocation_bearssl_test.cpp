// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// On BearSSL nothing allocates (spec section 3.2): make, seal, open, the incremental seal,
// equal and random_device's fill, ChaCha20-Poly1305's make, seal, open (good and failed)
// and move, and P-256's key pair make and generate and public key make (of a point and of
// coordinates) make no call of operator new, nor of the C library's
// allocator where the target lets a program count it; a control proves the counter moves.

#include <webcpp/crypto/backends/bearssl.hpp>
#include <webcpp/crypto/ciphers/chacha20_poly1305.hpp>
#include <webcpp/crypto/curves/p256.hpp>
#include <webcpp/crypto/equal.hpp>
#include <webcpp/crypto/random_device.hpp>  // lint-world: a test
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

int main() {
    namespace crypto = webcpp::crypto;
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
    std::array<std::uint8_t, 12> iv{};
    std::array<std::uint8_t, 4096> data{};
    std::size_t const before = webcpp::test::allocations();
    {
        crypto::random_device device;  // lint-world: a test
        BOOST_TEST(device.fill(key).has_value());
        auto made =
            crypto::ciphers::gcm<crypto::ciphers::aes256<crypto::backends::bearssl>>::make(key);
        BOOST_TEST(made.has_value());
        auto const tag = made->seal(iv, {}, data);
        BOOST_TEST(tag.has_value());
        BOOST_TEST(made->open(iv, {}, data, *tag).has_value());
        BOOST_TEST(made->begin_seal(iv, {}).has_value());
        BOOST_TEST(made->update(data).has_value());
        BOOST_TEST(made->result().has_value());
        BOOST_TEST(crypto::equal(*tag, *tag));
        using chacha = crypto::ciphers::chacha20_poly1305<crypto::backends::bearssl>;
        auto sealer = chacha::make(key);
        BOOST_TEST(sealer.has_value());
        auto const sealed = sealer->seal(iv, iv, data);
        BOOST_TEST(sealed.has_value());
        BOOST_TEST(sealer->open(iv, iv, data, *sealed).has_value());
        std::array<std::uint8_t, 16> const forged{};
        BOOST_TEST(sealer->open(iv, iv, data, forged).error() ==
                   crypto::error::authentication_failed);
        chacha const moved = std::move(*sealer);
        namespace p256 = crypto::curves::p256;
        namespace data = webcpp::test::p256;
        using keypair = p256::basic_keypair<crypto::backends::bearssl>;
        using public_key = p256::basic_public_key<crypto::backends::bearssl>;
        auto const pair = keypair::make(data::rfc6979_scalar);
        BOOST_TEST(pair.has_value());
        BOOST_TEST(keypair::generate().has_value());
        std::span<std::uint8_t const, 65> const point(data::rfc6979_public);
        BOOST_TEST(public_key::make(point).has_value());
        BOOST_TEST(public_key::make(point.subspan<1, 32>(), point.subspan<33, 32>()).has_value());
    }
    BOOST_TEST_EQ(webcpp::test::allocations(), before);
    return webcpp::test::exit_status(boost::report_errors());
}
