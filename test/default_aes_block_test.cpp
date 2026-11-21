// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The AES block cipher's default backend, apart from AES-GCM's (design D3): aes256<> is the block
// cipher's default, OpenSSL natively and ctaes on wasip2, wasip3 and Emscripten, while
// aes256_gcm, aes128_gcm and gcm<aes256<>> stay on AES-GCM's, OpenSSL natively and BearSSL on
// WebAssembly. test/Jamfile links both families' defaults through their aliases, so that on
// WebAssembly ctaes and BearSSL are linked side by side.

#include <webcpp/crypto/ciphers/aes.hpp>
#include <webcpp/crypto/ciphers/aes256_gcm.hpp>
#include <webcpp/test/exit_status.hpp>

#include <boost/core/lightweight_test.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <type_traits>

namespace crypto = webcpp::crypto;

#ifdef WEBCPP_CRYPTO_WEBASSEMBLY
using block_expected = crypto::backends::ctaes;
using gcm_expected = crypto::backends::bearssl;
#else
using block_expected = crypto::backends::openssl;
using gcm_expected = crypto::backends::openssl;
#endif

static_assert(std::is_same_v<crypto::ciphers::aes256<>::backend_type, block_expected>);
static_assert(std::is_same_v<crypto::ciphers::aes128<>::backend_type, block_expected>);
static_assert(std::is_same_v<crypto::ciphers::aes192<>::backend_type, block_expected>);
static_assert(std::is_same_v<crypto::ciphers::aes256<>::named_backend_type,
                             crypto::backends::family_default>);
static_assert(std::is_same_v<crypto::ciphers::aes256_gcm::backend_type, gcm_expected>);
static_assert(
    std::is_same_v<crypto::ciphers::gcm<crypto::ciphers::aes256<>>::backend_type, gcm_expected>);
static_assert(std::is_same_v<crypto::ciphers::aes128_gcm::backend_type, gcm_expected>);
// A backend named in the type is itself, for the block cipher and for GCM over it.
static_assert(std::is_same_v<crypto::ciphers::aes256<gcm_expected>::backend_type, gcm_expected>);
static_assert(
    std::is_same_v<crypto::ciphers::gcm<crypto::ciphers::aes256<gcm_expected>>::backend_type,
                   gcm_expected>);

int main() {
    // FIPS-197 appendix C.3: AES-256 of 00112233...eeff under the key 000102...1f.
    std::array<std::uint8_t, 32> key{};
    for (std::size_t i = 0; i < key.size(); ++i) {
        key[i] = static_cast<std::uint8_t>(i);
    }
    std::array<std::uint8_t, 16> const plain{
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    };
    std::array<std::uint8_t, 16> const expected{
        0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf,
        0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89,
    };
    auto aes = crypto::ciphers::aes256<>::make(key);
    BOOST_TEST(aes.has_value());
    if (aes) {
        std::array<std::uint8_t, 16> block = plain;
        BOOST_TEST(aes->encrypt(block).has_value());
        BOOST_TEST(block == expected);
        BOOST_TEST(aes->decrypt(block).has_value());
        BOOST_TEST(block == plain);
    }
    BOOST_TEST_EQ(crypto::ciphers::aes256<>::backend_type::name, block_expected::name);
    BOOST_TEST(crypto::ciphers::aes256_gcm::make(key).has_value());
    BOOST_TEST_EQ(crypto::ciphers::aes256_gcm::backend_type::name, gcm_expected::name);
    return webcpp::test::exit_status(boost::report_errors());
}
