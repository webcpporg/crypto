// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The AES block cipher on OpenSSL: the block cipher's checks (support/aes_checks.hpp), and
// OpenSSL's known answers, FIPS-197 appendix C and AES-128 of the zero block under the zero key.

#include <webcpp/crypto/aes.hpp>
#include <webcpp/crypto/backends/openssl.hpp>
#include <webcpp/test/exit_status.hpp>

#include "support/aes_checks.hpp"
#include "support/hex.hpp"

#include <boost/core/lightweight_test.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

namespace {

namespace crypto = webcpp::crypto;
using crypto::backends::openssl;
using webcpp::test::from_hex;
using webcpp::test::to_hex;

/** Encrypts `plain` with `Cipher` under `key`, checks `expected`, and decrypts it back. */
template <class Cipher>
void check_answer(std::span<std::uint8_t const> key, std::string_view plain,
                  std::string_view expected) {
    auto made = Cipher::make(key);
    if (!BOOST_TEST(made.has_value())) {
        return;
    }
    auto const plaintext = from_hex(plain);
    auto block = plaintext;
    BOOST_TEST(made->encrypt(block).has_value());
    BOOST_TEST_EQ(to_hex(block), expected);
    BOOST_TEST(made->decrypt(block).has_value());
    BOOST_TEST(block == plaintext);
}

/** FIPS-197 appendix C.1, C.2 and C.3: the key 00 01 02 ..., the block 00 11 22 ... ff. */
void check_fips197() {
    std::array<std::uint8_t, 32> key{};
    for (std::size_t i = 0; i < key.size(); ++i) {
        key[i] = static_cast<std::uint8_t>(i);
    }
    constexpr std::string_view plain = "00112233445566778899aabbccddeeff";
    check_answer<crypto::aes128<openssl>>(std::span(key).first(16), plain,
                                          "69c4e0d86a7b0430d8cdb78070b4c55a");
    check_answer<crypto::aes192<openssl>>(std::span(key).first(24), plain,
                                          "dda97ca4864cdfe06eaf70a0ec0d7191");
    check_answer<crypto::aes256<openssl>>(key, plain, "8ea2b7ca516745bfeafc49904b496089");
}

}  // namespace

int main() {
    webcpp::test::check_block_cipher<openssl>();
    check_fips197();
    std::array<std::uint8_t, 16> const zero_key{};
    check_answer<crypto::aes128<openssl>>(zero_key, "00000000000000000000000000000000",
                                          "66e94bd4ef8a2c3b884cfa59ca342b2e");
    return webcpp::test::exit_status(boost::report_errors());
}
