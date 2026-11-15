// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// ctaes against OpenSSL (spec section 8.2, second row): 10,000 random keys of each size and a
// random message of 0 to 64 blocks for each, from a seeded generator; encrypting and decrypting
// give the same bytes on both backends.

#include <webcpp/crypto/aes.hpp>
#include <webcpp/crypto/backends/ctaes.hpp>
#include <webcpp/crypto/backends/openssl.hpp>
#include <webcpp/test/exit_status.hpp>

#include <boost/core/lightweight_test.hpp>

#include <cstddef>
#include <cstdint>
#include <random>
#include <span>
#include <vector>

namespace {

namespace crypto = webcpp::crypto;

constexpr int keys_per_size = 10000;
constexpr std::size_t max_blocks = 64;

/** Fills bytes from the generator, one byte of each draw. */
void fill(std::mt19937_64& generator, std::span<std::uint8_t> bytes) {
    for (auto& byte : bytes) {
        byte = static_cast<std::uint8_t>(generator());
    }
}

/** Checks one random key and message on both backends; false once they disagree. */
template <template <class> class Cipher, std::size_t KeySize>
bool agree_once(std::mt19937_64& generator, std::vector<std::uint8_t>& key) {
    fill(generator, key);
    auto ours = Cipher<crypto::backends::ctaes>::make(key);
    auto theirs = Cipher<crypto::backends::openssl>::make(key);
    if (!BOOST_TEST(ours.has_value()) || !BOOST_TEST(theirs.has_value())) {
        return false;
    }
    std::vector<std::uint8_t> message(16 * (generator() % (max_blocks + 1)));
    fill(generator, message);
    auto a = message;
    auto b = message;
    BOOST_TEST(ours->encrypt(a).has_value());
    BOOST_TEST(theirs->encrypt(b).has_value());
    if (!BOOST_TEST(a == b)) {
        return false;
    }
    BOOST_TEST(ours->decrypt(a).has_value());
    BOOST_TEST(theirs->decrypt(b).has_value());
    return BOOST_TEST(a == message) && BOOST_TEST(b == message);
}

/** Runs the agreement for one key size, stopping at the first disagreement. */
template <template <class> class Cipher, std::size_t KeySize>
void agree(std::mt19937_64& generator) {
    std::vector<std::uint8_t> key(KeySize);
    for (int i = 0; i < keys_per_size; ++i) {
        if (!agree_once<Cipher, KeySize>(generator, key)) {
            return;
        }
    }
}

}  // namespace

int main() {
    // NOLINTNEXTLINE(bugprone-random-generator-seed): a fixed seed, so a failure repeats
    std::mt19937_64 generator(0x5eedae5ULL);
    agree<crypto::aes128, 16>(generator);
    agree<crypto::aes192, 24>(generator);
    agree<crypto::aes256, 32>(generator);
    return webcpp::test::exit_status(boost::report_errors());
}
