// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// Two backends on the same inputs (spec section 8.2), from a seeded generator whose seed a
// failure prints.
//
// AES-GCM: random keys of 16, 24 and 32 bytes, IVs of 12 bytes and of random lengths from 1
// to 64, additional data of 0 to 64 bytes, messages of every size within 1 of a multiple of
// 16 up to 4,096 bytes and 256 more of 0 to 4,096. What one seals the other opens, and the
// ciphertexts and tags are byte-identical.
//
// The AES block cipher: 10,000 random keys of each size, each with a random message of 0 to
// 64 blocks; encrypting and decrypting give the same bytes on both backends.
//
// ChaCha20-Poly1305: a random key, a 12-byte nonce and 0 to 64 bytes of additional data per
// message, messages of every size within 1 of a multiple of 64 up to 4,096 bytes and one in
// sixteen of the others. What one seals the other opens, and the ciphertexts and tags are
// byte-identical.

#ifndef WEBCPP_TEST_CRYPTO_SUPPORT_AGREEMENT_HPP
#define WEBCPP_TEST_CRYPTO_SUPPORT_AGREEMENT_HPP

#include <webcpp/crypto/ciphers/aes.hpp>
#include <webcpp/crypto/ciphers/chacha20_poly1305.hpp>
#include <webcpp/crypto/ciphers/gcm.hpp>

#include <boost/core/lightweight_test.hpp>

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <random>
#include <vector>

namespace webcpp::test {

/** Random bytes from the test's generator. */
inline std::vector<std::uint8_t> random_bytes(std::mt19937_64& generator, std::size_t size) {
    std::vector<std::uint8_t> out(size);
    for (auto& b : out) {
        b = static_cast<std::uint8_t>(generator());
    }
    return out;
}

/** Prints the seed and the case of a disagreement, so that it can be replayed. */
inline void print_disagreement(std::uint64_t seed, char const* what, std::size_t key_size,
                               std::size_t message_size) {
    static_cast<void>(
        std::fprintf(stderr, "%s disagrees: seed %llu, key of %zu bytes, message of %zu bytes\n",
                     what, static_cast<unsigned long long>(seed), key_size, message_size));
}

/** One AES-GCM case on both ciphers' backends; false once they disagree. */
template <class CipherA, class CipherB>
bool agree_gcm_once(std::mt19937_64& generator, std::size_t message_size, std::uint64_t seed) {
    namespace ciphers = crypto::ciphers;
    auto const key = random_bytes(generator, CipherA::key_size);
    auto const iv_size = generator() % 2 == 0 ? 12 : 1 + (generator() % 64);
    auto const iv = random_bytes(generator, iv_size);
    auto const additional_data = random_bytes(generator, generator() % 65);
    auto const message = random_bytes(generator, message_size);
    auto a = ciphers::gcm<CipherA>::from_key(key);
    auto b = ciphers::gcm<CipherB>::from_key(key);
    if (!BOOST_TEST(a.has_value()) || !BOOST_TEST(b.has_value())) {
        return false;
    }
    auto data_a = message;
    auto data_b = message;
    auto const tag_a = a->seal(iv, additional_data, data_a);
    auto const tag_b = b->seal(iv, additional_data, data_b);
    bool const same = tag_a && tag_b && data_a == data_b && *tag_a == *tag_b;
    if (!BOOST_TEST(same)) {
        print_disagreement(seed, "AES-GCM", CipherA::key_size, message_size);
        return false;
    }
    bool const opened = BOOST_TEST(b->open(iv, additional_data, data_a, *tag_a).has_value()) &&
                        BOOST_TEST(a->open(iv, additional_data, data_b, *tag_b).has_value()) &&
                        BOOST_TEST(data_a == message && data_b == message);
    if (!opened) {
        print_disagreement(seed, "AES-GCM", CipherA::key_size, message_size);
    }
    return opened;
}

/** The message sizes of AES-GCM's agreement, the fixed ones and 256 random ones. */
inline std::vector<std::size_t> gcm_message_sizes(std::mt19937_64& generator) {
    constexpr std::size_t largest = 4096;
    std::vector<std::size_t> sizes;
    for (std::size_t size = 0; size <= largest; size += 16) {
        for (std::size_t const near : {size == 0 ? 0 : size - 1, size, size + 1}) {
            if (near <= largest && (sizes.empty() || near != sizes.back())) {
                sizes.push_back(near);
            }
        }
    }
    for (int i = 0; i < 256; ++i) {
        sizes.push_back(static_cast<std::size_t>(generator() % (largest + 1)));
    }
    return sizes;
}

/**
 * Every case of spec section 8.2 for AES-GCM on backends A and B, with the three key sizes;
 * stops at the first disagreement.
 */
template <class A, class B>
void agree_gcm(std::uint64_t seed) {
    namespace ciphers = crypto::ciphers;
    std::mt19937_64 generator(seed);
    for (std::size_t const size : gcm_message_sizes(generator)) {
        if (!agree_gcm_once<ciphers::aes128<A>, ciphers::aes128<B>>(generator, size, seed) ||
            !agree_gcm_once<ciphers::aes192<A>, ciphers::aes192<B>>(generator, size, seed) ||
            !agree_gcm_once<ciphers::aes256<A>, ciphers::aes256<B>>(generator, size, seed)) {
            return;
        }
    }
}

/** One random key and message of the AES block cipher on both backends; false if they differ. */
template <class CipherA, class CipherB>
bool agree_aes_once(std::mt19937_64& generator, std::uint64_t seed) {
    constexpr std::size_t max_blocks = 64;
    auto const key = random_bytes(generator, CipherA::key_size);
    auto a = CipherA::from_key(key);
    auto b = CipherB::from_key(key);
    if (!BOOST_TEST(a.has_value()) || !BOOST_TEST(b.has_value())) {
        return false;
    }
    auto const message = random_bytes(generator, 16 * (generator() % (max_blocks + 1)));
    auto data_a = message;
    auto data_b = message;
    bool const same = BOOST_TEST(a->encrypt(data_a).has_value()) &&
                      BOOST_TEST(b->encrypt(data_b).has_value()) && BOOST_TEST(data_a == data_b) &&
                      BOOST_TEST(a->decrypt(data_a).has_value()) &&
                      BOOST_TEST(b->decrypt(data_b).has_value()) &&
                      BOOST_TEST(data_a == message && data_b == message);
    if (!same) {
        print_disagreement(seed, "AES", CipherA::key_size, message.size());
    }
    return same;
}

/** The AES block cipher's agreement for one key size, stopping at the first disagreement. */
template <class CipherA, class CipherB>
void agree_aes_size(std::mt19937_64& generator, std::uint64_t seed) {
    constexpr int keys_per_size = 10000;
    for (int i = 0; i < keys_per_size; ++i) {
        if (!agree_aes_once<CipherA, CipherB>(generator, seed)) {
            return;
        }
    }
}

/** Every case of spec section 8.2 for the AES block cipher on backends A and B. */
template <class A, class B>
void agree_aes(std::uint64_t seed) {
    namespace ciphers = crypto::ciphers;
    std::mt19937_64 generator(seed);
    agree_aes_size<ciphers::aes128<A>, ciphers::aes128<B>>(generator, seed);
    agree_aes_size<ciphers::aes192<A>, ciphers::aes192<B>>(generator, seed);
    agree_aes_size<ciphers::aes256<A>, ciphers::aes256<B>>(generator, seed);
}

/** One ChaCha20-Poly1305 message on backends A and B; false once they disagree. */
template <class A, class B>
bool agree_chacha_once(std::mt19937_64& generator, std::size_t message_size, std::uint64_t seed) {
    namespace ciphers = crypto::ciphers;
    auto const key = random_bytes(generator, 32);
    auto const iv = random_bytes(generator, 12);
    auto const additional_data = random_bytes(generator, generator() % 65);
    auto const message = random_bytes(generator, message_size);
    auto a = ciphers::chacha20_poly1305<A>::from_key(key);
    auto b = ciphers::chacha20_poly1305<B>::from_key(key);
    if (!BOOST_TEST(a.has_value()) || !BOOST_TEST(b.has_value())) {
        return false;
    }
    auto data_a = message;
    auto data_b = message;
    auto const tag_a = a->seal(iv, additional_data, data_a);
    auto const tag_b = b->seal(iv, additional_data, data_b);
    bool const same = tag_a && tag_b && data_a == data_b && *tag_a == *tag_b;
    if (!BOOST_TEST(same)) {
        print_disagreement(seed, "ChaCha20-Poly1305", 32, message_size);
        return false;
    }
    bool const opened = BOOST_TEST(b->open(iv, additional_data, data_a, *tag_a).has_value()) &&
                        BOOST_TEST(a->open(iv, additional_data, data_b, *tag_b).has_value()) &&
                        BOOST_TEST(data_a == message && data_b == message);
    if (!opened) {
        print_disagreement(seed, "ChaCha20-Poly1305", 32, message_size);
    }
    return opened;
}

/**
 * ChaCha20-Poly1305 on backends A and B: every message size within 1 of a multiple of 64 up to
 * 4,096 bytes, and one in sixteen of the others; stops at the first disagreement.
 */
template <class A, class B>
void agree_chacha(std::uint64_t seed) {
    constexpr std::size_t largest = 4096;
    std::mt19937_64 generator(seed);
    for (std::size_t size = 0; size <= largest; ++size) {
        bool const near = size % 64 <= 1 || size % 64 == 63;
        if (!near && generator() % 16 != 0) {
            continue;
        }
        if (!agree_chacha_once<A, B>(generator, size, seed)) {
            return;
        }
    }
}

}  // namespace webcpp::test

#endif
