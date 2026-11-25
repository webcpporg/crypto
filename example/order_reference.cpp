// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// Turns a sequential order id into an opaque 16-byte reference with the raw AES block cipher,
// and back. Customers then cannot guess other orders' numbers. This is NOT authenticated
// encryption: a forged reference still decrypts, to garbage, so the program checks the padding.
// tag::program[]
#include <webcpp/crypto/backends/ctaes.hpp>
#include <webcpp/crypto/ciphers/aes.hpp>
#include <webcpp/secure/erase_secret.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <span>

namespace crypto = webcpp::crypto;
namespace secure = webcpp::secure;
using cipher_type = crypto::ciphers::aes256<crypto::backends::ctaes>;

namespace {

bool padding_is_zero(std::span<std::uint8_t const, 16> block) {
    return std::ranges::all_of(block.last<8>(), [](std::uint8_t b) { return b == 0; });
}

}  // namespace

int main() {
    // A demonstration key, so that the output is the same on every run. A real program draws
    // it once from random_device and keeps it secret.
    std::array<std::uint8_t, 32> key{};
    for (std::size_t i = 0; i < key.size(); ++i) {
        key[i] = static_cast<std::uint8_t>(i);
    }
    auto cipher = cipher_type::from_key(key);
    secure::erase_secret(key);
    if (!cipher) {
        return 1;
    }

    // tag::block[]
    // The id goes big-endian in the first 8 bytes of a block; the other 8 stay zero.
    std::uint64_t const order = 1234;
    std::array<std::uint8_t, 16> block{};
    for (std::size_t i = 0; i < 8; ++i) {
        block[7 - i] = static_cast<std::uint8_t>(order >> (8U * i));
    }
    if (!cipher->encrypt(block)) {
        return 1;
    }
    std::printf("reference ");
    for (std::uint8_t const byte : block) {
        std::printf("%02x", byte);
    }
    std::printf("\n");
    auto const reference = block;

    if (!cipher->decrypt(block) || !padding_is_zero(block)) {
        return 1;
    }
    std::uint64_t decoded = 0;
    for (std::size_t i = 0; i < 8; ++i) {
        decoded = (decoded << 8U) | block[i];
    }
    std::printf("order %llu\n", static_cast<unsigned long long>(decoded));
    // end::block[]
    if (decoded != order) {
        return 1;
    }

    // A forged reference decrypts to a block whose padding is not zero.
    auto forged = reference;
    forged[0] ^= 1U;
    if (!cipher->decrypt(forged) || padding_is_zero(forged)) {
        return 1;
    }
    std::printf("forged reference refused\n");
    return 0;
}

// end::program[]
