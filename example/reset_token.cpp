// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// Draws a 32-byte password-reset token and a six-digit one-time code from the system's random
// generator. Tokens that can be guessed or repeated let an attacker take over accounts, so
// both come from random_device, never from rand() or the clock.
// tag::program[]
#include <webcpp/crypto/random_device.hpp>

#include <array>
#include <cstdint>
#include <cstdio>
#include <random>
#include <string>

namespace crypto = webcpp::crypto;

int main() {
    crypto::random_device device;

    // tag::token[]
    // 32 random bytes are 256 bits: far beyond any guessing, written as 64 hex digits.
    std::array<std::uint8_t, 32> raw{};
    if (!device.fill(raw)) {
        return 1;
    }
    std::string token;
    for (std::uint8_t const byte : raw) {
        char const* const hex = "0123456789abcdef";
        token += hex[byte >> 4U];
        token += hex[byte & 0x0FU];
    }
    // end::token[]

#ifndef WEBCPP_CRYPTO_NO_EXCEPTIONS
    // tag::code[]
    // The distribution removes the bias a plain modulo would add.
    std::uniform_int_distribution<unsigned> digits(0, 999999);
    unsigned const number = digits(device);
    std::array<char, 8> code{};
    if (std::snprintf(code.data(), code.size(), "%06u", number) != 6) {
        return 1;
    }
    // end::code[]
    std::size_t const code_length = std::char_traits<char>::length(code.data());
#else
    // Without exceptions the device has no operator(): draw from fill, rejecting the values that
    // would make some codes likelier than others.
    std::uint32_t number = 0;
    do {
        std::array<std::uint8_t, 4> word{};
        if (!device.fill(word)) {
            return 1;
        }
        number = (std::uint32_t{word[0]} << 24U) | (std::uint32_t{word[1]} << 16U) |
                 (std::uint32_t{word[2]} << 8U) | word[3];
    } while (number >= 4294000000U);
    std::array<char, 8> code{};
    if (std::snprintf(code.data(), code.size(), "%06u", number % 1000000U) != 6) {
        return 1;
    }
    std::size_t const code_length = std::char_traits<char>::length(code.data());
#endif
    std::printf("token: %zu hex digits\n", token.size());
    std::printf("code: %zu digits\n", code_length);
    return 0;
}

// end::program[]
