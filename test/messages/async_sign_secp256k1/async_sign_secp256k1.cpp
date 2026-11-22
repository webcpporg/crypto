// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// async_sign on a key pair of an algorithm WebCrypto lacks, secp256k1's, stops with the key pair's
// own signing to call instead, and with that error alone, while the key pair's sign_ecdsa
// compiles.

// clang-format off
// expected-error@webcpp/crypto/async.hpp:* {{webcpp::crypto: async_sign takes a key pair of an algorithm WebCrypto has (Ed25519, P-256): call the key pair's sign for the others.}}
// clang-format on
#include <webcpp/crypto/async.hpp>
#include <webcpp/crypto/curves/secp256k1.hpp>

#include <webcpp/asio/io_context.hpp>

#include <boost/system/error_code.hpp>

#include <array>
#include <cstdint>

int main() {
    namespace crypto = webcpp::crypto;
    std::array<std::uint8_t, 32> const seed{1};
    std::array<std::uint8_t, 32> const message{};
    auto made = crypto::curves::secp256k1::keypair::make(seed);
    if (!made) {
        return 1;
    }
    // The synchronous signing compiles.
    if (!made->sign_ecdsa(message)) {
        return 1;
    }
    webcpp::asio::io_context context;
    crypto::async_sign(context.get_executor(), *made, message,
                       [](boost::system::error_code, std::array<std::uint8_t, 64>) {});
    return 0;
}
