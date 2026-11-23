// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// async_sign of a P-256 key pair with crypto::eddsa, Ed25519's scheme, stops at async_sign's check
// of the key pair and the scheme, which names each key pair's scheme, and with that error alone.

// clang's -verify reads a directive from one comment line: wrapped, it checks nothing, so each
// whole text stays on one line.
// clang-format off
// expected-error@webcpp/crypto/async.hpp:* {{webcpp::crypto: async_sign: this key pair does not sign with this scheme: an Ed25519 key pair signs with crypto::eddsa, a P-256 key pair with crypto::ecdsa_sha256.}}
// clang-format on
#include <webcpp/crypto/async.hpp>
#include <webcpp/crypto/curves/p256.hpp>
#include <webcpp/crypto/signing.hpp>

#include <webcpp/asio/io_context.hpp>

#include <boost/system/error_code.hpp>

#include <array>
#include <cstdint>

int main() {
    namespace crypto = webcpp::crypto;
    std::array<std::uint8_t, 32> const scalar{1};
    std::array<std::uint8_t, 5> const message{'h', 'e', 'l', 'l', 'o'};
    auto const made = crypto::curves::p256::keypair::make(scalar);
    if (!made) {
        return 1;
    }
    webcpp::asio::io_context context;
    crypto::async_sign(context.get_executor(), *made, crypto::eddsa, message,
                       [](boost::system::error_code, std::array<std::uint8_t, 64>) {});
    return 0;
}
