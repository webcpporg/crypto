// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// async_verify of crypto::ecdsa_sha256 against a secp256k1 public key, an algorithm WebCrypto
// lacks, stops at the catch-all async_verify, which names the keys the asynchronous family takes
// and crypto::verify for the others, and with that error alone, while crypto::verify of the same
// arguments compiles.

// clang's -verify reads a directive from one comment line: wrapped, it checks nothing, so each
// whole text stays on one line.
// clang-format off
// expected-error@webcpp/crypto/async.hpp:* {{webcpp::crypto: async_verify takes crypto::eddsa with Ed25519's 32-byte key or crypto::ecdsa_sha256 with a curves::p256::basic_public_key, the algorithms WebCrypto has: call crypto::verify for the others.}}
// clang-format on
#include <webcpp/crypto/async.hpp>
#include <webcpp/crypto/curves/secp256k1.hpp>
#include <webcpp/crypto/signing.hpp>

#include <webcpp/asio/io_context.hpp>

#include <boost/system/error_code.hpp>

#include <array>
#include <cstdint>

int main() {
    namespace crypto = webcpp::crypto;
    std::array<std::uint8_t, 32> const seed{1};
    std::array<std::uint8_t, 5> const message{'h', 'e', 'l', 'l', 'o'};
    auto const made = crypto::curves::secp256k1::keypair::make(seed);
    if (!made) {
        return 1;
    }
    auto const encoded = made->public_key();
    if (!encoded) {
        return 1;
    }
    auto const public_key = crypto::curves::secp256k1::parse_public_key(*encoded);
    auto const signature = made->sign(crypto::ecdsa_sha256, message);
    if (!public_key || !signature) {
        return 1;
    }
    // The synchronous verification compiles.
    if (!crypto::verify(crypto::ecdsa_sha256, *signature, message, *public_key)) {
        return 1;
    }
    webcpp::asio::io_context context;
    crypto::async_verify(context.get_executor(), crypto::ecdsa_sha256, *signature, message,
                         *public_key, [](boost::system::error_code) {});
    return 0;
}
