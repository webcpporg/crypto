// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// async_agree given a secp256k1 key pair, an agreement_keypair of an algorithm WebCrypto lacks,
// stops with the key pair's own agree to call instead, and with that error alone, while the key
// pair's agree compiles.

// clang's -verify reads a directive from one comment line: wrapped, it checks nothing, so each
// whole text stays on one line.
// clang-format off
// expected-error@webcpp/crypto/async.hpp:* {{webcpp::crypto: async_agree takes a key pair of an algorithm WebCrypto has (X25519, P-256): call the key pair's synchronous agree for the others.}}
// clang-format on
#include <webcpp/crypto/async.hpp>
#include <webcpp/crypto/curves/secp256k1.hpp>
#include <webcpp/crypto/secret.hpp>

#include <webcpp/asio/io_context.hpp>

#include <boost/system/error_code.hpp>

#include <array>
#include <cstdint>

int main() {
    namespace crypto = webcpp::crypto;
    std::array<std::uint8_t, 32> const seed{1};
    auto const key = crypto::curves::secp256k1::keypair::from_secret(seed);
    if (!key) {
        return 1;
    }
    auto const peer = key->public_key();
    if (!peer) {
        return 1;
    }
    // The synchronous agreement compiles.
    if (!key->agree(*peer)) {
        return 1;
    }
    webcpp::asio::io_context context;
    crypto::async_agree(context.get_executor(), *key, *peer,
                        [](boost::system::error_code, crypto::secret<32>) {});
    return 0;
}
