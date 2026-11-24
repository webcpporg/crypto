// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// async_agree given an Ed25519 key pair, a signing_keypair that is no agreement_keypair, stops at
// async_agree's catch-all, which says that Ed25519 key pairs sign and do not agree, and names
// to_x25519(), with that error alone.

// clang's -verify reads a directive from one comment line: wrapped, it checks nothing, so each
// whole text stays on one line.
// clang-format off
// expected-error@webcpp/crypto/async.hpp:* {{webcpp::crypto: async_agree: Ed25519 key pairs sign; they do not agree: convert one with to_x25519() and agree with the X25519 key pair.}}
// clang-format on
#include <webcpp/crypto/async.hpp>
#include <webcpp/crypto/curves/ed25519.hpp>
#include <webcpp/crypto/secret.hpp>

#include <webcpp/asio/io_context.hpp>

#include <boost/system/error_code.hpp>

#include <array>
#include <cstdint>

int main() {
    namespace crypto = webcpp::crypto;
    std::array<std::uint8_t, 32> const seed{1};
    auto const key = crypto::curves::ed25519::keypair::from_secret(seed);
    if (!key) {
        return 1;
    }
    auto const peer = key->public_key();
    if (!peer) {
        return 1;
    }
    webcpp::asio::io_context context;
    crypto::async_agree(context.get_executor(), *key, *peer,
                        [](boost::system::error_code, crypto::secret<32>) {});
    return 0;
}
