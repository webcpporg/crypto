// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// async_sign given an X25519 key pair, an agreement_keypair that is no signing_keypair, stops at
// async_sign's catch-all, which says that X25519 key pairs agree and do not sign, and names the
// Ed25519 key pair that signs, with that error alone.

// clang's -verify reads a directive from one comment line: wrapped, it checks nothing, so each
// whole text stays on one line.
// clang-format off
// expected-error@webcpp/crypto/async.hpp:* {{webcpp::crypto: async_sign: X25519 key pairs agree; they do not sign: sign with an Ed25519 key pair, which to_x25519() converts for agreement.}}
// clang-format on
#include <webcpp/crypto/async.hpp>
#include <webcpp/crypto/curves/x25519.hpp>

#include <webcpp/asio/io_context.hpp>

#include <boost/system/error_code.hpp>

#include <array>
#include <cstdint>

int main() {
    namespace crypto = webcpp::crypto;
    std::array<std::uint8_t, 32> const secret_bytes{1};
    std::array<std::uint8_t, 5> const message{'h', 'e', 'l', 'l', 'o'};
    auto const key = crypto::curves::x25519::keypair::from_secret(secret_bytes);
    if (!key) {
        return 1;
    }
    webcpp::asio::io_context context;
    crypto::async_sign(context.get_executor(), *key, crypto::eddsa, message,
                       [](boost::system::error_code, crypto::curves::ed25519::signature) {});
    return 0;
}
