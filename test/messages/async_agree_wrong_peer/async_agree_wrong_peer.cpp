// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// async_agree given a P-256 key pair and a peer's key as bytes, which its async_agree does not
// take, stops at async_agree's catch-all, which names the peer each key pair takes, as the
// synchronous agree's does, with that error alone.

// clang's -verify reads a directive from one comment line: wrapped, it checks nothing, so each
// whole text stays on one line.
// clang-format off
// expected-error@webcpp/crypto/async.hpp:* {{webcpp::crypto: async_agree: this key pair does not agree with this peer: an X25519 key pair agrees with a curves::x25519::public_key, a P-256 key pair with a curves::p256::basic_public_key of its backend.}}
// clang-format on
#include <webcpp/crypto/async.hpp>
#include <webcpp/crypto/backends/bearssl.hpp>
#include <webcpp/crypto/curves/p256.hpp>
#include <webcpp/secure/secret.hpp>

#include <webcpp/asio/io_context.hpp>

#include <boost/system/error_code.hpp>

#include <array>
#include <cstdint>

int main() {
    namespace crypto = webcpp::crypto;
    namespace secure = webcpp::secure;
    std::array<std::uint8_t, 32> scalar{};
    scalar.back() = 1;
    auto const key = crypto::curves::p256::keypair::from_secret(scalar);
    if (!key) {
        return 1;
    }
    std::array<std::uint8_t, 65> const peer{0x04};
    webcpp::asio::io_context context;
    crypto::async_agree(context.get_executor(), *key, peer,
                        [](boost::system::error_code, secure::secret<32>) {});
    return 0;
}
