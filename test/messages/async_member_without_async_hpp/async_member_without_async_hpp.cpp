// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// A key pair's asynchronous member, async_sign, called without <webcpp/crypto/async.hpp>, which
// defines it (design D9), stops at the call with the compiler's own error, a deduced return type
// used before it is defined, and with that error alone: the curve's header declares the member and
// includes no Asio, while the key pair's synchronous sign compiles.

// clang's -verify reads a directive from one comment line: wrapped, it checks nothing, so each
// whole text stays on one line.
// clang-format off
// expected-error@async_member_without_async_hpp.cpp:* {{with deduced return type cannot be used before it is defined}}
// clang-format on
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
    auto const made = crypto::curves::p256::keypair::from_secret(scalar);
    if (!made || !made->sign(crypto::ecdsa_sha256, message)) {
        return 1;
    }
    webcpp::asio::io_context context;
    made->async_sign(context.get_executor(), crypto::ecdsa_sha256, message,
                     [](boost::system::error_code, std::array<std::uint8_t, 64>) {});
    return 0;
}
