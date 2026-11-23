// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// async_verify of crypto::eddsa given the public key as its 32 bytes, not as a
// curves::ed25519::public_key, stops at the catch-all async_verify, which names the keys the
// asynchronous family takes, and with that error alone (design R17), as crypto::verify does.

// clang's -verify reads a directive from one comment line: wrapped, it checks nothing, so each
// whole text stays on one line.
// clang-format off
// expected-error@webcpp/crypto/async.hpp:* {{webcpp::crypto: async_verify takes crypto::eddsa with a curves::ed25519::public_key or crypto::ecdsa_sha256 with a curves::p256::basic_public_key, the algorithms WebCrypto has: call crypto::verify for the others.}}
// clang-format on
#include <webcpp/crypto/async.hpp>
#include <webcpp/crypto/curves/ed25519.hpp>
#include <webcpp/crypto/signing.hpp>

#include <webcpp/asio/io_context.hpp>

#include <boost/system/error_code.hpp>

#include <array>
#include <cstdint>

int main() {
    namespace crypto = webcpp::crypto;
    crypto::curves::ed25519::signature const signature{};
    std::array<std::uint8_t, 5> const message{'h', 'e', 'l', 'l', 'o'};
    std::array<std::uint8_t, 32> const key_bytes{};
    webcpp::asio::io_context context;
    crypto::async_verify(context.get_executor(), crypto::eddsa, signature, message, key_bytes,
                         [](boost::system::error_code) {});
    return 0;
}
