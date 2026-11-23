// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// async_verify with its backend named first, as on every async_verify, and a scheme and key the
// asynchronous family lacks (crypto::schnorr and a 32-byte x-only key) still reaches the
// catch-all async_verify, which names the keys the family takes and crypto::verify for the
// others, and with that error alone.

// clang's -verify reads a directive from one comment line: wrapped, it checks nothing, so each
// whole text stays on one line.
// clang-format off
// expected-error@webcpp/crypto/async.hpp:* {{webcpp::crypto: async_verify takes crypto::eddsa with a curves::ed25519::public_key or crypto::ecdsa_sha256 with a curves::p256::basic_public_key, the algorithms WebCrypto has: call crypto::verify for the others.}}
// clang-format on
#include <webcpp/crypto/async.hpp>
#include <webcpp/crypto/backends/sodium.hpp>
#include <webcpp/crypto/curves/secp256k1.hpp>
#include <webcpp/crypto/signing.hpp>

#include <webcpp/asio/io_context.hpp>

#include <boost/system/error_code.hpp>

#include <array>
#include <cstdint>

int main() {
    namespace crypto = webcpp::crypto;
    crypto::curves::secp256k1::schnorr_signature const signature{};
    std::array<std::uint8_t, 5> const message{'h', 'e', 'l', 'l', 'o'};
    std::array<std::uint8_t, 32> const xonly_key{};
    webcpp::asio::io_context context;
    crypto::async_verify<crypto::backends::sodium>(context.get_executor(), crypto::schnorr,
                                                   signature, message, xonly_key,
                                                   [](boost::system::error_code) {});
    return 0;
}
