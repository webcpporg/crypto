// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// async_verify of ECDSA over SHA-256 given a P-256 public key and the signature as 64 bytes, not
// as a curves::p256::ecdsa_signature, stops where the public key's async_verify checks the
// signature, with P-256's verify text, which names the type it takes and how to make one, and
// with that error alone: the asynchronous forms take the type as the synchronous ones do
// (design R1).

// clang's -verify reads a directive from one comment line: wrapped, it checks nothing, so each
// whole text stays on one line.
// clang-format off
// expected-error@webcpp/crypto/signing.hpp:* {{webcpp::crypto: verify: a P-256 key verifies a curves::p256::ecdsa_signature: make one from 64 bytes with curves::p256::ecdsa_signature::from_bytes.}}
// clang-format on
#include <webcpp/crypto/async.hpp>
#include <webcpp/crypto/backends/bearssl.hpp>
#include <webcpp/crypto/curves/p256.hpp>
#include <webcpp/crypto/signing.hpp>

#include <webcpp/asio/io_context.hpp>

#include <boost/system/error_code.hpp>

#include <array>
#include <cstdint>

int main() {
    namespace crypto = webcpp::crypto;
    std::array<std::uint8_t, 32> scalar{};
    scalar.back() = 1;
    auto const key = crypto::curves::p256::keypair::from_secret(scalar);
    if (!key) {
        return 1;
    }
    auto const public_key = key->public_key();
    if (!public_key) {
        return 1;
    }
    std::array<std::uint8_t, 64> const signature{};
    std::array<std::uint8_t, 5> const message{'h', 'e', 'l', 'l', 'o'};
    webcpp::asio::io_context context;
    crypto::async_verify(context.get_executor(), crypto::ecdsa_sha256, signature, message,
                         *public_key, [](boost::system::error_code) {});
    return 0;
}
