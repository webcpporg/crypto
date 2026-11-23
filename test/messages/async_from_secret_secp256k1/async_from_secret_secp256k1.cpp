// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// async_from_secret on a key pair of an algorithm WebCrypto lacks, secp256k1's, stops with the
// synchronous call to from_secret instead, and with that error alone, while the key pair's own
// from_secret compiles.

// clang-format off
// expected-error@webcpp/crypto/async.hpp:* {{webcpp::crypto: async_from_secret takes a key pair of an algorithm WebCrypto has (Ed25519, P-256): call the synchronous from_secret for the others.}}
// clang-format on
#include <webcpp/crypto/async.hpp>
#include <webcpp/crypto/curves/secp256k1.hpp>

#include <webcpp/asio/io_context.hpp>

#include <boost/system/error_code.hpp>

#include <array>
#include <cstdint>

int main() {
    namespace crypto = webcpp::crypto;
    using keypair = crypto::curves::secp256k1::keypair;
    std::array<std::uint8_t, 32> const secret_key{1};
    // The synchronous from_secret compiles.
    if (!keypair::from_secret(secret_key)) {
        return 1;
    }
    webcpp::asio::io_context context;
    crypto::async_from_secret<keypair>(context.get_executor(), secret_key,
                                       [](boost::system::error_code, keypair) {});
    return 0;
}
