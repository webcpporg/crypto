// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// async_from_secret on a key pair of an algorithm WebCrypto lacks, secp256k1's, stops where it is
// called: on MSVC the compile fails. The text is checked on clang, in
// test/messages/async_from_secret_secp256k1.
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
    webcpp::asio::io_context context;
    crypto::async_from_secret<keypair>(context.get_executor(), secret_key,
                                       [](boost::system::error_code, keypair) {});
    return 0;
}
