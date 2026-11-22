// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// async_open on an AEAD WebCrypto lacks, XChaCha20-Poly1305, stops with the synchronous call to
// make instead, and with that error alone, while the AEAD's own seal compiles.

// clang-format off
// expected-error@webcpp/crypto/async.hpp:* {{webcpp::crypto: async_open takes AES-GCM, the AEAD WebCrypto has: call open for the others.}}
// clang-format on
#include <webcpp/crypto/async.hpp>
#include <webcpp/crypto/ciphers/chacha20_poly1305.hpp>

#include <webcpp/asio/io_context.hpp>

#include <boost/hash2/digest.hpp>
#include <boost/system/error_code.hpp>

#include <array>
#include <cstdint>

int main() {
    namespace crypto = webcpp::crypto;
    std::array<std::uint8_t, 32> const key{};
    auto made = crypto::ciphers::xchacha20_poly1305<>::make(key);
    if (!made) {
        return 1;
    }
    std::array<std::uint8_t, 24> const iv{};
    std::array<std::uint8_t, 16> data{};
    // The synchronous seal compiles.
    if (!made->seal(iv, {}, data)) {
        return 1;
    }
    webcpp::asio::io_context context;
    std::array<std::uint8_t, 16> const tag{};
    crypto::async_open(context.get_executor(), *made, iv, {}, data, tag,
                       [](boost::system::error_code) {});
    return 0;
}
