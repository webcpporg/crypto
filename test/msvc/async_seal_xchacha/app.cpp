// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// async_seal on an AEAD WebCrypto lacks, XChaCha20-Poly1305, stops where it is called: on MSVC the
// compile fails. The text is checked on clang, in test/messages/async_seal_xchacha.
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
    webcpp::asio::io_context context;
    crypto::async_seal(context.get_executor(), *made, iv, {}, data,
                       [](boost::system::error_code, boost::hash2::digest<16>) {});
    return 0;
}
