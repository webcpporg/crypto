// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// async_sign of an Ed25519 key pair given a digest marked as one, crypto::prehashed{digest}, with
// crypto::eddsa stops at the input's check, as the synchronous sign does: pure Ed25519 signs the
// message itself, and the text names Ed25519ph; with that error alone.

// clang's -verify reads a directive from one comment line: wrapped, it checks nothing, so each
// whole text stays on one line.
// clang-format off
// expected-error@webcpp/crypto/signing.hpp:* {{webcpp::crypto: crypto::eddsa signs the message itself (RFC 8032's pure Ed25519) and takes no digest; Ed25519ph, which hashes the message, is curves::ed25519::ph.}}
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
    std::array<std::uint8_t, 32> const seed{};
    std::array<std::uint8_t, 64> const digest{};
    auto const made = crypto::curves::ed25519::keypair::make(seed);
    if (!made) {
        return 1;
    }
    webcpp::asio::io_context context;
    crypto::async_sign(context.get_executor(), *made, crypto::eddsa, crypto::prehashed{digest},
                       [](boost::system::error_code, std::array<std::uint8_t, 64>) {});
    return 0;
}
