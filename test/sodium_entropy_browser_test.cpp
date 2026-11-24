// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// On Emscripten under node, as a page meets it: libsodium draws through crypto's entropy, not
// through its own JavaScript, whose stir throws "No secure random number generator found" when
// crypto.getRandomValues and node's randomBytes throw. A program of its own, so that no
// libsodium call precedes the plant. With every source throwing, a sealed box returns
// entropy_unavailable with its output zeroed: the first time from sodium_init's draw, which
// crypto watches, the second time from crypto_box_seal's draw of the ephemeral key; Ed25519's
// from_secret, which draws nothing, succeeds; the program runs on. With the originals back, a
// seal succeeds and the recipient's key pair opens it. The recipient is RFC 7748's Bob, whose
// public key is made with from_bytes, which calls no backend. The test runs as a CommonJS program
// under node, where require is a function.

#include <webcpp/crypto/curves/ed25519.hpp>
#include <webcpp/crypto/curves/x25519.hpp>
#include <webcpp/crypto/error.hpp>
#include <webcpp/crypto/public_key_encryption/sealed_box.hpp>
#include <webcpp/test/exit_status.hpp>

#include <boost/core/lightweight_test.hpp>

#include <emscripten/em_asm.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <vector>

namespace crypto = webcpp::crypto;
namespace x25519 = webcpp::crypto::curves::x25519;
namespace ed25519 = webcpp::crypto::curves::ed25519;
using crypto::public_key_encryption::sealed_box;

namespace {

// RFC 7748 section 6.1: Bob's secret key and public key.
constexpr std::array<std::uint8_t, 32> bob_secret_key{
    0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b, 0x79, 0xe1, 0x7f, 0x8b, 0x83, 0x80, 0x0e, 0xe6,
    0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18, 0xb6, 0xfd, 0x1c, 0x2f, 0x8b, 0x27, 0xff, 0x88, 0xe0, 0xeb};
constexpr std::array<std::uint8_t, 32> bob_public_key{
    0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4, 0xd3, 0x5b, 0x61, 0xc2, 0xec, 0xe4, 0x35, 0x37,
    0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d, 0xad, 0xfc, 0x7e, 0x14, 0x6f, 0x88, 0x2b, 0x4f};

// Every source a draw may reach throws, before any libsodium call: the browser's, which crypto
// and libsodium's JavaScript both try first, and node's randomBytes, libsodium's second.
// clang-format off: JavaScript, which clang-format would break
void plant_throwing_sources() {
    EM_ASM({
        const planted = () => { throw new Error('planted'); };
        globalThis.webcppSavedGetRandomValues = globalThis.crypto.getRandomValues;
        globalThis.crypto.getRandomValues = planted;
        if (typeof require === 'function') {
            const nodeCrypto = require('crypto');
            globalThis.webcppSavedRandomBytes = nodeCrypto.randomBytes;
            nodeCrypto.randomBytes = planted;
        }
    });
}

void restore_sources() {
    EM_ASM({
        globalThis.crypto.getRandomValues = globalThis.webcppSavedGetRandomValues;
        if (typeof require === 'function') {
            require('crypto').randomBytes = globalThis.webcppSavedRandomBytes;
        }
    });
}
// clang-format on

bool all_zero(std::vector<std::uint8_t> const& bytes) {
    return std::ranges::all_of(bytes, [](std::uint8_t byte) { return byte == 0; });
}

/** A seal that fails with entropy_unavailable, its output, filled with 0xa5 first, zeroed. */
void expect_seal_refused(x25519::public_key const& recipient,
                         std::vector<std::uint8_t> const& message) {
    std::vector<std::uint8_t> sealed(message.size() + sealed_box::overhead, 0xa5);
    auto const sealed_result = sealed_box::seal(recipient, message, sealed);
    BOOST_TEST(!sealed_result && sealed_result.error() == crypto::error::entropy_unavailable);
    BOOST_TEST(all_zero(sealed));
}

}  // namespace

int main() {
    plant_throwing_sources();
    auto const recipient = x25519::public_key::from_bytes(bob_public_key).value();
    std::vector<std::uint8_t> const message{'s', 'e', 'a', 'l', 'e', 'd'};

    // sodium_init's draw (its canary), which crypto watches.
    expect_seal_refused(recipient, message);
    // crypto_box_seal's draw of the ephemeral key pair.
    expect_seal_refused(recipient, message);
    std::array<std::uint8_t, 32> seed{};
    seed.fill(0x42);
    BOOST_TEST(ed25519::keypair::from_secret(seed).has_value());

    restore_sources();
    std::vector<std::uint8_t> sealed(message.size() + sealed_box::overhead, 0);
    BOOST_TEST(sealed_box::seal(recipient, message, sealed).has_value());
    auto const key_pair = x25519::keypair::from_secret(bob_secret_key).value();
    BOOST_TEST(std::ranges::equal(key_pair.public_key().value().bytes(), bob_public_key));
    std::vector<std::uint8_t> opened(message.size(), 0xa5);
    BOOST_TEST(sealed_box::open(key_pair, sealed, opened).has_value());
    BOOST_TEST(opened == message);
    return webcpp::test::exit_status(boost::report_errors());
}
