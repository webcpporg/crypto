// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// On Emscripten under node: a libsodium draw that fails outside a call crypto watches ends the
// program through sodium_misuse, never handing zeros on. A sealed box installs crypto's entropy
// as libsodium's generator; then, with crypto.getRandomValues throwing, the program calls
// randombytes_buf itself, which no caller of crypto's observes. The test passes when the program
// ends with a status other than 0 (webcpp.run-fail); it returns 0 when the draw returns, and when
// the setup before the plant fails, so that neither passes.

#include <webcpp/crypto/curves/x25519.hpp>
#include <webcpp/crypto/public_key_encryption/sealed_box.hpp>
#include <webcpp/test/exit_status.hpp>

#include <sodium/core.h>
#include <sodium/randombytes.h>

#include <emscripten/em_asm.h>

#include <array>
#include <cstdint>
#include <cstdio>

namespace x25519 = webcpp::crypto::curves::x25519;
using webcpp::crypto::public_key_encryption::sealed_box;

int main() {
    std::array<std::uint8_t, 32> recipient_bytes{};
    recipient_bytes.fill(0x09);
    auto const recipient = x25519::public_key::from_bytes(recipient_bytes).value();
    std::array<std::uint8_t, 4> const message{'s', 'e', 'a', 'l'};
    std::array<std::uint8_t, message.size() + sealed_box::overhead> sealed{};
    if (!sealed_box::seal(recipient, message, sealed)) {
        std::puts("setup: the seal before the plant failed");
        return webcpp::test::exit_status(0);
    }
    if (sodium_set_misuse_handler([] { std::puts("sodium_misuse: the program ends"); }) != 0) {
        std::puts("setup: no misuse handler");
        return webcpp::test::exit_status(0);
    }
    // clang-format off: JavaScript, which clang-format would break
    EM_ASM({ globalThis.crypto.getRandomValues = () => { throw new Error('planted'); }; });
    // clang-format on
    std::array<std::uint8_t, 32> drawn{};
    randombytes_buf(drawn.data(), drawn.size());
    std::puts("randombytes_buf returned: zeros handed on");
    return webcpp::test::exit_status(0);
}
