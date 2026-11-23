// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// A crypto_box's own seal on a backend that completes by itself (a stand-in whose
// detail::asynchronous_backend_v is true) stops with the refusal that sends it to a native backend,
// as its asynchronous forms do (design D6): WebCrypto has no crypto_box. That error alone: no
// engine is reached. The box is a parameter, since making one would run the stand-in's engine.

// clang's -verify reads a directive from one comment line: wrapped, it checks nothing, so each
// whole text stays on one line.
// clang-format off
// expected-error@webcpp/crypto/detail/asynchronous.hpp:* {{webcpp::crypto: WebCrypto has no ChaCha20-Poly1305, XChaCha20-Poly1305, secret box or crypto_box: their async_seal, async_open and async_from_key run on a native backend; on the browser's backend only AES-GCM is asynchronous.}}
// clang-format on
#include <webcpp/crypto/public_key_encryption/box.hpp>

#include <array>
#include <cstdint>

namespace {

/** A backend that completes by itself, as part B's browser backend will. */
struct stand_in_browser {};

}  // namespace

template <>
inline constexpr bool webcpp::crypto::detail::asynchronous_backend_v<stand_in_browser> = true;

/** A crypto_box on the stand-in. */
using stand_in_box =
    webcpp::crypto::public_key_encryption::basic_box<webcpp::crypto::families::box_xsalsa20poly1305,
                                                     stand_in_browser>;

namespace {

/** Seals with a box of the stand-in's. */
bool sealed(stand_in_box& box) {
    std::array<std::uint8_t, 24> const nonce{};
    std::array<std::uint8_t, 5> data{'h', 'e', 'l', 'l', 'o'};
    return box.seal(nonce, data).has_value();
}

}  // namespace

// The function is compiled, which is the test; it is never run.
int main() {
    static_cast<void>(&sealed);
    return 0;
}
