// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// An Ed25519 public key's own verify on a backend that completes by itself (a stand-in whose
// detail::asynchronous_backend_v is true, as part B's browser backend's will be) stops with the
// refusal that names async_verify, and with that error alone: no engine is reached.

// clang's -verify reads a directive from one comment line: wrapped, it checks nothing, so each
// whole text stays on one line.
// clang-format off
// expected-error@webcpp/crypto/curves/ed25519.hpp:* {{webcpp::crypto: verify on this backend completes asynchronously: call async_verify.}}
// clang-format on
#include <webcpp/crypto/curves/ed25519.hpp>
#include <webcpp/crypto/signing.hpp>

#include <array>
#include <cstdint>

namespace {

/** A backend that completes by itself, as part B's browser backend will. */
struct stand_in_browser {};

}  // namespace

template <>
inline constexpr bool webcpp::crypto::detail::asynchronous_backend_v<stand_in_browser> = true;

int main() {
    namespace crypto = webcpp::crypto;
    auto const public_key =
        crypto::curves::ed25519::public_key::from_bytes(std::array<std::uint8_t, 32>{});
    crypto::curves::ed25519::signature const signature{};
    std::array<std::uint8_t, 5> const message{'h', 'e', 'l', 'l', 'o'};
    return public_key && public_key->verify<stand_in_browser>(crypto::eddsa, signature, message)
               ? 0
               : 1;
}
