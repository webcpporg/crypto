// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// AES-GCM's seal on a backend that completes by itself (a stand-in whose
// detail::asynchronous_backend_v is true), through the free
// crypto::secret_key_encryption::aead::seal, stops with the refusal that names async_seal, and with
// that error alone: no engine is reached. The object is a parameter, since making one would run the
// stand-in's engine.

// clang's -verify reads a directive from one comment line: wrapped, it checks nothing, so each
// whole text stays on one line.
// clang-format off
// expected-error@webcpp/crypto/ciphers/gcm.hpp:* {{webcpp::crypto: seal on this backend completes asynchronously: call async_seal.}}
// clang-format on
#include <webcpp/crypto/ciphers/aes.hpp>
#include <webcpp/crypto/ciphers/gcm.hpp>

#include <array>
#include <cstdint>

namespace {

/** A backend that completes by itself, as part B's browser backend will. */
struct stand_in_browser {};

}  // namespace

template <>
inline constexpr bool webcpp::crypto::detail::asynchronous_backend_v<stand_in_browser> = true;

/** AES-GCM on the stand-in. */
using stand_in_gcm =
    webcpp::crypto::ciphers::gcm<webcpp::crypto::ciphers::aes256<stand_in_browser>>;

namespace {

/** Seals with an object of the stand-in's. */
bool sealed(stand_in_gcm& aead) {
    std::array<std::uint8_t, 12> const iv{};
    std::array<std::uint8_t, 5> data{'h', 'e', 'l', 'l', 'o'};
    return webcpp::crypto::secret_key_encryption::aead::seal(aead, iv, {}, data).has_value();
}

}  // namespace

// The function is compiled, which is the test; it is never run.
int main() {
    static_cast<void>(&sealed);
    return 0;
}
