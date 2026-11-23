// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// crypto::verify and the public key's own verify under crypto::eddsa_prehashed, named with a
// backend that completes by itself (a stand-in whose detail::asynchronous_backend_v is true), each
// stop at their first statement after the guard with the refusal that says WebCrypto has no
// Ed25519ph, and with those two errors alone: no engine is reached. Each form names a stand-in of
// its own, since one refusal of one backend is reported once however many calls reach it.

// clang's -verify reads a directive from one comment line: wrapped, it checks nothing, so each
// whole text stays on one line.
// clang-format off
// expected-error@webcpp/crypto/signing.hpp:* 2 {{webcpp::crypto: WebCrypto has no Ed25519ph: crypto::eddsa_prehashed's sign, verify, async_sign and async_verify run on a native backend.}}
// clang-format on
#include <webcpp/crypto/curves/ed25519.hpp>
#include <webcpp/crypto/signing.hpp>

#include <array>
#include <cstdint>

namespace {

/** A backend that completes by itself, as part B's browser backend will. */
struct stand_in_browser {};

/** Another such backend, for the second form. */
struct other_stand_in_browser {};

}  // namespace

template <>
inline constexpr bool webcpp::crypto::detail::asynchronous_backend_v<stand_in_browser> = true;

template <>
inline constexpr bool webcpp::crypto::detail::asynchronous_backend_v<other_stand_in_browser> = true;

namespace {

/** Verifies a signature of a digest, in both forms, on the stand-in. */
bool verified(webcpp::crypto::curves::ed25519::public_key const& public_key) {
    namespace crypto = webcpp::crypto;
    crypto::curves::ed25519::signature const signature{};
    std::array<std::uint8_t, 64> const digest{};
    auto const free_verified = crypto::verify<stand_in_browser>(
        crypto::eddsa_prehashed, signature, crypto::prehashed{digest}, public_key);
    auto const member_verified = public_key.verify<other_stand_in_browser>(
        crypto::eddsa_prehashed, signature, crypto::prehashed{digest});
    return free_verified && member_verified;
}

}  // namespace

// The function is compiled, which is the test; it is never run.
int main() {
    static_cast<void>(&verified);
    return 0;
}
