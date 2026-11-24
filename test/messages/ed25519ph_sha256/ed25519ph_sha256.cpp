// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// Ed25519ph named with SHA-256 stops at its static_assert: RFC 8032 defines it over SHA-512.

// clang-format off
// expected-error@webcpp/crypto/curves/ed25519.hpp:* {{webcpp::crypto: Ed25519ph is defined over SHA-512 (RFC 8032 section 5.1); name curves::ed25519::prehashed_signer<webcpp::hash::sha2_512>.}}
// clang-format on

#include <webcpp/crypto/curves/ed25519.hpp>
#include <webcpp/hash/algorithms.hpp>

int main() {
    return webcpp::crypto::curves::ed25519::prehashed_signer<webcpp::hash::sha2_256>::begin() ? 0
                                                                                              : 1;
}
