// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// Ed25519ph named with SHA-256 stops at its static_assert: on MSVC the compile fails. The text is
// checked on clang, in test/messages/ed25519ph_sha256.
#include <webcpp/crypto/curves/ed25519.hpp>
#include <webcpp/hash/algorithms.hpp>

int main() {
    return webcpp::crypto::curves::ed25519::ph<webcpp::hash::sha2_256>::begin() ? 0 : 1;
}
