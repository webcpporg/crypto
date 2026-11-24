// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// What a program that still makes a cipher through ciphers::aead<Family, Backend> as it did sees
// (design D12, owner decision 14): the alias over the old name stops the build, and the call
// through the alias with it, although the aliases' header, which includes
// ciphers::basic_chacha20_poly1305's, is included: those two errors alone. The alias, as programs
// name the template, keeps the errors the same on every clang: written inline in the call, the
// unknown name with its template arguments draws a typo correction to the C library's read and
// errors that differ with clang's version and the C library. The function is compiled, never run.

#include <webcpp/crypto/ciphers/chacha20_poly1305.hpp>

#include <array>
#include <cstdint>

namespace {

// expected-error@+1 {{no template named 'aead' in namespace 'webcpp::crypto::ciphers'}}
using cipher = webcpp::crypto::ciphers::aead<webcpp::crypto::families::chacha20_poly1305,
                                             webcpp::crypto::backends::sodium>;

/** Makes a ChaCha20-Poly1305 cipher through the removed template's name. */
bool made_from_key(std::array<std::uint8_t, 32> const& key) {
    // expected-error@+1 {{use of undeclared identifier 'cipher'}}
    return cipher::from_key(key).has_value();
}

}  // namespace

// The function is compiled, which is the test; it is never run.
int main() {
    static_cast<void>(&made_from_key);
    return 0;
}
