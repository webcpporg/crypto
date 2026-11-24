// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// Ed25519ph's streaming signer is curves::ed25519::prehashed_signer, with no alias left at the old
// name (design D9): a program that still names curves::ed25519::ph stops there, with those errors
// alone.

#include <webcpp/crypto/curves/ed25519.hpp>
#include <webcpp/hash/algorithms.hpp>

int main() {
    // With the name unknown, clang reads `<` as a comparison, the hash's type where a value goes
    // and `::begin` as a global name: four errors for the line, as a program that still names it
    // sees them, the first the missing name.
    // expected-error@+4 {{no member named 'ph' in namespace}}
    // expected-error@+3 {{expected '(' for function-style cast or type construction}} (knock-on)
    // expected-error@+2 {{no member named 'begin' in the global namespace}} (knock-on)
    // expected-error@+1 {{no matching function for call to 'begin'}} (knock-on)
    return webcpp::crypto::curves::ed25519::ph<webcpp::hash::sha2_512>::begin() ? 0 : 1;
}
