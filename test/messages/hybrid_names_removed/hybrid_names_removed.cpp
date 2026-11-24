// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The boxes are public_key_encryption's and crypto_kx is key_exchange's, with no alias left at
// the old names (design D3b): a program that still names crypto::hybrid::box or
// crypto::curves::x25519::kx_keypair stops at each name, with those errors alone, although the
// new headers and X25519's are included.

#include <webcpp/crypto/curves/x25519.hpp>
#include <webcpp/crypto/key_exchange/kx.hpp>
#include <webcpp/crypto/public_key_encryption/box.hpp>

int main() {
    namespace crypto = webcpp::crypto;
    // expected-error@+1 {{no member named 'hybrid'}}
    using old_box = crypto::hybrid::box<>;
    // Named by a using-declaration: with `<>`, clang reads the unknown name as a template and
    // reports "no template named" instead; either way it offers key_exchange::kx_keypair.
    // expected-error@+1 {{no member named 'kx_keypair'}}
    using crypto::curves::x25519::kx_keypair;
    return 0;
}
