// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The secret boxes are secret_key_encryption's, with no alias left in ciphers (design D11): a
// program that still names ciphers::secretbox or ciphers::secretbox_xchacha20poly1305 stops at
// each, with those two errors alone, although the new header and the AEADs' of ciphers are
// included. The names are declared, not used: clang corrects each to secret_key_encryption's in its
// message, and a use of the corrected type would add the refusal of its default backend, not
// linked here.

#include <webcpp/crypto/ciphers/chacha20_poly1305.hpp>
#include <webcpp/crypto/secret_key_encryption/secretbox.hpp>

// expected-error@+1 {{no member named 'secretbox' in namespace 'webcpp::crypto::ciphers'}}
using webcpp::crypto::ciphers::secretbox;
// clang-format off
// expected-error@+2 {{no member named 'secretbox_xchacha20poly1305' in namespace 'webcpp::crypto::ciphers'}}
// clang-format on
using webcpp::crypto::ciphers::secretbox_xchacha20poly1305;

int main() {
    return 0;
}
