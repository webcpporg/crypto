// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The one-shot ChaCha20-Poly1305 template is named for its algorithm (design D12, owner decision
// 14): ciphers::basic_chacha20_poly1305, with no alias left at the old name. A program that still
// names ciphers::aead stops there, with that error alone, although the aliases' header, which
// includes the template's, is included.

#include <webcpp/crypto/ciphers/chacha20_poly1305.hpp>

// Named by a using-declaration: with template arguments, clang reads the unknown name as a
// template and may report more; aead_template_removed_call pins that form.
// expected-error@+1 {{no member named 'aead' in namespace 'webcpp::crypto::ciphers'}}
using webcpp::crypto::ciphers::aead;

int main() {
    return 0;
}
