// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// A program that names ctaes and does not link it stops at backends/ctaes.hpp's instruction to
// add /third_party//ctaes (spec section 4.3): on MSVC the compile fails. The text is checked on
// clang, in test/messages/ctaes_not_linked.
#include <webcpp/crypto/backends/ctaes.hpp>
#include <webcpp/crypto/ciphers/aes.hpp>

int main() {
    return 0;
}
