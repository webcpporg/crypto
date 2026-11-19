// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// A program that includes OpenSSL's header and does not link it stops at backends/openssl.hpp's
// instruction to add /webcpp/crypto//openssl (spec section 4.3): on MSVC the compile fails.
// The text is checked on clang, in test/messages/openssl_not_linked.
#include <webcpp/crypto/backends/openssl.hpp>

int main() {
    return 0;
}
