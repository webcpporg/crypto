// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// A program whose OpenSSL headers are older than 3.0 stops at backends/openssl.hpp's instruction
// to name /webcpp/crypto//openssl (spec section 3.3): on MSVC the compile fails. The text is
// checked on clang, in test/messages/openssl_old, whose stand-in for the old version header
// this case includes.
#include <webcpp/crypto/backends/openssl.hpp>

int main() {
    return 0;
}
