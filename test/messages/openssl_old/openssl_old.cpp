// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// A program whose OpenSSL headers are older than 3.0 stops with the instruction to name
// /webcpp/crypto//openssl, which builds OpenSSL 3.5.9 (spec section 3.3).

// clang-format off
// expected-error@webcpp/crypto/backends/openssl.hpp:* {{webcpp::crypto: the backend OpenSSL needs OpenSSL 3.0 or later, and the headers found are of an older OpenSSL. In the program's Jamfile, name /webcpp/crypto//openssl, which builds OpenSSL 3.5.9. (without b2: put OpenSSL 3's include/ first)}}
// clang-format on
#include <webcpp/crypto/backends/openssl.hpp>

int main() {
    return 0;
}
