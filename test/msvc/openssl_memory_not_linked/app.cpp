// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// A native program that sets the memory option of the OpenSSL backend and does not link OpenSSL
// stops at config.hpp's instruction to add /webcpp/crypto//openssl (spec section 3.7): on MSVC
// the compile fails. The text is checked on clang, in test/messages/openssl_memory_not_linked.
#include <webcpp/crypto/config.hpp>

int main() {
    return 0;
}
