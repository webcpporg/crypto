// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// A program that names libsodium and does not link it stops at backends/sodium.hpp's instruction
// to add /third_party//sodium: on MSVC the compile fails. The text is checked on clang, in
// test/messages/sodium_not_linked.
#include <webcpp/crypto/backends/sodium.hpp>

int main() {
    return 0;
}
