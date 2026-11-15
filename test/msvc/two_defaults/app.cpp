// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// A program that selects both default backends stops at config.hpp's instruction to keep one
// (spec section 4.3): on MSVC the compile fails. The text is checked on clang, in
// test/messages/two_defaults.
#include <webcpp/crypto/config.hpp>

int main() {
    return 0;
}
