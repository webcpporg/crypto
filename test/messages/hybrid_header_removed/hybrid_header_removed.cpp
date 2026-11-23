// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The boxes' header moved to public_key_encryption/box.hpp, with no header left at the old path
// (design D3b): a program that still includes hybrid/box.hpp stops at the include, with that error
// alone. crypto::hybrid is kept free for the post-quantum hybrids.

// expected-error@+1 {{'webcpp/crypto/hybrid/box.hpp' file not found}}
#include <webcpp/crypto/hybrid/box.hpp>

int main() {
    return 0;
}
