// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The secret boxes' header moved to secret_key_encryption/secretbox.hpp, with no header left at the
// old path (design D11): a program that still includes ciphers/secretbox.hpp stops at the include,
// with that error alone.

// expected-error@+1 {{'webcpp/crypto/ciphers/secretbox.hpp' file not found}}
#include <webcpp/crypto/ciphers/secretbox.hpp>

int main() {
    return 0;
}
