// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// Version 0.1's WEBCPP_CRYPTO_DEFAULT_BACKEND_BEARSSL chose the default backend; the target alone
// chooses it now (design D32), so the define stops the build with the type to write, rather than
// change silently which code the program runs (the owner's answer Q3), on every target.

// clang-format off
// expected-error@webcpp/crypto/config.hpp:* {{webcpp::crypto: WEBCPP_CRYPTO_DEFAULT_BACKEND_BEARSSL no longer chooses a default. Write the backend in the type where the program wants it, as in ciphers::gcm<ciphers::aes256<backends::bearssl>>.}}
// clang-format on
#include <webcpp/crypto/config.hpp>

int main() {
    return 0;
}
