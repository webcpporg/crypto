// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// Version 0.1's WEBCPP_CRYPTO_DEFAULT_BACKEND_BEARSSL stops the build at config.hpp, with the type
// to write, on every target (the owner's answer Q3): on MSVC the compile fails. The text is
// checked on clang, in test/messages/default_selected.
#include <webcpp/crypto/config.hpp>

int main() {
    return 0;
}
