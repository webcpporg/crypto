// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// A program for wasip2 or wasip3 that links OpenSSL and selects it compiles: OpenSSL is
// refused on Emscripten alone, and the program's selection is the default backend.

#include <webcpp/crypto/config.hpp>

#include <type_traits>

static_assert(std::is_same_v<webcpp::crypto::default_backend, webcpp::crypto::backends::openssl>,
              "the program's selection is the default backend");

int main() {
    return 0;
}
