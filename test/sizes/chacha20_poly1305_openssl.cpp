// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The size of ChaCha20-Poly1305 on OpenSSL: bench/operations.hpp's chacha20_poly1305, once
// (test/sizes/Jamfile).

#include <webcpp/crypto/backends/openssl.hpp>

#include "sized.hpp"

int main(int argument_count, char** /*arguments*/) {
    return webcpp::crypto::test::sized<
        webcpp::crypto::bench::chacha20_poly1305<webcpp::crypto::backends::openssl>>(
        argument_count);
}
