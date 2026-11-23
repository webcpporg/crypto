// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The size of P-256's ECDSA verification of a digest on BearSSL,
// crypto::verify(ecdsa_sha256, signature, prehashed{digest}, public_key): bench/operations.hpp's
// p256_verify_ecdsa, once (test/sizes/Jamfile); the program keeps its name, crypto.json's
// sized operation `verify_ecdsa`.

#include <webcpp/crypto/backends/bearssl.hpp>

#include "sized.hpp"

int main(int argument_count, char** /*arguments*/) {
    return webcpp::crypto::test::sized<
        webcpp::crypto::bench::p256_verify_ecdsa<webcpp::crypto::backends::bearssl>>(
        argument_count);
}
