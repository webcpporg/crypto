// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The size of AES-256-GCM on BearSSL: bench/operations.hpp's gcm, once (test/sizes/Jamfile).

#include <webcpp/crypto/backends/bearssl.hpp>

#include "sized.hpp"

int main(int argument_count, char** /*arguments*/) {
    return webcpp::crypto::test::sized<
        webcpp::crypto::bench::gcm<webcpp::crypto::backends::bearssl>>(argument_count);
}
