// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The AES block cipher on OpenSSL: FIPS-197, the guards and moved-from objects
// (support/aes_checks.hpp).

#include <webcpp/crypto/backends/openssl.hpp>
#include <webcpp/test/exit_status.hpp>

#include "support/aes_checks.hpp"

int main() {
    using webcpp::crypto::backends::openssl;
    webcpp::test::check_fips197<openssl>();
    webcpp::test::check_aes_guards<openssl>();
    webcpp::test::check_aes_moved_from<openssl>();
    return webcpp::test::exit_status(boost::report_errors());
}
