// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// gcm on OpenSSL refuses a message past its limit before reading a byte of it
// (support/gcm_checks.hpp; natively, where 64-bit sizes reach the limit).

#include <webcpp/crypto/backends/openssl.hpp>
#include <webcpp/test/exit_status.hpp>

#include "support/gcm_checks.hpp"

int main() {
    webcpp::test::check_limits<webcpp::crypto::backends::openssl>();
    return webcpp::test::exit_status(boost::report_errors());
}
