// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// gcm on OpenSSL against Wycheproof's AES-GCM vectors (support/wycheproof_gcm.hpp).

#include <webcpp/crypto/backends/openssl.hpp>
#include <webcpp/test/exit_status.hpp>

#include "support/wycheproof_gcm.hpp"

int main() {
    webcpp::test::check_wycheproof_gcm<webcpp::crypto::backends::openssl>();
    return webcpp::test::exit_status(boost::report_errors());
}
