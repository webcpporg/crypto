// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// gcm on OpenSSL: the GCM specification's cases, the guards, tampering, moved-from
// objects, aliasing spans and the incremental seal (support/gcm_checks.hpp).

#include <webcpp/crypto/backends/openssl.hpp>
#include <webcpp/test/exit_status.hpp>

#include "support/gcm_checks.hpp"

int main() {
    using webcpp::crypto::backends::openssl;
    webcpp::test::check_spec_cases<openssl>();
    webcpp::test::check_guards<openssl>();
    webcpp::test::check_tampering<openssl>();
    webcpp::test::check_moved_from<openssl>();
    webcpp::test::check_edges<openssl>();
    webcpp::test::check_incremental<openssl>();
    webcpp::test::check_machine<openssl>();
    webcpp::test::check_one_shot_during_message<openssl>();
    return webcpp::test::exit_status(boost::report_errors());
}
