// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// gcm on BearSSL: the GCM specification's cases, the guards, tampering, moved-from
// objects and aliasing spans, the incremental seal: every case in pieces of every size,
// its machine, and a one-shot call during a message, and the incremental open in two
// passes (support/gcm_checks.hpp).

#include <webcpp/crypto/backends/bearssl.hpp>
#include <webcpp/test/exit_status.hpp>

#include "support/gcm_checks.hpp"

#include <boost/core/lightweight_test.hpp>

int main() {
    using webcpp::crypto::backends::bearssl;
    webcpp::test::check_spec_cases<bearssl>();
    webcpp::test::check_guards<bearssl>();
    webcpp::test::check_tampering<bearssl>();
    webcpp::test::check_moved_from<bearssl>();
    webcpp::test::check_edges<bearssl>();
    webcpp::test::check_incremental<bearssl>();
    webcpp::test::check_machine<bearssl>();
    webcpp::test::check_one_shot_during_message<bearssl>();
    webcpp::test::check_incremental_open<bearssl>();
    return webcpp::test::exit_status(boost::report_errors());
}
