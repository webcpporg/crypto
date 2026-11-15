// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// gcm's limits on BearSSL, natively, where size_t has 64 bits: a message one byte over
// max_message_size, in address space that faults on any access, is refused by seal, open
// and update before BearSSL reads a byte of it (support/gcm_checks.hpp).

#include <webcpp/crypto/backends/bearssl.hpp>
#include <webcpp/test/exit_status.hpp>

#include "support/gcm_checks.hpp"

#include <boost/core/lightweight_test.hpp>

int main() {
    webcpp::test::check_limits<webcpp::crypto::backends::bearssl>();
    return webcpp::test::exit_status(boost::report_errors());
}
