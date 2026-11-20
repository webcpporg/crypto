// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// Every public function that runs ctaes's code enters detail::timing_guard and leaves the
// thread's DIT as it found it, on every target, also where DIT does not apply: the AES block
// cipher of each key size, with valid input and with input refused before the backend
// (support/timing_coverage.hpp).

#include "support/timing_seam.hpp"

#include <webcpp/crypto/backends/ctaes.hpp>
#include <webcpp/crypto/ciphers/aes.hpp>
#include <webcpp/test/exit_status.hpp>

#include "support/timing_coverage.hpp"

#include <boost/core/lightweight_test.hpp>

namespace {

namespace crypto = webcpp::crypto;
using crypto::backends::ctaes;

// The ciphers: the AES block cipher.
void cover_ciphers() {
    webcpp::test::cover_aes<crypto::ciphers::aes128<ctaes>>("aes128", "ctaes");
    webcpp::test::cover_aes<crypto::ciphers::aes192<ctaes>>("aes192", "ctaes");
    webcpp::test::cover_aes<crypto::ciphers::aes256<ctaes>>("aes256", "ctaes");
}

}  // namespace

int main() {
    cover_ciphers();
    return webcpp::test::exit_status(boost::report_errors());
}
