// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// Every public function that runs ctaes's code enters its own webcpp::secure::timing_guard and
// leaves the thread's DIT as it found it, on every target, also where DIT does not apply, each with
// valid input and with input refused before the backend (support/timing_coverage.hpp). A check
// fails, naming itself, when its call enters no guard or when the first guard it enters is not the
// one of the function it names (support/timing_seam.hpp), so that a function that forgot its own
// guard fails although it calls another guarded function.
//
// What it covers, by family; a family ctaes gains adds its line and its checks:
// - The AES block cipher, aes128, aes192 and aes256: from_key; basic_aes: encrypt, decrypt.

#include "support/timing_seam.hpp"

#include <webcpp/crypto/backends/ctaes.hpp>
#include <webcpp/crypto/ciphers/aes.hpp>
#include <webcpp/test/exit_status.hpp>

#include "support/timing_coverage.hpp"

#include <boost/core/lightweight_test.hpp>

namespace {

namespace crypto = webcpp::crypto;
namespace secure = webcpp::secure;
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
