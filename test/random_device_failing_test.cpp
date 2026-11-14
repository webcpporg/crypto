// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// With the source failing (the test seam WEBCPP_CRYPTO_DETAIL_TEST_ENTROPY), fill returns
// entropy_unavailable and zeroes the whole buffer, a source that fails on the second
// piece of 256 included; ENOTSUP is not_supported, Emscripten's answer in an audio
// worklet; operator() throws the error with exceptions on.

#include <webcpp/crypto/random_device.hpp>
#include <webcpp/test/exit_status.hpp>

#include <boost/core/lightweight_test.hpp>
#include <boost/system/errc.hpp>
#include <boost/system/system_error.hpp>

#include <algorithm>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

namespace {

// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables): the planted source's script
int answer_after = 0;
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables): the planted source's script
int failure = EIO;

}  // namespace

extern "C" int webcpp_test_entropy(void* out, std::size_t size) {
    if (answer_after == 0) {
        return failure;
    }
    --answer_after;
    std::memset(out, 0x5a, size);
    return 0;
}

int main() {
    namespace crypto = webcpp::crypto;
    crypto::random_device device;
    std::vector<std::uint8_t> buffer(600, 0xff);

    answer_after = 0;
    auto filled = device.fill(buffer);
    BOOST_TEST(!filled && filled.error() == crypto::error::entropy_unavailable);
    BOOST_TEST(std::all_of(buffer.begin(), buffer.end(), [](std::uint8_t b) { return b == 0; }));

    std::fill(buffer.begin(), buffer.end(), 0xff);
    answer_after = 1;  // the first piece of 256 succeeds, the second fails
    filled = device.fill(buffer);
    BOOST_TEST(!filled && filled.error() == crypto::error::entropy_unavailable);
    BOOST_TEST(std::all_of(buffer.begin(), buffer.end(), [](std::uint8_t b) { return b == 0; }));

    answer_after = 0;
    failure = ENOTSUP;
    filled = device.fill(buffer);
    BOOST_TEST(!filled && filled.error() == boost::system::errc::not_supported);
    failure = EIO;

#ifndef WEBCPP_CRYPTO_NO_EXCEPTIONS
    answer_after = 0;
    bool threw = false;
    try {
        static_cast<void>(device());
    } catch (boost::system::system_error const& e) {
        threw = e.code() == crypto::error::entropy_unavailable;
    }
    BOOST_TEST(threw);
#endif
    return webcpp::test::exit_status(boost::report_errors());
}
