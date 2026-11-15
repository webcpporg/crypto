// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// With the source failing (the test seam WEBCPP_CRYPTO_DETAIL_TEST_ENTROPY), fill returns
// entropy_unavailable and zeroes the whole buffer, a source that fails on the second
// piece of 256 included; ENOTSUP is not_supported, Emscripten's answer in an audio
// worklet; a failure that leaves errno 0 is entropy_unavailable too; operator() throws the error
// with exceptions on.

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
#include <span>
#include <utility>
#include <vector>

namespace {

// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables): the planted source's script
int answer_after = 0;
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables): the planted source's script
int failure = EIO;
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables): the planted source's tally
std::size_t calls = 0;

}  // namespace

extern "C" int webcpp_test_entropy(void* output_bytes, std::size_t byte_count) {
    // getentropy refuses more than 256 bytes at once: the device never asks for more.
    BOOST_TEST(byte_count <= 256);
    ++calls;
    // As getentropy does: 0 when it fills, -1 with errno set when it fails.
    if (answer_after == 0) {
        errno = failure;
        return -1;
    }
    --answer_after;
    std::memset(output_bytes, 0x5a, byte_count);
    return 0;
}

int main() {
    namespace crypto = webcpp::crypto;
    crypto::random_device device;
    std::vector<std::uint8_t> buffer(600, 0xff);

    answer_after = 0;
    auto filled = device.fill(buffer);
    BOOST_TEST(!filled && filled.error() == crypto::error::entropy_unavailable);
    BOOST_TEST(std::ranges::all_of(buffer, [](std::uint8_t b) { return b == 0; }));

    std::ranges::fill(buffer, 0xff);
    answer_after = 1;  // the first piece of 256 succeeds, the second fails
    filled = device.fill(buffer);
    BOOST_TEST(!filled && filled.error() == crypto::error::entropy_unavailable);
    BOOST_TEST(std::ranges::all_of(buffer, [](std::uint8_t b) { return b == 0; }));

    std::ranges::fill(buffer, 0xff);
    answer_after = 0;
    failure = ENOTSUP;
    filled = device.fill(buffer);
    BOOST_TEST(!filled && filled.error() == boost::system::errc::not_supported);
    BOOST_TEST(std::ranges::all_of(buffer, [](std::uint8_t b) { return b == 0; }));

    // A failed call that leaves errno 0 is still a failure, never a filled piece.
    std::ranges::fill(buffer, 0xff);
    failure = 0;
    filled = device.fill(buffer);
    BOOST_TEST(!filled && filled.error() == crypto::error::entropy_unavailable);
    BOOST_TEST(std::ranges::all_of(buffer, [](std::uint8_t b) { return b == 0; }));
    failure = EIO;

    // The pieces of a fill that succeeds: 257 bytes are two calls (256 and 1), 600 are three,
    // none of more than 256 bytes (checked in the source), and the buffer holds what it gave.
    for (auto const& [size, pieces] : {std::pair<std::size_t, std::size_t>{257, 2}, {600, 3}}) {
        std::ranges::fill(buffer, 0xff);
        answer_after = 100;
        calls = 0;
        filled = device.fill(std::span(buffer).first(size));
        BOOST_TEST(filled.has_value());
        BOOST_TEST_EQ(calls, pieces);
        BOOST_TEST(std::all_of(buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(size),
                               [](std::uint8_t b) { return b == 0x5a; }));
    }

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
