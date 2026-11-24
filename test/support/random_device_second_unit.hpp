// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// A second translation unit that draws from random_device, linked into random_device_browser:
// whatever the Emscripten draw defines in a header must link from two units of one program.

#ifndef WEBCPP_TEST_CRYPTO_SUPPORT_RANDOM_DEVICE_SECOND_UNIT_HPP
#define WEBCPP_TEST_CRYPTO_SUPPORT_RANDOM_DEVICE_SECOND_UNIT_HPP

#include <boost/system/result.hpp>

#include <cstdint>
#include <span>

namespace webcpp::test {

/** Fills `output_bytes` through a `random_device` made in another translation unit. */
[[nodiscard]] boost::system::result<void> fill_in_second_unit(
    std::span<std::uint8_t> output_bytes) noexcept;

}  // namespace webcpp::test

#endif  // WEBCPP_TEST_CRYPTO_SUPPORT_RANDOM_DEVICE_SECOND_UNIT_HPP
