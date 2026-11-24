// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

#include "random_device_second_unit.hpp"

#include <webcpp/crypto/random_device.hpp>

#include <boost/system/result.hpp>

#include <cstdint>
#include <span>

namespace webcpp::test {

boost::system::result<void> fill_in_second_unit(std::span<std::uint8_t> output_bytes) noexcept {
    return crypto::random_device{}.fill(output_bytes);
}

}  // namespace webcpp::test
