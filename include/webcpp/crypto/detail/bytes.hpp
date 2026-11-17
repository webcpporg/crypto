// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

#ifndef WEBCPP_CRYPTO_DETAIL_BYTES_HPP
#define WEBCPP_CRYPTO_DETAIL_BYTES_HPP

#include <webcpp/crypto/config.hpp>

#include <cstdint>
#include <span>

namespace webcpp::crypto::detail {

/**
 * Whether every byte is zero, in a time that does not depend on the bytes: an OR over all of
 * them in a volatile local, read once after the loop, with no early exit, and reduced to one
 * bit without a branch, as `equal` does.
 *
 * @param checked_bytes A secret, such as a shared secret checked for the all-zero result.
 * @return Whether every byte is zero (true for none).
 */
[[nodiscard]] inline bool is_all_zero(std::span<std::uint8_t const> checked_bytes) noexcept {
    unsigned volatile accumulated_bits = 0;
    for (std::uint8_t const checked_byte : checked_bytes) {
        accumulated_bits = accumulated_bits | static_cast<unsigned>(checked_byte);
    }
    unsigned const total_bits = accumulated_bits;
    // total_bits is at most 255: total_bits - 1 wraps to the type's maximum only when it is 0.
    return (((total_bits - 1U) >> 8U) & 1U) != 0;
}

}  // namespace webcpp::crypto::detail

#endif  // WEBCPP_CRYPTO_DETAIL_BYTES_HPP
