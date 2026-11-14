// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

#ifndef WEBCPP_CRYPTO_DETAIL_LIMITS_HPP
#define WEBCPP_CRYPTO_DETAIL_LIMITS_HPP

#include <webcpp/crypto/config.hpp>

#include <cstdint>

namespace webcpp::crypto::detail {

/**
 * Whether `value` is above `limit`, both in 64 bits.
 *
 * Tip: a `size_t` compared with a 64-bit limit is a tautology on wasm32, which clang reports
 * as an error under `<warnings-as-errors>on`; a function of two `uint64_t` is not.
 *
 * @param value The size, widened.
 * @param limit The limit.
 * @return `value > limit`.
 */
inline bool exceeds(std::uint64_t value, std::uint64_t limit) noexcept {
    return value > limit;
}

}  // namespace webcpp::crypto::detail

#endif  // WEBCPP_CRYPTO_DETAIL_LIMITS_HPP
