// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

#ifndef WEBCPP_CRYPTO_DETAIL_WIPE_HPP
#define WEBCPP_CRYPTO_DETAIL_WIPE_HPP

#include <webcpp/crypto/config.hpp>

#include <atomic>
#include <cstddef>
#include <type_traits>

namespace webcpp::crypto::detail {

/**
 * Zeroes `size` bytes at `data` with stores the optimiser cannot drop.
 *
 * Tip: a `memset` before an object dies is a dead store a compiler may remove; stores through
 * a volatile pointer, then a signal fence, are kept.
 *
 * @param data The first byte, or null when `size` is 0.
 * @param size How many bytes.
 */
inline void wipe(void* data, std::size_t size) noexcept {
    auto* const bytes = static_cast<unsigned char volatile*>(data);
    for (std::size_t i = 0; i < size; ++i) {
        bytes[i] = 0;
    }
    std::atomic_signal_fence(std::memory_order_seq_cst);
}

/**
 * Zeroes an object's bytes, as @ref wipe does.
 *
 * @tparam T A trivially copyable type, a C library's key schedule or context.
 * @param object The object.
 */
template <class T>
void wipe_object(T& object) noexcept {
    static_assert(std::is_trivially_copyable_v<T>, "only a C library's plain state is wiped");
    wipe(&object, sizeof object);
}

}  // namespace webcpp::crypto::detail

#endif  // WEBCPP_CRYPTO_DETAIL_WIPE_HPP
