// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

/**
 `equal`, the constant-time comparison of tags and MACs, Boost.Hash2's included.
*/
#ifndef WEBCPP_CRYPTO_EQUAL_HPP
#define WEBCPP_CRYPTO_EQUAL_HPP

#include <webcpp/crypto/config.hpp>

#include <boost/hash2/digest.hpp>

#include <cstddef>
#include <cstdint>
#include <span>

namespace webcpp::crypto {

/**
 * Whether two byte sequences are equal, in a time that does not depend on their contents.
 *
 * Every byte is read, and no branch or index depends on one: the XOR of each pair is
 * accumulated with OR in a volatile local, read once after the loop, and reduced to one bit
 * without a branch, as BearSSL's tag check does. Sizes are public: spans of different sizes
 * compare unequal without reading their contents.
 *
 * @param a The first sequence, a tag or a MAC.
 * @param b The second.
 * @return Whether they have the same size and the same bytes.
 */
inline bool equal(std::span<std::uint8_t const> a, std::span<std::uint8_t const> b) noexcept {
    if (a.size() != b.size()) {
        return false;
    }
    unsigned volatile accumulated = 0;
    for (std::size_t i = 0; i < a.size(); ++i) {
        accumulated = accumulated | static_cast<unsigned>(a[i] ^ b[i]);
    }
    unsigned const all = accumulated;
    // all is at most 255: all - 1 wraps to the type's maximum only when all is 0.
    return (((all - 1U) >> 8U) & 1U) != 0;
}

/**
 * Whether two digests are equal, in a time that does not depend on their contents.
 *
 * Boost.Hash2's own `operator==` is `memcmp`, which is not constant time: a MAC is checked
 * with this one.
 *
 * @tparam N The digests' size in bytes.
 * @param a The first digest.
 * @param b The second.
 * @return Whether every byte is equal.
 */
template <std::size_t N>
bool equal(boost::hash2::digest<N> const& a, boost::hash2::digest<N> const& b) noexcept {
    return equal(std::span<std::uint8_t const>(a.data(), N),
                 std::span<std::uint8_t const>(b.data(), N));
}

}  // namespace webcpp::crypto

#endif  // WEBCPP_CRYPTO_EQUAL_HPP
