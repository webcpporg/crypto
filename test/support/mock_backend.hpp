// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// A backend for the tests of the generic layer: it specialises the block cipher's traits
// with a reversible transform. It is NOT a cipher: it only lets the guards, the moves and
// the error paths of aes.hpp run on every target before a real backend exists, and its
// knobs make each engine call fail on demand. Every engine call also checks the contract
// the generic layer owes a backend (a move into an empty state, no work on a moved-from
// state) and counts each breach in mock_control.violations, which a test expects to stay 0.

#ifndef WEBCPP_TEST_CRYPTO_SUPPORT_MOCK_BACKEND_HPP
#define WEBCPP_TEST_CRYPTO_SUPPORT_MOCK_BACKEND_HPP

#include <webcpp/crypto/config.hpp>

#include <webcpp/crypto/detail/engines.hpp>
#include <webcpp/crypto/error.hpp>

#include <boost/system/error_code.hpp>
#include <boost/system/result.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

namespace webcpp::test {

/** The mock backend's tag. */
struct mock {
    /** The backend's name. */
    static constexpr std::string_view name = "mock";
};

/** What a test makes the mock do: each error, when set, is what that engine call returns. */
struct mock_knobs {
    /** The error of the block cipher's `init`. */
    boost::system::error_code init;
    /** The error of the block cipher's `encrypt` and `decrypt`. */
    boost::system::error_code block;
    /** The breaches of the engine contract seen so far. */
    int violations = 0;
};

// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables): the knobs a test turns
inline mock_knobs mock_control{};

/** Clears every error and setting of the knobs; the counters stay. */
inline void mock_clear() {
    auto const violations = mock_control.violations;
    mock_control = mock_knobs{};
    mock_control.violations = violations;
}

namespace mock_detail {

/** SplitMix64's finaliser, a bijection of 64 bits. */
constexpr std::uint64_t mix(std::uint64_t x) noexcept {
    x += 0x9e3779b97f4a7c15U;
    x = (x ^ (x >> 30U)) * 0xbf58476d1ce4e5b9U;
    x = (x ^ (x >> 27U)) * 0x94d049bb133111ebU;
    return x ^ (x >> 31U);
}

/** Absorbs bytes into h, one at a time, so that any change of a byte changes the result. */
inline std::uint64_t absorb(std::uint64_t h, std::span<std::uint8_t const> bytes) noexcept {
    for (std::uint8_t const b : bytes) {
        h = mix(h ^ b);
    }
    return mix(h ^ bytes.size());
}

/** The hash of a key, which every derived value starts from. */
inline std::uint64_t key_hash(std::span<std::uint8_t const> key) noexcept {
    return absorb(0x6b6579U, key);
}

/** Byte `index` of the stream that `seed` starts. */
constexpr std::uint8_t stream_byte(std::uint64_t seed, std::uint64_t index) noexcept {
    return static_cast<std::uint8_t>(mix(seed ^ (index / 8)) >> (8 * (index % 8)));
}

}  // namespace mock_detail

}  // namespace webcpp::test

namespace webcpp::crypto::detail {

/** The block cipher's state on the mock: the key's hash. */
template <std::size_t KeySize>
struct block_state<test::mock, KeySize> {
    std::uint64_t key;
    bool live;
};

/** The block cipher's work on the mock: per block, a byte-wise reversible transform. */
template <std::size_t KeySize>
struct block_engine<test::mock, KeySize> {
    using state = block_state<test::mock, KeySize>;

    static boost::system::result<void> init(state& s, std::span<std::uint8_t const> key) noexcept {
        breach(s.live || key.size() != KeySize);
        if (test::mock_control.init) {
            return test::mock_control.init;
        }
        s.key = test::mock_detail::key_hash(key) ^ KeySize;
        s.live = true;
        return {};
    }

    static boost::system::result<void> encrypt(state& s, std::span<std::uint8_t> blocks) noexcept {
        breach(!s.live || blocks.size() % 16 != 0);
        if (test::mock_control.block) {
            return test::mock_control.block;
        }
        for (std::size_t i = 0; i < blocks.size(); ++i) {
            auto const at = i % 16;
            blocks[i] = static_cast<std::uint8_t>((blocks[i] ^ pad(s, at)) + pad(s, at + 16));
        }
        return {};
    }

    static boost::system::result<void> decrypt(state& s, std::span<std::uint8_t> blocks) noexcept {
        breach(!s.live || blocks.size() % 16 != 0);
        if (test::mock_control.block) {
            return test::mock_control.block;
        }
        for (std::size_t i = 0; i < blocks.size(); ++i) {
            auto const at = i % 16;
            blocks[i] = static_cast<std::uint8_t>((blocks[i] - pad(s, at + 16)) ^ pad(s, at));
        }
        return {};
    }

    static void move(state& to, state& from) noexcept {
        breach(to.live || !from.live);
        to = from;
        from = state{};
    }

    static void reset(state& s) noexcept { s = state{}; }

private:
    static std::uint8_t pad(state const& s, std::size_t index) noexcept {
        return test::mock_detail::stream_byte(s.key, index);
    }

    static void breach(bool happened) noexcept {
        if (happened) {
            ++test::mock_control.violations;
        }
    }
};

}  // namespace webcpp::crypto::detail

#endif
