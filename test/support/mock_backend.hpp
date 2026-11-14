// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// A backend for the tests of the generic layer: it specialises the block cipher's and
// GCM's traits with a reversible transform and a tag computed from the key, the IV, the
// additional data and the data. It is NOT a cipher: it only lets the guards, the state
// machine, the moves and the error paths of aes.hpp and gcm.hpp run on every target before
// a real backend exists, and its knobs make each engine call fail on demand. Every engine
// call also checks the contract the generic layer owes a backend (a move into an empty
// state, no work on a moved-from state, a tag only after a start) and counts each breach in
// mock_control.violations, which a test expects to stay 0.

#ifndef WEBCPP_TEST_CRYPTO_SUPPORT_MOCK_BACKEND_HPP
#define WEBCPP_TEST_CRYPTO_SUPPORT_MOCK_BACKEND_HPP

#include "gcm_spec_vectors.hpp"
#include "hex.hpp"

#include <webcpp/crypto/config.hpp>

#include <webcpp/crypto/detail/engines.hpp>
#include <webcpp/crypto/error.hpp>

#include <boost/hash2/digest.hpp>
#include <boost/system/error_code.hpp>
#include <boost/system/result.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>

namespace webcpp::test {

/** The mock backend's tag. */
struct mock {
    /** The backend's name. */
    static constexpr std::string_view name = "mock";
};

/** What a test makes the mock do: each error, when set, is what that engine call returns. */
struct mock_knobs {
    /** The error of the block cipher's and GCM's `init`. */
    boost::system::error_code init;
    /** The error of the block cipher's `encrypt` and `decrypt`. */
    boost::system::error_code block;
    /** The error of GCM's `start`. */
    boost::system::error_code start;
    /** The error of GCM's `run`. */
    boost::system::error_code run;
    /** The error of GCM's `tag`. */
    boost::system::error_code tag;
    /** The error of GCM's `check`, in place of its verdict. */
    boost::system::error_code check;
    /** Whether GCM's `run` leaves the data unread, for the limits summed over pieces. */
    bool skip_data = false;
    /** The breaches of the engine contract seen so far. */
    int violations = 0;
    /** The calls of GCM's `abandon` so far. */
    int abandons = 0;
};

// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables): the knobs a test turns
inline mock_knobs mock_control{};

/** Clears every error and setting of the knobs; the counters stay. */
inline void mock_clear() {
    auto const violations = mock_control.violations;
    auto const abandons = mock_control.abandons;
    mock_control = mock_knobs{};
    mock_control.violations = violations;
    mock_control.abandons = abandons;
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

/** The first value of a message's tag, from the key, the IV and the additional data. */
inline std::uint64_t mac_start(std::uint64_t key, std::span<std::uint8_t const> iv,
                               std::span<std::uint8_t const> additional_data) noexcept {
    return absorb(absorb(mix(key ^ 0x6d6163U), iv), additional_data);
}

/** The seed of a message's stream, from the key and the IV. */
inline std::uint64_t stream_start(std::uint64_t key, std::span<std::uint8_t const> iv) noexcept {
    return absorb(mix(key ^ 0x737472U), iv);
}

/** The tag of a message whose ciphertext's `size` bytes were absorbed into `mac`. */
inline void finish(std::uint64_t mac, std::uint64_t size,
                   std::span<std::uint8_t, 16> out) noexcept {
    auto const first = mix(mac ^ size);
    auto const second = mix(first ^ 0x746167U);
    for (std::size_t i = 0; i < 8; ++i) {
        out[i] = static_cast<std::uint8_t>(first >> (8 * i));
        out[8 + i] = static_cast<std::uint8_t>(second >> (8 * i));
    }
}

/** The mock's whole seal in one pass, the reference the generic layer's results must match. */
inline std::array<std::uint8_t, 16> reference_seal(std::span<std::uint8_t const> key,
                                                   std::span<std::uint8_t const> iv,
                                                   std::span<std::uint8_t const> additional_data,
                                                   std::span<std::uint8_t> data) noexcept {
    auto const k = key_hash(key);
    auto const seed = stream_start(k, iv);
    auto mac = mac_start(k, iv, additional_data);
    for (std::size_t i = 0; i < data.size(); ++i) {
        data[i] = static_cast<std::uint8_t>(data[i] ^ stream_byte(seed, i));
        mac = mix(mac ^ data[i]);
    }
    std::array<std::uint8_t, 16> tag{};
    finish(mac, data.size(), tag);
    return tag;
}

}  // namespace mock_detail

/**
 * The GCM specification's 18 inputs with the mock's ciphertexts and tags, which every check
 * of support/gcm_checks.hpp takes in place of the specification's own. Built in place, and
 * neither copied nor moved: its cases view its strings.
 */
class mock_cases {
public:
    mock_cases() {
        for (std::size_t i = 0; i < gcm_spec_cases.size(); ++i) {
            auto const& spec = gcm_spec_cases[i];
            auto data = from_hex(spec.plaintext);
            auto const tag = mock_detail::reference_seal(from_hex(spec.key), from_hex(spec.iv),
                                                         from_hex(spec.additional_data), data);
            ciphertexts_[i] = to_hex(data);
            tags_[i] = to_hex(tag);
            cases_[i] = {spec.key, spec.plaintext,  spec.additional_data,
                         spec.iv,  ciphertexts_[i], tags_[i]};
        }
    }

    mock_cases(mock_cases const&) = delete;
    mock_cases& operator=(mock_cases const&) = delete;
    ~mock_cases() = default;

    /** The 18 cases, in the specification's order. */
    std::span<gcm_case const> view() const noexcept { return cases_; }

private:
    std::array<std::string, 18> ciphertexts_;
    std::array<std::string, 18> tags_;
    std::array<gcm_case, 18> cases_{};
};

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

/** GCM's state on the mock: the key's hash and the message's running values. */
template <std::size_t KeySize>
struct gcm_state<test::mock, KeySize> {
    std::uint64_t key;
    std::uint64_t stream;
    std::uint64_t mac;
    std::uint64_t position;
    bool live;
    bool started;
    bool sealing;
};

/** GCM's work on the mock, with the contract of every GCM engine (Tasks 7 and 8). */
template <std::size_t KeySize>
struct gcm_engine<test::mock, KeySize> {
    using state = gcm_state<test::mock, KeySize>;

    static boost::system::result<void> init(state& s, std::span<std::uint8_t const> key) noexcept {
        breach(s.live || key.size() != KeySize);
        if (test::mock_control.init) {
            return test::mock_control.init;
        }
        s = state{};
        s.key = test::mock_detail::key_hash(key);
        s.live = true;
        return {};
    }

    // The IV and the additional data are consumed here, whole: nothing of them is kept.
    static boost::system::result<void> start(
        state& s, bool sealing, std::span<std::uint8_t const> iv,
        std::span<std::uint8_t const> additional_data) noexcept {
        breach(!s.live || iv.empty() || iv.size() > 128);
        if (test::mock_control.start) {
            return test::mock_control.start;
        }
        s.stream = test::mock_detail::stream_start(s.key, iv);
        s.mac = test::mock_detail::mac_start(s.key, iv, additional_data);
        s.position = 0;
        s.sealing = sealing;
        s.started = true;
        return {};
    }

    static boost::system::result<void> run(state& s, std::span<std::uint8_t> data) noexcept {
        breach(!s.live || !s.started);
        if (test::mock_control.run) {
            return test::mock_control.run;
        }
        if (!test::mock_control.skip_data) {
            for (std::size_t i = 0; i < data.size(); ++i) {
                auto const pad = test::mock_detail::stream_byte(s.stream, s.position + i);
                if (s.sealing) {
                    data[i] = static_cast<std::uint8_t>(data[i] ^ pad);
                    s.mac = test::mock_detail::mix(s.mac ^ data[i]);
                } else {
                    s.mac = test::mock_detail::mix(s.mac ^ data[i]);
                    data[i] = static_cast<std::uint8_t>(data[i] ^ pad);
                }
            }
        }
        s.position += data.size();
        return {};
    }

    static boost::system::result<void> tag(state& s, boost::hash2::digest<16>& out) noexcept {
        breach(!s.live || !s.started || !s.sealing);
        if (test::mock_control.tag) {
            return test::mock_control.tag;
        }
        test::mock_detail::finish(s.mac, s.position, std::span<std::uint8_t, 16>(out.data(), 16));
        s.started = false;
        return {};
    }

    static boost::system::result<void> check(state& s,
                                             std::array<std::uint8_t, 16> const& tag) noexcept {
        breach(!s.live || !s.started || s.sealing);
        if (test::mock_control.check) {
            return test::mock_control.check;
        }
        std::array<std::uint8_t, 16> expected{};
        test::mock_detail::finish(s.mac, s.position, expected);
        s.started = false;
        if (expected != tag) {
            return error::authentication_failed;
        }
        return {};
    }

    // As BearSSL's: the key moves, a message in progress does not.
    static void move(state& to, state& from) noexcept {
        breach(to.live || !from.live);
        to = state{};
        to.key = from.key;
        to.live = true;
        from = state{};
    }

    static void reset(state& s) noexcept { s = state{}; }

    // The message's state is dropped, the key kept (Task 8).
    static void abandon(state& s) noexcept {
        breach(!s.live);
        ++test::mock_control.abandons;
        auto const key = s.key;
        s = state{};
        s.key = key;
        s.live = true;
    }

private:
    static void breach(bool happened) noexcept {
        if (happened) {
            ++test::mock_control.violations;
        }
    }
};

}  // namespace webcpp::crypto::detail

#endif
