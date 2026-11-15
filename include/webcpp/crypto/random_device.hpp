// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

/**
 The random device: the system's or the browser's generator, shaped as the standard
 library's.
*/
#ifndef WEBCPP_CRYPTO_RANDOM_DEVICE_HPP
#define WEBCPP_CRYPTO_RANDOM_DEVICE_HPP

#include <webcpp/crypto/config.hpp>

#include <webcpp/crypto/detail/entropy.hpp>

#include <boost/system/result.hpp>
#include <boost/system/system_error.hpp>
#include <boost/throw_exception.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <span>

namespace webcpp::crypto {

/**
 * The operating system's or the browser's generator, and nothing else.
 *
 * Every call reads the source: there is no cache and no generator in between. It holds no
 * state and needs no backend. With exceptions it is a UniformRandomBitGenerator, as the
 * standard library's random device is; without them its interface is `fill`.
 *
 * @see "Entropy", in the guide.
 */
class random_device {  // lint-world: the system's entropy, this class's purpose
public:
    /** The standard library's random device's own type. */
    using result_type = unsigned int;

    /** Makes the device, which holds nothing. */
    random_device() noexcept = default;  // lint-world: reads the system's entropy
    /** Not copyable: the device holds nothing to copy. */
    random_device(random_device const&) = delete;  // lint-world: not copyable
    /** Not copyable: the device holds nothing to copy. */
    random_device& operator=(random_device const&) = delete;  // lint-world: not copyable

    /**
     * The smallest value `operator()` gives.
     *
     * @return 0.
     */
    [[nodiscard]] static constexpr result_type(min)() noexcept { return 0; }

    /**
     * The largest value `operator()` gives.
     *
     * @return The largest `unsigned int`.
     */
    [[nodiscard]] static constexpr result_type(max)() noexcept {
        // The parentheses keep windows.h's max macro out.
        // NOLINTNEXTLINE(readability-redundant-parentheses)
        return (std::numeric_limits<result_type>::max)();
    }

    /**
     * The entropy of a value, in bits: every bit is the system's.
     *
     * @return The digits of `result_type`.
     */
    // A member, as the standard library's random device has it.
    // NOLINTNEXTLINE(readability-convert-member-functions-to-static)
    [[nodiscard]] double entropy() const noexcept {
        return static_cast<double>(std::numeric_limits<result_type>::digits);
    }

    /**
     * Fills `output_bytes` from the system's generator.
     *
     * @param output_bytes The bytes to fill; zeroed on error.
     * @return Nothing; `error::entropy_unavailable` when the source fails;
     * `errc::not_supported` where there is none (an Emscripten audio worklet).
     */
    // A member, so that a generator of another kind can stand in for this one.
    // NOLINTNEXTLINE(readability-convert-member-functions-to-static)
    [[nodiscard]] boost::system::result<void> fill(std::span<std::uint8_t> output_bytes) noexcept {
        return detail::fill_from_system(output_bytes);
    }

#ifndef WEBCPP_CRYPTO_NO_EXCEPTIONS
    /**
     * A value from the system's generator, as the standard library's random device gives one.
     *
     * A failure of the read is thrown as `boost::system::system_error`, carrying @ref fill's
     * error.
     *
     * @return The value.
     */
    [[nodiscard]] result_type operator()() {
        std::array<std::uint8_t, sizeof(result_type)> drawn_bytes{};
        auto const fill_result = fill(drawn_bytes);
        if (!fill_result) {
            boost::throw_exception(boost::system::system_error(fill_result.error()));
        }
        result_type drawn_value = 0;
        std::memcpy(&drawn_value, drawn_bytes.data(), drawn_bytes.size());
        return drawn_value;
    }
#endif
};

}  // namespace webcpp::crypto

#endif  // WEBCPP_CRYPTO_RANDOM_DEVICE_HPP
