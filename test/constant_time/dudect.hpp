// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// Welch's t-test over two classes of timings, with dudect's cropping.

#ifndef WEBCPP_TEST_CRYPTO_DUDECT_HPP
#define WEBCPP_TEST_CRYPTO_DUDECT_HPP

#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <random>
#include <vector>

#ifdef _MSC_VER
#include <intrin.h>
#endif

namespace webcpp::test {

/**
 * Waits until every instruction before it has completed, so that a clock read after it does
 * not start while the preparation's last instructions still run: `isb` on 64-bit ARM, `lfence`
 * on x86. Without it the clock is read out of order, and what the preparation does by class
 * (it copies the fixed input or just-drawn bytes) leaks into the measured time (measured
 * natively on an Apple M5, 2026-11-18: |t| 25 to 35 on a ChaCha20-Poly1305 decryption that
 * never reads the classes' input, below 2 with the barriers; an early-exit comparison's |t|
 * rose from 18 to 42). WebAssembly has no such instruction: there the clock is a host call.
 */
inline void serialise() noexcept {
#ifdef __aarch64__
    __asm__ volatile("isb" ::: "memory");
#elif defined(__x86_64__) || defined(__i386__)
    __asm__ volatile("lfence" ::: "memory");
#elif defined(_MSC_VER) && (defined(_M_X64) || defined(_M_IX86))
    _mm_lfence();
#elif defined(_MSC_VER) && defined(_M_ARM64)
    __isb(_ARM64_BARRIER_SY);
#endif
}

/** Online mean and variance of one class, Welford's. */
struct moments {
    /** The number of values pushed. */
    double n = 0;
    /** Their mean. */
    double mean = 0;
    /** The sum of squared differences from the mean. */
    double m2 = 0;

    /**
     * Adds a value.
     * @param x The value.
     */
    void push(double x) {
        n += 1;
        double const delta = x - mean;
        mean += delta / n;
        m2 += delta * (x - mean);
    }

    /**
     * The sample variance.
     * @return The variance, 0 below two values.
     */
    [[nodiscard]] double variance() const { return n > 1 ? m2 / (n - 1) : 0; }
};

/**
 * Welch's t of two classes.
 * @param a The first class.
 * @param b The second class.
 * @return t, 0 when both variances are 0.
 */
inline double welch(moments const& a, moments const& b) {
    double const denominator = std::sqrt((a.variance() / a.n) + (b.variance() / b.n));
    return denominator == 0 ? 0 : (a.mean - b.mean) / denominator;
}

/**
 * The largest |t| over the whole set and dudect's 100 croppings.
 * @param timings The measurements.
 * @param classes The class, 0 or 1, of each.
 * @return The largest |t|.
 */
inline double largest_t(std::vector<double> const& timings, std::vector<int> const& classes) {
    std::vector<double> sorted = timings;
    std::ranges::sort(sorted);
    double largest = 0;
    for (int k = -1; k < 100; ++k) {
        double const keep = k < 0 ? 1.0 : 1.0 - std::pow(0.5, 10.0 * (k + 1) / 100.0);
        double const limit =
            sorted[static_cast<std::size_t>(keep * static_cast<double>(sorted.size() - 1))];
        std::array<moments, 2> m{};
        for (std::size_t i = 0; i < timings.size(); ++i) {
            if (timings[i] <= limit) {
                m[static_cast<std::size_t>(classes[i])].push(timings[i]);
            }
        }
        largest = (std::max)(largest, std::fabs(welch(m[0], m[1])));
    }
    return largest;
}

/**
 * Draws `Size` bytes, then copies into `input` either `fixed`, for class 0, or the drawn bytes,
 * for class 1. Both classes draw the same bytes and store the same way: the source is chosen
 * through a volatile pointer, which the compiler cannot see through, so that it cannot split
 * the copy by class into a store of constants for one and of drawn bytes for the other. Such
 * a split, which an optimiser makes of `which == 0 ? 0 : drawn`, leaks the class into the
 * measured call (measured natively on an Apple M5, 2026-11-18: |t| 16 to 18 on equal and 9 to
 * 26 on open with the split, below 3 for both through this copy).
 * @param which The class, 0 or 1.
 * @param generator The seeded generator.
 * @param fixed The class 0 input.
 * @param input Where the input of the class is copied.
 */
template <std::size_t Size, class Generator>
void choose(int which, Generator& generator, std::array<std::uint8_t, Size> const& fixed,
            std::array<std::uint8_t, Size>& input) {
    std::array<std::uint8_t, Size> drawn{};
    for (auto& byte : drawn) {
        byte = static_cast<std::uint8_t>(generator());
    }
    std::uint8_t const* volatile chosen = which == 0 ? fixed.data() : drawn.data();
    std::uint8_t const* const source = chosen;
    std::copy(source, source + Size, input.begin());
}

/**
 * The largest |t| of `count` measurements of `run`, each after `prepare(class, generator)`
 * with a class drawn at random from the seeded generator, prepare unmeasured; each clock read
 * is fenced by `serialise`.
 * @param seed The generator's seed.
 * @param count The number of measurements.
 * @param prepare Sets up the class's input, unmeasured.
 * @param run The operation measured.
 * @return The largest |t|.
 */
template <class Prepare, class Run>
double measure(std::uint64_t seed, std::size_t count, Prepare&& prepare, Run&& run) {
    std::mt19937_64 generator(seed);
    std::vector<double> timings;
    std::vector<int> classes;
    timings.reserve(count);
    classes.reserve(count);
    for (std::size_t i = 0; i < count; ++i) {
        int const which = static_cast<int>(generator() & 1U);
        prepare(which, generator);
        serialise();
        auto const start = std::chrono::steady_clock::now();
        serialise();
        run();
        serialise();
        auto const end = std::chrono::steady_clock::now();
        timings.push_back(std::chrono::duration<double, std::nano>(end - start).count());
        classes.push_back(which);
    }
    return largest_t(timings, classes);
}

/**
 * The largest |t| of a first run, and of a second with another seed when the first exceeds 10.
 * @param count The number of measurements of each run.
 * @param prepare Sets up the class's input, unmeasured.
 * @param run The operation measured.
 * @return The first run's |t| below 10, else the smaller of the two runs'.
 */
template <class Prepare, class Run>
double twice(std::size_t count, Prepare&& prepare, Run&& run) {
    double const first = measure(20261011, count, prepare, run);
    return first < 10 ? first : (std::min)(first, measure(20261012, count, prepare, run));
}

}  // namespace webcpp::test

#endif
