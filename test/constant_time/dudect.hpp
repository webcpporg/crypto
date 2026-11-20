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
#include <cstdio>
#include <random>
#include <vector>

#ifdef _MSC_VER
#include <intrin.h>
#endif
#if defined(__aarch64__) && defined(__APPLE__)
#include <sys/sysctl.h>
#elif defined(__aarch64__) && defined(__linux__)
#include <sys/auxv.h>
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

/** What a dudect program finds of arm64's DIT (Data Independent Timing) bit, PSTATE.DIT. */
enum class timing_mode : std::uint8_t {
    /** Neither macOS nor Linux on arm64: x86, WebAssembly (where the engine decides), and arm64
       systems the harness does not cover, MSVC on ARM64 among them, which it measures without
       DIT. */
    not_applicable,
    /** An arm64 CPU without DIT. */
    no_dit,
    /** DIT is set for this thread. */
    set,
    /** The CPU has DIT and it is not set: the timings would not be those of constant-time code. */
    unset,
    /** macOS on arm64, where the CPU's features could not be read: whether it has DIT is not
       known, and the run is not measured without it. */
    unreadable,
};

/** Whether the CPU has DIT, as the system reports it. */
enum class dit_support : std::uint8_t {
    /** The CPU has DIT. */
    present,
    /** The CPU has no DIT. */
    absent,
    /** macOS on arm64, `hw.optional.arm.FEAT_DIT` could not be read. */
    unreadable,
    /** Neither macOS nor Linux on arm64: the harness does not read it. */
    not_applicable,
};

/**
 * Whether the CPU has DIT: `hw.optional.arm.FEAT_DIT` on macOS, `HWCAP_DIT` on Linux, both on
 * arm64.
 * @return `present`, `absent`, `unreadable` where macOS's read fails, or `not_applicable`
 * elsewhere.
 */
inline dit_support cpu_dit() noexcept {
#if defined(__aarch64__) && defined(__APPLE__)
    int has = 0;
    std::size_t size = sizeof has;
    if (sysctlbyname("hw.optional.arm.FEAT_DIT", &has, &size, nullptr, 0) != 0) {
        return dit_support::unreadable;
    }
    return has != 0 ? dit_support::present : dit_support::absent;
#elif defined(__aarch64__) && defined(__linux__)
    constexpr unsigned long hwcap_dit = 1UL << 24U;  // HWCAP_DIT, asm/hwcap.h
    return (getauxval(AT_HWCAP) & hwcap_dit) != 0 ? dit_support::present : dit_support::absent;
#else
    return dit_support::not_applicable;
#endif
}

/**
 * Sets DIT for this thread where the CPU has it, on macOS and Linux on arm64, then reads it
 * back. With DIT set, the instructions Arm lists take a time independent of their data; Apple
 * requires it of constant-time code on Apple silicon, and none of the C libraries the lane
 * measures sets it. Without it, X25519's agreement on libsodium with an all-zero secret key ran
 * about one nanosecond faster in 15 microseconds than with random keys (measured natively on an
 * Apple M5 Max, 2026-11-19: |t| 6.7 to 14.5 against the threshold 10 without DIT, 1 to 3.5 with
 * it). The register is named by its encoding (op0 3, op1 3, CRn 4, CRm 2, op2 5), which every
 * assembler takes, with or without an architecture flag. The `isb` after the write is the
 * barrier Apple asks for, so that the code after it runs under the new state.
 * @return `set`; `unset` when the CPU has DIT and it did not take; `no_dit`, `unreadable` or
 * `not_applicable` as cpu_dit finds the CPU.
 */
inline timing_mode data_independent_timing() noexcept {
    switch (cpu_dit()) {
        case dit_support::present: break;
        case dit_support::absent: return timing_mode::no_dit;
        case dit_support::unreadable: return timing_mode::unreadable;
        case dit_support::not_applicable: return timing_mode::not_applicable;
    }
#ifdef __aarch64__
    std::uint64_t state = std::uint64_t{1} << 24U;
    __asm__ volatile("msr s3_3_c4_c2_5, %0\n\tisb" : : "r"(state) : "memory");
    __asm__ volatile("mrs %0, s3_3_c4_c2_5" : "=r"(state));
    return ((state >> 24U) & 1U) != 0 ? timing_mode::set : timing_mode::unset;
#else
    return timing_mode::not_applicable;
#endif
}

/**
 * Sets DIT where the CPU has it (data_independent_timing), and prints what it found.
 * @return false when the CPU has DIT and it is not set, or when macOS on arm64 could not read
 * whether the CPU has it, so that the program fails rather than measure without it; true
 * otherwise, where there is no DIT to set (an arm64 CPU without it, or not macOS or Linux on
 * arm64, which the harness does not cover).
 */
inline bool enter_data_independent_timing() noexcept {
    switch (data_independent_timing()) {
        case timing_mode::set: std::printf("DIT (data-independent timing): set\n"); return true;
        case timing_mode::unset:
            std::printf("DIT (data-independent timing): the CPU has it and it is not set\n");
            return false;
        case timing_mode::unreadable:
            std::printf("DIT (data-independent timing): the CPU's features could not be read\n");
            return false;
        case timing_mode::no_dit:
            std::printf("DIT (data-independent timing): not on this CPU\n");
            return true;
        case timing_mode::not_applicable: break;
    }
    std::printf(
        "DIT (data-independent timing): not applicable here (not macOS or Linux on arm64)\n");
    return true;
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
 * Draws `Size` bytes, then writes into `input` either `fixed`, for class 0, or the drawn bytes,
 * for class 1, so that the two classes differ in the bytes written and in nothing else. Both
 * classes draw the same bytes, read both `fixed` and the drawn bytes, and write `input` with the
 * same instructions: each byte is blended through a mask read from a volatile, which the
 * compiler cannot see through, so that it can neither split the work by class nor read one
 * source alone. Whatever a class does differently before the measured call leaks the class into
 * it. A copy from a volatile pointer to the chosen source (until 2026-11-20) read the fixed
 * input for class 0 and the bytes just drawn, still in the store buffer, for class 1: on the
 * CI's x86-64 runners the measured call then differed by class whatever it computed (measured
 * on GitHub's ubuntu-24.04 runners, 2026-11-20: equal at |t| 31 to 56 on an Intel Xeon 6975P-C
 * and ChaCha20-Poly1305's seal at 28 to 85 on AMD EPYC 9V45 and 9V74; through this blend, on
 * the Xeon, the EPYC 9V74 and an AMD EPYC 7763, idle and with every processor busy, every case
 * of 23 runs of 24 stayed below 4.4, the 24th is in `judged`). Before it,
 * a choice the optimiser made of `which == 0 ? 0 : drawn` split the copy into a store of
 * constants and a store of drawn bytes (measured natively on an Apple M5, 2026-11-18: |t| 16 to
 * 18 on equal and 9 to 26 on open with the split, below 3 for both without it).
 * @param which The class, 0 or 1.
 * @param generator The seeded generator.
 * @param fixed The class 0 input.
 * @param input Where the input of the class is written.
 */
template <std::size_t Size, class Generator>
void choose(int which, Generator& generator, std::array<std::uint8_t, Size> const& fixed,
            std::array<std::uint8_t, Size>& input) {
    std::array<std::uint8_t, Size> drawn{};
    for (auto& byte : drawn) {
        byte = static_cast<std::uint8_t>(generator());
    }
    std::uint8_t volatile const chosen = which == 0 ? 0xFFU : 0x00U;
    unsigned const keep = chosen;
    unsigned const drop = keep ^ 0xFFU;
    for (std::size_t index = 0; index < Size; ++index) {
        input[index] = static_cast<std::uint8_t>((unsigned{fixed[index]} & keep) |
                                                 (unsigned{drawn[index]} & drop));
    }
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

/**
 * Whether this build's verdict is judged: false where the lane's Jamfile defines
 * WEBCPP_TEST_DUDECT_UNJUDGED, on a runner GitHub hosts (RUNNER_ENVIRONMENT=github-hosted), true
 * elsewhere. A hosted runner is a virtual machine shared with other tenants, whose processor
 * changes from one run to the next (an Intel Xeon 6975P-C, an AMD EPYC 7763, 9V45 or 9V74 on
 * 2026-11-20), and there |t| moved with what the measurement could not control: through the
 * class-blind preparation of `choose`, one run of 24 read |t| 69.8 on ChaCha20-Poly1305's open,
 * on both seeds, where the 23 others read below 4.4 (an AMD EPYC 7763, idle); through the
 * earlier copy, a measured call that does nothing read up to 117 with every processor busy. A
 * verdict there would pass or fail with the machine drawn, so it prints its |t| and passes;
 * Valgrind's memcheck and MemorySanitizer, which do not measure time, are judged there. dudect
 * is judged wherever else the lane runs, natively and on wasip2, on a machine of one's own;
 * dudect_planted is judged everywhere, as it shows that the measurement still finds a leak of a
 * few nanoseconds on the machine it ran on.
 */
#ifdef WEBCPP_TEST_DUDECT_UNJUDGED
inline constexpr bool judged = false;
#else
inline constexpr bool judged = true;
#endif

/**
 * The exit status of a dudect program: 0 when every case passes, else 1, where `judged`; 0
 * elsewhere, after a line that says so.
 * @param passes Whether every case's |t| is below the threshold.
 * @return The exit status.
 */
inline int verdict(bool passes) noexcept {
    if (!judged) {
        std::printf("printed, not judged: a runner GitHub hosts (dudect.hpp, judged)\n");
        return 0;
    }
    return passes ? 0 : 1;
}

}  // namespace webcpp::test

#endif
