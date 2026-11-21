// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The cost of detail::timing_guard, the scope every public operation of crypto runs in, which sets
// 64-bit ARM's DIT (data-independent timing) bit where the CPU has it and restores the thread's
// state after it.
//
// Run as `timing --measure`, it times, in one process, 10^7 iterations each of an empty loop body,
// of a guard entered from a thread whose DIT is clear (it sets DIT and clears it again), and of a
// guard entered with DIT already set (it reads DIT and leaves it; the program sets DIT for that
// part with the same `msr` as the guard, and clears it after), five runs of each, interleaved, and
// prints one JSON line: `{"dit": true|false, "clear": <ns>, "set": <ns>, ...}`, each cost the
// median of its runs minus the empty loop's, in nanoseconds per guard, then the iterations, the
// runs, the target and the compiler. "dit" says whether the guard sets DIT here (a target it
// covers, on a CPU that has it); where it does not, the guard executes no instruction and both
// costs are the loop's noise. Run with no argument, it is the correctness test: the same
// measurement at 10^3 iterations, whose line must have that form, whose "dit" must be what the
// library reads, and after each part of which the thread's DIT must be clear again. A measurement
// never fails on its time; bench/collect.py --timing runs it and writes doc/performance.adoc.

#include <webcpp/crypto/detail/timing.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <span>
#include <string_view>

namespace detail = webcpp::crypto::detail;

namespace {

#ifdef WEBCPP_TARGET_WASIP2
constexpr std::string_view target = "wasip2";
#elif defined(WEBCPP_TARGET_WASIP3)
constexpr std::string_view target = "wasip3";
#elif defined(WEBCPP_TARGET_EMSCRIPTEN)
constexpr std::string_view target = "emscripten";
#else
constexpr std::string_view target = "native";
#endif

// The compiler, as it names itself: MSVC defines no __VERSION__.
#ifdef __VERSION__
constexpr std::string_view compiler = __VERSION__;
#elif defined(_MSC_FULL_VER)
#define WEBCPP_CRYPTO_BENCH_STRING(x) #x
#define WEBCPP_CRYPTO_BENCH_VERSION(x) WEBCPP_CRYPTO_BENCH_STRING(x)
constexpr std::string_view compiler = "MSVC " WEBCPP_CRYPTO_BENCH_VERSION(_MSC_FULL_VER);
#else
constexpr std::string_view compiler = "unknown";
#endif

// The iterations of a measured run, and of the correctness test's.
constexpr std::uint64_t measured_iterations = 10'000'000;
constexpr std::uint64_t checked_iterations = 1'000;

// The runs of each part; their median is the part's time.
constexpr std::size_t runs = 5;

// Whether the guard sets DIT on this target and CPU.
bool guard_sets_dit() noexcept {
#ifdef WEBCPP_CRYPTO_DETAIL_TIMING_COVERED
    return detail::cpu_has_dit();
#else
    return false;
#endif
}

// Sets or clears this thread's DIT where the guard would, as a program that asks for it does.
void force_dit([[maybe_unused]] bool set) noexcept {
#ifdef WEBCPP_CRYPTO_DETAIL_TIMING_COVERED
    if (detail::cpu_has_dit()) {
        detail::write_dit(set ? detail::dit_bit : 0);
    }
#endif
}

// The nanoseconds of one iteration of body, over iterations of it.
template <class Body>
double nanoseconds_per_iteration(std::uint64_t iterations, Body body) {
    auto const start = std::chrono::steady_clock::now();
    for (std::uint64_t i = 0; i < iterations; ++i) {
        body(i);
    }
    std::chrono::duration<double, std::nano> const elapsed =
        std::chrono::steady_clock::now() - start;
    return elapsed.count() / static_cast<double>(iterations);
}

double median(std::array<double, runs> values) {
    std::ranges::sort(values);
    return values[runs / 2];
}

// What one measurement gives: the guard's two costs, and whether DIT was clear after each part.
struct result {
    double clear = 0;
    double set = 0;
    bool restored = true;
};

result measure(std::uint64_t iterations) {
    std::array<double, runs> empty{};
    std::array<double, runs> clear{};
    std::array<double, runs> set{};
    bool restored = true;
    // Written by every iteration of every part, so that no loop is removed or merged.
    std::uint64_t volatile sink = 0;
    for (std::size_t run = 0; run < runs; ++run) {
        empty[run] = nanoseconds_per_iteration(iterations, [&sink](std::uint64_t i) { sink = i; });
        clear[run] = nanoseconds_per_iteration(iterations, [&sink](std::uint64_t i) {
            detail::timing_guard const guard;
            sink = i;
        });
        restored = restored && !detail::dit_is_set();
        force_dit(true);
        set[run] = nanoseconds_per_iteration(iterations, [&sink](std::uint64_t i) {
            detail::timing_guard const guard;
            sink = i;
        });
        restored = restored && detail::dit_is_set() == guard_sets_dit();
        force_dit(false);
        restored = restored && !detail::dit_is_set();
    }
    double const loop = median(empty);
    return {.clear = median(clear) - loop, .set = median(set) - loop, .restored = restored};
}

// Writes the JSON line of a measurement into line; the number of characters, or -1.
int format(std::span<char> line, result const& measured, std::uint64_t iterations) {
    return std::snprintf(line.data(), line.size(),
                         R"({"dit": %s, "clear": %.3f, "set": %.3f, "iterations": %llu, )"
                         R"("runs": %zu, "target": "%.*s", "compiler": "%.*s"})",
                         guard_sets_dit() ? "true" : "false", measured.clear, measured.set,
                         static_cast<unsigned long long>(iterations), runs,
                         static_cast<int>(target.size()), target.data(),
                         static_cast<int>(compiler.size()), compiler.data());
}

// Skips prefix at the start of text, or returns null when text does not start with it.
char const* skip(char const* text, std::string_view prefix) {
    return text != nullptr && std::string_view(text).starts_with(prefix) ? text + prefix.size()
                                                                         : nullptr;
}

// Reads a finite number at the start of text into value; what follows it, or null.
char const* number(char const* text, double& value) {
    if (text == nullptr) {
        return nullptr;
    }
    char* end = nullptr;
    value = std::strtod(text, &end);
    return end != text && std::isfinite(value) ? end : nullptr;
}

// Whether line opens with the form collect.py reads: "dit" as the library reads it, then the two
// costs as finite numbers.
bool well_formed(char const* line) {
    double clear = 0;
    double set = 0;
    char const* rest =
        skip(line, guard_sets_dit() ? R"({"dit": true, "clear": )" : R"({"dit": false, "clear": )");
    rest = number(skip(number(rest, clear), R"(, "set": )"), set);
    return skip(rest, R"(, "iterations": )") != nullptr;
}

int usage() {
    static_cast<void>(std::fprintf(stderr, "usage: timing [--measure]\n"));
    return 2;
}

}  // namespace

int main(int argument_count, char** arguments) {
    std::span<char*> const given(arguments, static_cast<std::size_t>(argument_count));
    bool const measuring = given.size() == 2 && std::string_view(given[1]) == "--measure";
    if (given.size() != 1 && !measuring) {
        return usage();
    }
    std::uint64_t const iterations = measuring ? measured_iterations : checked_iterations;
    result const measured = measure(iterations);
    std::array<char, 512> line{};
    int const written = format(line, measured, iterations);
    if (written < 0 || static_cast<std::size_t>(written) >= line.size()) {
        static_cast<void>(std::fprintf(stderr, "timing: the line does not fit\n"));
        return 1;
    }
    std::printf("%s\n", line.data());
    if (measuring) {
        return 0;
    }
    bool const formed = well_formed(line.data());
    std::printf("form %s\nstate restored %s\n", formed ? "ok" : "FAILED",
                measured.restored ? "ok" : "FAILED");
    return formed && measured.restored ? 0 : 1;
}
