// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The throughput of each family's fixed operation (bench/operations.hpp) on each backend this
// build links: AES-256-GCM on BearSSL and OpenSSL, the AES block cipher on ctaes and OpenSSL,
// BIP340 signing on libsecp256k1, Ed25519 signing and X25519 agreement on libsodium, and the
// ChaCha20-Poly1305 family on libsodium, BearSSL and OpenSSL (OpenSSL natively and on WASI only).
//
// Run with a family and a backend, `throughput <family> <backend> [--runs N]`, it repeats the
// operation enough times for a run to last at least 50 ms, times N runs (5 by default), and prints
// one JSON line: the family, the backend, the operation, the target, the compiler, the repetitions
// of a run, each run's microseconds per operation and their median. `--list` prints the cells this
// build has, one "<family> <backend>" per line. Run with no argument, it is the correctness test:
// each cell's operation is checked once (an open of what it sealed, a verification of what it
// signed, both sides of an agreement), and the program exits 0 only when every check holds. A
// measurement never fails on its time; bench/collect.py runs it and writes doc/performance.adoc.

#include <webcpp/crypto/backends/bearssl.hpp>
#include <webcpp/crypto/backends/ctaes.hpp>
#include <webcpp/crypto/backends/secp256k1.hpp>
#include <webcpp/crypto/backends/sodium.hpp>
#ifdef WEBCPP_CRYPTO_HAS_OPENSSL
#include <webcpp/crypto/backends/openssl.hpp>
#endif

#include "operations.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <span>
#include <string_view>
#include <system_error>
#include <vector>

namespace bench = webcpp::crypto::bench;
namespace backends = webcpp::crypto::backends;

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

// The shortest run measured, in seconds: long enough that the clock's resolution is no part of it.
constexpr double shortest_run = 0.05;

// A cell: a family on a backend, its operation, and what measures and checks it.
struct cell {
    std::string_view family;
    std::string_view backend;
    std::string_view operation;
    void (*measure)(std::string_view family, int runs);
    bool (*check)();
};

// The seconds of `repetitions` operations, with a byte folded from their results.
template <class Operation>
double timed(Operation& operation, std::uint64_t repetitions, std::uint8_t& folded) {
    auto const start = std::chrono::steady_clock::now();
    for (std::uint64_t i = 0; i < repetitions; ++i) {
        folded = static_cast<std::uint8_t>(folded ^ operation.run());
    }
    return std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count();
}

void print_string(char const* key, std::string_view value) {
    std::printf(R"("%s": "%.*s", )", key, static_cast<int>(value.size()), value.data());
}

template <class Operation>
void measure(std::string_view family, int runs) {
    Operation operation(1);
    std::uint8_t folded = 0;
    std::uint64_t repetitions = 1;
    while (timed(operation, repetitions, folded) < shortest_run) {
        repetitions *= 2;
    }
    std::vector<double> per_operation_us;
    per_operation_us.reserve(static_cast<std::size_t>(runs));
    for (int run = 0; run < runs; ++run) {
        per_operation_us.push_back(timed(operation, repetitions, folded) * 1e6 /
                                   static_cast<double>(repetitions));
    }
    std::vector<double> sorted = per_operation_us;
    std::ranges::sort(sorted);
    std::size_t const middle = sorted.size() / 2;
    double const median =
        sorted.size() % 2 != 0 ? sorted[middle] : (sorted[middle - 1] + sorted[middle]) / 2;
    std::printf("{");
    print_string("family", family);
    print_string("backend", Operation::backend_name);
    print_string("operation", Operation::operation);
    print_string("target", target);
    print_string("compiler", compiler);
    std::printf(R"("repetitions": %llu, "runs_us": [)",
                static_cast<unsigned long long>(repetitions));
    for (std::size_t i = 0; i < per_operation_us.size(); ++i) {
        std::printf("%s%.4f", i == 0 ? "" : ", ", per_operation_us[i]);
    }
    std::printf(R"(], "median_us": %.4f, "folded": %u})", median, static_cast<unsigned>(folded));
    std::printf("\n");
}

template <class Operation>
bool check() {
    Operation operation(1);
    return operation.check();
}

// The operation of a family on Backend, which also names its backend.
template <template <class> class Family, class Backend>
struct on : Family<Backend> {
    using base = Family<Backend>;
    using base::base;
    static constexpr std::string_view backend_name = Backend::name;
};

template <template <class> class Family, class Backend>
constexpr cell cell_of(std::string_view family) {
    using operation = on<Family, Backend>;
    return {family, Backend::name, operation::operation, &measure<operation>, &check<operation>};
}

constexpr auto cells = std::to_array<cell>({
    cell_of<bench::gcm, backends::bearssl>("gcm"),
#ifdef WEBCPP_CRYPTO_HAS_OPENSSL
    cell_of<bench::gcm, backends::openssl>("gcm"),
    cell_of<bench::aes_block, backends::openssl>("aes_block"),
#endif
    cell_of<bench::aes_block, backends::ctaes>("aes_block"),
    cell_of<bench::secp256k1, backends::secp256k1>("secp256k1"),
    cell_of<bench::ed25519, backends::sodium>("ed25519"),
    cell_of<bench::x25519, backends::sodium>("x25519"),
    cell_of<bench::chacha20_poly1305, backends::sodium>("chacha20_poly1305"),
    cell_of<bench::chacha20_poly1305, backends::bearssl>("chacha20_poly1305"),
#ifdef WEBCPP_CRYPTO_HAS_OPENSSL
    cell_of<bench::chacha20_poly1305, backends::openssl>("chacha20_poly1305"),
#endif
    cell_of<bench::chacha20_poly1305_original, backends::sodium>("chacha20_poly1305_original"),
    cell_of<bench::xchacha20_poly1305, backends::sodium>("xchacha20_poly1305"),
});

int usage() {
    static_cast<void>(
        std::fprintf(stderr, "usage: throughput [--list | <family> <backend> [--runs N]]\n"));
    return 2;
}

}  // namespace

int main(int argument_count, char** arguments) {
    std::span<char*> const given(arguments, static_cast<std::size_t>(argument_count));
    if (given.size() == 1) {
        bool all = true;
        for (cell const& each : cells) {
            bool const held = each.check();
            all = all && held;
            std::printf("%.*s %.*s %s\n", static_cast<int>(each.family.size()), each.family.data(),
                        static_cast<int>(each.backend.size()), each.backend.data(),
                        held ? "ok" : "FAILED");
        }
        return all ? 0 : 1;
    }
    std::string_view const first = given[1];
    if (first == "--list" && given.size() == 2) {
        for (cell const& each : cells) {
            std::printf("%.*s %.*s\n", static_cast<int>(each.family.size()), each.family.data(),
                        static_cast<int>(each.backend.size()), each.backend.data());
        }
        return 0;
    }
    int runs = 5;
    if (given.size() == 5 && std::string_view(given[3]) == "--runs") {
        std::string_view const count = given[4];
        auto const parsed = std::from_chars(count.data(), count.data() + count.size(), runs);
        if (parsed.ec != std::errc{} || parsed.ptr != count.data() + count.size() || runs < 1) {
            return usage();
        }
    } else if (given.size() != 3) {
        return usage();
    }
    std::string_view const backend = given[2];
    for (cell const& each : cells) {
        if (each.family == first && each.backend == backend) {
            each.measure(each.family, runs);
            return 0;
        }
    }
    static_cast<void>(
        std::fprintf(stderr, "throughput: no cell %s %s in this build\n", given[1], given[2]));
    return 2;
}
