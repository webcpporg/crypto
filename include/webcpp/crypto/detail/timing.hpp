// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

#ifndef WEBCPP_CRYPTO_DETAIL_TIMING_HPP
#define WEBCPP_CRYPTO_DETAIL_TIMING_HPP

#include <webcpp/crypto/config.hpp>

/*
 * timing_guard sets 64-bit ARM's DIT (Data Independent Timing) bit, PSTATE.DIT, for the scope of
 * one public operation and restores the thread's state after it. With DIT set, the instructions
 * Arm lists take a time independent of their data; Apple requires it of constant-time code on
 * Apple silicon, and none of the C libraries crypto calls sets it. Every public function that
 * runs a backend's cryptographic code, and equal, holds one as its first statement.
 *
 * The guard applies on arm64 under macOS, iOS, Linux and Android, where the system says whether
 * the CPU has FEAT_DIT. Everywhere else (x86, WebAssembly, where the engine decides, and Windows
 * on ARM64, which documents no way to ask) it is an empty class that executes no instruction.
 */
#if defined(__aarch64__) && (defined(__APPLE__) || defined(__linux__))
/** Defined where timing_guard sets DIT: arm64 under an Apple system or Linux, Android included. */
#define WEBCPP_CRYPTO_DETAIL_TIMING_COVERED 1
#include <cstddef>
#include <cstdint>
#ifdef __APPLE__
#include <sys/sysctl.h>
#else
#include <sys/auxv.h>
#endif
#endif

/*
 * WEBCPP_CRYPTO_DETAIL_TIMING_ENTERED() runs first in timing_guard's constructor, on every target.
 * Nothing in a program's build; a test defines it before its first include to count the guards a
 * call enters (test/support/timing_seam.hpp), so that a public function that forgets its guard
 * fails on every lane, also where DIT does not apply.
 */
#ifndef WEBCPP_CRYPTO_DETAIL_TIMING_ENTERED
/** Marks the entry into a timing_guard: nothing in a program's build. */
#define WEBCPP_CRYPTO_DETAIL_TIMING_ENTERED() static_cast<void>(0)
#endif

namespace webcpp::crypto::detail {

#ifdef WEBCPP_CRYPTO_DETAIL_TIMING_COVERED
/** DIT's bit in the value of the register s3_3_c4_c2_5, bit 24 as in PSTATE. */
inline constexpr std::uint64_t dit_bit = std::uint64_t{1} << 24U;

/**
 * Writes the DIT register, then waits with `isb` until the write takes effect.
 *
 * The register is named by its encoding (op0 3, op1 3, CRn 4, CRm 2, op2 5), which every
 * assembler takes, with or without an architecture flag. The `isb` is the barrier Apple asks for
 * after the write, so that the instructions after it run under the new state.
 *
 * @param value `dit_bit` to set DIT, 0 to clear it.
 */
inline void write_dit(std::uint64_t value) noexcept {
    __asm__ volatile("msr s3_3_c4_c2_5, %0\n\tisb" : : "r"(value) : "memory");
}
#endif

/**
 * Whether the CPU has DIT, read once per process.
 *
 * `hw.optional.arm.FEAT_DIT` on Apple's systems, where a value that cannot be read counts as
 * absent; `HWCAP_DIT` (bit 24 of `AT_HWCAP`) on Linux. Executing DIT's instructions on a CPU
 * without it traps, so nothing reads or writes the register unless this is true.
 *
 * @return Whether the CPU has FEAT_DIT; `false` on every target the guard does not cover.
 */
[[nodiscard]] inline bool cpu_has_dit() noexcept {
#if defined(WEBCPP_CRYPTO_DETAIL_TIMING_COVERED) && defined(__APPLE__)
    static bool const has_dit = [] {
        int feature = 0;
        std::size_t size = sizeof feature;
        return sysctlbyname("hw.optional.arm.FEAT_DIT", &feature, &size, nullptr, 0) == 0 &&
               feature != 0;
    }();
    return has_dit;
#elif defined(WEBCPP_CRYPTO_DETAIL_TIMING_COVERED)
    constexpr unsigned long hwcap_dit = 1UL << 24U;  // HWCAP_DIT, asm/hwcap.h
    static bool const has_dit = (getauxval(AT_HWCAP) & hwcap_dit) != 0;
    return has_dit;
#else
    return false;
#endif
}

/**
 * Whether DIT is set for the calling thread.
 *
 * @return PSTATE.DIT, read with `mrs`, where the CPU has DIT on a target the guard covers;
 * `false` elsewhere, without executing `mrs`.
 */
[[nodiscard]] inline bool dit_is_set() noexcept {
#ifdef WEBCPP_CRYPTO_DETAIL_TIMING_COVERED
    if (!cpu_has_dit()) {
        return false;
    }
    std::uint64_t state = 0;
    __asm__ volatile("mrs %0, s3_3_c4_c2_5" : "=r"(state) : : "memory");
    return (state & dit_bit) != 0;
#else
    return false;
#endif
}

/**
 * Sets DIT for its scope where the CPU has it, and leaves the thread's DIT as it found it.
 *
 * Construction finds DIT clear, sets it and remembers to clear it; the destructor clears it then
 * only. A guard that finds DIT set does nothing and leaves it set: the program set it itself (as
 * Apple's `timingsafe_enable_if_supported` does), or an outer guard did, so that guards nest and
 * a thread whose program asked for DIT keeps it after every call. DIT is a thread's own state,
 * so a guard never changes another thread's.
 */
class timing_guard {
public:
    /** Sets DIT where the CPU has it and it is clear. */
    timing_guard() noexcept {
        WEBCPP_CRYPTO_DETAIL_TIMING_ENTERED();
#ifdef WEBCPP_CRYPTO_DETAIL_TIMING_COVERED
        if (cpu_has_dit() && !dit_is_set()) {
            write_dit(dit_bit);
            armed_ = true;
        }
#endif
    }

    /** Clears DIT when this guard set it. */
    ~timing_guard() {
#ifdef WEBCPP_CRYPTO_DETAIL_TIMING_COVERED
        if (armed_) {
            write_dit(0);
        }
#endif
    }

    /** Not copyable: the state it restores is the scope's. */
    timing_guard(timing_guard const&) = delete;

    /** Not assignable. */
    timing_guard& operator=(timing_guard const&) = delete;

    /** Not movable: the state it restores is the scope's. */
    timing_guard(timing_guard&&) = delete;

    /** Not move-assignable. */
    timing_guard& operator=(timing_guard&&) = delete;

private:
#ifdef WEBCPP_CRYPTO_DETAIL_TIMING_COVERED
    /** Whether this guard set DIT, and so clears it. */
    bool armed_ = false;
#endif
};

}  // namespace webcpp::crypto::detail

#endif  // WEBCPP_CRYPTO_DETAIL_TIMING_HPP
