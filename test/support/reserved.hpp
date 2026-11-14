// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

#ifndef WEBCPP_TEST_CRYPTO_SUPPORT_RESERVED_HPP
#define WEBCPP_TEST_CRYPTO_SUPPORT_RESERVED_HPP

#include <cstddef>
#include <cstdint>
#include <span>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#endif

namespace webcpp::test {

/**
 * Address space of `size` bytes that faults on any access, never released: a span a guard
 * must refuse by its size alone, since reading one byte of it ends the program. Natively on
 * 64-bit targets only.
 */
inline std::span<std::uint8_t> reserved(std::size_t size) {
#ifdef _WIN32
    void* const at = VirtualAlloc(nullptr, size, MEM_RESERVE, PAGE_NOACCESS);
#else
    void* at = mmap(nullptr, size, PROT_NONE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (at == MAP_FAILED) {
        at = nullptr;
    }
#endif
    return {static_cast<std::uint8_t*>(at), at != nullptr ? size : 0};
}

}  // namespace webcpp::test

#endif
