// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// Counts the C library's allocations and releases on macOS, from any caller, while the test
// says so (spec section 8.5): through malloc_logger, the hook libsystem_malloc calls on every
// allocation and release of the process, installed at static initialisation as
// test/support/counting.hpp installs it. Nothing here reads a thread_local: the first read of
// one on a thread allocates through dyld, inside the hook (counting.hpp's N1). The hook relies
// on the private malloc_logger symbol of libsystem_malloc and overwrites any hook already
// there (MallocStackLogging's, a sanitizer's).

#include <malloc/malloc.h>

#include <atomic>
#include <cstddef>
#include <cstdint>

// libsystem_malloc's hook, called on every allocation and release of the process.
using webcpp_test_malloc_logger = void(std::uint32_t, std::uintptr_t, std::uintptr_t,
                                       std::uintptr_t, std::uintptr_t, std::uint32_t);
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables): libsystem_malloc's hook
extern "C" webcpp_test_malloc_logger* malloc_logger;

namespace {
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables): the interposer's count
std::atomic<std::size_t> counted{0};
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables): the interposer's switch
std::atomic<bool> counting{false};

void count_c_call(std::uint32_t type, std::uintptr_t /*zone*/, std::uintptr_t /*first*/,
                  std::uintptr_t /*second*/, std::uintptr_t /*result*/, std::uint32_t /*skip*/) {
    constexpr std::uint32_t allocate = 2;    // MALLOC_LOG_TYPE_ALLOCATE
    constexpr std::uint32_t deallocate = 4;  // MALLOC_LOG_TYPE_DEALLOCATE
    if ((type & (allocate | deallocate)) != 0 && counting.load(std::memory_order_relaxed)) {
        counted.fetch_add(1, std::memory_order_relaxed);
    }
}

// Installs the hook at static initialisation, before main.
[[maybe_unused]] bool const installed = (malloc_logger = &count_c_call, true);
}  // namespace

extern "C" {
std::size_t webcpp_test_c_allocations(void) {
    return counted.load();
}

void webcpp_test_count_c_allocations(int on) {
    counting.store(on != 0);
}
}
