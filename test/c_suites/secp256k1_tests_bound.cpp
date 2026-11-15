// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// libsecp256k1's tests are upstream C, which cannot call webcpp::test::bound: this unit,
// linked into them under node alone, re-arms the support's bound at static initialisation.

#include <webcpp/test/exit_status.hpp>

#include <chrono>

namespace {

// One run of the 16 iterations took 477 s under node (2026-11-14, a loaded machine), above the
// support's 120 s: 30 minutes, half the own-lanes job's 60, leaves it room on a slower runner.
// A static initialiser run for its effect, which nothing reads; bound throws nothing (an EM_ASM
// call, or nothing natively).
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables,cert-err58-cpp,bugprone-throwing-static-initialization)
[[maybe_unused]] bool const bounded = (webcpp::test::bound(std::chrono::minutes(30)), true);

}  // namespace
