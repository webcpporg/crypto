// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// erase_secret writes the buffer it erases: a program that hands it a const string stops at the
// call, with a message that names the ranges it takes, and with that error alone.

// clang's -verify reads a directive from one comment line: wrapped, it checks nothing, so each
// whole text stays on one line.
// clang-format off
// expected-error@webcpp/crypto/erase_secret.hpp:* {{webcpp::crypto: erase_secret zeroes a buffer the program may write, of trivially copyable elements: a std::vector<std::uint8_t>, a std::string, a std::array, a std::span<std::byte>; this range's elements are const or not trivially copyable.}}
// clang-format on

#include <webcpp/crypto/erase_secret.hpp>

#include <string>

namespace {

void forget(std::string const& password) {
    webcpp::crypto::erase_secret(password);
}

}  // namespace

int main() {
    forget("correct horse battery staple");
    return 0;
}
