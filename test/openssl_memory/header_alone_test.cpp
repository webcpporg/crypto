// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// The backend OpenSSL's header alone with the memory option: the option's branch compiles
// with nothing before it (webcpp.headers-alone takes a header once, and the header's call
// in test/Jamfile is for the build without the option).

#include <webcpp/crypto/backends/openssl.hpp>
