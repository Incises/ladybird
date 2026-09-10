/*
 * Copyright (c) 2026, GM-Lab contributors.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <AK/Vector.h>
#include <LibURL/URL.h>

namespace Requests {

// Immutable for the lifetime of a RequestServer process.
class TLCPPolicy {
public:
    ErrorOr<void> add_endpoint(StringView);
    bool requires_tlcp(URL::URL const&) const;

private:
    Vector<URL::URL> m_endpoints;
};

}
