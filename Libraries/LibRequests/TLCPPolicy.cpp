/*
 * Copyright (c) 2026, GM-Lab contributors.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <LibRequests/TLCPPolicy.h>
#include <LibURL/Parser.h>

namespace Requests {

ErrorOr<void> TLCPPolicy::add_endpoint(StringView endpoint)
{
    // Accept an authority, not a URL. Reject URL parser repairs and credentials.
    for (auto ch : endpoint) {
        if (static_cast<u8>(ch) <= 0x20 || ch == 0x7f || ch == '/' || ch == '\\' || ch == '?' || ch == '#' || ch == '@' || ch == '%' || ch == '*')
            return Error::from_string_literal("Invalid TLCP endpoint: expected host[:port] or [IPv6][:port]");
    }
    if (endpoint.is_empty() || endpoint.ends_with(':'))
        return Error::from_string_literal("Invalid TLCP endpoint");
    auto url = URL::Parser::basic_parse(ByteString::formatted("https://{}/", endpoint));
    if (!url.has_value() || url->serialized_host().is_empty() || url->port_or_default() == 0)
        return Error::from_string_literal("Invalid TLCP endpoint");
    m_endpoints.append(url.release_value());
    return {};
}

bool TLCPPolicy::requires_tlcp(URL::URL const& url) const
{
    if (!url.scheme().is_one_of("https"sv, "wss"sv))
        return false;
    for (auto const& endpoint : m_endpoints) {
        if (endpoint.serialized_host() == url.serialized_host() && endpoint.port_or_default() == url.port_or_default())
            return true;
    }
    return false;
}

}
