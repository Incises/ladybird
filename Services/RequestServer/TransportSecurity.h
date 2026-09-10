/*
 * Copyright (c) 2026, GM-Lab contributors.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <LibRequests/TLCPPolicy.h>
#include <LibRequests/TransportSecurityInfo.h>

namespace RequestServer {

Requests::TLCPPolicy& tlcp_policy();
void set_log_transport_security(bool);
void log_transport_security(u64 id, StringView kind, Requests::TransportSecurityInfo const&);

// Captures the live SSL object before HTTP is sent, including reused connections.
class TransportSecurity {
public:
    ErrorOr<void> configure(void* handle, URL::URL const&);
    Requests::TransportSecurityInfo finish(int result);
    bool is_secure() const { return m_is_secure; }

private:
    static int before_request(void*, char*, char*, int, int);
    bool capture_and_validate();

    void* m_handle { nullptr };
    bool m_is_secure { false };
    bool m_policy_rejected { false };
    Requests::TransportSecurityInfo m_info;
};

}
