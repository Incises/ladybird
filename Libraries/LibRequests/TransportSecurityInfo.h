/*
 * Copyright (c) 2026, GM-Lab contributors.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <AK/ByteString.h>
#include <LibIPC/Forward.h>

namespace Requests {

struct TransportSecurityInfo {
    ByteString endpoint;
    bool tlcp_required { false };
    bool is_tlcp { false };
    // Empty until an authenticated connection is available. Never inferred from configuration.
    ByteString protocol;
    ByteString cipher;
    i64 certificate_verify_result { -1 };
    i32 curl_result { 0 };
};

}

namespace IPC {

template<>
ErrorOr<void> encode(Encoder&, Requests::TransportSecurityInfo const&);
template<>
ErrorOr<Requests::TransportSecurityInfo> decode(Decoder&);

}
