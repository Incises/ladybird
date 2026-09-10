/*
 * Copyright (c) 2026, GM-Lab contributors.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <LibIPC/Decoder.h>
#include <LibIPC/Encoder.h>
#include <LibRequests/TransportSecurityInfo.h>

namespace IPC {

template<>
ErrorOr<void> encode(Encoder& encoder, Requests::TransportSecurityInfo const& info)
{
    TRY(encoder.encode(info.endpoint));
    TRY(encoder.encode(info.tlcp_required));
    TRY(encoder.encode(info.is_tlcp));
    TRY(encoder.encode(info.protocol));
    TRY(encoder.encode(info.cipher));
    TRY(encoder.encode(info.certificate_verify_result));
    TRY(encoder.encode(info.curl_result));
    return {};
}

template<>
ErrorOr<Requests::TransportSecurityInfo> decode(Decoder& decoder)
{
    Requests::TransportSecurityInfo info;
    info.endpoint = TRY(decoder.decode<ByteString>());
    info.tlcp_required = TRY(decoder.decode<bool>());
    info.is_tlcp = TRY(decoder.decode<bool>());
    info.protocol = TRY(decoder.decode<ByteString>());
    info.cipher = TRY(decoder.decode<ByteString>());
    info.certificate_verify_result = TRY(decoder.decode<i64>());
    info.curl_result = TRY(decoder.decode<i32>());
    return info;
}

}
