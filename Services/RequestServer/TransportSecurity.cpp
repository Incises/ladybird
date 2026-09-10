/*
 * Copyright (c) 2026, GM-Lab contributors.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <RequestServer/CURL.h>
#include <RequestServer/Resolver.h>
#include <RequestServer/TransportSecurity.h>
#include <openssl/ssl.h>

namespace RequestServer {

static bool s_log_transport_security = false;

Requests::TLCPPolicy& tlcp_policy()
{
    static Requests::TLCPPolicy policy;
    return policy;
}

void set_log_transport_security(bool enabled)
{
    s_log_transport_security = enabled;
}

void log_transport_security(u64 id, StringView kind, Requests::TransportSecurityInfo const& info)
{
    if (s_log_transport_security || info.tlcp_required)
        dbgln("TransportSecurity: kind={} id={} endpoint={} selected={} is_ntls={} protocol={} cipher={} verify={} curl_result={}",
            kind, id, info.endpoint, info.tlcp_required ? "TLCP" : "TLS", info.is_tlcp,
            info.protocol.is_empty() ? "unavailable" : info.protocol.characters(),
            info.cipher.is_empty() ? "unavailable" : info.cipher.characters(), info.certificate_verify_result, info.curl_result);
}

ErrorOr<void> TransportSecurity::configure(void* handle, URL::URL const& url)
{
    m_handle = handle;
    m_policy_rejected = false;
    m_is_secure = url.scheme().is_one_of("https"sv, "wss"sv);
    m_info = {};
    if (!m_is_secure)
        return {};
    m_info.endpoint = ByteString::formatted("{}:{}", url.serialized_host(), url.port_or_default());
    m_info.tlcp_required = tlcp_policy().requires_tlcp(url);
    auto set_option = [&](auto option, auto value) -> ErrorOr<void> {
        auto result = curl_easy_setopt(handle, option, value);
        if (result != CURLE_OK)
            return Error::from_string_literal("Could not configure transport security");
        return {};
    };
    TRY(set_option(CURLOPT_SSLVERSION, m_info.tlcp_required ? CURL_SSLVERSION_NTLSv1_1 : CURL_SSLVERSION_DEFAULT));
    TRY(set_option(CURLOPT_SSL_VERIFYPEER, 1L));
    TRY(set_option(CURLOPT_SSL_VERIFYHOST, 2L));
    if (auto const& path = default_certificate_path(); !path.is_empty())
        TRY(set_option(CURLOPT_CAINFO, path.characters()));
    TRY(set_option(CURLOPT_PREREQFUNCTION, before_request));
    TRY(set_option(CURLOPT_PREREQDATA, this));
    return {};
}

bool TransportSecurity::capture_and_validate()
{
    curl_tlssessioninfo* session = nullptr;
    if (curl_easy_getinfo(m_handle, CURLINFO_TLS_SSL_PTR, &session) != CURLE_OK || !session || session->backend != CURLSSLBACKEND_OPENSSL || !session->internals)
        return !m_info.tlcp_required;
    auto* ssl = static_cast<SSL*>(session->internals);
    if (!SSL_is_init_finished(ssl))
        return !m_info.tlcp_required;
    m_info.is_tlcp = SSL_is_ntls(ssl);
    m_info.protocol = SSL_get_version(ssl);
    m_info.cipher = SSL_get_cipher_name(ssl);
    m_info.certificate_verify_result = SSL_get_verify_result(ssl);
    return m_info.is_tlcp == m_info.tlcp_required && m_info.certificate_verify_result == X509_V_OK;
}

int TransportSecurity::before_request(void* context, char*, char*, int, int)
{
    auto& security = *static_cast<TransportSecurity*>(context);
    security.m_policy_rejected = !security.capture_and_validate();
    return security.m_policy_rejected ? CURL_PREREQFUNC_ABORT : CURL_PREREQFUNC_OK;
}

Requests::TransportSecurityInfo TransportSecurity::finish(int result)
{
    if (m_policy_rejected)
        result = CURLE_PEER_FAILED_VERIFICATION;
    // CONNECT_ONLY may complete without invoking the pre-request callback.
    if (result == CURLE_OK && m_info.protocol.is_empty() && !capture_and_validate())
        result = CURLE_PEER_FAILED_VERIFICATION;
    if (result != CURLE_OK && m_info.protocol.is_empty()) {
        long verify_result = -1;
        if (curl_easy_getinfo(m_handle, CURLINFO_SSL_VERIFYRESULT, &verify_result) == CURLE_OK && verify_result != 0)
            m_info.certificate_verify_result = verify_result;
    }
    m_info.curl_result = result;
    return m_info;
}

}
