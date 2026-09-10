/*
 * Copyright (c) 2026, GM-Lab contributors.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <LibRequests/TLCPPolicy.h>
#include <LibTest/TestCase.h>
#include <LibURL/Parser.h>
#include <RequestServer/RequestClientEndpoint.h>

static URL::URL url(StringView value)
{
    return URL::Parser::basic_parse(value).release_value();
}

TEST_CASE(default_is_tls)
{
    Requests::TLCPPolicy policy;
    EXPECT(!policy.requires_tlcp(url("https://gm-lab.test/"sv)));
}

TEST_CASE(exact_endpoint_and_default_port)
{
    Requests::TLCPPolicy policy;
    MUST(policy.add_endpoint("GM-LAB.test"sv));
    MUST(policy.add_endpoint("gm-lab.test:8443"sv));
    EXPECT(policy.requires_tlcp(url("https://gm-lab.test/"sv)));
    EXPECT(policy.requires_tlcp(url("https://gm-lab.test:443/"sv)));
    EXPECT(policy.requires_tlcp(url("wss://gm-lab.test:8443/socket"sv)));
    EXPECT(!policy.requires_tlcp(url("https://gm-lab.test:8446/"sv)));
    EXPECT(!policy.requires_tlcp(url("https://sub.gm-lab.test/"sv)));
    EXPECT(!policy.requires_tlcp(url("https://gm-lab.test.evil/"sv)));
    EXPECT(!policy.requires_tlcp(url("http://gm-lab.test:443/"sv)));
    EXPECT(!policy.requires_tlcp(url("ws://gm-lab.test:8443/"sv)));
}

TEST_CASE(ip_literals_are_normalized_but_dns_is_not_followed)
{
    Requests::TLCPPolicy policy;
    MUST(policy.add_endpoint("[0:0:0:0:0:0:0:1]:8443"sv));
    MUST(policy.add_endpoint("127.0.0.1"sv));
    EXPECT(policy.requires_tlcp(url("https://[::1]:8443/"sv)));
    EXPECT(policy.requires_tlcp(url("https://127.0.0.1/"sv)));
    EXPECT(!policy.requires_tlcp(url("https://localhost/"sv)));
}

TEST_CASE(reject_ambiguous_or_malformed_endpoints)
{
    for (auto endpoint : { ""sv, "https://gm-lab.test"sv, "user@gm-lab.test"sv, "*.test"sv, "gm-lab.test/"sv, "gm-lab.test?x"sv, "gm-lab.test#x"sv, "gm-lab.test:"sv, "gm-lab.test:0"sv, "gm-lab.test:65536"sv, "gm-lab.test:no"sv, " gm-lab.test"sv, "gm-lab.test\n"sv, "%67m-lab.test"sv, "::1"sv }) {
        Requests::TLCPPolicy policy;
        EXPECT(policy.add_endpoint(endpoint).is_error());
        EXPECT(!policy.requires_tlcp(url("https://gm-lab.test/"sv)));
    }
}

TEST_CASE(redirect_target_has_its_own_policy)
{
    Requests::TLCPPolicy policy;
    MUST(policy.add_endpoint("gm-lab.test:8443"sv));
    EXPECT(policy.requires_tlcp(url("https://gm-lab.test:8443/start"sv)));
    EXPECT(!policy.requires_tlcp(url("https://gm-lab.test:8446/destination"sv)));
}

TEST_CASE(transport_evidence_survives_ipc)
{
    Requests::TransportSecurityInfo info {
        .endpoint = "gm-lab.test:8443",
        .tlcp_required = true,
        .is_tlcp = true,
        .protocol = "NTLSv1.1",
        .cipher = "ECC-SM2-SM4-GCM-SM3",
        .certificate_verify_result = 0,
        .curl_result = 0,
    };
    auto buffer = MUST(Messages::RequestClient::TransportSecurityInfo::static_encode(42, "websocket"sv, info));
    Queue<IPC::Attachment> attachments;
    auto message = MUST(RequestClientEndpoint::decode_message(buffer.data().span(), attachments));
    EXPECT_EQ(message->message_id(), Messages::RequestClient::TransportSecurityInfo::static_message_id());
    auto const& decoded = static_cast<Messages::RequestClient::TransportSecurityInfo const&>(*message);
    EXPECT_EQ(decoded.connection_id(), 42u);
    EXPECT_EQ(decoded.kind(), "websocket"sv);
    EXPECT_EQ(decoded.info().endpoint, info.endpoint);
    EXPECT(decoded.info().tlcp_required);
    EXPECT(decoded.info().is_tlcp);
    EXPECT_EQ(decoded.info().protocol, info.protocol);
    EXPECT_EQ(decoded.info().cipher, info.cipher);
    EXPECT_EQ(decoded.info().certificate_verify_result, 0);
}
