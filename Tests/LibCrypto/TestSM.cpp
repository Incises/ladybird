/*
 * Copyright (c) 2026, Zhengchao Ding <dingzhengchao@outlook.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <LibCrypto/Cipher/SM4.h>
#include <LibCrypto/Hash/SM3.h>
#include <LibCrypto/PK/SM2.h>
#include <LibTest/TestCase.h>
#include <cstring>

static ReadonlyBytes operator""_b(char const* string, size_t length)
{
    return ReadonlyBytes(string, length);
}

// GB/T 32905-2016, appendix A.1: SM3("abc").
TEST_CASE(test_SM3_abc)
{
    u8 expected[] {
        0x66, 0xc7, 0xf0, 0xf4, 0x62, 0xee, 0xed, 0xd9, 0xd1, 0xf2, 0xd4, 0x6b, 0xdc, 0x10, 0xe4, 0xe2,
        0x41, 0x67, 0xc4, 0x87, 0x5c, 0xf2, 0xf7, 0xa2, 0x29, 0x7d, 0xa0, 0x2b, 0x8f, 0x4b, 0xa8, 0xe0
    };
    auto digest = Crypto::Hash::SM3::hash("abc"sv);
    EXPECT_EQ(Crypto::Hash::SM3::digest_size(), sizeof(expected));
    EXPECT(memcmp(expected, digest.data, sizeof(expected)) == 0);
}

TEST_CASE(test_SM3_name_and_incremental)
{
    auto sm3 = Crypto::Hash::SM3::create();
    EXPECT_EQ(sm3->class_name(), "SM3"sv);
    sm3->update("a"sv);
    sm3->update("b"sv);
    sm3->update("c"sv);
    auto incremental = sm3->digest();
    auto oneshot = Crypto::Hash::SM3::hash("abc"sv);
    EXPECT(memcmp(incremental.data, oneshot.data, Crypto::Hash::SM3::digest_size()) == 0);
}

// GB/T 32907-2016, appendix: single-block SM4 in ECB with the standard key/plaintext.
TEST_CASE(test_SM4_ecb_known_vector)
{
    u8 key[] { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10 };
    u8 plaintext[] { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10 };
    u8 expected[] { 0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e, 0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e, 0x42, 0x46 };

    Crypto::Cipher::SM4ECBCipher cipher(ReadonlyBytes { key, sizeof(key) }, /* no_padding */ true);
    auto out = TRY_OR_FAIL(cipher.encrypt(ReadonlyBytes { plaintext, sizeof(plaintext) }));
    EXPECT_EQ(out.size(), sizeof(expected));
    EXPECT(memcmp(out.data(), expected, out.size()) == 0);

    auto back = TRY_OR_FAIL(cipher.decrypt(out));
    EXPECT_EQ(back.size(), sizeof(plaintext));
    EXPECT(memcmp(back.data(), plaintext, back.size()) == 0);
}

TEST_CASE(test_SM4_cbc_round_trip)
{
    u8 key[] { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10 };
    u8 iv[16] { 0 };
    Crypto::Cipher::SM4CBCCipher cipher(ReadonlyBytes { key, sizeof(key) });

    auto plaintext = "The quick brown fox jumps over the lazy dog"_b;
    auto ct = TRY_OR_FAIL(cipher.encrypt(plaintext, ReadonlyBytes { iv, sizeof(iv) }));
    auto pt = TRY_OR_FAIL(cipher.decrypt(ct, ReadonlyBytes { iv, sizeof(iv) }));
    EXPECT_EQ(pt.size(), plaintext.size());
    EXPECT(memcmp(pt.data(), plaintext.data(), pt.size()) == 0);
}

TEST_CASE(test_SM4_ctr_round_trip)
{
    u8 key[] { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10 };
    u8 iv[16] { 0 };
    Crypto::Cipher::SM4CTRCipher cipher(ReadonlyBytes { key, sizeof(key) });

    auto plaintext = "counter-mode does not need block-aligned input"_b;
    auto ct = TRY_OR_FAIL(cipher.encrypt(plaintext, ReadonlyBytes { iv, sizeof(iv) }));
    EXPECT_EQ(ct.size(), plaintext.size());
    auto pt = TRY_OR_FAIL(cipher.decrypt(ct, ReadonlyBytes { iv, sizeof(iv) }));
    EXPECT(memcmp(pt.data(), plaintext.data(), pt.size()) == 0);
}

TEST_CASE(test_SM2_sign_and_verify)
{
    auto key = TRY_OR_FAIL(Crypto::PK::SM2::generate_key_pair());

    auto message = "message to be signed with SM2"_b;
    auto signature = TRY_OR_FAIL(key.sign(message));

    EXPECT(TRY_OR_FAIL(key.verify(message, signature)));

    // A tampered message must not verify.
    auto tampered = "message to be signed with SM3"_b;
    EXPECT(!TRY_OR_FAIL(key.verify(tampered, signature)));
}

TEST_CASE(test_SM2_encrypt_and_decrypt)
{
    auto key = TRY_OR_FAIL(Crypto::PK::SM2::generate_key_pair());

    auto plaintext = "SM2 public-key encryption round trip"_b;
    auto ciphertext = TRY_OR_FAIL(key.encrypt(plaintext));
    auto decrypted = TRY_OR_FAIL(key.decrypt(ciphertext));

    EXPECT_EQ(decrypted.size(), plaintext.size());
    EXPECT(memcmp(decrypted.data(), plaintext.data(), decrypted.size()) == 0);
}

TEST_CASE(test_SM2_import_public_key_verifies_signature)
{
    auto signer = TRY_OR_FAIL(Crypto::PK::SM2::generate_key_pair());
    auto public_point = TRY_OR_FAIL(signer.public_key_bytes());

    auto message = "verify with an imported public-only key"_b;
    auto signature = TRY_OR_FAIL(signer.sign(message));

    auto verifier = TRY_OR_FAIL(Crypto::PK::SM2::from_public_key(public_point));
    EXPECT(TRY_OR_FAIL(verifier.verify(message, signature)));
}
