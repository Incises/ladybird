/*
 * Copyright (c) 2026, Zhengchao Ding <dingzhengchao@outlook.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <LibCrypto/Cipher/SM4.h>
#include <LibCrypto/OpenSSL.h>

#include <openssl/evp.h>

namespace Crypto::Cipher {

size_t SM4Cipher::block_size() const
{
    auto size = EVP_CIPHER_get_block_size(m_cipher);
    VERIFY(size != 0);
    return size;
}

SM4CBCCipher::SM4CBCCipher(ReadonlyBytes key, bool no_padding)
    : SM4Cipher(EVP_sm4_cbc(), key)
    , m_no_padding(no_padding)
{
}

ErrorOr<ByteBuffer> SM4CBCCipher::encrypt(ReadonlyBytes plaintext, ReadonlyBytes iv) const
{
    auto ctx = TRY(OpenSSL_CIPHER_CTX::create());

    OPENSSL_TRY(EVP_EncryptInit(ctx.ptr(), m_cipher, m_key.data(), iv.data()));
    OPENSSL_TRY(EVP_CIPHER_CTX_set_padding(ctx.ptr(), m_no_padding ? 0 : 1));

    auto out = TRY(ByteBuffer::create_uninitialized(plaintext.size() + block_size()));
    int out_size = 0;
    OPENSSL_TRY(EVP_EncryptUpdate(ctx.ptr(), out.data(), &out_size, plaintext.data(), plaintext.size()));

    int final_size = 0;
    OPENSSL_TRY(EVP_EncryptFinal(ctx.ptr(), out.data() + out_size, &final_size));

    return out.slice(0, out_size + final_size);
}

ErrorOr<ByteBuffer> SM4CBCCipher::decrypt(ReadonlyBytes ciphertext, ReadonlyBytes iv) const
{
    auto ctx = TRY(OpenSSL_CIPHER_CTX::create());

    OPENSSL_TRY(EVP_DecryptInit(ctx.ptr(), m_cipher, m_key.data(), iv.data()));
    OPENSSL_TRY(EVP_CIPHER_CTX_set_padding(ctx.ptr(), m_no_padding ? 0 : 1));

    auto out = TRY(ByteBuffer::create_uninitialized(ciphertext.size() + block_size()));
    int out_size = 0;
    OPENSSL_TRY(EVP_DecryptUpdate(ctx.ptr(), out.data(), &out_size, ciphertext.data(), ciphertext.size()));

    int final_size = 0;
    OPENSSL_TRY(EVP_DecryptFinal(ctx.ptr(), out.data() + out_size, &final_size));

    return out.slice(0, out_size + final_size);
}

SM4ECBCipher::SM4ECBCipher(ReadonlyBytes key, bool no_padding)
    : SM4Cipher(EVP_sm4_ecb(), key)
    , m_no_padding(no_padding)
{
}

ErrorOr<ByteBuffer> SM4ECBCipher::encrypt(ReadonlyBytes plaintext) const
{
    auto ctx = TRY(OpenSSL_CIPHER_CTX::create());

    OPENSSL_TRY(EVP_EncryptInit(ctx.ptr(), m_cipher, m_key.data(), nullptr));
    OPENSSL_TRY(EVP_CIPHER_CTX_set_padding(ctx.ptr(), m_no_padding ? 0 : 1));

    auto out = TRY(ByteBuffer::create_uninitialized(plaintext.size() + block_size()));
    int out_size = 0;
    OPENSSL_TRY(EVP_EncryptUpdate(ctx.ptr(), out.data(), &out_size, plaintext.data(), plaintext.size()));

    int final_size = 0;
    OPENSSL_TRY(EVP_EncryptFinal(ctx.ptr(), out.data() + out_size, &final_size));

    return out.slice(0, out_size + final_size);
}

ErrorOr<ByteBuffer> SM4ECBCipher::decrypt(ReadonlyBytes ciphertext) const
{
    auto ctx = TRY(OpenSSL_CIPHER_CTX::create());

    OPENSSL_TRY(EVP_DecryptInit(ctx.ptr(), m_cipher, m_key.data(), nullptr));
    OPENSSL_TRY(EVP_CIPHER_CTX_set_padding(ctx.ptr(), m_no_padding ? 0 : 1));

    auto out = TRY(ByteBuffer::create_uninitialized(ciphertext.size() + block_size()));
    int out_size = 0;
    OPENSSL_TRY(EVP_DecryptUpdate(ctx.ptr(), out.data(), &out_size, ciphertext.data(), ciphertext.size()));

    int final_size = 0;
    OPENSSL_TRY(EVP_DecryptFinal(ctx.ptr(), out.data() + out_size, &final_size));

    return out.slice(0, out_size + final_size);
}

SM4CTRCipher::SM4CTRCipher(ReadonlyBytes key)
    : SM4Cipher(EVP_sm4_ctr(), key)
{
}

ErrorOr<ByteBuffer> SM4CTRCipher::encrypt(ReadonlyBytes plaintext, ReadonlyBytes iv) const
{
    auto ctx = TRY(OpenSSL_CIPHER_CTX::create());

    OPENSSL_TRY(EVP_EncryptInit(ctx.ptr(), m_cipher, m_key.data(), iv.data()));

    auto out = TRY(ByteBuffer::create_uninitialized(plaintext.size() + block_size()));
    int out_size = 0;
    OPENSSL_TRY(EVP_EncryptUpdate(ctx.ptr(), out.data(), &out_size, plaintext.data(), plaintext.size()));

    int final_size = 0;
    OPENSSL_TRY(EVP_EncryptFinal(ctx.ptr(), out.data() + out_size, &final_size));

    return out.slice(0, out_size + final_size);
}

ErrorOr<ByteBuffer> SM4CTRCipher::decrypt(ReadonlyBytes ciphertext, ReadonlyBytes iv) const
{
    auto ctx = TRY(OpenSSL_CIPHER_CTX::create());

    OPENSSL_TRY(EVP_DecryptInit(ctx.ptr(), m_cipher, m_key.data(), iv.data()));

    auto out = TRY(ByteBuffer::create_uninitialized(ciphertext.size() + block_size()));
    int out_size = 0;
    OPENSSL_TRY(EVP_DecryptUpdate(ctx.ptr(), out.data(), &out_size, ciphertext.data(), ciphertext.size()));

    int final_size = 0;
    OPENSSL_TRY(EVP_DecryptFinal(ctx.ptr(), out.data() + out_size, &final_size));

    return out.slice(0, out_size + final_size);
}

}
