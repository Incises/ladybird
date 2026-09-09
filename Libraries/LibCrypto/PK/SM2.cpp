/*
 * Copyright (c) 2026, Zhengchao Ding <dingzhengchao@outlook.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <AK/ScopeGuard.h>
#include <LibCrypto/OpenSSL.h>
#include <LibCrypto/PK/SM2.h>

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>

namespace Crypto::PK {

static ErrorOr<OpenSSL_PKEY> build_sm2_key(ReadonlyBytes public_point, Optional<ReadonlyBytes> private_scalar)
{
    auto ctx = TRY(OpenSSL_PKEY_CTX::wrap(EVP_PKEY_CTX_new_from_name(nullptr, "SM2", nullptr)));

    OPENSSL_TRY(EVP_PKEY_fromdata_init(ctx.ptr()));

    auto* params_bld = OPENSSL_TRY_PTR(OSSL_PARAM_BLD_new());
    ScopeGuard const free_params_bld = [&] { OSSL_PARAM_BLD_free(params_bld); };

    OPENSSL_TRY(OSSL_PARAM_BLD_push_utf8_string(params_bld, OSSL_PKEY_PARAM_GROUP_NAME, "SM2", 0));
    OPENSSL_TRY(OSSL_PARAM_BLD_push_octet_string(params_bld, OSSL_PKEY_PARAM_PUB_KEY, public_point.data(), public_point.size()));

    int selection = EVP_PKEY_PUBLIC_KEY;

    Optional<OpenSSL_BN> d;
    if (private_scalar.has_value()) {
        d = TRY(unsigned_big_integer_to_openssl_bignum(UnsignedBigInteger::import_data(private_scalar.value())));
        OPENSSL_TRY(OSSL_PARAM_BLD_push_BN(params_bld, OSSL_PKEY_PARAM_PRIV_KEY, d->ptr()));
        selection = EVP_PKEY_KEYPAIR;
    }

    auto* params = OSSL_PARAM_BLD_to_param(params_bld);
    ScopeGuard const free_params = [&] { OSSL_PARAM_free(params); };

    EVP_PKEY* key_ptr = nullptr;
    OPENSSL_TRY(EVP_PKEY_fromdata(ctx.ptr(), &key_ptr, selection, params));

    return OpenSSL_PKEY::wrap(key_ptr);
}

ErrorOr<SM2> SM2::generate_key_pair()
{
    auto ctx = TRY(OpenSSL_PKEY_CTX::wrap(EVP_PKEY_CTX_new_from_name(nullptr, "SM2", nullptr)));

    OPENSSL_TRY(EVP_PKEY_keygen_init(ctx.ptr()));

    EVP_PKEY* key_ptr = nullptr;
    OPENSSL_TRY(EVP_PKEY_generate(ctx.ptr(), &key_ptr));

    return SM2(TRY(OpenSSL_PKEY::wrap(key_ptr)));
}

ErrorOr<SM2> SM2::from_private_key(ReadonlyBytes private_scalar, ReadonlyBytes public_point)
{
    return SM2(TRY(build_sm2_key(public_point, private_scalar)));
}

ErrorOr<SM2> SM2::from_public_key(ReadonlyBytes public_point)
{
    return SM2(TRY(build_sm2_key(public_point, {})));
}

ErrorOr<ByteBuffer> SM2::public_key_bytes() const
{
    return get_byte_buffer_param_from_key(const_cast<OpenSSL_PKEY&>(m_key), OSSL_PKEY_PARAM_PUB_KEY);
}

ErrorOr<ByteBuffer> SM2::sign(ReadonlyBytes message) const
{
    auto* key = const_cast<OpenSSL_PKEY&>(m_key).ptr();

    auto md_ctx = TRY(OpenSSL_MD_CTX::create());
    OPENSSL_TRY(EVP_DigestSignInit(md_ctx.ptr(), nullptr, EVP_sm3(), nullptr, key));

    size_t sig_len = 0;
    OPENSSL_TRY(EVP_DigestSign(md_ctx.ptr(), nullptr, &sig_len, message.data(), message.size()));

    auto sig = TRY(ByteBuffer::create_uninitialized(sig_len));
    OPENSSL_TRY(EVP_DigestSign(md_ctx.ptr(), sig.data(), &sig_len, message.data(), message.size()));

    return sig.slice(0, sig_len);
}

ErrorOr<bool> SM2::verify(ReadonlyBytes message, ReadonlyBytes signature) const
{
    auto* key = const_cast<OpenSSL_PKEY&>(m_key).ptr();

    auto md_ctx = TRY(OpenSSL_MD_CTX::create());
    OPENSSL_TRY(EVP_DigestVerifyInit(md_ctx.ptr(), nullptr, EVP_sm3(), nullptr, key));

    auto rc = EVP_DigestVerify(md_ctx.ptr(), signature.data(), signature.size(), message.data(), message.size());
    if (rc == 1)
        return true;
    if (rc == 0)
        return false;

    ERR_print_errors_cb(openssl_print_errors, nullptr);
    return Error::from_string_literal("EVP_DigestVerify failed");
}

ErrorOr<ByteBuffer> SM2::encrypt(ReadonlyBytes plaintext) const
{
    auto* key = const_cast<OpenSSL_PKEY&>(m_key).ptr();

    auto ctx = TRY(OpenSSL_PKEY_CTX::wrap(EVP_PKEY_CTX_new_from_pkey(nullptr, key, nullptr)));
    OPENSSL_TRY(EVP_PKEY_encrypt_init(ctx.ptr()));

    size_t out_size = 0;
    OPENSSL_TRY(EVP_PKEY_encrypt(ctx.ptr(), nullptr, &out_size, plaintext.data(), plaintext.size()));

    auto out = TRY(ByteBuffer::create_uninitialized(out_size));
    OPENSSL_TRY(EVP_PKEY_encrypt(ctx.ptr(), out.data(), &out_size, plaintext.data(), plaintext.size()));

    return out.slice(0, out_size);
}

ErrorOr<ByteBuffer> SM2::decrypt(ReadonlyBytes ciphertext) const
{
    auto* key = const_cast<OpenSSL_PKEY&>(m_key).ptr();

    auto ctx = TRY(OpenSSL_PKEY_CTX::wrap(EVP_PKEY_CTX_new_from_pkey(nullptr, key, nullptr)));
    OPENSSL_TRY(EVP_PKEY_decrypt_init(ctx.ptr()));

    size_t out_size = 0;
    OPENSSL_TRY(EVP_PKEY_decrypt(ctx.ptr(), nullptr, &out_size, ciphertext.data(), ciphertext.size()));

    auto out = TRY(ByteBuffer::create_uninitialized(out_size));
    OPENSSL_TRY(EVP_PKEY_decrypt(ctx.ptr(), out.data(), &out_size, ciphertext.data(), ciphertext.size()));

    return out.slice(0, out_size);
}

}
