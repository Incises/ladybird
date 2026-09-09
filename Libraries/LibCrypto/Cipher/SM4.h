/*
 * Copyright (c) 2026, Zhengchao Ding <dingzhengchao@outlook.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <AK/ByteBuffer.h>
#include <LibCrypto/OpenSSLForward.h>

namespace Crypto::Cipher {

// GB/T 32907-2016 (SM4 block cipher). Fixed 128-bit key and 128-bit block.
class SM4Cipher {
public:
    size_t block_size() const;

protected:
    explicit SM4Cipher(EVP_CIPHER const* cipher, ReadonlyBytes key)
        : m_cipher(cipher)
        , m_key(key)
    {
    }

    EVP_CIPHER const* m_cipher;
    ReadonlyBytes m_key;
};

class SM4CBCCipher final : public SM4Cipher {
public:
    explicit SM4CBCCipher(ReadonlyBytes key, bool no_padding = false);

    ErrorOr<ByteBuffer> encrypt(ReadonlyBytes plaintext, ReadonlyBytes iv) const;
    ErrorOr<ByteBuffer> decrypt(ReadonlyBytes ciphertext, ReadonlyBytes iv) const;

private:
    bool m_no_padding { false };
};

class SM4ECBCipher final : public SM4Cipher {
public:
    explicit SM4ECBCipher(ReadonlyBytes key, bool no_padding = false);

    ErrorOr<ByteBuffer> encrypt(ReadonlyBytes plaintext) const;
    ErrorOr<ByteBuffer> decrypt(ReadonlyBytes ciphertext) const;

private:
    bool m_no_padding { false };
};

class SM4CTRCipher final : public SM4Cipher {
public:
    explicit SM4CTRCipher(ReadonlyBytes key);

    ErrorOr<ByteBuffer> encrypt(ReadonlyBytes plaintext, ReadonlyBytes iv) const;
    ErrorOr<ByteBuffer> decrypt(ReadonlyBytes ciphertext, ReadonlyBytes iv) const;
};

}
