/*
 * Copyright (c) 2026, Zhengchao Ding <dingzhengchao@outlook.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <AK/ByteBuffer.h>
#include <AK/Noncopyable.h>
#include <LibCrypto/OpenSSL.h>

namespace Crypto::PK {

// GM/T 0003-2012 (SM2 elliptic-curve public-key algorithm), backed by OpenSSL's
// SM2 provider. Signatures use SM3 as the digest, matching the SM2 specification.
//
// Public keys are exchanged as the uncompressed EC point encoding (0x04 || X || Y),
// private keys as the 32-byte big-endian scalar.
class SM2 {
    AK_MAKE_NONCOPYABLE(SM2);
    AK_MAKE_DEFAULT_MOVABLE(SM2);

public:
    // Generate a fresh SM2 key pair.
    static ErrorOr<SM2> generate_key_pair();

    // Import a key pair from the private scalar and matching uncompressed public point.
    static ErrorOr<SM2> from_private_key(ReadonlyBytes private_scalar, ReadonlyBytes public_point);

    // Import a public-only key from the uncompressed public point. Suitable for verify/encrypt.
    static ErrorOr<SM2> from_public_key(ReadonlyBytes public_point);

    // The uncompressed public point (0x04 || X || Y).
    ErrorOr<ByteBuffer> public_key_bytes() const;

    // SM2 digital signature over `message` (DER-encoded r,s), digesting with SM3.
    ErrorOr<ByteBuffer> sign(ReadonlyBytes message) const;
    ErrorOr<bool> verify(ReadonlyBytes message, ReadonlyBytes signature) const;

    // SM2 public-key encryption / decryption (C1C3C2 as produced by OpenSSL).
    ErrorOr<ByteBuffer> encrypt(ReadonlyBytes plaintext) const;
    ErrorOr<ByteBuffer> decrypt(ReadonlyBytes ciphertext) const;

private:
    explicit SM2(OpenSSL_PKEY key)
        : m_key(move(key))
    {
    }

    OpenSSL_PKEY m_key;
};

}
