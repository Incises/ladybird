/*
 * Copyright (c) 2026, Zhengchao Ding <dingzhengchao@outlook.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <AK/ByteString.h>
#include <LibCrypto/Hash/OpenSSLHashFunction.h>

namespace Crypto::Hash {

// GB/T 32905-2016 (SM3 cryptographic hash algorithm): 512-bit block, 256-bit digest.
class SM3 final : public OpenSSLHashFunction<SM3, 512, 256> {
    AK_MAKE_NONCOPYABLE(SM3);

public:
    explicit SM3(EVP_MD_CTX* context);

    virtual ByteString class_name() const override
    {
        return "SM3";
    }
};

}
