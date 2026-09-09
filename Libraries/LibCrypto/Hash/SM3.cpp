/*
 * Copyright (c) 2026, Zhengchao Ding <dingzhengchao@outlook.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <LibCrypto/Hash/SM3.h>

#include <openssl/evp.h>

namespace Crypto::Hash {

SM3::SM3(EVP_MD_CTX* context)
    : OpenSSLHashFunction(EVP_sm3(), context)
{
}

}
