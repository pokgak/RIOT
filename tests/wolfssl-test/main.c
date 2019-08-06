/*
 * Copyright (C) 2019 Kaleb J. Himes
 *
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */


/**
 * @ingroup     examples
 * @{
 *
 * @file
 * @brief       wolfSSL cryptographic library test
 *
 * @author      Kaleb J. Himes <kaleb@wolfssl.com>
 *
 * @}
 */

#include <stdio.h>

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfcrypt/test/test.h>
#ifdef MODULE_WOLFCRYPT_BENCHMARK
#include <wolfcrypt/benchmark/benchmark.h>
#endif

int main(void)
{
    puts("wolfSSL Crypto Test!");
    wolfcrypt_test(NULL);
#ifdef MODULE_WOLFCRYPT_BENCHMARK
    puts("wolfSSL Benchmark!");
    benchmark_test(NULL);
#endif
    return 0;
}
