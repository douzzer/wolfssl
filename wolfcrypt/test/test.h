/* wolfcrypt/test/test.h
 *
 * Copyright (C) 2006-2023 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */


#ifndef WOLFCRYPT_TEST_H
#define WOLFCRYPT_TEST_H


#ifdef __cplusplus
    extern "C" {
#endif

#ifdef HAVE_STACK_SIZE
THREAD_RETURN WOLFSSL_THREAD wolfcrypt_test(void* args);
#else
int wolfcrypt_test(void* args);
#endif

#ifndef NO_MAIN_DRIVER
int wolfcrypt_test_main(int argc, char** argv);
#endif

#if defined(WOLFSSL_ESPIDF) || defined(_WIN32_WCE)
int wolf_test_task(void);
#endif

#ifndef WC_TEST_RET_ENC
#define WC_TEST_RET_ENC(line, i) \
        (-((line) + (((unsigned)(i) & 0x7ff) * 1000000)))
#endif

#ifndef WC_TEST_RET_LN
#define WC_TEST_RET_LN __LINE__
#endif

#ifndef WC_TEST_RET_ENC_I
/* encode positive integer */
#define WC_TEST_RET_ENC_I(i) WC_TEST_RET_ENC(WC_TEST_RET_LN, i)
#endif

#ifndef WC_TEST_RET_ENC_EC
/* encode error code (negative integer) */
#define WC_TEST_RET_ENC_EC(ec) WC_TEST_RET_ENC(WC_TEST_RET_LN, -(ec))
#endif

#ifndef WC_TEST_RET_ENC_NC
/* encode no code */
#define WC_TEST_RET_ENC_NC (-WC_TEST_RET_LN)
#endif

#ifndef WC_TEST_RET_ENC_ERRNO
/* encode system/libc error code */
#if defined(HAVE_ERRNO_H) && !defined(NO_FILESYSTEM) && !defined(NO_STDIO_FILESYSTEM) && !defined(WOLFSSL_USER_IO)
#include <errno.h>
#define WC_TEST_RET_ENC_ERRNO WC_TEST_RET_ENC_I(errno)
#else
#define WC_TEST_RET_ENC_ERRNO WC_TEST_RET_ENC_NC
#endif
#endif

#ifndef WC_TEST_RET_DEC_LN
/* decode line number */
#define WC_TEST_RET_DEC_LN(x) ((-(x)) % 1000000)
#endif

#ifndef WC_TEST_RET_DEC_I
/* decode integer or errno */
#define WC_TEST_RET_DEC_I(x) ((-(x)) / 1000000)
#endif

#ifndef WC_TEST_RET_DEC_EC
/* decode error code */
#define WC_TEST_RET_DEC_EC(x) (-WC_TEST_RET_DEC_I(x))
#endif

#ifdef __cplusplus
    }  /* extern "C" */
#endif


#endif /* WOLFCRYPT_TEST_H */

