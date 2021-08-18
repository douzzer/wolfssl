/* module_hooks.c -- module load/unload hooks for libwolfssl.ko
 *
 * Copyright (C) 2006-2021 wolfSSL Inc.
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

#define FIPS_NO_WRAPPERS

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/ssl.h>
#ifdef HAVE_FIPS
#include <wolfssl/wolfcrypt/fips_test.h>
#endif
#ifndef NO_CRYPT_TEST
#include <wolfcrypt/test/test.h>
#include <linux/delay.h>
#endif

static int libwolfssl_cleanup(void) {
    int ret;
#ifdef WOLFCRYPT_ONLY
    ret = wolfCrypt_Cleanup();
    if (ret != 0)
        pr_err("wolfCrypt_Cleanup() failed: %s", wc_GetErrorString(ret));
    else
        pr_info("wolfCrypt " LIBWOLFSSL_VERSION_STRING " cleanup complete.\n");
#else
    ret = wolfSSL_Cleanup();
    if (ret != WOLFSSL_SUCCESS)
        pr_err("wolfSSL_Cleanup() failed: %s", wc_GetErrorString(ret));
    else
        pr_info("wolfSSL " LIBWOLFSSL_VERSION_STRING " cleanup complete.\n");
#endif

    return ret;
}

#ifdef USE_WOLFSSL_LINUXKM_PIE_REDIRECT_TABLE
extern struct wolfssl_linuxkm_pie_redirect_table wolfssl_linuxkm_pie_redirect_table;
static int set_up_wolfssl_linuxkm_pie_redirect_table(void);
extern const unsigned int wolfCrypt_All_ro_end[];
#endif

#ifdef HAVE_FIPS
static void lkmFipsCb(int ok, int err, const char* hash)
{
    if ((! ok) || (err != 0))
        pr_err("libwolfssl FIPS error: %s\n", wc_GetErrorString(err));
    if (err == IN_CORE_FIPS_E) {
        pr_err("In-core integrity hash check failure.\n");
        pr_err("Update verifyCore[] in fips_test.c with new hash \"%s\" and rebuild.\n",
               hash ? hash : "<null>");
    }
}
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)
static int __init wolfssl_init(void)
#else
static int wolfssl_init(void)
#endif
{
    int ret;

#ifdef USE_WOLFSSL_LINUXKM_PIE_REDIRECT_TABLE
    ret = set_up_wolfssl_linuxkm_pie_redirect_table();
    if (ret < 0)
        return ret;
#endif

#ifdef HAVE_FIPS
    ret = wolfCrypt_SetCb_fips(lkmFipsCb);
    if (ret != 0) {
        pr_err("wolfCrypt_SetCb_fips() failed: %s", wc_GetErrorString(ret));
        return -ECANCELED;
    }
    fipsEntry();
    ret = wolfCrypt_GetStatus_fips();
    if (ret != 0) {
        pr_err("wolfCrypt_GetStatus_fips() failed: %s", wc_GetErrorString(ret));
        if (ret == IN_CORE_FIPS_E) {
            const char *newhash = wolfCrypt_GetCoreHash_fips();
            pr_err("Update verifyCore[] in fips_test.c with new hash \"%s\" and rebuild.\n",
                   newhash ? newhash : "<null>");
        }
        return -ECANCELED;
    }

    pr_info("wolfCrypt FIPS ["

#if defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION == 3)
            "ready"
#elif defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION == 2) \
    && defined(WOLFCRYPT_FIPS_RAND)
            "140-2 rand"
#elif defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION == 2)
            "140-2"
#else
            "140"
#endif
            "] POST succeeded.\n");
#endif /* HAVE_FIPS */

#ifdef WOLFCRYPT_ONLY
    ret = wolfCrypt_Init();
    if (ret != 0) {
        pr_err("wolfCrypt_Init() failed: %s", wc_GetErrorString(ret));
        return -ECANCELED;
    }
#else
    ret = wolfSSL_Init();
    if (ret != WOLFSSL_SUCCESS) {
        pr_err("wolfSSL_Init() failed: %s", wc_GetErrorString(ret));
        return -ECANCELED;
    }
#endif

#ifndef NO_CRYPT_TEST
    ret = wolfcrypt_test(NULL);
    if (ret < 0) {
        pr_err("wolfcrypt self-test failed with return code %d.", ret);
        (void)libwolfssl_cleanup();
        msleep(10);
        return -ECANCELED;
    }
    pr_info("wolfCrypt self-test passed.\n");
#endif

#ifdef WOLFCRYPT_ONLY
    pr_info("wolfCrypt " LIBWOLFSSL_VERSION_STRING " loaded. See https://www.wolfssl.com/ for information.\n");
#else
    pr_info("wolfSSL " LIBWOLFSSL_VERSION_STRING " loaded. See https://www.wolfssl.com/ for information.\n");
#endif

    pr_info("Copyright (C) 2006-2020 wolfSSL Inc. All Rights Reserved.\n");

    return 0;
}

module_init(wolfssl_init);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)
static void __exit wolfssl_exit(void)
#else
static void wolfssl_exit(void)
#endif
{
    (void)libwolfssl_cleanup();
    return;
}

module_exit(wolfssl_exit);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("https://www.wolfssl.com/");
MODULE_DESCRIPTION("libwolfssl cryptographic and protocol facilities");
MODULE_VERSION(LIBWOLFSSL_VERSION_STRING);

#ifdef USE_WOLFSSL_LINUXKM_PIE_REDIRECT_TABLE

static int set_up_wolfssl_linuxkm_pie_redirect_table(void) {
    memset(
        &wolfssl_linuxkm_pie_redirect_table,
        0,
        sizeof wolfssl_linuxkm_pie_redirect_table);

#ifndef __ARCH_MEMCMP_NO_REDIRECT
    wolfssl_linuxkm_pie_redirect_table.memcmp = memcmp;
#endif
#ifndef __ARCH_MEMCPY_NO_REDIRECT
    wolfssl_linuxkm_pie_redirect_table.memcpy = memcpy;
#endif
#ifndef __ARCH_MEMSET_NO_REDIRECT
    wolfssl_linuxkm_pie_redirect_table.memset = memset;
#endif
#ifndef __ARCH_MEMMOVE_NO_REDIRECT
    wolfssl_linuxkm_pie_redirect_table.memmove = memmove;
#endif
#ifndef __ARCH_STRNCMP_NO_REDIRECT
    wolfssl_linuxkm_pie_redirect_table.strncmp = strncmp;
#endif
#ifndef __ARCH_STRLEN_NO_REDIRECT
    wolfssl_linuxkm_pie_redirect_table.strlen = strlen;
#endif
#ifndef __ARCH_STRSTR_NO_REDIRECT
    wolfssl_linuxkm_pie_redirect_table.strstr = strstr;
#endif
#ifndef __ARCH_STRNCPY_NO_REDIRECT
    wolfssl_linuxkm_pie_redirect_table.strncpy = strncpy;
#endif
#ifndef __ARCH_STRNCAT_NO_REDIRECT
    wolfssl_linuxkm_pie_redirect_table.strncat = strncat;
#endif
#ifndef __ARCH_STRNCASECMP_NO_REDIRECT
    wolfssl_linuxkm_pie_redirect_table.strncasecmp = strncasecmp;
#endif
    wolfssl_linuxkm_pie_redirect_table.kstrtoll = kstrtoll;

    wolfssl_linuxkm_pie_redirect_table.printk = printk;
    wolfssl_linuxkm_pie_redirect_table.snprintf = snprintf;

    wolfssl_linuxkm_pie_redirect_table._ctype = _ctype;

    wolfssl_linuxkm_pie_redirect_table.kmalloc = kmalloc;
    wolfssl_linuxkm_pie_redirect_table.kfree = kfree;
    wolfssl_linuxkm_pie_redirect_table.ksize = ksize;
    wolfssl_linuxkm_pie_redirect_table.krealloc = krealloc;
#ifdef HAVE_KVMALLOC
    wolfssl_linuxkm_pie_redirect_table.kvmalloc_node = kvmalloc_node;
    wolfssl_linuxkm_pie_redirect_table.kvfree = kvfree;
#endif
    wolfssl_linuxkm_pie_redirect_table.is_vmalloc_addr = is_vmalloc_addr;
    wolfssl_linuxkm_pie_redirect_table.kmem_cache_alloc_trace =
        kmem_cache_alloc_trace;
    wolfssl_linuxkm_pie_redirect_table.kmalloc_order_trace =
        kmalloc_order_trace;

    wolfssl_linuxkm_pie_redirect_table.get_random_bytes = get_random_bytes;
    wolfssl_linuxkm_pie_redirect_table.ktime_get_real_seconds =
        ktime_get_real_seconds;
    wolfssl_linuxkm_pie_redirect_table.ktime_get_with_offset =
        ktime_get_with_offset;

#if defined(WOLFSSL_AESNI) || defined(USE_INTEL_SPEEDUP)
    #ifdef kernel_fpu_begin
    wolfssl_linuxkm_pie_redirect_table.kernel_fpu_begin_mask =
        kernel_fpu_begin_mask;
    #else
    wolfssl_linuxkm_pie_redirect_table.kernel_fpu_begin =
        kernel_fpu_begin;
    #endif
    wolfssl_linuxkm_pie_redirect_table.kernel_fpu_end = kernel_fpu_end;
#endif

    wolfssl_linuxkm_pie_redirect_table.__mutex_init = __mutex_init;
    wolfssl_linuxkm_pie_redirect_table.mutex_lock = mutex_lock;
    wolfssl_linuxkm_pie_redirect_table.mutex_unlock = mutex_unlock;

#ifdef HAVE_FIPS
    wolfssl_linuxkm_pie_redirect_table.wolfCrypt_FIPS_first =
        wolfCrypt_FIPS_first;
    wolfssl_linuxkm_pie_redirect_table.wolfCrypt_FIPS_last =
        wolfCrypt_FIPS_last;
#endif

#if !defined(WOLFCRYPT_ONLY) && !defined(NO_CERTS)
    wolfssl_linuxkm_pie_redirect_table.GetCA = GetCA;
    wolfssl_linuxkm_pie_redirect_table.GetCAByName = GetCAByName;
#endif

    /* runtime assert that the table has no null slots after initialization. */
    {
        unsigned long *i;
        for (i = (unsigned long *)&wolfssl_linuxkm_pie_redirect_table;
             i < (unsigned long *)&wolfssl_linuxkm_pie_redirect_table._last_slot;
             ++i)
            if (*i == 0) {
                pr_err("wolfCrypt container redirect table initialization was incomplete.\n");
                return -EFAULT;
            }
    }

    return 0;
}

#endif /* USE_WOLFSSL_LINUXKM_PIE_REDIRECT_TABLE */
