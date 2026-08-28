/* rng_bank.h
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
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

/*!
    \file wolfssl/wolfcrypt/rng_bank.h
*/

/* This facility allocates and manages a bank of persistent RNGs with thread
 * safety and provisions for automatic affinity.  It is typically used in kernel
 * applications.
 */

#ifndef WOLF_CRYPT_RNG_BANK_H
#define WOLF_CRYPT_RNG_BANK_H

#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/random.h>

#ifdef WC_RNG_BANK_SUPPORT

#ifdef WC_NO_RNG
    #error WC_RNG_BANK_SUPPORT requires RNG support.
#endif

#define WC_RNG_BANK_FLAG_NONE                     0
#define WC_RNG_BANK_FLAG_INITED               (1<<0)
#define WC_RNG_BANK_FLAG_CAN_FAIL_OVER_INST   (1<<1)
#define WC_RNG_BANK_FLAG_CAN_WAIT             (1<<2)
#define WC_RNG_BANK_FLAG_NO_VECTOR_OPS        (1<<3)
#define WC_RNG_BANK_FLAG_PREFER_AFFINITY_INST (1<<4)
#define WC_RNG_BANK_FLAG_AFFINITY_LOCK        (1<<5)
/* WC_RNG_BANK_FLAG_SEED_UNCREDITED applies only to wc_rng_bank_seed(): the
 * supplied seed material is mixed into each instance without entropy credit
 * (wc_RNG_DRBG_Reseed_Uncredited()), leaving the reseed schedule governed
 * solely by the module's own seed source. */
#define WC_RNG_BANK_FLAG_SEED_UNCREDITED      (1<<6)
/* WC_RNG_BANK_FLAG_CONSUME_NEXT_SEED applies only to wc_rng_bank_checkout():
 * if the checked-out instance has a ready banked next seed (see
 * wc_RNG_DRBG_NextSeedGenerate() et al.), consume it in an immediate,
 * source-free credited reseed before returning the instance; a no-op when
 * no bank is ready or the build/instance has no next-seed support.  Safe in
 * atomic context. */
#define WC_RNG_BANK_FLAG_CONSUME_NEXT_SEED    (1<<7)
/* WC_RNG_BANK_FLAG_FOR_RECOVERY declares a recovery-intent checkout of a
 * specific instance (e.g. by a reseed-and-recovery daemon's patrol):
 * out-of-service status is expected and accepted, and the
 * WC_RNG_BANK_FLAG_CONSUME_NEXT_SEED arm is suppressed (a consume would
 * fail on exactly the instances recovery targets).  Requires an explicit
 * instance: rejected in combination with _CAN_FAIL_OVER_INST or
 * _PREFER_AFFINITY_INST, and by the seed/reseed walkers.  Note that a
 * targeted (non-failover) checkout admits out-of-service instances with or
 * without this flag; the flag makes the intent explicit and
 * interaction-safe. */
#define WC_RNG_BANK_FLAG_FOR_RECOVERY         (1<<8)
/* WC_RNG_BANK_FLAG_ERROR_ON_RNG_FAILED guarantees that
 * wc_rng_bank_checkout() (and APIs built on it, e.g. wc_rng_bank_spawn())
 * either returns a lease on an in-service instance (status WC_DRBG_OK) or
 * returns an error with NO lease held -- never a lease on an out-of-service
 * instance.  This closes the two paths that can otherwise lease one: a
 * targeted (non-failover) checkout, and a failover checkout after a full
 * unsuccessful lap (the anti-livelock disarm).  Under _CAN_WAIT, an
 * out-of-service instance is retried within the timeout budget (allowing a
 * recovery patrol to restore it) before the error is returned; the
 * distinguished error for a lap or wait that found only out-of-service
 * instances is BAD_STATE_E.  Contradicts, and is rejected with,
 * _FOR_RECOVERY.  Applies to instance status only; reseed-due diversion
 * semantics are unchanged. */
#define WC_RNG_BANK_FLAG_ERROR_ON_RNG_FAILED  (1<<9)
/* WC_RNG_BANK_FLAG_QUIET suppresses the facility's WC_VERBOSE_RNG
 * operational warnings -- expected-condition notices such as the
 * reseed-due-instance handout, reinit retry/timeout reports, the
 * all-instances-busy notice, and the seed-walker's out-of-service reports
 * -- so that deliberate exercising (e.g. unit tests) doesn't spam the
 * log.  A bank-level flag only, set at wc_rng_bank_init(); it has no
 * per-call meaning and never suppresses refcount/consistency
 * diagnostics. */
#define WC_RNG_BANK_FLAG_QUIET                (1<<10)
/* WC_RNG_BANK_FLAG_NO_CHECKOUT_REFCOUNTING (bank-level, set at
 * wc_rng_bank_init()) declares that the bank's lifetime is guaranteed by
 * its container to enclose all checkouts (e.g. a bank embedded in a
 * kernel crypto tfm context, torn down only after the API has quiesced
 * callers).  Per-checkout refcount traffic -- the one bank-global RMW
 * pair on the readout hot path -- is suppressed; refcount checks degrade
 * to read-only validity tests.  The refcount itself remains, serving its
 * standing roles: the INITED baseline, default-bank registration
 * (wc_rng_bank_default_set()), and per-bankref lifetime references.
 * Contract: with this flag, a wc_rng_bank_fini() racing live checkouts is
 * a use-after-free instead of BUSY_E -- only containers whose teardown
 * provably quiesces consumers first may set it. */
#define WC_RNG_BANK_FLAG_NO_CHECKOUT_REFCOUNTING (1<<11)

/* base lock states are WC_RNG_LOCK_FREE / WC_RNG_LOCK_HELD in random.h;
 * these annotation bits ride above WC_RNG_LOCK_HELD via
 * wc_RNG_lock_get()/_set_extra()/_clear_extra(). */

#ifndef WC_RNG_HAVE_LOCK
    #define WC_RNG_LOCK_FREE 0
    #define WC_RNG_LOCK_HELD (1U<<0)
    #define WC_RNG_LOCK_REQUIRED (1U<<1)
    #define WC_RNG_LOCK_EXTRA_SHIFT 2U
    #ifdef WOLFSSL_NO_ATOMICS
        typedef word32 WC_RNG_lock_t;
        typedef word32 WC_RNG_lock_arg_t;
    #else
        typedef wolfSSL_Atomic_Uint WC_RNG_lock_t;
        typedef WC_ATOMIC_UINT_ARG WC_RNG_lock_arg_t;
    #endif
#endif

#define WC_RNG_BANK_INST_LOCK_AFFINITY_LOCKED (1U<<(WC_RNG_LOCK_EXTRA_SHIFT+0))
#define WC_RNG_BANK_INST_LOCK_VEC_OPS_INH     (1U<<(WC_RNG_LOCK_EXTRA_SHIFT+1))

typedef int (*wc_affinity_lock_fn_t)(void *arg);
typedef int (*wc_affinity_get_id_fn_t)(void *arg, int *id);
typedef int (*wc_affinity_unlock_fn_t)(void *arg);

struct wc_rng_bank;

#define WC_RNG_BANK_INST_FLAG_NONE 0
#define WC_RNG_BANK_INST_FLAG_ALREADY_WARNED (1U << 0)

struct wc_rng_bank_inst {
    #ifdef WC_RNG_HAVE_LOCK
        /* the exclusivity latch lives in rng.lock (wc_RNG_lock_*()) --
         * in-FIPS-boundary, module-enforced.  This struct persists for the
         * parent pointer and future bank-side slots. */
    #else
        #ifdef WOLFSSL_NO_ATOMICS
            word32 lock;
        #else
            wolfSSL_Atomic_Uint lock;
        #endif
    #endif
    struct wc_rng_bank *bank;
    WC_RNG rng;
    volatile word32 flags;
};

#if defined(WOLFSSL_NO_MALLOC) && defined(NO_WOLFSSL_MEMORY) && \
    !defined(WC_RNG_BANK_STATIC)
    #define WC_RNG_BANK_STATIC
#endif

#ifndef WC_RNG_BANK_STATIC_SIZE
    #define WC_RNG_BANK_STATIC_SIZE 4
#endif

struct wc_rng_bank {
    wolfSSL_Ref refcount;
    void *heap;
    word32 flags;
    wc_affinity_lock_fn_t affinity_lock_cb;
    wc_affinity_get_id_fn_t affinity_get_id_cb;
    wc_affinity_unlock_fn_t affinity_unlock_cb;
    void *cb_arg; /* if mutable, caller is responsible for thread safety. */
    int n_rngs;
    int first_failover_inst;
#ifdef WC_RNG_HAVE_NEXT_SEED
    /* Serializes whole-instance operations (wc_rng_bank_inst_reinit()'s
     * free/reinstantiate cycle) against the entropy daemon's lockless
     * banking calls (wc_rng_bank_next_seed_generate()).  0 = free,
     * WC_RNG_BANK_INST_OP_DAEMON = daemon banking in progress,
     * WC_RNG_BANK_INST_OP_REINIT = reinit in progress.  Lease-holders
     * never consult it: instance-lock exclusion already covers every
     * lease-holder <-> reinit and lease-holder <-> consume interaction. */
    wolfSSL_Atomic_Int inst_op_gate;
#endif
#ifdef WC_RNG_BANK_STATIC
    struct wc_rng_bank_inst rngs[WC_RNG_BANK_STATIC_SIZE];
#else
    struct wc_rng_bank_inst *rngs; /* typically one per CPU ID, plus a few */
#endif
};

#ifndef WC_RNG_BANK_STATIC
WOLFSSL_API int wc_rng_bank_new(
    struct wc_rng_bank **ctx,
    int n_rngs,
    word32 flags,
    int timeout_secs,
    void *heap,
    int devId);
#endif

WOLFSSL_API int wc_rng_bank_init(
    struct wc_rng_bank *ctx,
    int n_rngs,
    word32 flags,
    int timeout_secs,
    void *heap,
    int devId);

WOLFSSL_API int wc_rng_bank_first_failover_inst_set(
    struct wc_rng_bank *ctx,
    int first_failover_inst);

WOLFSSL_API int wc_rng_bank_set_affinity_handlers(
    struct wc_rng_bank *ctx,
    wc_affinity_lock_fn_t affinity_lock_cb,
    wc_affinity_get_id_fn_t affinity_get_id_cb,
    wc_affinity_unlock_fn_t affinity_unlock_cb,
    void *cb_arg);

WOLFSSL_API int wc_rng_bank_fini(struct wc_rng_bank *ctx);

#ifndef WC_RNG_BANK_STATIC
WOLFSSL_API int wc_rng_bank_free(struct wc_rng_bank **ctx);
#endif

#ifdef WC_RNG_BANK_NO_DEFAULT_SUPPORT
#undef WC_RNG_BANK_DEFAULT_SUPPORT
#else /* !WC_RNG_BANK_NO_DEFAULT_SUPPORT */
#ifndef WC_RNG_BANK_DEFAULT_SUPPORT
#define WC_RNG_BANK_DEFAULT_SUPPORT
#endif
WOLFSSL_API int wc_rng_bank_default_set(struct wc_rng_bank *bank);
WOLFSSL_API int wc_rng_bank_default_checkout(struct wc_rng_bank **bank);
WOLFSSL_API int wc_rng_bank_default_checkin(struct wc_rng_bank **bank);
WOLFSSL_API int wc_rng_bank_default_clear(struct wc_rng_bank *bank);
#endif /* !WC_RNG_BANK_NO_DEFAULT_SUPPORT */

WOLFSSL_API int wc_rng_bank_checkout(
    struct wc_rng_bank *bank,
    struct wc_rng_bank_inst **rng_inst,
    int preferred_inst_offset,
    int timeout_secs,
    word32 flags);

#if defined(WC_DRBG_BANKREF) && !defined(WC_HAVE_RNG_BANKREF)
    /* forward compat for FIPS v5.2.4 random.h */
    #define WC_HAVE_RNG_BANKREF
#endif

#ifdef WC_HAVE_RNG_BANKREF
WOLFSSL_LOCAL int wc_local_rng_bank_checkout_for_bankref(
    struct wc_rng_bank *bank,
    struct wc_rng_bank_inst **rng_inst);
#endif

WOLFSSL_API int wc_rng_bank_get_inst_id(struct wc_rng_bank_inst *rng_inst);

static WC_INLINE int WC_ARG_NOT_NULL(1) wc_rng_bank_inst_flags_up(
    struct wc_rng_bank_inst *rng_inst, word32 flags)
{
    if (! (rng_inst->flags & flags)) {
        rng_inst->flags = rng_inst->flags | flags;
        return 1;
    }
    else
        return 0;
}

static WC_INLINE int WC_ARG_NOT_NULL(1) wc_rng_bank_inst_flags_down(
    struct wc_rng_bank_inst *rng_inst, word32 flags)
{
    if (rng_inst->flags & flags) {
        rng_inst->flags = rng_inst->flags & ~flags;
        return 1;
    }
    else
        return 0;
}

WOLFSSL_API int wc_rng_bank_checkin(
    struct wc_rng_bank *bank,
    struct wc_rng_bank_inst **rng_inst);

WOLFSSL_API int wc_rng_bank_inst_checkin(
    struct wc_rng_bank_inst **rng_inst);

#ifdef WC_RNG_HAVE_NEXT_SEED
/* Daemon entry point for banking next-seed material: resolves the instance
 * at inst_offset and calls wc_RNG_DRBG_NextSeedGenerate(rng, n) under the
 * bank's whole-instance-operation gate, so a concurrent
 * wc_rng_bank_inst_reinit() can never free the DRBG out from under the
 * gather.  Returns BUSY_E (skip this turn) when the gate is held by a
 * reinit; ALREADY_E when the instance's bank is already complete (sleep
 * until consumed); MISSING_RNG_E when the instance has no DRBG (RDRAND
 * et al.) and can be retired from the banking rotation permanently.
 * Other errors are transient gather/health-test failures: skip the turn
 * and alarm if persistent.  The caller must hold a bank reference (e.g.
 * per the daemon association) for the duration of the call.
 */
WOLFSSL_API int wc_rng_bank_next_seed_generate(
    struct wc_rng_bank *bank,
    int inst_offset,
    word32 n);
#endif

WOLFSSL_API int wc_rng_bank_inst_reinit(
    struct wc_rng_bank *bank,
    struct wc_rng_bank_inst *rng_inst,
    int timeout_secs,
    word32 flags);

/* Patrol helper: check out the instance at inst_offset with
 * WC_RNG_BANK_FLAG_FOR_RECOVERY, reinitialize it iff it is out of service,
 * and check it back in.  A healthy instance is a success no-op, so callers
 * can invoke this unconditionally on a status observed locklessly (a stale
 * observation costs one harmless round trip).  Returns BUSY_E when the
 * instance lock or the whole-instance-operation gate is contended -- retry
 * on a later patrol turn.  flags may include WC_RNG_BANK_FLAG_CAN_WAIT and
 * WC_RNG_BANK_FLAG_AFFINITY_LOCK, which are passed through; bank must be
 * non-NULL. */
WOLFSSL_API int wc_rng_bank_recover_inst(
    struct wc_rng_bank *bank,
    int inst_offset,
    int timeout_secs,
    word32 flags);

#ifdef WC_RNG_HAVE_RBGC

/* Spawn an SP 800-90C chain leaf from a bank instance: check out an
 * instance (honoring the usual selection flags), wc_InitRngNonceRBGC() /
 * wc_InitRngNonceRBGC_New() the leaf from it, and check the instance back
 * in.  The leaf's lifetime is thereafter decoupled from the bank: it is
 * lock-free for its owner and is released with wc_FreeRng() (stack form)
 * or wc_rng_free() (heap form).  nonce/nonceSz may be NULL/0 for a plain
 * spawn; per the bank's distinctness convention, passing the address of
 * the leaf's owning object or request is recommended.  bank == NULL uses
 * the default bank where support is compiled in.
 * WC_RNG_BANK_FLAG_CONSUME_NEXT_SEED composes (banked reseed before the
 * spawn draw); WC_RNG_BANK_FLAG_SEED_UNCREDITED and
 * WC_RNG_BANK_FLAG_FOR_RECOVERY are rejected.
 * WC_RNG_BANK_FLAG_ERROR_ON_RNG_FAILED is implied: the root is guaranteed
 * in-service, or an error is returned with no lease and no leaf. */
WOLFSSL_API int wc_rng_bank_spawn(
    struct wc_rng_bank *bank,
    WC_RNG *leaf_rng,
    byte *nonce,
    word32 nonceSz,
    int preferred_inst_offset,
    int timeout_secs,
    word32 flags);

#ifndef WC_NO_CONSTRUCTORS
WOLFSSL_API int wc_rng_bank_spawn_new(
    struct wc_rng_bank *bank,
    WC_RNG **leaf_rng,
    byte *nonce,
    word32 nonceSz,
    int preferred_inst_offset,
    int timeout_secs,
    word32 flags);
#endif /* !WC_NO_CONSTRUCTORS */

#endif /* WC_RNG_HAVE_RBGC */

WOLFSSL_API int wc_rng_bank_seed(struct wc_rng_bank *bank,
                                 const byte* seed, word32 seedSz,
                                 int timeout_secs,
                                 word32 flags);

WOLFSSL_API int wc_rng_bank_seed_range(struct wc_rng_bank *bank,
                                       int first_inst, int last_inst,
                                       const byte* seed, word32 seedSz,
                                       int timeout_secs,
                                       word32 flags);

WOLFSSL_API int wc_rng_bank_reseed(struct wc_rng_bank *bank,
                                   int timeout_secs,
                                   word32 flags);

WOLFSSL_API int wc_rng_bank_reseed_range(struct wc_rng_bank *bank,
                                         int first_inst, int last_inst,
                                         int timeout_secs,
                                         word32 flags);

#ifdef WC_HAVE_RNG_BANKREF
WOLFSSL_API int wc_InitRng_BankRef(struct wc_rng_bank *bank, WC_RNG *rng);

WOLFSSL_API int wc_BankRef_Release(WC_RNG *rng);

#if !defined(WC_RNG_BANK_STATIC) && !defined(WC_NO_CONSTRUCTORS)
WOLFSSL_API int wc_rng_new_bankref(struct wc_rng_bank *bank, WC_RNG **rng);
/* note, free with wc_rng_free(). */
#endif
#endif /* WC_HAVE_RNG_BANKREF */

#define WC_RNG_BANK_INST_TO_RNG(rng_inst) (&(rng_inst)->rng)

#ifdef WC_RNG_HAVE_LOCK

    static WC_INLINE int wc_rng_bank_inst_lock_get(struct wc_rng_bank_inst *inst, WC_RNG_lock_arg_t extra_bits) {
        return wc_RNG_lock_get(WC_RNG_BANK_INST_TO_RNG(inst), extra_bits);
    }
    static WC_INLINE int wc_rng_bank_inst_lock_put(struct wc_rng_bank_inst *inst) {
        return wc_RNG_lock_put(WC_RNG_BANK_INST_TO_RNG(inst), 0);
    }
    static WC_INLINE int wc_rng_bank_inst_lock_put_conditional(struct wc_rng_bank_inst *inst, WC_RNG_lock_arg_t expect_extra_bits) {
        return wc_RNG_lock_put_conditional(WC_RNG_BANK_INST_TO_RNG(inst), expect_extra_bits, 0);
    }
    static WC_INLINE int wc_rng_bank_inst_lock_read(struct wc_rng_bank_inst *inst, WC_RNG_lock_arg_t *state) {
        return wc_RNG_lock_read(WC_RNG_BANK_INST_TO_RNG(inst), state);
    }
    static WC_INLINE int wc_rng_bank_inst_lock_set_extra(struct wc_rng_bank_inst *inst, WC_RNG_lock_arg_t extra_bits) {
        return wc_RNG_lock_set_extra(WC_RNG_BANK_INST_TO_RNG(inst), extra_bits);
    }
    static WC_INLINE int wc_rng_bank_inst_lock_add_extra(struct wc_rng_bank_inst *inst, WC_RNG_lock_arg_t extra_bits) {
        return wc_RNG_lock_add_extra(WC_RNG_BANK_INST_TO_RNG(inst), extra_bits);
    }
    static WC_INLINE int wc_rng_bank_inst_lock_clear_extra(struct wc_rng_bank_inst *inst, WC_RNG_lock_arg_t extra_bits) {
        return wc_RNG_lock_clear_extra(WC_RNG_BANK_INST_TO_RNG(inst), extra_bits);
    }


#else /* !WC_RNG_HAVE_LOCK */

/* Backward compat */

static WC_INLINE int wc_rng_bank_inst_lock_get(struct wc_rng_bank_inst *inst, WC_RNG_lock_arg_t extra_bits)
{
    WC_RNG_lock_arg_t expected;

    if (inst == NULL)
        return BAD_FUNC_ARG;
    expected = WOLFSSL_ATOMIC_LOAD(inst->lock) & WC_RNG_LOCK_REQUIRED;
    if (wolfSSL_Atomic_Uint_CompareExchange(
            &inst->lock, &expected,
            WC_RNG_LOCK_HELD | extra_bits | expected))
    {
        return 0;
    }
    return BUSY_E;
}

static WC_INLINE int wc_rng_bank_inst_lock_put(struct wc_rng_bank_inst *inst)
{
    WC_RNG_lock_arg_t cur_lock;
    if (inst == NULL)
        return BAD_FUNC_ARG;
    cur_lock = WOLFSSL_ATOMIC_LOAD(inst->lock);
    if (! (cur_lock & WC_RNG_LOCK_HELD))
        return BAD_STATE_E;
    /* unconditional release, preserving only the sticky bit */
    WOLFSSL_ATOMIC_STORE(inst->lock, cur_lock & WC_RNG_LOCK_REQUIRED);
    return 0;
}

static WC_INLINE WC_MAYBE_UNUSED int wc_rng_bank_inst_lock_put_conditional(struct wc_rng_bank_inst *inst, WC_RNG_lock_arg_t extra_bits)
{
    WC_RNG_lock_arg_t expected;

    if (inst == NULL)
        return BAD_FUNC_ARG;
    expected = WC_RNG_LOCK_HELD | extra_bits;
    /* release preserves the sticky bit if the caller reports it held */
    if (wolfSSL_Atomic_Uint_CompareExchange(
            &inst->lock, &expected,
            extra_bits & WC_RNG_LOCK_REQUIRED))
    {
        return 0;
    }
    /* conditional release failed: the caller is still the holder, at both
     * layers -- the mutex stays held. */
    return BAD_STATE_E;
}

static WC_INLINE int wc_rng_bank_inst_lock_read(struct wc_rng_bank_inst *inst, WC_RNG_lock_arg_t* state)
{
    if ((inst == NULL) || (state == NULL))
        return BAD_FUNC_ARG;
    *state = WOLFSSL_ATOMIC_LOAD(inst->lock);
    return 0;
}

static WC_INLINE int wc_rng_bank_inst_lock_set_extra(struct wc_rng_bank_inst *inst, WC_RNG_lock_arg_t extra_bits)
{
    WC_RNG_lock_arg_t cur_lock;
    if (inst == NULL)
        return BAD_FUNC_ARG;
    cur_lock = WOLFSSL_ATOMIC_LOAD(inst->lock);
    if ((cur_lock & WC_RNG_LOCK_REQUIRED) &&
        (! (cur_lock & WC_RNG_LOCK_HELD)))
    {
        return OBJECT_NOT_LOCKED_E;
    }
    cur_lock |= (extra_bits & WC_RNG_LOCK_REQUIRED);
    /* replace the extra field: keep the core (HELD/REQUIRED) bits of the
     * latch, take only the extra-field bits of the argument. */
    cur_lock &= (1U << WC_RNG_LOCK_EXTRA_SHIFT) - 1U;
    extra_bits &= ~((1U << WC_RNG_LOCK_EXTRA_SHIFT) - 1U);
    /* owner-only by contract; a plain release store suffices because the
     * holder is the sole writer while HELD */
    WOLFSSL_ATOMIC_STORE(inst->lock, cur_lock | extra_bits);
    return 0;
}

static WC_INLINE WC_MAYBE_UNUSED int wc_rng_bank_inst_lock_add_extra(struct wc_rng_bank_inst *inst, WC_RNG_lock_arg_t extra_bits)
{
    WC_RNG_lock_arg_t cur_lock;
    if (inst == NULL)
        return BAD_FUNC_ARG;
    cur_lock = WOLFSSL_ATOMIC_LOAD(inst->lock);
    if ((cur_lock & WC_RNG_LOCK_REQUIRED) &&
        (! (cur_lock & WC_RNG_LOCK_HELD)))
    {
        return OBJECT_NOT_LOCKED_E;
    }
    cur_lock |= (extra_bits & WC_RNG_LOCK_REQUIRED);
    /* additive: keep the whole latch, OR in only the extra-field bits of
     * the argument. */
    extra_bits &= ~((1U << WC_RNG_LOCK_EXTRA_SHIFT) - 1U);
    /* owner-only by contract; a plain release store suffices because the
     * holder is the sole writer while HELD */
    WOLFSSL_ATOMIC_STORE(inst->lock, cur_lock | extra_bits);
    return 0;
}

static WC_INLINE WC_MAYBE_UNUSED int wc_rng_bank_inst_lock_clear_extra(struct wc_rng_bank_inst *inst, WC_RNG_lock_arg_t extra_bits)
{
    WC_RNG_lock_arg_t cur_lock;
    if (inst == NULL)
        return BAD_FUNC_ARG;
    if (extra_bits & WC_RNG_LOCK_REQUIRED) {
        /* WC_RNG_LOCK_REQUIRED is sticky by contract */
        return BAD_FUNC_ARG;
    }
    cur_lock = WOLFSSL_ATOMIC_LOAD(inst->lock);
    if ((cur_lock & WC_RNG_LOCK_REQUIRED) &&
        (! (cur_lock & WC_RNG_LOCK_HELD)))
    {
        return OBJECT_NOT_LOCKED_E;
    }

    cur_lock &= ~extra_bits;
    WOLFSSL_ATOMIC_STORE(inst->lock, cur_lock);
    return 0;
}

#endif /* !WC_RNG_HAVE_LOCK */

#endif /* WC_RNG_BANK_SUPPORT */

#endif /* WOLF_CRYPT_RNG_BANK_H */
