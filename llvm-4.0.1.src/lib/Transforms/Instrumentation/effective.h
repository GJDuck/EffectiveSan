/*
 *        __  __           _   _           ____
 *   ___ / _|/ _| ___  ___| |_(_)_   _____/ ___|  __ _ _ __
 *  / _ \ |_| |_ / _ \/ __| __| \ \ / / _ \___ \ / _` | '_ \
 * |  __/  _|  _|  __/ (__| |_| |\ V /  __/___) | (_| | | | |
 *  \___|_| |_|  \___|\___|\__|_| \_/ \___|____/ \__,_|_| |_|
 *
 * Gregory J. Duck.
 *
 * Copyright (c) 2018 The National University of Singapore.
 * All rights reserved.
 *
 * This file is distributed under the University of Illinois Open Source
 * License. See the LICENSE file for details.
 */

#ifndef __EFFECTIVE_H
#define __EFFECTIVE_H

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#define EFFECTIVE_DELTA             (16 * ((int64_t)1 << 30))   // 16GB
#define EFFECTIVE_RADIX             63
#define EFFECTIVE_MAX_PROBE         8

#define EFFECTIVE_HOT               __attribute__((__hot__))
#define EFFECTIVE_PURE              __attribute__((__pure__))
#define EFFECTIVE_CONST             __attribute__((__const__))
#define EFFECTIVE_CONSTRUCTOR(N)    __attribute__((__constructor__(N)))
#define EFFECTIVE_DESTRUCTOR(N)     __attribute__((__destructor__(N)))
#define EFFECTIVE_VECTOR_SIZE(N)    __attribute__((__vector_size__(N)))
#define EFFECTIVE_PACKED            __attribute__((__packed__))
#define EFFECTIVE_ALIGNED(N)        __attribute__((__aligned__(N)))
#define EFFECTIVE_ALIAS(N)          __attribute__((__alias__(N)))
#define EFFECTIVE_NOINLINE          __attribute__((__noinline__))
#define EFFECTIVE_ALWAYS_INLINE     __attribute__((__always_inline__))
#define EFFECTIVE_NORETURN          __attribute__((__noreturn__))

#define EFFECTIVE_LIKELY(x)         __builtin_expect((x), 1)
#define EFFECTIVE_UNLIKELY(x)       __builtin_expect((x), 0)

#define EFFECTIVE_HASH(h1, h2, offset)                                      \
    ((uint64_t)__builtin_ia32_crc32di((h2), (offset)) ^ ((h1) ^ (h2)))
#define EFFECTIVE_MAGIC(size)                                               \
    (((~(SIZE_MAX << EFFECTIVE_RADIX)) / (size)) + 1)

#define EFFECTIVE_SANITY            0x4FEBF99B      // Random

// #define EFFECTIVE_FLAG_DEBUG        1
// #define EFFECTIVE_FLAG_PROFILE      1
// #define EFFECTIVE_FLAG_COUNT        1
// #define EFFECTIVE_FLAG_FATAL        1
// #define EFFECTIVE_FLAG_SINGLE_THREADED   1
#ifdef EFFECTIVE_FLAG_SINGLE_THREADED
#define EFFECTIVE_COUNT(stat)       (stat)++
#else   /* EFFECTIVE_FLAG_SINGLE_THREADED */
#define EFFECTIVE_COUNT(stat)       __sync_fetch_and_add(&(stat), 1)
#endif  /* EFFECTIVE_FLAG_SINGLE_THREADED */

#ifdef EFFECTIVE_FLAG_PROFILE
#define EFFECTIVE_PROFILE_COUNT(stat)   EFFECTIVE_COUNT(stat)
#else   /* EFFECTIVE_FLAG_PROFILE */
#define EFFECTIVE_PROFILE_COUNT(stat)   /* NOP */
#endif  /* EFFECTIVE_FLAG_PROFILE */

#ifdef EFFECTIVE_FLAG_DEBUG
#define EFFECTIVE_DEBUG(msg, ...)                                           \
    fprintf(stderr, (msg), ##__VA_ARGS__)
#else   /* EFFECTIVE_FLAG_DEBUG */
#define EFFECTIVE_DEBUG(msg, ...)   /* NOP */
#endif  /* EFFECTIVE_FLAG_DEBUG */

/*
 * Pre-defined hash values.
 */
#define EFFECTIVE_TYPE_NIL_HASH         ((uint64_t)-1)
#define EFFECTIVE_TYPE_INT8_HASH        0x703EDF97BC60677Dull   // Random
#define EFFECTIVE_TYPE_INT8_PTR_HASH    0x8D0DECDF6C6A8711ull   // Random

#define EFFECTIVE_COERCED_INT32_HASH    0x51A0B9BF4F692902ull   // Random
#define EFFECTIVE_COERCED_INT8_PTR_HASH 0x2317E969C295951Dull   // Random

/*
 * Forward decls.
 */
typedef struct EFFECTIVE_TYPE EFFECTIVE_TYPE;

/*
 * Object bounds representation.
 * Essentially a vector 2 x intptr_t, where index 0 is the lower bounds, and
 * index 1 is the upper bound.
 */
typedef intptr_t EFFECTIVE_BOUNDS EFFECTIVE_VECTOR_SIZE(16);

/*
 * Type meta-data layout entry.
 */
struct EFFECTIVE_ENTRY
{
    uint64_t hash;              // Layout entry type.
    uint64_t _pad;              // Padding.
    EFFECTIVE_BOUNDS bounds;    // Sub-object bounds.
} EFFECTIVE_PACKED;
typedef struct EFFECTIVE_ENTRY EFFECTIVE_ENTRY;

#define EFFECTIVE_ENTRY_EMPTY_HASH  EFFECTIVE_TYPE_NIL_HASH

/*
 * Type meta-data representation.
 */
typedef struct EFFECTIVE_INFO EFFECTIVE_INFO;
struct EFFECTIVE_TYPE
{
    uint64_t hash;              // Type-specific hash value.
    uint64_t hash2;             // 2nd type-specific hash value.
    uint32_t size;              // sizeof(T)
    uint32_t size_fam;          // sizeof any FAM, else sizeof(T)
    uint32_t offset_fam;        // offset of 1st FAM element, else 0
    uint32_t sanity;            // EFFECTIVE_SANITY.
    size_t magic;               // Fixed-point (1 / size_fam) representation
    size_t mask;                // Mask for layout[]
    const EFFECTIVE_INFO *info; // Type info
    uint64_t next;              // Hash of next type coercion
    EFFECTIVE_ENTRY layout[];   // The layout hash table.
};

/*
 * Per-allocated-object meta-data representation.
 */
struct EFFECTIVE_META
{
    const EFFECTIVE_TYPE *type; // Object's effective type sans bounds.
    size_t size;                // Object's allocation size.
};
typedef struct EFFECTIVE_META EFFECTIVE_META;

/*
 * Type info entry.
 */
struct EFFECTIVE_INFO_ENTRY
{
    const EFFECTIVE_INFO *type;
    uint32_t flags;
    size_t lb;
    size_t ub;
};
typedef struct EFFECTIVE_INFO_ENTRY EFFECTIVE_INFO_ENTRY;

#define EFFECTIVE_INFO_ENTRY_FLAG_INHERITANCE   0x1
#define EFFECTIVE_INFO_ENTRY_FLAG_VIRTUAL       0x2

/*
 * Type info (for human readable type information).
 */
struct EFFECTIVE_INFO
{
    const char *name;
    uint32_t size;
    uint32_t num_entries;
    uint32_t flags;
    const EFFECTIVE_INFO *next;
    EFFECTIVE_INFO_ENTRY entries[];
};

#define EFFECTIVE_INFO_FLAG_UNION               0x1
#define EFFECTIVE_INFO_FLAG_FLEXIBLE_LEN        0x2
#define EFFECTIVE_INFO_FLAG_INCOMPLETE          0x4

/*
 * Pre-defined types.
 */
extern const struct EFFECTIVE_TYPE EFFECTIVE_TYPE_FREE;
extern const struct EFFECTIVE_TYPE EFFECTIVE_TYPE_INT8;

/*
 * Pre-defined bounds.
 */
extern const EFFECTIVE_BOUNDS EFFECTIVE_BOUNDS_NEG_DELTA_DELTA;
extern const EFFECTIVE_BOUNDS EFFECTIVE_BOUNDS_NEG_1_0;

/*
 * Stats.
 */
extern size_t effective_num_nonfat_type_checks;
extern size_t effective_num_char_type_checks;
extern size_t effective_num_fast_type_checks;
extern size_t effective_num_slow_type_checks;
extern size_t effective_num_bounds_checks;
extern size_t effective_num_type_errors;
extern size_t effective_num_bounds_errors;
extern size_t effective_num_double_free_errors;
extern size_t effective_num_bad_free_errors;

/*
 * Type checking.
 */
extern EFFECTIVE_BOUNDS effective_type_check(const void *ptr,
    const EFFECTIVE_TYPE *u);
extern EFFECTIVE_BOUNDS effective_get_bounds(const void *ptr);
extern void effective_bounds_check(EFFECTIVE_BOUNDS bounds, const void *ptr,
    intptr_t lb, intptr_t ub);

/*
 * Error tracking.
 */
extern void effective_type_error(const EFFECTIVE_TYPE *expected,
    const EFFECTIVE_TYPE *actual, const void *ptr, size_t offset,
    const void *location);
extern void effective_bounds_error(EFFECTIVE_BOUNDS bounds, const void *ptr,
    size_t size);
extern void effective_double_free_error(const void *ptr,
    const void *location);
extern void effective_bad_free_error(const void *ptr, const void *location);
extern size_t effective_get_num_type_errors(void);
extern size_t effective_get_num_bounds_errors(void);

/*
 * Memory allocation.
 */
extern EFFECTIVE_BOUNDS effective_malloc(size_t size, const EFFECTIVE_TYPE *t);
extern EFFECTIVE_BOUNDS effective__Znwm(size_t size, const EFFECTIVE_TYPE *t);
extern EFFECTIVE_BOUNDS effective__Znam(size_t size, const EFFECTIVE_TYPE *t);
extern EFFECTIVE_BOUNDS effective__ZnwmRKSt9nothrow_t(size_t size,
    const EFFECTIVE_TYPE *t);
extern EFFECTIVE_BOUNDS effective__ZnamRKSt9nothrow_t(size_t size,
    const EFFECTIVE_TYPE *t);
extern EFFECTIVE_BOUNDS effective_calloc(size_t nmemb, size_t size,
    const EFFECTIVE_TYPE *t);
extern EFFECTIVE_BOUNDS effective_realloc(void *ptr, size_t new_size);
extern void effective_free(void *ptr);
extern void effective__ZdlPv(void *ptr);
extern void effective__ZdaPv(void *ptr);

/*
 * Debugging.
 */
extern void effective_dump(const void *ptr);

#endif      /* __EFFECTIVE_H */
