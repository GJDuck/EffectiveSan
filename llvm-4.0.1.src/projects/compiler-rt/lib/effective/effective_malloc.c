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

/*
 * EffectiveSan "typed" memory allocation functions.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "lowfat.h"
#include "effective.h"

extern void *__libc_realloc(void *ptr, size_t size);
extern void __libc_free(void *ptr);

/*
 * Typed memory allocation.
 */
EFFECTIVE_BOUNDS effective_malloc(size_t size, const EFFECTIVE_TYPE *t)
{
    void *ptr = lowfat_malloc(sizeof(EFFECTIVE_META) + size);
    if (!lowfat_is_ptr(ptr))
    {
        // Failed to allocate object as a low-fat pointer.  Do not insert
        // object meta data.
        EFFECTIVE_BOUNDS bounds = {(intptr_t)ptr, (intptr_t)ptr + size};
        return bounds;
    }

    EFFECTIVE_META *meta = (EFFECTIVE_META *)ptr;
    meta->size = size;
    meta->type = t;

    ptr = (void *)(meta + 1);
    EFFECTIVE_BOUNDS bounds = {(intptr_t)ptr, (intptr_t)ptr + size};

#ifdef EFFECTIVE_FLAG_DEBUG
    fprintf(stderr, "effective_malloc(%zu, %s) = %p..%p\n", size, t->info->name,
        (void *)bounds[0], (void *)bounds[1]);
#endif

    return bounds;
}

EFFECTIVE_BOUNDS effective__Znwm(size_t size, const EFFECTIVE_TYPE *t)
    EFFECTIVE_ALIAS("effective_malloc");
EFFECTIVE_BOUNDS effective__Znam(size_t size, const EFFECTIVE_TYPE *t)
    EFFECTIVE_ALIAS("effective_malloc");
EFFECTIVE_BOUNDS effective__ZnwmRKSt9nothrow_t(size_t size,
    const EFFECTIVE_TYPE *t) EFFECTIVE_ALIAS("effective_malloc");
EFFECTIVE_BOUNDS effective__ZnamRKSt9nothrow_t(size_t size,
    const EFFECTIVE_TYPE *t) EFFECTIVE_ALIAS("effective_malloc");

EFFECTIVE_BOUNDS effective_calloc(size_t nmemb, size_t size,
    const EFFECTIVE_TYPE *t)
{
    EFFECTIVE_BOUNDS bounds = effective_malloc(nmemb * size, t);
    memset((void *)bounds[0], 0, bounds[1] - bounds[0]);
    return bounds;
}

/*
 * Typed memory reallocation.
 * - The type is preserved.
 * - We use a "naive" implementation of realloc() since it gives the best
 *   chance to catch reuse-after-realloc() errors.
 */
EFFECTIVE_BOUNDS effective_realloc(void *ptr, size_t new_size)
{
    if (!lowfat_is_ptr(ptr))
    {
        ptr = __libc_realloc(ptr, new_size);
        EFFECTIVE_BOUNDS new_bounds = {(intptr_t)ptr, (intptr_t)ptr + new_size};
        return new_bounds;
    }

    EFFECTIVE_META *meta = (EFFECTIVE_META *)lowfat_base(ptr);
    const EFFECTIVE_TYPE *t = meta->type;
    size_t old_size = meta->size;
    void *old_ptr = (void *)(meta + 1);

    EFFECTIVE_BOUNDS new_bounds = effective_malloc(new_size, t);
    void *new_ptr = (void *)new_bounds[0];
    new_size = (new_size > old_size? old_size: new_size);
    memcpy(new_ptr, old_ptr, new_size);
    effective_free(old_ptr);

    return new_bounds;
}

/*
 * Realloc wrapper for library call interception.
 */
void *realloc(void *ptr, size_t new_size)
{
    EFFECTIVE_BOUNDS new_bounds = effective_realloc(ptr, new_size);
    return (void *)new_bounds[0];
}

/*
 * Typed memory deallocation.
 */
void effective_free(void *ptr)
{
    if (!lowfat_is_ptr(ptr))
    {
        __libc_free(ptr);
        return;
    }
    if (!lowfat_is_heap_ptr(ptr))
    {
#ifndef EFFECTIVE_FLAG_COUNT
        effective_bad_free_error(ptr, __builtin_return_address(0));
#else
        EFFECTIVE_COUNT(effective_num_bad_free_errors);
#endif
        return;
    }

    ptr = lowfat_base(ptr);
    EFFECTIVE_META *meta = (EFFECTIVE_META *)ptr;
    if (meta->type == NULL)
    {
#ifndef EFFECTIVE_FLAG_COUNT
        effective_double_free_error(ptr, __builtin_return_address(0));
#else
        EFFECTIVE_COUNT(effective_num_double_free_errors);
#endif
        return;
    }
    meta->type = NULL;

    lowfat_free(ptr);
}

void effective__ZdlPv(void *ptr) EFFECTIVE_ALIAS("effective_free");
void effective__ZdaPv(void *ptr) EFFECTIVE_ALIAS("effective_free");

extern void free(void *ptr) EFFECTIVE_ALIAS("effective_free");
extern void _ZdlPv(void *ptr) EFFECTIVE_ALIAS("effective_free");
extern void _ZdaPv(void *ptr) EFFECTIVE_ALIAS("effective_free");

