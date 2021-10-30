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
 * This module handles error reporting and logging.
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <execinfo.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "lowfat.h"
#include "effective.h"

#define EFFECTIVE_TYPESTACK_SIZE    128

#ifdef EFFECTIVE_FLAG_COUNT
#define effective_count_only    true
#else
#define effective_count_only    false
#endif

extern void *__libc_malloc(size_t size);
extern void *__libc_realloc(void *ptr, size_t size);
extern void __libc_free(void *ptr);

#ifdef EFFECTIVE_FLAG_SINGLE_THREADED
typedef int effective_mutex_t;
#define EFFECTIVE_MUTEX_INIT    0
static inline void effective_mutex_lock(effective_mutex_t *mutex)
{
    /* NOP */
}
static inline void effective_mutex_unlock(effective_mutex_t *mutex)
{
    /* NOP */
}
static inline size_t effective_count(size_t *count)
{
    *count = *count + 1;
    return *count;
}
#else   /* EFFECTIVE_FLAG_SINGLE_THREADED */
typedef pthread_mutex_t effective_mutex_t;
#define EFFECTIVE_MUTEX_INIT    PTHREAD_MUTEX_INITIALIZER
static bool effective_single_threaded;
static inline void effective_mutex_lock(effective_mutex_t *mutex)
{
    if (!effective_single_threaded)
        pthread_mutex_lock(mutex);
}
static inline void effective_mutex_unlock(effective_mutex_t *mutex)
{
    if (!effective_single_threaded)
        pthread_mutex_unlock(mutex);
}
static inline size_t effective_count(size_t *count)
{
    if (!effective_single_threaded)
        return __sync_add_and_fetch(count, 1);
    else
    {
        *count = *count + 1;
        return *count;
    }
}
#endif  /* EFFECTIVE_FLAG_SINGLE_THREADED */

#define EFFECTIVE_CONST     __attribute__((__const__))

#define EFFECTIVE_TYPE_HASH(h1, h2, offset)                                 \
    effective_type_hash(h1, h2, offset)
#define EFFECTIVE_BOUNDS_HASH(h, lb, ub)                                    \
    effective_bounds_hash(h, lb, ub);
#define EFFECTIVE_DOUBLE_FREE_HASH      0x947EE7434B62FD5Eull
#define EFFECTIVE_BAD_FREE_HASH         0xED8D9A42BD043669ull

#define EFFECTIVE_MAX_TRACE             32

#define EFFECTIVE_NONE                  0
#define EFFECTIVE_RED                   1
#define EFFECTIVE_GREEN                 2
#define EFFECTIVE_BLUE                  3
#define EFFECTIVE_YELLOW                4
#define EFFECTIVE_CYAN                  5
#define EFFECTIVE_MAGENTA               6

/*
 * Error hash functions.
 */
static size_t effective_hash_counter = 0;
static uint64_t effective_type_hash_v0(uint64_t h1, uint64_t h2, size_t offset)
{
    return h2;
}
static uint64_t effective_type_hash_v1(uint64_t h1, uint64_t h2, size_t offset)
{
    return h1 ^ h2 + h2;
}
static uint64_t effective_type_hash_v2(uint64_t h1, uint64_t h2, size_t offset)
{
    return EFFECTIVE_HASH(h1, h2, offset);
}
static uint64_t effective_type_hash_v9(uint64_t h1, uint64_t h2, size_t offset)
{
    return effective_count(&effective_hash_counter);
}
static uint64_t effective_bounds_hash_v0(uint64_t h, size_t lb, size_t ub)
{
    return EFFECTIVE_HASH(h, 0x2E55C1DEB81601D9ull, 0xD97F5DD01665D640ull);
}
static uint64_t effective_bounds_hash_v2(uint64_t h, size_t lb, size_t ub)
{
    if (lb < ub)
        return (uint64_t)__builtin_ia32_crc32di(h, lb) |
            ((uint64_t)__builtin_ia32_crc32di(h, ub) << 32);
    else
        return effective_bounds_hash_v0(h, lb, ub);
}
static uint64_t effective_bounds_hash_v9(uint64_t h, size_t lb, size_t ub)
{
    return effective_count(&effective_hash_counter);
}

static uint64_t (*effective_type_hash)(uint64_t, uint64_t, size_t) =
    effective_type_hash_v0;
static uint64_t (*effective_bounds_hash)(uint64_t, size_t, size_t) =
    effective_bounds_hash_v0;

/*
 * Representation of different error kinds.
 */
enum EFFECTIVE_ERROR_KIND
{
    EFFECTIVE_TYPE_ERROR_KIND,
    EFFECTIVE_BOUNDS_ERROR_KIND,
    EFFECTIVE_DOUBLE_FREE_ERROR_KIND,
    EFFECTIVE_BAD_FREE_ERROR_KIND
};
typedef enum EFFECTIVE_ERROR_KIND EFFECTIVE_ERROR_KIND;

/*
 * An entry in the error log.
 */
struct EFFECTIVE_ERROR
{
    uint64_t hash;
    struct EFFECTIVE_ERROR *next;
    uint64_t count;
    EFFECTIVE_ERROR_KIND kind;
    int trace_len;
    char **trace;
    const void *location;
    void *info;
};
typedef struct EFFECTIVE_ERROR EFFECTIVE_ERROR;

struct EFFECTIVE_TYPE_ERROR
{
    const void *ptr;
    const EFFECTIVE_TYPE *expected;
    const EFFECTIVE_TYPE *actual;
    size_t offset;
};
typedef struct EFFECTIVE_TYPE_ERROR EFFECTIVE_TYPE_ERROR;

struct EFFECTIVE_BOUNDS_ERROR
{
    const void *ptr;
    const EFFECTIVE_TYPE *actual;
    ssize_t lb;
    ssize_t ub;
    ssize_t offset;
    size_t size;
    bool subobject;
};
typedef struct EFFECTIVE_BOUNDS_ERROR EFFECTIVE_BOUNDS_ERROR;

struct EFFECTIVE_BAD_FREE_ERROR
{
    const void *ptr;
};
typedef struct EFFECTIVE_BAD_FREE_ERROR EFFECTIVE_BAD_FREE_ERROR;

/*
 * Type stacks.
 */
struct EFFECTIVE_TYPESTACK_ENTRY
{
    size_t offset:40;
    size_t indent:8;
    size_t index:16;
    const EFFECTIVE_INFO *info;
};
typedef struct EFFECTIVE_TYPESTACK_ENTRY EFFECTIVE_TYPESTACK_ENTRY;

struct EFFECTIVE_TYPESTACK
{
    ssize_t ptr;
    EFFECTIVE_TYPESTACK_ENTRY entry[EFFECTIVE_TYPESTACK_SIZE];
};
typedef struct EFFECTIVE_TYPESTACK EFFECTIVE_TYPESTACK;

static void effective_typestack_init(EFFECTIVE_TYPESTACK *stack,
    size_t offset, const EFFECTIVE_INFO *info)
{
    stack->ptr = 0;
    stack->entry[0].offset = offset;
    stack->entry[0].indent = 0;
    stack->entry[0].index  = 0;
    stack->entry[0].info   = info;
}
static bool effective_typestack_empty(const EFFECTIVE_TYPESTACK *stack)
{
    return stack->ptr < 0;
}
static const EFFECTIVE_INFO *effective_typestack_peek_info(
    const EFFECTIVE_TYPESTACK *stack)
{
    return stack->entry[stack->ptr].info;
}
static size_t effective_typestack_peek_offset(
    const EFFECTIVE_TYPESTACK *stack)
{
    return stack->entry[stack->ptr].offset;
}
static size_t effective_typestack_peek_indent(
    const EFFECTIVE_TYPESTACK *stack)
{
    return stack->entry[stack->ptr].indent;
}

/*
 * Streams.
 */
struct EFFECTIVE_STREAM
{
    uint32_t ptr;
    bool full;
    char buf[BUFSIZ];
};
typedef struct EFFECTIVE_STREAM EFFECTIVE_STREAM;

/*
 * Stats.
 */
size_t effective_num_nonfat_type_checks = 0;
size_t effective_num_char_type_checks = 0;
size_t effective_num_fast_type_checks = 0;
size_t effective_num_slow_type_checks = 0;
size_t effective_num_bounds_checks = 0;
size_t effective_num_type_errors = 0;
size_t effective_num_bounds_errors = 0;
size_t effective_num_double_free_errors = 0;
size_t effective_num_bad_free_errors = 0;
static bool effective_no_trace = false;
static bool effective_no_log = false;
static bool effective_single_threaded = false;
static bool effective_abort = false;
static size_t effective_max_errs = SIZE_MAX;

/*
 * Signal handling.
 */
static void (*effective_old_action)(int, siginfo_t *, void *) = NULL;

/*
 * Misc.
 */
static effective_mutex_t effective_print_mutex = EFFECTIVE_MUTEX_INIT;

/*
 * Prototypes.
 */
static EFFECTIVE_NOINLINE EFFECTIVE_NORETURN void effective_error(
    const char *format, ...);
static EFFECTIVE_CONST const void *effective_baseof(const void *ptr);
static EFFECTIVE_PURE const EFFECTIVE_TYPE *effective_typeof(const void *ptr);
static EFFECTIVE_NOINLINE void effective_write_char(EFFECTIVE_STREAM *stream,
    char c);
static EFFECTIVE_NOINLINE void effective_write_string(EFFECTIVE_STREAM *stream,
    const char *str);
static EFFECTIVE_NOINLINE void effective_write_type(EFFECTIVE_STREAM *stream,
    const EFFECTIVE_INFO *info, bool expand, bool offsets, bool array);
static void effective_dump_type_stack(const EFFECTIVE_INFO *info,
    size_t indent, size_t offset);
static void effective_dump_bounds_stack(const EFFECTIVE_INFO *info,
    size_t indent, ssize_t lb, ssize_t ub);

/*
 * The error table stores all generated error messages.
 */
#define EFFECTIVE_ERROR_TABLE_MAX_SIZE  (32 * (1 << 20))
static effective_mutex_t EFFECTIVE_ERROR_TABLE_MUTEX =
    EFFECTIVE_MUTEX_INIT;
static EFFECTIVE_ERROR **EFFECTIVE_ERROR_TABLE = NULL;
static size_t EFFECTIVE_ERROR_TABLE_SIZE = 0;
static size_t EFFECTIVE_ERROR_TABLE_NUM_ENTRIES = 0;

/*
 * Get number of type/bounds errors.  NOT thread safe.
 */
size_t effective_get_num_type_errors(void)
{
    if (effective_no_log || effective_count_only)
        return effective_num_type_errors;
    size_t num_type_errors = 0;
    for (size_t i = 0; i < EFFECTIVE_ERROR_TABLE_SIZE; i++)
    {
        EFFECTIVE_ERROR *entry = EFFECTIVE_ERROR_TABLE[i];
        while (entry != NULL)
        {
            num_type_errors += (entry->kind == EFFECTIVE_TYPE_ERROR_KIND?
                entry->count: 0);
            entry = entry->next;
        }
    }
    return num_type_errors;
}
size_t effective_get_num_bounds_errors(void)
{
    if (effective_no_log || effective_count_only)
        return effective_num_bounds_errors;
    size_t num_bounds_errors = 0;
    for (size_t i = 0; i < EFFECTIVE_ERROR_TABLE_SIZE; i++)
    {
        EFFECTIVE_ERROR *entry = EFFECTIVE_ERROR_TABLE[i];
        while (entry != NULL)
        {
            num_bounds_errors += (entry->kind == EFFECTIVE_BOUNDS_ERROR_KIND?
                entry->count: 0);
            entry = entry->next;
        }
    }
    return num_bounds_errors;
}

/*
 * Get the backtrace of the error.
 */
static char **effective_backtrace(int *len_ptr)
{
    if (effective_no_trace)
        return NULL;
    void *trace[EFFECTIVE_MAX_TRACE+1];
    int len = backtrace(trace, EFFECTIVE_MAX_TRACE);
    char **trace_strs = backtrace_symbols(trace, len);
    *len_ptr = len;
    return trace_strs;
}

/*
 * Test if we need to exit or not.
 */
static void effective_maybe_stop(void)
{
    if (effective_max_errs != SIZE_MAX)
    {
        effective_mutex_lock(&EFFECTIVE_ERROR_TABLE_MUTEX);
        bool stop = (EFFECTIVE_ERROR_TABLE_NUM_ENTRIES >= effective_max_errs);
        effective_mutex_unlock(&EFFECTIVE_ERROR_TABLE_MUTEX);
        if (stop)
            exit(EXIT_FAILURE);
    }
}

/*
 * Insert a new error and return it.  If the error already exists, then
 * returns NULL.
 */
static EFFECTIVE_ERROR *effective_insert_error(uint64_t hash)
{
    effective_mutex_lock(&EFFECTIVE_ERROR_TABLE_MUTEX);

    // (0) Initialize the error table if necessary.
    if (EFFECTIVE_ERROR_TABLE == NULL)
    {
        EFFECTIVE_ERROR_TABLE = (EFFECTIVE_ERROR **)mmap(NULL,
            EFFECTIVE_ERROR_TABLE_MAX_SIZE * sizeof(EFFECTIVE_ERROR *),
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE,
            -1, 0);
        if (EFFECTIVE_ERROR_TABLE == (EFFECTIVE_ERROR **)MAP_FAILED)
        {
            effective_error("failed to allocate memory for error table: %s",
                strerror(errno));
        }
        EFFECTIVE_ERROR_TABLE_SIZE = 256;
        if (EFFECTIVE_ERROR_TABLE == NULL)
        {
            effective_error("failed to allocate memory for error table: %s",
                strerror(errno));
        }
    }

    // (1) Find an existing entry:
    size_t idx = hash & (EFFECTIVE_ERROR_TABLE_SIZE-1);
    EFFECTIVE_ERROR *entry = EFFECTIVE_ERROR_TABLE[idx];
    while (entry != NULL)
    {
        if (entry->hash == hash)
        {
            entry->count++;
            effective_mutex_unlock(&EFFECTIVE_ERROR_TABLE_MUTEX);
            return NULL;
        }
        entry = entry->next;
    }

    // (2) Create a new entry:
    EFFECTIVE_ERROR_TABLE_NUM_ENTRIES++;
    if (EFFECTIVE_ERROR_TABLE_NUM_ENTRIES > 2 * EFFECTIVE_ERROR_TABLE_SIZE &&
        EFFECTIVE_ERROR_TABLE_SIZE < EFFECTIVE_ERROR_TABLE_MAX_SIZE)
    {
        // (2a) Re-size the table:
        size_t new_size = 2 * EFFECTIVE_ERROR_TABLE_SIZE;
        for (size_t i = 0; i < EFFECTIVE_ERROR_TABLE_SIZE; i++)
        {
            EFFECTIVE_ERROR *entry = EFFECTIVE_ERROR_TABLE[i];
            EFFECTIVE_ERROR_TABLE[i] = NULL;
            while (entry != NULL)
            {
                EFFECTIVE_ERROR *curr = entry;
                entry = entry->next;
                size_t idx = curr->hash & (new_size-1);
                curr->next = EFFECTIVE_ERROR_TABLE[idx];
                EFFECTIVE_ERROR_TABLE[idx] = curr;
            }
        }
        EFFECTIVE_ERROR_TABLE_SIZE = new_size;
        idx = hash & (EFFECTIVE_ERROR_TABLE_SIZE-1);
    }
    entry = (EFFECTIVE_ERROR *)__libc_malloc(sizeof(EFFECTIVE_ERROR));
    if (entry == NULL)
        effective_error("failed to allocate memory for error: %s",
            strerror(errno));
    entry->hash = hash;
    entry->next = EFFECTIVE_ERROR_TABLE[idx];
    EFFECTIVE_ERROR_TABLE[idx] = entry;
    entry->count = 1;
    // The rest is to be initialized by the caller.

    effective_mutex_unlock(&EFFECTIVE_ERROR_TABLE_MUTEX);
    return entry;
}

/*
 * Handle a type error.  Type errors are bucketed based on the triple:
 * (effectiveType, expectedType, offset)
 */
void effective_type_error(const EFFECTIVE_TYPE *expected,
    const EFFECTIVE_TYPE *actual, const void *ptr, size_t offset,
    const void *location)
{
    if (effective_no_log || effective_count_only)
    {
        effective_count(&effective_num_type_errors);
        return;
    }

    uint64_t hval = EFFECTIVE_TYPE_HASH(actual->hash2, expected->hash, offset);
    EFFECTIVE_ERROR *error = effective_insert_error(hval);
    if (error == NULL)
        return;
    error->kind     = EFFECTIVE_TYPE_ERROR_KIND;
    error->location = location;
    error->trace    = effective_backtrace(&error->trace_len);
    EFFECTIVE_TYPE_ERROR *type_error =
        (EFFECTIVE_TYPE_ERROR *)__libc_malloc(sizeof(EFFECTIVE_TYPE_ERROR));
    error->info = (void *)type_error;
    if (type_error != NULL)
    {
        type_error->ptr      = ptr;
        type_error->expected = expected;
        type_error->actual   = actual;
        type_error->offset   = offset;
    }
    effective_maybe_stop();
}

/*
 * Handle a bounds error.  Bounds errors are bucketed based on the triple:
 * (effectiveType, lb, ub).  Note that the magnitude of the overflow is not
 * part of the triple.
 */
void effective_bounds_error(EFFECTIVE_BOUNDS bounds, const void *ptr,
    size_t size)
{
    if (effective_no_log || effective_count_only)
    {
        effective_count(&effective_num_bounds_errors);
        return;
    }

    const void *base = effective_baseof((const void *)bounds[0]);
    if (base == NULL)
    {
        // This is a non-fat pointer.  It is possible that we still detect
        // errors thanks to narrowing, so this case should be handled in
        // future versions. (TODO)
        return;
    }
    const EFFECTIVE_TYPE *t = effective_typeof((const void *)bounds[0]);
    const EFFECTIVE_META *meta = (const EFFECTIVE_META *)base;
    base = (const void *)(meta + 1);
    ssize_t lb = (bounds[0] - (intptr_t)base);
    ssize_t ub = (bounds[1] - (intptr_t)base);

    uint64_t hval = EFFECTIVE_BOUNDS_HASH(t->hash2, lb, ub);

    EFFECTIVE_ERROR *error = effective_insert_error(hval);
    if (error == NULL)
        return;
    ssize_t offset = (intptr_t)ptr - (intptr_t)base;
    error->kind     = EFFECTIVE_BOUNDS_ERROR_KIND;
    error->location = __builtin_return_address(0);
    error->trace    = effective_backtrace(&error->trace_len);
    EFFECTIVE_BOUNDS_ERROR *bounds_error =
        (EFFECTIVE_BOUNDS_ERROR *)__libc_malloc(sizeof(EFFECTIVE_BOUNDS_ERROR));
    error->info = (void *)bounds_error;
    if (bounds_error != NULL)
    {
        bounds_error->ptr       = ptr;
        bounds_error->actual    = t;
        bounds_error->lb        = lb;
        bounds_error->ub        = ub;
        bounds_error->offset    = offset;
        bounds_error->size      = size;
        bounds_error->subobject = (ptr >= base &&
            (uint8_t *)ptr < (uint8_t *)base + meta->size);
    }
    effective_maybe_stop();
}

/*
 * Handle a double-free error.
 */
void effective_double_free_error(const void *ptr, const void *location)
{
    if (effective_no_log || effective_count_only)
    {
        effective_count(&effective_num_double_free_errors);
        return;
    }

    uint64_t hval = EFFECTIVE_DOUBLE_FREE_HASH;
    EFFECTIVE_ERROR *error = effective_insert_error(hval);
    if (error == NULL)
        return;
    error->kind     = EFFECTIVE_DOUBLE_FREE_ERROR_KIND;
    error->location = location;
    error->trace    = effective_backtrace(&error->trace_len);
    error->info     = NULL;
    effective_maybe_stop();
}

/*
 * Handle a bad-free error.
 */
void effective_bad_free_error(const void *ptr, const void *location)
{
    if (effective_no_log || effective_count_only)
    {
        effective_count(&effective_num_bad_free_errors);
        return;
    }

    uint64_t hval = EFFECTIVE_BAD_FREE_HASH;
    EFFECTIVE_ERROR *error = effective_insert_error(hval);
    if (error == NULL)
        return;
    error->kind            = EFFECTIVE_BAD_FREE_ERROR_KIND;
    error->location        = location;
    error->trace           = effective_backtrace(&error->trace_len);
    EFFECTIVE_BAD_FREE_ERROR *bad_free_error = (EFFECTIVE_BAD_FREE_ERROR *)
        __libc_malloc(sizeof(EFFECTIVE_BAD_FREE_ERROR));
    error->info = (void *)bad_free_error;
    if (bad_free_error != NULL)
        bad_free_error->ptr = ptr;
    effective_maybe_stop();
}

/*
 * Get the base address of a pointer.
 */
static EFFECTIVE_CONST const void *effective_baseof(const void *ptr)
{
    size_t idx = lowfat_index(ptr);
    if (idx > 1024 || _LOWFAT_MAGICS[idx] == 0)     // XXX: 1024 magic
        return NULL;
    return lowfat_base(ptr);
}

/*
 * Get the effective type of a pointer.
 */
static EFFECTIVE_PURE const EFFECTIVE_TYPE *effective_typeof(const void *ptr)
{
    const void *base = effective_baseof(ptr);
    if (base == NULL)
        return &EFFECTIVE_TYPE_INT8;
    const EFFECTIVE_META *meta = (const EFFECTIVE_META *)base;
    return meta->type;
}

/*
 * Set color if terminal.
 */
static const char *effective_set_color(int color)
{
    if (!isatty(STDERR_FILENO))
        return "";
    switch (color)
    {
        case EFFECTIVE_NONE:
            return "\33[0m";
        case EFFECTIVE_RED:
            return "\33[31m";
        case EFFECTIVE_GREEN:
            return "\33[32m";
        case EFFECTIVE_BLUE:
            return "\33[34m";
        case EFFECTIVE_YELLOW:
            return "\33[33m";
        case EFFECTIVE_CYAN:
            return "\33[36m";
        case EFFECTIVE_MAGENTA:
            return "\33[35m";
        default:
            return "";
    }
}

/*
 * Check if a pointer is accessible or not.
 */
static bool effective_is_ptr_accessible(const void *ptr)
{
    if (ptr == NULL)
        return false;
    ptr = (const void *)((uintptr_t)ptr - (uintptr_t)ptr %
        sysconf(_SC_PAGESIZE));
    unsigned char res;
    if (mincore((void *)ptr, 1, &res) < 0)
        return false;
    // ptr is valid, regardless of whether the page is resident or not:
    return true;
}

/*
 * Check if the given type is valid or not.
 */
static bool effective_is_type_valid(const EFFECTIVE_TYPE *t)
{
    if (!effective_is_ptr_accessible(t))
        return false;
    return (t->sanity == EFFECTIVE_SANITY);
}

/*
 * Classify a pointer.
 */
static const char *effective_pointer_kind(const void *ptr)
{
    if (lowfat_is_heap_ptr(ptr))
        return "heap";
    if (lowfat_is_stack_ptr(ptr))
        return "stack";
    if (lowfat_is_global_ptr(ptr))
        return "global";
    if (!lowfat_is_ptr(ptr))
        return "nonfat";
    return "unused";
}

/*
 * Report an error.
 */
static void effective_report_error(const EFFECTIVE_ERROR *error)
{
    if (error->hash == 0)
        return;
    const char *errstr = NULL;
    switch (error->kind)
    {
        case EFFECTIVE_TYPE_ERROR_KIND:
        {
            // Check for use-after-free errors:
            const EFFECTIVE_TYPE_ERROR *type_error =
                (EFFECTIVE_TYPE_ERROR *)error->info;
            if (type_error != NULL &&
                    type_error->actual == &EFFECTIVE_TYPE_FREE)
                errstr = "USE-AFTER-FREE";
            else
                errstr = "TYPE";
            break;
        }
        case EFFECTIVE_BOUNDS_ERROR_KIND:
        {
            // Check for sub-object bounds errors:
            const EFFECTIVE_BOUNDS_ERROR *bounds_error =
                (EFFECTIVE_BOUNDS_ERROR *)error->info;
            if (bounds_error != NULL && bounds_error->subobject)
                errstr = "SUBOBJECT BOUNDS";
            else
                errstr = "BOUNDS";
            break;
        }
        case EFFECTIVE_DOUBLE_FREE_ERROR_KIND:
            errstr = "DOUBLE FREE";
            break;
        case EFFECTIVE_BAD_FREE_ERROR_KIND:
            errstr = "BAD FREE";
            break;
    }
    fprintf(stderr, "%s%s ERROR%s:\n", effective_set_color(EFFECTIVE_RED),
        errstr, effective_set_color(EFFECTIVE_NONE));
    if (error->count != 1)
        fprintf(stderr, "        count    = %zu\n", error->count);
    switch (error->kind)
    {
        case EFFECTIVE_TYPE_ERROR_KIND:
        {
            const EFFECTIVE_TYPE_ERROR *type_error =
                (EFFECTIVE_TYPE_ERROR *)error->info;
            effective_num_type_errors++;
            if (type_error == NULL)
                break;
            const void *ptr = type_error->ptr;
            fprintf(stderr, "        pointer  = %p (%s)\n",
                ptr, effective_pointer_kind(ptr));
            EFFECTIVE_STREAM stream;
            stream.ptr = 0;
            stream.full = false;
            if (effective_is_type_valid(type_error->expected))
                effective_write_type(&stream, type_error->expected->info,
                    false, true, false);
            else
                effective_write_string(&stream, "<invalid type meta data>");
            effective_write_char(&stream, '\0');
            fprintf(stderr, "        expected = %s%s%s\n",
                effective_set_color(EFFECTIVE_GREEN),
                stream.buf, effective_set_color(EFFECTIVE_NONE));
            fprintf(stderr, "        actual   = ");
            if (effective_is_type_valid(type_error->actual))
            {
                effective_dump_type_stack(type_error->actual->info, 19,
                    type_error->offset);
                if ((type_error->actual->info->flags &
                        EFFECTIVE_INFO_FLAG_INCOMPLETE) != 0)
                {
                    fprintf(stderr, "        note     = "
                        "%sThis error may be the result of incomplete type "
                        "meta data; see the (-effective-max-sub-objs=N) "
                        "compiler option.%s\n",
                        effective_set_color(EFFECTIVE_YELLOW),
                        effective_set_color(EFFECTIVE_NONE));
                }
            }
            else
                fprintf(stderr, "%s<invalid type meta data>%s\n",
                    effective_set_color(EFFECTIVE_GREEN),
                    effective_set_color(EFFECTIVE_NONE));
            break;
        }
        case EFFECTIVE_BOUNDS_ERROR_KIND:
        {
            const EFFECTIVE_BOUNDS_ERROR *bounds_error =
                (EFFECTIVE_BOUNDS_ERROR *)error->info;
            effective_num_bounds_errors++;
            if (bounds_error == NULL)
                break;
            const void *ptr = bounds_error->ptr;
            fprintf(stderr, "        pointer  = %p (%s)\n",
                ptr, effective_pointer_kind(ptr));
            fprintf(stderr, "        type     = ");
            ssize_t lb = bounds_error->lb;
            ssize_t ub = bounds_error->ub;
            ssize_t offset = lb;
            if (effective_is_type_valid(bounds_error->actual))
                effective_dump_bounds_stack(bounds_error->actual->info, 19,
                    lb, ub);
            else
                fprintf(stderr, "%s<invalid type meta data>%s\n",
                    effective_set_color(EFFECTIVE_GREEN),
                    effective_set_color(EFFECTIVE_NONE));
            if (lb >= ub)
                fprintf(stderr, "        bounds   = (empty)\n");
            else
            {
                fprintf(stderr, "        bounds   = 0..%zd (%zd..%zd)\n",
                    ub - offset, lb, ub);
            }
            lb = bounds_error->offset;
            ub = lb + bounds_error->size;
            if (lb == ub)
                fprintf(stderr, "        access   = (escape) (%zd)\n", lb);
            else
                fprintf(stderr, "        access   = %zd..%zd (%zd..%zd)\n",
                    lb - offset, ub - offset, lb, ub);
            break;
        }
        case EFFECTIVE_DOUBLE_FREE_ERROR_KIND:
            effective_num_double_free_errors++;
            break;
        case EFFECTIVE_BAD_FREE_ERROR_KIND:
        {
            const EFFECTIVE_BAD_FREE_ERROR *bad_free_error =
                (EFFECTIVE_BAD_FREE_ERROR *)error->info;
            if (bad_free_error == NULL)
                break;
            effective_num_bad_free_errors++;
            const void *ptr = bad_free_error->ptr;
            fprintf(stderr, "        pointer  = %p (%s)\n",
                ptr, effective_pointer_kind(ptr));
            break;
        }
    }
    if (error->trace != NULL)
    {
        fprintf(stderr, "        trace    = ");
        for (int i = 0; i < error->trace_len; i++)
        {
            fprintf(stderr, "%s%s%s\n", effective_set_color(EFFECTIVE_CYAN),
                error->trace[i], effective_set_color(EFFECTIVE_NONE));
            if (i+1 < error->trace_len)
                fprintf(stderr, "                 = ");
        }
        if (error->trace_len >= EFFECTIVE_MAX_TRACE)
            fprintf(stderr, "                 = %s...%s\n",
                effective_set_color(EFFECTIVE_CYAN),
                effective_set_color(EFFECTIVE_NONE));
    }
    fputc('\n', stderr);
}

/*
 * Print the EffectiveSan banner.
 */
static EFFECTIVE_NOINLINE void effective_print_banner(void)
{
    fprintf(stderr, "       __  __           _   _           ____\n");
    fprintf(stderr,
        "  ___ / _|/ _| ___  ___| |_(_)_   _____/ ___|  __ _ _ __\n");
    fprintf(stderr,
        " / _ \\ |_| |_ / _ \\/ __| __| \\ \\ / / _ \\___ \\ / _` | '_ \\\n");
    fprintf(stderr,
        "|  __/  _|  _|  __/ (__| |_| |\\ V /  __/___) | (_| | | | |\n");
    fprintf(stderr,
        " \\___|_| |_|  \\___|\\___|\\__|_| \\_/ \\___|____/ \\__,_|_| |_|\n");
    fputc('\n', stderr);
}

/*
 * Report all generated error messages.
 */
static EFFECTIVE_DESTRUCTOR(12399) void effective_report(void)
{
    struct rusage usage;
    long t = 0, m = 0;
    bool have_rusage = false;
    if (getrusage(RUSAGE_SELF, &usage) == 0)
    {
        t = usage.ru_utime.tv_sec * 1000 + usage.ru_utime.tv_usec / 1000 +
            usage.ru_stime.tv_sec * 1000 + usage.ru_stime.tv_usec / 1000;
        m = usage.ru_maxrss;
        have_rusage = true;
    }
    const char *filename = getenv("EFFECTIVE_LOGFILE");
    if (filename != NULL)
        freopen(filename, "a", stderr);

    effective_print_banner();

#ifndef EFFECTIVE_FLAG_COUNT
    if (!effective_no_log)
    {
        effective_num_type_errors = 0;
        effective_num_bounds_errors = 0;
        effective_num_double_free_errors = 0;
        effective_num_bad_free_errors = 0;

        for (unsigned i = 0; i < EFFECTIVE_ERROR_TABLE_SIZE; i++)
        {
            EFFECTIVE_ERROR *error = EFFECTIVE_ERROR_TABLE[i];
            while (error != NULL)
            {
                effective_report_error(error);
                error = error->next;
            }
        }
    }
#endif

    fprintf(stderr, "--------------------------------------------------\n");
    char path[BUFSIZ];
    ssize_t len = readlink("/proc/self/exe", path, sizeof(path)-1);
    if (len > 0 && len < (ssize_t)(sizeof(path)-1))
    {
        path[len] = '\0';
        fprintf(stderr, "program        = %s\n", path);
    }
#ifdef EFFECTIVE_FLAG_PROFILE
    size_t effective_num_type_checks =
        effective_num_nonfat_type_checks +
        effective_num_char_type_checks +
        effective_num_fast_type_checks +
        effective_num_slow_type_checks;
    fprintf(stderr, "#type checks   = %zu (%zunonfat + %zuchar + %zufast + "
        "%zuslow)\n",
        effective_num_type_checks, effective_num_nonfat_type_checks,
        effective_num_char_type_checks, effective_num_fast_type_checks,
        effective_num_slow_type_checks);
#endif
    fprintf(stderr, "#type errors   = %zu\n", effective_num_type_errors);
#ifdef EFFECTIVE_FLAG_PROFILE
    fprintf(stderr, "#bounds checks = %zu\n", effective_num_bounds_checks);
#endif
    fprintf(stderr, "#bounds errors = %zu\n", effective_num_bounds_errors);
    if (have_rusage)
    {
        fprintf(stderr, "time (ms)      = %lu\n", t);
        fprintf(stderr, "memory (KB)    = %lu\n", m);
    }
    fprintf(stderr, "--------------------------------------------------\n");
    fflush(stderr);

    if (effective_abort && EFFECTIVE_ERROR_TABLE_NUM_ENTRIES)
      abort();
}

/*
 * SEGV handler.
 */
static void effective_segv_handler(int sig, siginfo_t *info, void *context0)
{
    static bool run_once = false;
    if (run_once)
    {
        raise(SIGTERM);     // Fail-safe.
        raise(SIGKILL);
    }
    run_once = true;
    if (effective_old_action != NULL)
        effective_old_action(sig, info, context0);
    effective_report();
    abort();
}

/*
 * Initialize logging.
 */
static EFFECTIVE_CONSTRUCTOR(17777) void effective_log_init(void)
{
    // This should override the LowFat SEGV handler:
    struct sigaction action, old_action;
    memset(&action, 0, sizeof(action));
    action.sa_sigaction = effective_segv_handler;
    sigaction(SIGSEGV, &action, &old_action);
    effective_old_action = old_action.sa_sigaction;

    // Save configuration:
    if (getenv("EFFECTIVE_NOTRACE") != NULL)
        effective_no_trace = true;
    if (getenv("EFFECTIVE_NOLOG") != NULL)
        effective_no_log = true;
    if (getenv("EFFECTIVE_SINGLETHREADED") != NULL)
        effective_single_threaded = true;
    if (getenv("EFFECTIVE_ABORT") != NULL)
        effective_abort = true;
    const char *max = getenv("EFFECTIVE_MAXERRS");
    size_t tmp;
    if (max != NULL && sscanf(max, "%zu", &tmp) == 1)
    {
        if (effective_no_log || effective_count_only)
            effective_error("cannot combine EFFECTIVE_MAXERRS with "
                "EFFECTIVE_NOLOG");
        effective_max_errs = tmp;
    }
    const char *verb = getenv("EFFECTIVE_VERBOSITY");
    if (verb != NULL)
    {
        switch (verb[0])
        {
            case '0':
                break;
            case '1':
                effective_type_hash = effective_type_hash_v1;
                break;
            case '2':
                effective_type_hash = effective_type_hash_v2;
                effective_bounds_hash = effective_bounds_hash_v2;
                break;
            case '9':
                effective_type_hash = effective_type_hash_v9;
                effective_bounds_hash = effective_bounds_hash_v9;
                break;
            default:
            verbosity_error:
                effective_error("invalid value (%s) for EFFECTIVE_VERBOSITY; "
                    "expected (0|1|2|9)", verb);
        }
        if (verb[1] != '\0')
            goto verbosity_error;
    }
}

/****************************************************************************/

/*
 * Write a character to a stream.
 */
static EFFECTIVE_NOINLINE void effective_write_char(EFFECTIVE_STREAM *stream,
    char c)
{
    if (stream->full)
        return;
    stream->buf[stream->ptr++] = c;
    if (sizeof(stream->buf) - stream->ptr == 4)
    {
        stream->full = true;
        stream->buf[sizeof(stream->buf)-4] = '.';
        stream->buf[sizeof(stream->buf)-3] = '.';
        stream->buf[sizeof(stream->buf)-2] = '.';
        stream->buf[sizeof(stream->buf)-1] = '\0';
    }
}

/*
 * Write a string to a stream.
 */
static EFFECTIVE_NOINLINE void effective_write_string(EFFECTIVE_STREAM *stream,
    const char *str)
{
    for (size_t i = 0; str[i] && !stream->full; i++)
        effective_write_char(stream, str[i]);
}

/*
 * Write an integer to a stream.
 */
static EFFECTIVE_NOINLINE void effective_write_int(EFFECTIVE_STREAM *stream,
    ssize_t i)
{
    if (stream->full)
        return;
    char buf[100];
    ssize_t r = snprintf(buf, sizeof(buf)-1, "%zd", i);
    if (r > 0 && r <= (ssize_t)sizeof(buf)-1)
        effective_write_string(stream, buf);
}

/*
 * Write offsets to a stream.
 */
static EFFECTIVE_NOINLINE void effective_write_offsets(EFFECTIVE_STREAM *stream,
    const EFFECTIVE_INFO_ENTRY *entry)
{
    effective_write_string(stream, effective_set_color(EFFECTIVE_CYAN));
    effective_write_string(stream, "/*");
    effective_write_int(stream, entry->lb);
    effective_write_string(stream, "..");
    if (entry->ub != UINT32_MAX)
        effective_write_int(stream, entry->ub);
    effective_write_string(stream, "*/");
    effective_write_string(stream, effective_set_color(EFFECTIVE_GREEN));
}

/*
 * Write a type to a stream.
 */
static EFFECTIVE_NOINLINE void effective_write_type(EFFECTIVE_STREAM *stream,
    const EFFECTIVE_INFO *info, bool expand, bool offsets, bool array)
{
    if (stream->full)
        return;
    if (expand)
        effective_write_string(stream, effective_set_color(EFFECTIVE_GREEN));
    if (!array)
    {
        for (size_t i = 0; info->name[i] != '[' && info->name[i] != '\0'; i++)
            effective_write_char(stream, info->name[i]);
    }
    else
        effective_write_string(stream, info->name);
        
    bool is_anon = false;
    if (strcmp(info->name, "struct ") == 0)
        is_anon = true;
    if (!is_anon && !expand)
        return;

    char prefix_struct[] = "struct";
    char prefix_class[]  = "class";
    char prefix_union[]  = "union";
    char prefix_new[]    = "new";
    if (strncmp(info->name, prefix_struct, sizeof(prefix_struct)-1) != 0 &&
        strncmp(info->name, prefix_class, sizeof(prefix_class)-1) != 0 &&
        strncmp(info->name, prefix_union, sizeof(prefix_union)-1) != 0 &&
        strncmp(info->name, prefix_new, sizeof(prefix_union)-1) != 0)
    {
not_composite:
        effective_write_string(stream, effective_set_color(EFFECTIVE_NONE));
        return;
    }
    size_t len = strlen(info->name);
    if (len == 0 || info->name[len-1] == '*')
        goto not_composite;

    bool inheritance = false;
    for (size_t i = 0; i < info->num_entries && !stream->full; i++)
    {
        if (!(info->entries[i].flags & EFFECTIVE_INFO_ENTRY_FLAG_INHERITANCE))
            continue;
        if (!inheritance)
        {
            effective_write_string(stream, " : ");
            inheritance = true;
        }
        else
            effective_write_string(stream, ", ");
        bool virtual =
            info->entries[i].flags & EFFECTIVE_INFO_ENTRY_FLAG_VIRTUAL;
        if (virtual)
            effective_write_string(stream, "virtual ");
        else
            effective_write_string(stream, "public ");
        effective_write_type(stream, info->entries[i].type, false, false,
            false);
        if (offsets && !virtual)
        {
            effective_write_char(stream, ' ');
            effective_write_offsets(stream, &info->entries[i]);
        }
    }

    if (!is_anon)
        effective_write_char(stream, ' ');
    effective_write_string(stream, "{ ");
    for (size_t i = 0; i < info->num_entries && !stream->full; i++)
    {
        if (info->entries[i].flags & EFFECTIVE_INFO_ENTRY_FLAG_INHERITANCE)
            continue;
        size_t count = 1;
        if (info->entries[i].type->size != 0)
            count = (info->entries[i].ub - info->entries[i].lb) /
                info->entries[i].type->size;
        if (count == 0)
            continue;
        effective_write_type(stream, info->entries[i].type, false, false,
            false);
        if (count != 1)
        {
            effective_write_char(stream, '[');
            if (count != 0)
                effective_write_int(stream, count);
            effective_write_char(stream, ']');
            const char *idxs = strchr(info->entries[i].type->name, '[');
            if (idxs != NULL)
                effective_write_string(stream, idxs);
        }
        effective_write_string(stream, "; ");
        if (offsets)
        {
            effective_write_offsets(stream, &info->entries[i]);
            effective_write_char(stream, ' ');
        }
    }
    if ((info->flags & EFFECTIVE_INFO_FLAG_FLEXIBLE_LEN) != 0)
    {
        effective_write_type(stream, info->next, false, false, false);
        effective_write_string(stream, "[]; ");
        if (offsets)
        {
            EFFECTIVE_INFO_ENTRY entry;
            entry.lb = info->size;
            entry.ub = UINT32_MAX;
            effective_write_offsets(stream, &entry);
            effective_write_char(stream, ' ');
        }
    }
    effective_write_string(stream, "}");
    effective_write_string(stream, effective_set_color(EFFECTIVE_NONE));
}

/*
 * Expand the type stack.
 */
static EFFECTIVE_NOINLINE void effective_typestack_next(
    EFFECTIVE_TYPESTACK *stack, size_t minsize)
{
    while (stack->ptr >= 0)
    {
        size_t offset = stack->entry[stack->ptr].offset;
        size_t indent = stack->entry[stack->ptr].indent;
        const EFFECTIVE_INFO *info = stack->entry[stack->ptr].info;

        if (offset >= info->size && offset > 0)
        {
            if ((info->flags & EFFECTIVE_INFO_FLAG_FLEXIBLE_LEN) != 0)
            {
                offset = offset - info->size;
                stack->entry[stack->ptr].offset = offset;
                stack->entry[stack->ptr].indent = indent + 1;
                stack->entry[stack->ptr].info = info->next;
                return;
            }
            offset = (info->size == 0? 0: offset % info->size);
            stack->entry[stack->ptr].offset = offset;
            return;
        }
        for (size_t i = stack->entry[stack->ptr].index; i < info->num_entries;
            i++)
        {
            stack->entry[stack->ptr].index = i+1;
            bool virtual =
                (info->entries[i].flags & EFFECTIVE_INFO_ENTRY_FLAG_VIRTUAL);
            if (!virtual && offset >= info->entries[i].lb &&
                offset < info->entries[i].ub &&
                info->entries[i].ub - info->entries[i].lb >= minsize)
            {
                stack->ptr++;
                if (stack->ptr >= EFFECTIVE_TYPESTACK_SIZE)
                {
                    stack->ptr--;
                    continue;
                }
                offset = offset - info->entries[i].lb;
                stack->entry[stack->ptr].offset = offset;
                stack->entry[stack->ptr].indent = indent + 1;
                stack->entry[stack->ptr].index = 0;
                stack->entry[stack->ptr].info = info->entries[i].type;
                return;
            }
        }
        stack->ptr--;
    }
    return;
}

/*
 * Dump a type error stack.
 */
static void effective_dump_type_stack(const EFFECTIVE_INFO *info,
    size_t indent, size_t offset)
{
    EFFECTIVE_TYPESTACK stack0;
    EFFECTIVE_TYPESTACK *stack = &stack0;
    effective_typestack_init(stack, offset, info);

    size_t count = 0;
    while (!effective_typestack_empty(stack))
    {
        EFFECTIVE_STREAM stream;
        stream.ptr = 0;
        stream.full = false;
        effective_write_type(&stream, effective_typestack_peek_info(stack),
            true, true, true);
        effective_write_char(&stream, '\0');
        for (size_t i = 0; count != 0 && i < indent && i < 80; i++)
            putc(' ', stderr);
        for (size_t i = 0; i < effective_typestack_peek_indent(stack); i++)
            putc('>', stderr);
        fprintf(stderr, "%s [+%zu]\n", stream.buf,
            effective_typestack_peek_offset(stack));
        effective_typestack_next(stack, 0);
        count++;
    }
}

/*
 * Dump a bounds error stack.
 */
static void effective_dump_bounds_stack(const EFFECTIVE_INFO *info,
    size_t indent, ssize_t lb, ssize_t ub)
{
    EFFECTIVE_TYPESTACK stack0;
    EFFECTIVE_TYPESTACK *stack = &stack0;
    effective_typestack_init(stack, lb, info);

    size_t count = 0;
    size_t size = ub - lb;
    while (!effective_typestack_empty(stack))
    {
        EFFECTIVE_STREAM stream;
        stream.ptr = 0;
        stream.full = false;
        effective_write_type(&stream, effective_typestack_peek_info(stack),
            true, true, true);
        effective_write_char(&stream, '\0');
        for (size_t i = 0; count != 0 && i < indent && i < 80; i++)
            putc(' ', stderr);
        for (size_t i = 0; i < effective_typestack_peek_indent(stack); i++)
            putc('>', stderr);
        ssize_t offset = (ssize_t)effective_typestack_peek_offset(stack);
        if (lb >= ub)
        {
            fprintf(stderr, "%s (empty)\n", stream.buf);
            return;
        }
        else
            fprintf(stderr, "%s [%+zd..%+zd]\n", stream.buf, offset,
                offset + size);
        effective_typestack_next(stack, size);
        count++;
    }
}

/*
 * Dump information about the given pointer.
 */
void effective_dump(const void *ptr)
{
    const void *base = effective_baseof(ptr);
    const EFFECTIVE_TYPE *t = effective_typeof(ptr);
    const EFFECTIVE_META *meta = (const EFFECTIVE_META *)base;
    base = (const void *)(meta + 1);
    ssize_t offset = (intptr_t)ptr - (intptr_t)base;
    fprintf(stderr, "%p: %s%s%s (%+zd)\n", ptr,
        effective_set_color(EFFECTIVE_GREEN), t->info->name,
        effective_set_color(EFFECTIVE_NONE), offset);
    effective_dump_type_stack(t->info, 0, offset);
}

/*
 * Generic error handling.
 */
static EFFECTIVE_NOINLINE EFFECTIVE_NORETURN void effective_error(
    const char *format, ...)
{
    va_list ap;
    va_start(ap, format);
    effective_mutex_lock(&effective_print_mutex);  // Never unlock
    fprintf(stderr, "%sFATAL ERROR%s:\n", effective_set_color(EFFECTIVE_RED),
        effective_set_color(EFFECTIVE_NONE));
    vfprintf(stderr, format, ap);
    fputc('\n', stderr);
    va_end(ap);
    abort();
}
