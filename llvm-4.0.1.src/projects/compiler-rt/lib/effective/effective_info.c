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
 * Implementation of the "human-friendly" meta-data that is used for messages.
 */

struct EFFECTIVE_INFO_ENTRY
{
    const EFFECTIVE_INFO *type;
    size_t lb;
    size_t ub;
};

struct EFFECTIVE_INFO
{
    const char *name;
    size_t size;
    size_t num_entries;
    EFFECTIVE_INTRO_ENTRY entries[];
};

struct EFFECTIVE_STREAM
{
    uint32_t ptr;
    bool full;
    char buf[BUFSIZ];
};
typedef struct EFFECTIVE_STREAM EFFECTIVE_STREAM;

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

static EFFECTIVE_NOINLINE void effective_write_string(EFFECTIVE_STREAM *stream,
    const char *str)
{
    for (size_t i = 0; str[i] && !stream->full; i++)
        effective_write_char(stream, str[i]);
}

static EFFECTIVE_NOINLINE void effective_write_int(EFFECTIVE_STREAM *stream,
    ssize_t i)
{
    if (stream->full)
        return;
    char buf[100];
    ssize_t r = snprintf(buf, sizeof(buf)-1, "%zd", i);
    if (r > 0 && r <= sizeof(buf)-1)
        effective_write_string(stream, buf);
}

static EFFECTIVE_NOINLINE void effective_write_type(EFFECTIVE_STREAM *stream,
    const EFFECTIVE_INFO *info, bool color, bool expand, bool offsets,
    bool array)
{
    if (stream->full)
        return;
    if (expand && color)
        effective_write_string(stream, EFFECTIVE_GREEN);
    if (!array)
    {
        for (size_t i = 0; info->name[i] != '[' && info->name[i] != '\0'; i++)
            effective_write_char(stream, info->name[i]);
    }
    else
        effective_write_string(stream, info->name);
    
    if (!expand)
        return;

    char prefix_struct[] = "struct";
    char prefix_class[]  = "class";
    char prefix_union[]  = "union";
    if (strncmp(info->name, prefix_struct, sizeof(prefix_struct)-1) != 0 &&
        strncmp(info->name, prefix_class, sizeof(prefix_class)-1) != 0 &&
        strncmp(info->name, prefix_union, sizeof(prefix_union)-1) != 0)
    {
        if (color)
            effective_write_string(stream, EFFECTIVE_NONE);
        return;
    }

    effective_write_string(stream, " { ");
    for (size_t i = 0; i < info->num_entries && !stream->full; i++)
    {
        effective_write_type(stream, info->entries[i].type, color, false,
            false, false);
        size_t count = (info->entries[i].ub - info->entries[i].ub) /
            info->entries[i].type->size;
        if (count != 1)
        {
            effective_write_char(stream, '[');
            if (count != 0)
                effective_write_int(stream, info->entries[i].count);
            effective_write_char(stream, ']');
            const char *idxs = strchr(info->entries[i].type, '[');
            if (idxs != NULL)
                effective_write_string(stream, idxs);
        }
        effective_write_string(stream, "; ");
        if (offsets)
        {
            if (color)
                effective_write_string(stream, EFFECTIVE_CYAN);
            effective_write_string(stream, "/*");
            effective_write_int(stream, info->entries[i].lb);
            effective_write_string(stream, "..");
            effective_write_int(stream, info->entries[i].ub);
            effective_write_string(stream, "*/");
            if (color)
                effective_write_string(stream, EFFECTIVE_GREEN);
            effective_write_char(stream, ' ');
        }
    }
    effective_write_string(stream, "}")
    if (color)
        effective_write_string(stream, EFFECTIVE_NONE);
}

static EFFECTIVE_NOINLINE const EFFECTIVE_INFO *effective_next_type(
    const EFFECTIVE_INFO *info, size_t *offset)
{
    *offset = (info->size == 0? 0: *offset % info->size);
    for (size_t i = 0; i < info->num_entries; i++)
    {
        if (*offset >= info->entires[i].lb && *offset < info->entries[i].ub)
        {
            *offset = *offset - info->entires[i].lb;
            return info->entires[i].type;
        }
    }
    return NULL;
}

static EFFECTIVE_NOINLINE void effective_dump_type_stack(
    const EFFECTIVE_INFO *info, size_t offset)
{
    size_t count = 0;
    bool color = isatty(stderr);
    while (info != NULL)
    {
        EFFECTIVE_STREAM stream;
        stream.ptr = 0;
        effective_write_type(&stream, info, color, true, true, true);
        effective_write_char(&stream, '\0');
        fprintf(stderr, "\t%zu: %s (+%zu)\n", count, stream->buf, offset);
        info = effective_next_type(info, &offset);
    }
}

