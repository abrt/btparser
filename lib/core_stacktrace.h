/*
    core_stacktrace.h

    Copyright (C) 2010  Red Hat, Inc.

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/
#ifndef BTPARSER_CORE_STACKTRACE_H
#define BTPARSER_CORE_STACKTRACE_H

/**
 * @file
 * @brief A stack trace of a core dump.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <inttypes.h>

struct btp_core_thread;
struct btp_location;

/**
 * @brief A stack trace of a core dump.
 */
struct btp_core_stacktrace
{
    struct btp_core_thread *threads;
};

/**
 * Creates and initializes a new stacktrace structure.
 * @returns
 * It never returns NULL. The returned pointer must be released by
 * calling the function btp_core_stacktrace_free().
 */
struct btp_core_stacktrace *
btp_core_stacktrace_new();

/**
 * Initializes all members of the stacktrace structure to their default
 * values.  No memory is released, members are simply overwritten.
 * This is useful for initializing a stacktrace structure placed on the
 * stack.
 */
void
btp_core_stacktrace_init(struct btp_core_stacktrace *stacktrace);

/**
 * Releases the memory held by the stacktrace, its threads and frames.
 * @param stacktrace
 * If the stacktrace is NULL, no operation is performed.
 */
void
btp_core_stacktrace_free(struct btp_core_stacktrace *stacktrace);

/**
 * Creates a duplicate of the stacktrace.
 * @param stacktrace
 * The stacktrace to be copied. It's not modified by this function.
 * @returns
 * This function never returns NULL.  The returned duplicate must be
 * released by calling the function btp_core_stacktrace_free().
 */
struct btp_core_stacktrace *
btp_core_stacktrace_dup(struct btp_core_stacktrace *stacktrace);

/**
 * Returns a number of threads in the stacktrace.
 * @param stacktrace
 * It's not modified by calling this function.
 */
int
btp_core_stacktrace_get_thread_count(struct btp_core_stacktrace *stacktrace);

/**
 * Parses a textual stacktrace and puts it into a structure.  If
 * parsing fails, the input parameter is not changed and NULL is
 * returned.
 *
 * @note
 * Stacktrace can be serialized to string via
 * btp_core_stacktrace_to_text().
 */
struct btp_core_stacktrace *
btp_core_stacktrace_parse(const char **input,
                         struct btp_location *location);

/**
 * Serializes stacktrace to string.
 * @returnes
 * Newly allocated memory containing the textual representation of the
 * provided stacktrace.  Caller should free the memory when it's no
 * longer needed.
 */
char *
btp_core_stacktrace_to_text(struct btp_core_stacktrace *stacktrace);


struct btp_core_stacktrace *
btp_core_stacktrace_create(const char *gdb_stacktrace_text,
                          const char *unstrip_text,
                          const char *executable_path);

#ifdef __cplusplus
}
#endif

#endif