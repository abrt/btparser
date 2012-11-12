/*
    core_unwind.c

    Copyright (C) 2012  Red Hat, Inc.

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
#include "utils.h"
#include "core_frame.h"
#include "core_thread.h"
#include "core_stacktrace.h"
#include "config.h"

#if (defined HAVE_LIBELF_H && defined HAVE_GELF_H && defined HAVE_LIBELF && defined HAVE_LIBDW && defined HAVE_ELFUTILS_LIBDWFL_H)
#  define WITH_LIBDWFL
#endif

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#ifdef WITH_LIBDWFL
#include <libelf.h>
#include <gelf.h>
#include <elfutils/libdwfl.h>
#endif

#ifdef HAVE_LIBLZMA
#include <lzma.h>
#endif

/* Error/warning reporting macros. Allows the error reporting code to be less
 * verbose with the restrictions that:
 *  - pointer to error message pointer must be always named "error_msg"
 *  - the variable "elf_file" must always contain the filename that is operated
 *    on by the libelf
 */
#define set_error(fmt, ...) _set_error(error_msg, fmt, ##__VA_ARGS__)
#define set_error_elf(func) _set_error(error_msg, "%s failed for '%s': %s", \
        func, elf_file, elf_errmsg(-1))
#define warn_elf(func) warn("%s failed for '%s': %s", \
        func, elf_file, elf_errmsg(-1))
#define set_error_dwfl(func) _set_error(error_msg, "%s failed: %s", \
        func, dwfl_errmsg(-1))

#define list_append(head,tail,item)          \
    do{                                      \
        if (head == NULL)                    \
        {                                    \
            head = tail = item;              \
        }                                    \
        else                                 \
        {                                    \
            tail->next = item;               \
            tail = tail->next;               \
        }                                    \
    } while(0)

static void
_set_error(char **error_msg, const char *fmt, ...)
{
    va_list ap;

    if (error_msg == NULL)
        return;

    va_start(ap, fmt);
    *error_msg = btp_vasprintf(fmt, ap);
    va_end(ap);
}

#ifdef WITH_LIBDWFL

struct core_handle
{
    int fd;
    Elf *eh;
    Dwfl *dwfl;
    Dwfl *dwfl_minidebug; /* another dwfl handle, one that uses minidebuginfos */
    Dwfl_Callbacks cb;
    Dwfl_Callbacks cb_minidebug;
};

/* FIXME: is there another way to pass the executable name to the find_elf
 * callback? */
const char *executable_file = NULL;

static void
warn(const char *fmt, ...)
{
    va_list ap;

    if (!btp_debug_parser)
        return;

    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);

}

/* Delete the temporary file created in find_debuginfo_lzma. */
static int
unlink_tempfile(Dwfl_Module *mod, void **userdata, const char *name,
                Dwarf_Addr start_addr, void *arg)
{
    char *filename = *userdata;
    if (filename)
    {
        unlink(filename);
    }
    return DWARF_CB_OK;
}

static void
core_handle_free(struct core_handle *ch)
{
    if (ch)
    {
        if (ch->dwfl)
            dwfl_end(ch->dwfl);
        if (ch->dwfl_minidebug)
        {
            /* Delete the temporary files. */
            dwfl_getmodules(ch->dwfl_minidebug, unlink_tempfile, NULL, 0);
            dwfl_end(ch->dwfl_minidebug);
        }
        if (ch->eh)
            elf_end(ch->eh);
        if (ch->fd > 0)
            close(ch->fd);
        free(ch);
    }
}

static int
find_elf_core (Dwfl_Module *mod, void **userdata, const char *modname,
               Dwarf_Addr base, char **file_name, Elf **elfp)
{
    int ret = -1;

    if (strcmp("[exe]", modname) == 0 || strcmp("[pie]", modname) == 0)
    {
        int fd = open(executable_file, O_RDONLY);
        if (fd < 0)
            return -1;

        *file_name = realpath(executable_file, NULL);
        *elfp = elf_begin(fd, ELF_C_READ, NULL);
        if (*elfp == NULL)
        {
            warn("Unable to open executable '%s': %s", executable_file,
                 elf_errmsg(-1));
            return -1;
        }

        ret = fd;
    }
    else
    {
        ret = dwfl_build_id_find_elf(mod, userdata, modname, base,
                                     file_name, elfp);
    }

    return ret;
}

/* Do not use debuginfo files at all. */
static int
find_debuginfo_none (Dwfl_Module *mod, void **userdata, const char *modname,
                     GElf_Addr base, const char *file_name,
                     const char *debuglink_file, GElf_Word debuglink_crc,
                     char **debuginfo_file_name)
{
    return -1;
}

/* TODO: move all the LZMA stuff to its own file so that this one is not
 * polluted with #ifdefs. Requires private header. */
#ifdef HAVE_LIBLZMA
static Elf_Data*
get_gnu_debugdata(Elf *e)
{
    size_t shstrndx;
    if (elf_getshdrstrndx(e, &shstrndx) < 0)
        return NULL;

    Elf_Scn *scn = NULL;
    while ((scn = elf_nextscn(e, scn)) != NULL)
    {
        GElf_Shdr shdr;
        if (gelf_getshdr(scn, &shdr) != &shdr)
            return NULL;

        char *name = elf_strptr(e, shstrndx, shdr.sh_name);
        if (name == NULL)
            return NULL;

        if (strcmp(name, ".gnu_debugdata") == 0)
            break;
    }

    if (scn == NULL)
        return NULL;

    Elf_Data *data = elf_getdata(scn, NULL);
    if (data == NULL)
        return NULL;

    return data;
}

static int
do_write(int fd, const void *buf, size_t len)
{
    ssize_t ret;
    ssize_t total = 0;

    while (len)
    {
        ret = TEMP_FAILURE_RETRY(write(fd, buf, len));

        if (ret < 0)
        {
            if (total)
            {
                /* we already wrote some! */
                /* user can do another write to know the error code */
                return total;
            }
            return ret; /* write() returns -1 on failure. */
        }

        total += ret;
        buf = ((const char *)buf) + ret;
        len -= ret;
    }

    return total;
}

static int
unlzma_section_to_file(Elf_Data *data, char **filename)
{
    lzma_ret ret;
    lzma_stream strm = LZMA_STREAM_INIT;

    ret = lzma_stream_decoder(&strm, UINT64_MAX, 0);
    if (ret != LZMA_OK)
    {
        warn("Cannot initialize LZMA decoder: error code %u", ret);
        return -1;
    }

    /* NOTE: we may unlink the tempfile immediately and do not worry about
     * deleting them later. I'm not sure whether libdwfl doesn't require a
     * valid file name though. */
    char *fname = btp_strdup("/tmp/btparser.XXXXXX");
    int tempfd = mkstemp(fname);
    if (tempfd < 0)
    {
        warn("Cannot create temporary file: %s", strerror(errno));
        return -1;
    }

    uint8_t outbuf[BUFSIZ];
    strm.next_in = (uint8_t*)data->d_buf;
    strm.avail_in = data->d_size;
    strm.next_out = outbuf;
    strm.avail_out = sizeof(outbuf);
    ret = LZMA_OK;

    while(1)
    {
        ret = lzma_code(&strm, LZMA_RUN);

        if (strm.avail_out == 0 || ret == LZMA_STREAM_END)
        {
            size_t write_size = sizeof(outbuf) - strm.avail_out;
            if (do_write(tempfd, outbuf, write_size) != write_size)
            {
                warn("Unable to write to temporary file: %s", strerror(errno));
                goto fail_unlink;
            }

            strm.next_out = outbuf;
            strm.avail_out = sizeof(outbuf);
        }

        if (ret == LZMA_STREAM_END)
            break;

        if (ret != LZMA_OK)
        {
            warn("LZMA decoder failed: error code %u", ret);
            goto fail_unlink;
        }
    }

    *filename = fname;
    return tempfd;

fail_unlink:
    unlink(fname);
    close(tempfd);
    free(fname);
    return -1;
}

static int
find_debuginfo_lzma (Dwfl_Module *mod, void **userdata,
        const char *modname, GElf_Addr base, const char *file_name,
        const char *debuglink_file, GElf_Word debuglink_crc,
        char **debuginfo_file_name)
{
    btp_debug_parser = 1;

    /* Find the .gnu_debugdata section. */
    GElf_Addr bias;
    Elf *elf = dwfl_module_getelf(mod, &bias);
    if (!elf)
        return -1;

    Elf_Data *data = get_gnu_debugdata(elf);
    if (!data)
        return -1;

    /* UnLZMA to temporary file. */
    int fd = unlzma_section_to_file(data, debuginfo_file_name);

    /* Save the tempfile path so that we can delete it later. */
    *userdata = btp_strdup(*debuginfo_file_name);

    return fd;
}
#endif

static int
touch_module(Dwfl_Module *mod, void **userdata, const char *name,
             Dwarf_Addr start_addr, void *arg)
{
    GElf_Addr bias;

    if (dwfl_module_getelf (mod, &bias) == NULL)
    {
        warn("cannot find ELF for '%s': %s", name, dwfl_errmsg(-1));
        return DWARF_CB_OK;
    }

    return DWARF_CB_OK;
}

static Dwfl*
init_dwfl(Elf *e, Dwfl_Callbacks *dwcb, char **error_msg)
{
    Dwfl *dwfl = dwfl_begin(dwcb);

    if (dwfl_core_file_report(dwfl, e) == -1)
    {
        set_error_dwfl("dwfl_core_file_report");
        goto fail_dwfl;
    }

    if (dwfl_report_end(dwfl, NULL, NULL) != 0)
    {
        set_error_dwfl("dwfl_report_end");
        goto fail_dwfl;
    }

    /* needed so that module filenames are available during unwinding */
    ptrdiff_t ret = dwfl_getmodules(dwfl, touch_module, NULL, 0);
    if (ret == -1)
    {
        set_error_dwfl("dwfl_getmodules");
        goto fail_dwfl;
    }

    return dwfl;

fail_dwfl:
    dwfl_end(dwfl);
    return NULL;
}

/* Gets dwfl handle and executable map data to be used for unwinding */
static struct core_handle *
open_coredump(const char *elf_file, const char *exe_file, char **error_msg)
{
    struct core_handle *ch = btp_mallocz(sizeof(*ch));

    /* Initialize libelf, open the file and get its Elf handle. */
    if (elf_version(EV_CURRENT) == EV_NONE)
    {
        set_error_elf("elf_version");
        goto fail_free;
    }

    /* Open input file, and parse it. */
    ch->fd = open(elf_file, O_RDONLY);
    if (ch->fd < 0)
    {
        set_error("Unable to open '%s': %s", elf_file, strerror(errno));
        goto fail_free;
    }

    ch->eh = elf_begin(ch->fd, ELF_C_READ, NULL);
    if (ch->eh == NULL)
    {
        set_error_elf("elf_begin");
        goto fail_close;
    }

    /* Check that we are working with a coredump. */
    GElf_Ehdr ehdr;
    if (gelf_getehdr(ch->eh, &ehdr) == NULL || ehdr.e_type != ET_CORE)
    {
        set_error("File '%s' is not a coredump", elf_file);
        goto fail_elf;
    }

    executable_file = exe_file;

    /* We're initializing two dwfl instances, and you may ask why? This is a
     * workaround to support binaries containing "MiniDebugInfo" [1]. As of
     * today (Nov 2012), elfutils does not support this feature. Elfutils does
     * support custom hooks for supplying debuginfo file, so why not use those?
     *
     * The issue is in how elfutils handles symbol table lookup for a given
     * address. When either the main ELF file or the external debuginfo
     * contains .symtab section, this section is used for the lookup, as it is
     * assumed to be the full symbol table. Stripped binaries do not contain
     * this section so if it is not found .dynsym section is used. This section
     * contains only dynamic symbols and is a subset of the full symbol table.
     *
     * The "MiniDebugInfo" contained in .gnu_debugdata is a compressed
     * debuginfo file containing a .symtab section. This symtab section is,
     * however, not a superset of the .dynsym section of the binary - it
     * contains all the symbol table entries that are not in the .dynsym
     * section. So to get the full symbol table, you've got to merge the two.
     * Elfutils do not look up both .symtab and .dynsym, though.
     *
     * Here comes this ugly hack. We keep two independent dwfl handles, one
     * that accesses the .dynsym sections (or full .symtab if present) and the
     * other that accesses the .symtab sections from the MiniDebugInfo. The
     * MiniDebugInfo is uncompressed to a temporary file and deleted
     * afterwards. So whenever we try to resolve an address to a symbol, we do
     * this on both dwfl handles (and take the better result, see
     * resolve_addr_name).
     *
     * [1] http://fedoraproject.org/wiki/Features/MiniDebugInfo
     */
    ch->cb.find_elf = find_elf_core;
    ch->cb.find_debuginfo = find_debuginfo_none; /* dwfl_build_id_find_debuginfo; */
    ch->cb.section_address = dwfl_offline_section_address;
    ch->dwfl = init_dwfl(ch->eh, &(ch->cb), error_msg);
    if (!ch->dwfl)
        goto fail_elf;

#ifdef HAVE_LIBLZMA
    ch->cb_minidebug.find_elf = find_elf_core;
    ch->cb_minidebug.find_debuginfo = find_debuginfo_lzma;
    ch->cb_minidebug.section_address = dwfl_offline_section_address;
    ch->dwfl_minidebug = init_dwfl(ch->eh, &(ch->cb_minidebug), error_msg);
    if (!ch->dwfl_minidebug)
        goto fail_dwfl;
#endif

    return ch;

fail_dwfl:
    dwfl_end(ch->dwfl);
fail_elf:
    elf_end(ch->eh);
fail_close:
    close(ch->fd);
fail_free:
    free(ch);

    return NULL;
}

/* Resolve symbol in given dwfl instance. Returns true if the symbol has size
 * and thus is probably the function symbol. */
static bool
resolve_one(Dwfl *dwfl, GElf_Addr pc, const char **out_name, GElf_Addr *addr)
{
    const char *name;
    Dwfl_Module *mod;
    GElf_Sym sym;

    mod = dwfl_addrmodule(dwfl, pc);
    if (mod)
    {
        name = dwfl_module_addrsym(mod, pc, &sym, NULL);
        if (name)
        {
            if (sym.st_size > 0)
            {
                *out_name = name;
                return true;
            }
            else if (sym.st_value > *addr)
            {
                *out_name = name;
                *addr = sym.st_value;
            }
        }
    }

    return false;
}

static char*
resolve_addr_name(struct core_handle *ch, Dwarf_Addr pc)
{
    GElf_Addr sizeless_addr = 0;
    const char *name = NULL;

    /* If the first instance has symbol w/ size, return it.
     * Otherwise store the closest sizeless. */
    if (resolve_one(ch->dwfl, (GElf_Addr)pc, &name, &sizeless_addr))
        return btp_strdup(name);

    /* Only if we have dwfl instance for minidebuginfo:
     * If the second instance has symbol w/ size, return it.
     * If the closest symbol w/o size is closer than the previous, store it */
    if (ch->dwfl_minidebug
            && resolve_one(ch->dwfl_minidebug, (GElf_Addr)pc, &name,
                           &sizeless_addr))
        return btp_strdup(name);

    /* We did not find a symbol with size at this point.
     * Did we find *any* * symbol? */
    if (name)
        return btp_strdup(name);

    /* No symbol. */
    return NULL;
}

static struct btp_core_thread *
unwind_thread(struct core_handle *ch, Dwfl_Frame_State *state, char **error_msg)
{
    int ret;
    struct btp_core_frame *head = NULL, *tail = NULL;
    pid_t tid = 0;

    if (state)
    {
        tid = dwfl_frame_tid_get(state);
    }

    while (state)
    {
        Dwarf_Addr pc, pc_adjusted;
        bool minus_one;
        if (!dwfl_frame_state_pc(state, &pc, &minus_one))
        {
            warn("Failed to obtain PC: %s", dwfl_errmsg(-1));
            break;
        }
        pc_adjusted = pc - (minus_one ? 1 : 0);

        struct btp_core_frame *frame = btp_core_frame_new();
        frame->address = frame->build_id_offset = (uint64_t)pc;
        list_append(head, tail, frame);

        Dwfl_Module *mod = dwfl_addrmodule(ch->dwfl, pc_adjusted);
        if (mod)
        {
            const unsigned char *build_id_bits;
            const char *filename;
            GElf_Addr bid_addr;
            Dwarf_Addr start;

            ret = dwfl_module_build_id(mod, &build_id_bits, &bid_addr);
            if (ret > 0)
            {
                frame->build_id = btp_mallocz(2*ret + 1);
                btp_bin2hex(frame->build_id, (const char *)build_id_bits, ret);
            }

            if (dwfl_module_info(mod, NULL, &start, NULL, NULL, NULL,
                                 &filename, NULL) != NULL)
            {
                frame->build_id_offset = pc - start;
                if (filename)
                    frame->file_name = btp_strdup(filename);
            }
        }
        frame->function_name = resolve_addr_name(ch, pc_adjusted);

        if (!dwfl_frame_unwind(&state))
        {
            warn("Cannot unwind frame: %s", dwfl_errmsg(-1));
            break;
        }
    }

    if (!error_msg && !head)
    {
        set_error("No frames found for thread id %d", (int)tid);
    }

    struct btp_core_thread *thread = btp_core_thread_new();
    thread->tid = (int64_t)tid;
    thread->frames = head;
    return thread;
}

#endif /* WITH_LIBDWFL */

struct btp_core_stacktrace *
btp_parse_coredump(const char *core_file,
                   const char *exe_file,
                   char **error_msg)
{
#ifdef WITH_LIBDWFL
    struct btp_core_stacktrace *stacktrace = NULL;

    /* Initialize error_msg to 'no error'. */
    if (error_msg)
        *error_msg = NULL;

    struct core_handle *ch = open_coredump(core_file, exe_file, error_msg);
    if (*error_msg)
        return NULL;

    Dwfl_Frame_State *state = dwfl_frame_state_core(ch->dwfl, core_file);
    if (!state)
    {
        set_error("Failed to initialize frame state from core '%s'",
                   core_file);
        goto fail_destroy_handle;
    }

    stacktrace = btp_core_stacktrace_new();
    if (!stacktrace)
    {
        set_error("Failed to initialize stacktrace memory");
        goto fail_destroy_handle;
    }
    struct btp_core_thread *threads_tail = NULL;

    do
    {
        struct btp_core_thread *t = unwind_thread(ch, state, error_msg);
        if (*error_msg)
        {
            goto fail_destroy_trace;
        }
        list_append(stacktrace->threads, threads_tail, t);
        state = dwfl_frame_thread_next(state);
    } while (state);

fail_destroy_trace:
    if (*error_msg)
    {
        btp_core_stacktrace_free(stacktrace);
        stacktrace = NULL;
    }
fail_destroy_handle:
    core_handle_free(ch);

    stacktrace->executable = btp_strdup(executable_file);
    /* FIXME: determine signal */
    stacktrace->signal = 0;
    /* FIXME: is this the best we can do? */
    stacktrace->crash_thread = stacktrace->threads;
    return stacktrace;

#else /* WITH_LIBDWFL */
    set_error("Btparser is built without elfutils-based unwind support");
    return NULL;
#endif /* WITH_LIBDWFL */
}
