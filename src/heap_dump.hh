/*
 * heap_walk.h — Walk the glibc 2.39 main-arena heap and list every chunk.
 *
 * Usage:
 *     #include "heap_walk.h"
 *
 *     heap_walk();                   // list all chunks
 *     heap_walk_known_structs(ptr);  // search for known types + a tracked pointer
 */

#ifndef HEAP_WALK_H
#define HEAP_WALK_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "http.hh"

/* ── Constants & flag masks ──────────────────────────────────────────── */

#define HW_PREV_INUSE  0x1
#define HW_IS_MMAPPED  0x2
#define HW_NON_MAIN    0x4
#define HW_SIZE_MASK   (~(size_t)0x7)

#define HW_SIZE_SZ         sizeof(size_t)
#define HW_MIN_CHUNK_SIZE  (4 * HW_SIZE_SZ)
#define HW_CHUNK_ALIGN     (2 * HW_SIZE_SZ)

/* ── Chunk header ────────────────────────────────────────────────────── */

typedef struct hw_chunk {
    size_t prev_size;
    size_t size;
} hw_chunk_t;

/* ── Accessors ───────────────────────────────────────────────────────── */

static inline size_t hw_chk_size(const hw_chunk_t *c)    { return c->size & HW_SIZE_MASK; }
static inline int    hw_chk_pinuse(const hw_chunk_t *c)  { return c->size & HW_PREV_INUSE; }
static inline int    hw_chk_mmapped(const hw_chunk_t *c) { return c->size & HW_IS_MMAPPED; }
static inline int    hw_chk_nonmain(const hw_chunk_t *c) { return c->size & HW_NON_MAIN;   }

/* ── Locate the [heap] mapping ───────────────────────────────────────── */

static int hw_find_heap_region(uintptr_t *start, uintptr_t *end)
{
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) { perror("heap_walk: fopen(/proc/self/maps)"); return -1; }

    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "[heap]")) {
            unsigned long s, e;
            if (sscanf(line, "%lx-%lx", &s, &e) == 2) {
                *start = (uintptr_t)s;
                *end   = (uintptr_t)e;
                fclose(fp);
                return 0;
            }
        }
    }
    fclose(fp);
    fprintf(stderr, "heap_walk: [heap] not found in /proc/self/maps\n");
    return -1;
}

/* ── Chain validation ────────────────────────────────────────────────── */

#define HW_MIN_CHAIN  3

static int hw_validate_chain(uintptr_t addr, uintptr_t heap_end)
{
    unsigned  count = 0;
    uintptr_t cur   = addr;

    while (cur + HW_MIN_CHUNK_SIZE <= heap_end && count < HW_MIN_CHAIN) {
        const hw_chunk_t *ch = (const hw_chunk_t *)cur;
        size_t sz = hw_chk_size(ch);

        if (sz < HW_MIN_CHUNK_SIZE)        return 0;
        if (sz & (HW_CHUNK_ALIGN - 1))     return 0;
        if (cur + sz > heap_end)            return 0;
        if (hw_chk_mmapped(ch))             return 0;
        if (hw_chk_nonmain(ch))             return 0;

        if (cur + sz >= heap_end)
            return 1;

        cur += sz;
        count++;
    }
    return count >= HW_MIN_CHAIN;
}

/* ── Find the first real chunk ───────────────────────────────────────── */

static uintptr_t hw_find_first_chunk(uintptr_t heap_start, uintptr_t heap_end)
{
    for (uintptr_t a = heap_start;
         a + HW_MIN_CHUNK_SIZE <= heap_end;
         a += HW_CHUNK_ALIGN)
    {
        const hw_chunk_t *ch = (const hw_chunk_t *)a;
        size_t sz = hw_chk_size(ch);

        if (sz < HW_MIN_CHUNK_SIZE)        continue;
        if (sz & (HW_CHUNK_ALIGN - 1))     continue;
        if (a + sz > heap_end)             continue;
        if (!hw_chk_pinuse(ch))            continue;
        if (hw_chk_mmapped(ch))            continue;
        if (hw_chk_nonmain(ch))            continue;

        if (hw_validate_chain(a, heap_end))
            return a;
    }
    return 0;
}

/* ── Walk every chunk in the main-arena heap ─────────────────────────── */

static int heap_walk(void)
{
    uintptr_t heap_start, heap_end;
    if (hw_find_heap_region(&heap_start, &heap_end) != 0)
        return -1;

    printf("=== Heap Walk (glibc 2.39, main arena) ===\n");
    printf("Heap region : 0x%lx - 0x%lx  (%zu bytes)\n",
           (unsigned long)heap_start, (unsigned long)heap_end,
           (size_t)(heap_end - heap_start));

    uintptr_t first = hw_find_first_chunk(heap_start, heap_end);
    if (!first) {
        fprintf(stderr, "heap_walk: could not locate the first chunk\n");
        return -1;
    }

    if (first != heap_start)
        printf("First chunk : 0x%lx  (+%zu bytes from mapping start)\n",
               (unsigned long)first, (size_t)(first - heap_start));

    printf("\n%-4s  %-18s  %-18s  %10s  %5s  %s\n",
           "#", "Chunk Addr", "User Addr", "Size", "Flags", "Status");
    printf("--------------------------------------------------------------"
           "-------------------\n");

    uintptr_t cursor = first;
    unsigned  idx    = 0;

    while (cursor + HW_MIN_CHUNK_SIZE <= heap_end) {
        const hw_chunk_t *ch = (const hw_chunk_t *)cursor;
        size_t csize = hw_chk_size(ch);

        if (csize < HW_MIN_CHUNK_SIZE || (csize & (HW_CHUNK_ALIGN - 1))) {
            fprintf(stderr,
                    "\nheap_walk: corrupt chunk #%u at 0x%lx "
                    "(raw size = 0x%zx). Stopping.\n",
                    idx, (unsigned long)cursor, ch->size);
            break;
        }
        if (cursor + csize > heap_end) {
            fprintf(stderr,
                    "\nheap_walk: chunk #%u at 0x%lx overflows heap "
                    "(size = %zu). Stopping.\n",
                    idx, (unsigned long)cursor, csize);
            break;
        }

        uintptr_t user_ptr = cursor + 2 * HW_SIZE_SZ;

        char flags[4] = {
            hw_chk_pinuse(ch)  ? 'P' : '-',
            hw_chk_mmapped(ch) ? 'M' : '-',
            hw_chk_nonmain(ch) ? 'A' : '-',
            '\0'
        };

        int is_top = (cursor + csize >= heap_end);
        const char *status;

        if (is_top) {
            status = "top (wilderness)";
        } else {
            const hw_chunk_t *next =
                (const hw_chunk_t *)(cursor + csize);
            status = hw_chk_pinuse(next) ? "in-use" : "free";
        }

        printf("%-4u  0x%016lx  0x%016lx  %10zu  %5s  %s\n",
               idx,
               (unsigned long)cursor,
               (unsigned long)user_ptr,
               csize,
               flags,
               status);

        cursor += csize;
        idx++;
        if (is_top) break;
    }

    printf("\nTotal chunks walked: %u\n", idx);
    return 0;
}

/* ====================================================================
 * Vtable-based object search (generic)
 * ==================================================================== */

static inline const void *hw_vptr(const void *obj)
{
    return *(const void *const *)obj;
}

static inline int hw_chunk_has_vptr(uintptr_t user_ptr, size_t chunk_size,
                                    const void *target_vptr)
{
    if (chunk_size < 2 * HW_SIZE_SZ + sizeof(void *))
        return 0;
    const void *first_word = *(const void *const *)user_ptr;
    return first_word == target_vptr;
}

/* ── Size histogram with in-use / free separation ────────────────────── */

typedef struct hw_size_bucket {
    size_t   chunk_size;
    unsigned count;
} hw_size_bucket_t;

typedef struct hw_size_histogram {
    hw_size_bucket_t *buckets;
    unsigned          n_buckets;
    unsigned          capacity;
} hw_size_histogram_t;

static void hw_hist_init(hw_size_histogram_t *h)
{
    h->buckets   = NULL;
    h->n_buckets = 0;
    h->capacity  = 0;
}

static void hw_hist_free(hw_size_histogram_t *h)
{
    free(h->buckets);
    hw_hist_init(h);
}

static void hw_hist_add(hw_size_histogram_t *h, size_t chunk_size)
{
    for (unsigned i = 0; i < h->n_buckets; i++) {
        if (h->buckets[i].chunk_size == chunk_size) {
            h->buckets[i].count++;
            return;
        }
    }
    if (h->n_buckets == h->capacity) {
        unsigned new_cap = h->capacity ? h->capacity * 2 : 32;
        hw_size_bucket_t *tmp = (hw_size_bucket_t *)realloc(
            h->buckets, new_cap * sizeof(hw_size_bucket_t));
        if (!tmp) { fprintf(stderr, "heap_walk: OOM\n"); return; }
        h->buckets  = tmp;
        h->capacity = new_cap;
    }
    h->buckets[h->n_buckets].chunk_size = chunk_size;
    h->buckets[h->n_buckets].count      = 1;
    h->n_buckets++;
}

static int hw_bucket_cmp(const void *a, const void *b)
{
    const hw_size_bucket_t *ba = (const hw_size_bucket_t *)a;
    const hw_size_bucket_t *bb = (const hw_size_bucket_t *)b;
    if (ba->chunk_size < bb->chunk_size) return -1;
    if (ba->chunk_size > bb->chunk_size) return  1;
    return 0;
}

static void hw_hist_print_section(const hw_size_histogram_t *h,
                                  const char *indent,
                                  const char *label)
{
    if (h->n_buckets == 0) return;

    hw_size_bucket_t *sorted = (hw_size_bucket_t *)malloc(
        h->n_buckets * sizeof(hw_size_bucket_t));
    if (!sorted) { fprintf(stderr, "heap_walk: OOM\n"); return; }
    memcpy(sorted, h->buckets, h->n_buckets * sizeof(hw_size_bucket_t));
    qsort(sorted, h->n_buckets, sizeof(hw_size_bucket_t), hw_bucket_cmp);

    unsigned total_chunks = 0;
    size_t   total_bytes  = 0;
    for (unsigned i = 0; i < h->n_buckets; i++) {
        total_chunks += sorted[i].count;
        total_bytes  += sorted[i].count * sorted[i].chunk_size;
    }

    printf("%s%s: %u chunk%s (%zu bytes)\n",
           indent, label,
           total_chunks, total_chunks == 1 ? "" : "s",
           total_bytes);

    for (unsigned i = 0; i < h->n_buckets; i++) {
        printf("%s    %4u × %zu bytes\n",
               indent,
               sorted[i].count,
               sorted[i].chunk_size);
    }

    free(sorted);
}

static void hw_hist_reset(hw_size_histogram_t *h)
{
    h->n_buckets = 0;
}

/* ── Generic heap search by vptr (unchanged) ─────────────────────────── */

static int heap_find_by_vptr(const void *target_vptr, const char *type_name)
{
    uintptr_t heap_start, heap_end;
    if (hw_find_heap_region(&heap_start, &heap_end) != 0)
        return -1;

    uintptr_t first = hw_find_first_chunk(heap_start, heap_end);
    if (!first) {
        fprintf(stderr, "heap_find_by_vptr: could not locate the first chunk\n");
        return -1;
    }

    printf("=== Heap Search: looking for \"%s\" (vptr = %p) ===\n",
           type_name, target_vptr);
    printf("Heap region : 0x%lx - 0x%lx  (%zu bytes)\n\n",
           (unsigned long)heap_start, (unsigned long)heap_end,
           (size_t)(heap_end - heap_start));

    uintptr_t cursor = first;
    unsigned  idx    = 0;
    unsigned  found  = 0;

    hw_size_histogram_t hist_inuse, hist_free;
    hw_hist_init(&hist_inuse);
    hw_hist_init(&hist_free);

    #define HW_FLUSH_OTHER_GENERIC() do {                                  \
        if (hist_inuse.n_buckets > 0 || hist_free.n_buckets > 0) {         \
            printf("      ... other:\n");                                   \
            hw_hist_print_section(&hist_inuse, "          ", "In-use");     \
            hw_hist_print_section(&hist_free,  "          ", "Free");       \
            hw_hist_reset(&hist_inuse);                                     \
            hw_hist_reset(&hist_free);                                      \
            printf("\n");                                                   \
        }                                                                   \
    } while (0)

    while (cursor + HW_MIN_CHUNK_SIZE <= heap_end) {
        const hw_chunk_t *ch = (const hw_chunk_t *)cursor;
        size_t csize = hw_chk_size(ch);

        if (csize < HW_MIN_CHUNK_SIZE || (csize & (HW_CHUNK_ALIGN - 1)))
            break;
        if (cursor + csize > heap_end)
            break;

        uintptr_t user_ptr = cursor + 2 * HW_SIZE_SZ;
        int       is_top   = (cursor + csize >= heap_end);

        int is_free = 0;
        if (!is_top) {
            const hw_chunk_t *next = (const hw_chunk_t *)(cursor + csize);
            is_free = !hw_chk_pinuse(next);
        }

        int match = 0;
        if (!is_top && !is_free) {
            match = hw_chunk_has_vptr(user_ptr, csize, target_vptr);
        }

        if (match) {
            HW_FLUSH_OTHER_GENERIC();

            char flags[4] = {
                hw_chk_pinuse(ch)  ? 'P' : '-',
                hw_chk_mmapped(ch) ? 'M' : '-',
                hw_chk_nonmain(ch) ? 'A' : '-',
                '\0'
            };

            printf("[%s]  #%-4u  chunk=0x%lx  user=0x%lx  "
                   "size=%-6zu  flags=%s  in-use\n",
                   type_name,
                   idx,
                   (unsigned long)cursor,
                   (unsigned long)user_ptr,
                   csize,
                   flags);
            found++;
        } else {
            if (is_free)
                hw_hist_add(&hist_free, csize);
            else
                hw_hist_add(&hist_inuse, csize);
        }

        cursor += csize;
        idx++;
        if (is_top) break;
    }

    if (hist_inuse.n_buckets > 0 || hist_free.n_buckets > 0) {
        printf("\n");
        printf("      ... other:\n");
        hw_hist_print_section(&hist_inuse, "          ", "In-use");
        hw_hist_print_section(&hist_free,  "          ", "Free");
    }

    hw_hist_free(&hist_inuse);
    hw_hist_free(&hist_free);

    printf("\nFound %u \"%s\" instance%s in %u total chunks.\n",
           found, type_name, found == 1 ? "" : "s", idx);

    #undef HW_FLUSH_OTHER_GENERIC
    return (int)found;
}

/* ====================================================================
 * Connection-specific search with string buffer tracking
 * and extra named pointer tracking
 * ==================================================================== */

#define HW_MAX_CONNS          128
#define HW_MAX_EXTRA_PTRS     16

typedef struct hw_tracked_buf {
    unsigned    conn_id;
    const char *label;
    uintptr_t   data_ptr;
    size_t      str_size;
} hw_tracked_buf_t;

typedef struct hw_conn_info {
    uintptr_t chunk_addr;
    uintptr_t user_addr;
    size_t    chunk_size;
} hw_conn_info_t;

typedef struct hw_extra_ptr {
    const char *label;
    uintptr_t   ptr;       /* points somewhere inside a chunk's user data */
} hw_extra_ptr_t;

static inline int hw_string_is_heap(uintptr_t str_data,
                                    uintptr_t owner_chunk,
                                    size_t    owner_chunk_size)
{
    return str_data < owner_chunk || str_data >= owner_chunk + owner_chunk_size;
}

/*
 * Check whether a pointer falls inside a chunk's user data region.
 * The pointer doesn't have to be at the start — it could point
 * partway into the allocation (e.g. a StrView into a string's buffer).
 */
static inline int hw_ptr_in_chunk(uintptr_t ptr,
                                  uintptr_t chunk_addr,
                                  size_t    chunk_size)
{
    uintptr_t user_start = chunk_addr + 2 * HW_SIZE_SZ;
    uintptr_t user_end   = chunk_addr + chunk_size;
    return ptr >= user_start && ptr < user_end;
}

static int heap_find_connections(const hw_extra_ptr_t *extra_ptrs,
                                 unsigned              n_extra_ptrs)
{
    uintptr_t heap_start, heap_end;
    if (hw_find_heap_region(&heap_start, &heap_end) != 0)
        return -1;

    uintptr_t first = hw_find_first_chunk(heap_start, heap_end);
    if (!first) {
        fprintf(stderr, "heap_find_connections: could not locate the first chunk\n");
        return -1;
    }

    http::Connection probe;
    const void *conn_vptr = hw_vptr(&probe);

    /* ── Pass 1: collect Connection locations & string data pointers ── */

    hw_conn_info_t   conns[HW_MAX_CONNS];
    hw_tracked_buf_t tracked[HW_MAX_CONNS * 2];
    unsigned n_conns   = 0;
    unsigned n_tracked = 0;

    uintptr_t cursor = first;
    while (cursor + HW_MIN_CHUNK_SIZE <= heap_end) {
        const hw_chunk_t *ch = (const hw_chunk_t *)cursor;
        size_t csize = hw_chk_size(ch);

        if (csize < HW_MIN_CHUNK_SIZE || (csize & (HW_CHUNK_ALIGN - 1)))
            break;
        if (cursor + csize > heap_end)
            break;

        uintptr_t user_ptr = cursor + 2 * HW_SIZE_SZ;
        int is_top = (cursor + csize >= heap_end);

        if (!is_top) {
            const hw_chunk_t *next = (const hw_chunk_t *)(cursor + csize);
            int in_use = hw_chk_pinuse(next);

            if (in_use &&
                hw_chunk_has_vptr(user_ptr, csize, conn_vptr) &&
                n_conns < HW_MAX_CONNS)
            {
                unsigned id = n_conns;
                conns[n_conns].chunk_addr = cursor;
                conns[n_conns].user_addr  = user_ptr;
                conns[n_conns].chunk_size = csize;
                n_conns++;

                const http::Connection *conn =
                    (const http::Connection *)user_ptr;

                uintptr_t req_data = (uintptr_t)conn->request_buffer.data();
                if (hw_string_is_heap(req_data, cursor, csize) &&
                    n_tracked < HW_MAX_CONNS * 2)
                {
                    tracked[n_tracked].conn_id  = id;
                    tracked[n_tracked].label    = "request_buffer";
                    tracked[n_tracked].data_ptr = req_data;
                    tracked[n_tracked].str_size = conn->request_buffer.size();
                    n_tracked++;
                }

                uintptr_t resp_data = (uintptr_t)conn->response_buffer.data();
                if (hw_string_is_heap(resp_data, cursor, csize) &&
                    n_tracked < HW_MAX_CONNS * 2)
                {
                    tracked[n_tracked].conn_id  = id;
                    tracked[n_tracked].label    = "response_buffer";
                    tracked[n_tracked].data_ptr = resp_data;
                    tracked[n_tracked].str_size = conn->response_buffer.size();
                    n_tracked++;
                }
            }
        }

        cursor += csize;
        if (is_top) break;
    }

    /* ── Pass 2: display ─────────────────────────────────────────────── */

    printf("=== Heap Search: Connection objects (vptr = %p) ===\n", conn_vptr);
    printf("Heap region  : 0x%lx - 0x%lx  (%zu bytes)\n",
           (unsigned long)heap_start, (unsigned long)heap_end,
           (size_t)(heap_end - heap_start));
    printf("Connections  : %u found\n", n_conns);
    printf("String bufs  : %u on heap (%u possible, rest are SSO)\n",
           n_tracked, n_conns * 2);
    if (n_extra_ptrs > 0) {
        printf("Extra tracked:\n");
        for (unsigned i = 0; i < n_extra_ptrs; i++) {
            printf("  %-30s  ptr=0x%lx\n",
                   extra_ptrs[i].label,
                   (unsigned long)extra_ptrs[i].ptr);
        }
    }
    printf("\n");

    hw_size_histogram_t hist_inuse, hist_free;
    hw_hist_init(&hist_inuse);
    hw_hist_init(&hist_free);

    #define HW_FLUSH_OTHER_CONN() do {                                     \
        if (hist_inuse.n_buckets > 0 || hist_free.n_buckets > 0) {         \
            printf("      ... other:\n");                                   \
            hw_hist_print_section(&hist_inuse, "          ", "In-use");     \
            hw_hist_print_section(&hist_free,  "          ", "Free");       \
            hw_hist_reset(&hist_inuse);                                     \
            hw_hist_reset(&hist_free);                                      \
            printf("\n");                                                   \
        }                                                                   \
    } while (0)

    cursor = first;
    unsigned idx       = 0;
    unsigned conn_idx  = 0;

    while (cursor + HW_MIN_CHUNK_SIZE <= heap_end) {
        const hw_chunk_t *ch = (const hw_chunk_t *)cursor;
        size_t csize = hw_chk_size(ch);

        if (csize < HW_MIN_CHUNK_SIZE || (csize & (HW_CHUNK_ALIGN - 1)))
            break;
        if (cursor + csize > heap_end)
            break;

        uintptr_t user_ptr = cursor + 2 * HW_SIZE_SZ;
        int       is_top   = (cursor + csize >= heap_end);

        int is_free = 0;
        if (!is_top) {
            const hw_chunk_t *next = (const hw_chunk_t *)(cursor + csize);
            is_free = !hw_chk_pinuse(next);
        }

        /* Check: Connection chunk? */
        int is_conn = 0;
        unsigned this_conn_id = 0;
        if (conn_idx < n_conns && cursor == conns[conn_idx].chunk_addr) {
            is_conn      = 1;
            this_conn_id = conn_idx;
            conn_idx++;
        }

        /* Check: tracked string buffer? */
        int is_strbuf = 0;
        unsigned strbuf_idx = 0;
        if (!is_conn && !is_free && !is_top) {
            for (unsigned i = 0; i < n_tracked; i++) {
                if (tracked[i].data_ptr == user_ptr) {
                    is_strbuf  = 1;
                    strbuf_idx = i;
                    break;
                }
            }
        }

        /* Check: extra tracked pointer? (can point anywhere in the chunk) */
        int is_extra = 0;
        unsigned extra_idx = 0;
        if (!is_conn && !is_strbuf && !is_free && !is_top) {
            for (unsigned i = 0; i < n_extra_ptrs; i++) {
                if (hw_ptr_in_chunk(extra_ptrs[i].ptr, cursor, csize)) {
                    is_extra  = 1;
                    extra_idx = i;
                    break;
                }
            }
        }

        if (is_conn) {
            HW_FLUSH_OTHER_CONN();

            char flags[4] = {
                hw_chk_pinuse(ch)  ? 'P' : '-',
                hw_chk_mmapped(ch) ? 'M' : '-',
                hw_chk_nonmain(ch) ? 'A' : '-',
                '\0'
            };

            printf("[Connection %u]  #%-4u  chunk=0x%lx  user=0x%lx  "
                   "size=%-6zu  flags=%s  in-use\n",
                   this_conn_id, idx,
                   (unsigned long)cursor,
                   (unsigned long)user_ptr,
                   csize, flags);

            const http::Connection *conn =
                (const http::Connection *)user_ptr;

            uintptr_t req_data = (uintptr_t)conn->request_buffer.data();
            if (hw_string_is_heap(req_data, cursor, csize)) {
                printf("    request_buffer:  heap  data=0x%lx  size=%zu\n",
                       (unsigned long)req_data,
                       conn->request_buffer.size());
            } else {
                printf("    request_buffer:  SSO   size=%zu\n",
                       conn->request_buffer.size());
            }

            uintptr_t resp_data = (uintptr_t)conn->response_buffer.data();
            if (hw_string_is_heap(resp_data, cursor, csize)) {
                printf("    response_buffer: heap  data=0x%lx  size=%zu\n",
                       (unsigned long)resp_data,
                       conn->response_buffer.size());
            } else {
                printf("    response_buffer: SSO   size=%zu\n",
                       conn->response_buffer.size());
            }

        } else if (is_strbuf) {
            HW_FLUSH_OTHER_CONN();

            printf("  [%s %u]  #%-4u  chunk=0x%lx  user=0x%lx  "
                   "chunk_size=%-6zu  str_size=%zu\n",
                   tracked[strbuf_idx].label,
                   tracked[strbuf_idx].conn_id,
                   idx,
                   (unsigned long)cursor,
                   (unsigned long)user_ptr,
                   csize,
                   tracked[strbuf_idx].str_size);

        } else if (is_extra) {
            HW_FLUSH_OTHER_CONN();

            size_t offset = (size_t)(extra_ptrs[extra_idx].ptr - user_ptr);

            printf("  [%s]  #%-4u  chunk=0x%lx  user=0x%lx  "
                   "chunk_size=%-6zu  ptr_offset=+%zu\n",
                   extra_ptrs[extra_idx].label,
                   idx,
                   (unsigned long)cursor,
                   (unsigned long)user_ptr,
                   csize,
                   offset);

        } else {
            if (is_free)
                hw_hist_add(&hist_free, csize);
            else
                hw_hist_add(&hist_inuse, csize);
        }

        cursor += csize;
        idx++;
        if (is_top) break;
    }

    if (hist_inuse.n_buckets > 0 || hist_free.n_buckets > 0) {
        printf("\n");
        printf("      ... other:\n");
        hw_hist_print_section(&hist_inuse, "          ", "In-use");
        hw_hist_print_section(&hist_free,  "          ", "Free");
    }

    hw_hist_free(&hist_inuse);
    hw_hist_free(&hist_free);

    printf("\nTotal: %u Connection%s, %u string buffer%s on heap, "
           "%u chunks walked.\n",
           n_conns,   n_conns   == 1 ? "" : "s",
           n_tracked, n_tracked == 1 ? "" : "s",
           idx);

    #undef HW_FLUSH_OTHER_CONN
    return (int)n_conns;
}

/* ── Search for known struct types ───────────────────────────────────── */

static int heap_walk_known_structs(const void *update_response_ptr)
{
    hw_extra_ptr_t extras[1];
    unsigned n_extras = 0;

    if (update_response_ptr) {
        extras[0].label = "Update Get Response";
        extras[0].ptr   = (uintptr_t)update_response_ptr;
        n_extras = 1;
    }

    return heap_find_connections(extras, n_extras);
}

#endif /* HEAP_WALK_H */
