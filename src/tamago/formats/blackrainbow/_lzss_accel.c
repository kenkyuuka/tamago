/*
 * _lzss_accel.c — C accelerator for the classic Okumura LZSS stream.
 *
 * The stream: a 4 KiB ring buffer that starts zero-filled with its write
 * position at 0xFEE, flag bytes read LSB first (1 = literal, 0 = reference),
 * and two-byte references holding a 12-bit absolute ring position and a 4-bit
 * length (3 to 18 bytes).
 *
 * Three functions, each giving exactly the same output as its pure-Python
 * reference, which is also the fallback when this module is unavailable:
 *
 *   decompress(data, size)  blackrainbow/lzss.py decompress (shared by AI6WIN)
 *   compress_greedy(data)   blackrainbow/lzss.py compress
 *   compress_okumura(data)  ai6win/lzss.py compress
 */

#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define RING_SIZE 0x1000
#define RING_MASK (RING_SIZE - 1)
#define RING_START 0xFEE
#define MIN_MATCH 3
#define MAX_MATCH 18

/* ------------------------------------------------------------------------ */
/* Decompression                                                            */
/* ------------------------------------------------------------------------ */

enum { DEC_OK = 0, DEC_TRUNCATED, DEC_TRUNCATED_REF };

/*
 * Decode into out, which holds RING_SIZE zero bytes followed by room for
 * size more: the zeros stand in for the ring's initial contents, so every
 * ring position corresponds to a distance back into out.
 */
static int lzss_decompress(const unsigned char *src, Py_ssize_t end, unsigned char *out, Py_ssize_t size,
                           Py_ssize_t *produced, Py_ssize_t *fail_at)
{
    Py_ssize_t i = 0;
    Py_ssize_t o = RING_SIZE;
    Py_ssize_t limit = RING_SIZE + size;

    while (o < limit) {
        unsigned flags;
        int bit;
        if (i >= end)
            goto truncated;
        flags = src[i++];
        for (bit = 0; bit < 8 && o < limit; bit++) {
            if (flags >> bit & 1) {
                if (i >= end)
                    goto truncated;
                out[o++] = src[i++];
            } else {
                unsigned lo, hi, position, length, write_pos, distance;
                Py_ssize_t from, n;
                if (i + 1 >= end) {
                    *fail_at = i;
                    return DEC_TRUNCATED_REF;
                }
                lo = src[i];
                hi = src[i + 1];
                i += 2;
                position = lo | (hi & 0xF0) << 4;
                length = (hi & 0x0F) + MIN_MATCH;
                write_pos = (unsigned)((RING_START + o) & RING_MASK);
                distance = (write_pos - position) & RING_MASK;
                if (!distance)
                    distance = RING_SIZE;
                from = o - distance;
                n = length;
                if (n > limit - o)
                    n = limit - o;
                /* Byte by byte, so a source overlapping the output repeats. */
                while (n--)
                    out[o++] = out[from++];
            }
        }
    }
    *produced = size;
    return DEC_OK;

truncated:
    *produced = o - RING_SIZE;
    return DEC_TRUNCATED;
}

static PyObject *py_decompress(PyObject *self, PyObject *args)
{
    Py_buffer buf;
    Py_ssize_t size, produced = 0, fail_at = 0;
    unsigned char *out;
    PyObject *result;
    int rc;

    if (!PyArg_ParseTuple(args, "y*n", &buf, &size))
        return NULL;
    if (size < 0) {
        PyBuffer_Release(&buf);
        PyErr_SetString(PyExc_ValueError, "size must not be negative");
        return NULL;
    }
    if (size > PY_SSIZE_T_MAX - RING_SIZE) {
        PyBuffer_Release(&buf);
        return PyErr_NoMemory();
    }
    out = (unsigned char *)calloc((size_t)(RING_SIZE + size), 1);
    if (!out) {
        PyBuffer_Release(&buf);
        return PyErr_NoMemory();
    }
    Py_BEGIN_ALLOW_THREADS
    rc = lzss_decompress((const unsigned char *)buf.buf, buf.len, out, size, &produced, &fail_at);
    Py_END_ALLOW_THREADS
    PyBuffer_Release(&buf);

    if (rc == DEC_TRUNCATED) {
        PyErr_Format(PyExc_ValueError, "LZSS stream ended after %zd of %zd bytes", produced, size);
        result = NULL;
    } else if (rc == DEC_TRUNCATED_REF) {
        PyErr_Format(PyExc_ValueError, "LZSS stream ended inside a reference at offset %zd", fail_at);
        result = NULL;
    } else {
        result = PyBytes_FromStringAndSize((const char *)out + RING_SIZE, size);
    }
    free(out);
    return result;
}

/* ------------------------------------------------------------------------ */
/* Output buffer shared by the encoders                                     */
/* ------------------------------------------------------------------------ */

/* Worst case: every byte a literal, plus one flag byte per eight. */
static Py_ssize_t max_compressed(Py_ssize_t n)
{
    return n + (n + 7) / 8;
}

/* ------------------------------------------------------------------------ */
/* Greedy encoder (BlackRainbow)                                            */
/* ------------------------------------------------------------------------ */

/*
 * At each position, the longest match of 3-18 bytes whose source starts 1 to
 * 4096 bytes back (it may overlap the bytes being encoded), the nearest one
 * among equally long matches, else a literal.  The Python version finds that
 * match with rfind and a binary search on the length; this one walks a hash
 * chain of earlier positions, nearest first, and keeps the first candidate
 * of each new best length, which picks the same match.
 */

#define HASH_BITS 16
#define HASH_SIZE (1 << HASH_BITS)

static unsigned hash3(const unsigned char *p)
{
    return ((unsigned)p[0] << 8 ^ (unsigned)p[1] << 4 ^ (unsigned)p[2]) * 2654435761u >> (32 - HASH_BITS);
}

static Py_ssize_t compress_greedy(const unsigned char *src, Py_ssize_t end, unsigned char *out,
                                  int32_t *head, int32_t *prev)
{
    Py_ssize_t pos = 0, inserted = 0, o = 0;
    int32_t k;

    for (k = 0; k < HASH_SIZE; k++)
        head[k] = -1;

    while (pos < end) {
        Py_ssize_t flag_at = o++;
        unsigned flags = 0;
        int bit;
        for (bit = 0; bit < 8 && pos < end; bit++) {
            Py_ssize_t longest = end - pos, window = pos - RING_SIZE, best_len = 0, best_at = 0;
            if (longest > MAX_MATCH)
                longest = MAX_MATCH;
            if (window < 0)
                window = 0;
            /* Every position before pos that starts a full 3-byte sequence. */
            while (inserted < pos && inserted + MIN_MATCH <= end) {
                unsigned h = hash3(src + inserted);
                prev[inserted] = head[h];
                head[h] = (int32_t)inserted;
                inserted++;
            }
            if (longest >= MIN_MATCH) {
                int32_t cand = head[hash3(src + pos)];
                while (cand >= 0 && cand >= window) {
                    const unsigned char *a = src + cand, *b = src + pos;
                    Py_ssize_t n = 0;
                    while (n < longest && a[n] == b[n])
                        n++;
                    if (n >= MIN_MATCH && n > best_len) {
                        best_len = n;
                        best_at = cand;
                        if (n == longest)
                            break;
                    }
                    cand = prev[cand];
                }
            }
            if (best_len) {
                unsigned position = (unsigned)((RING_START + best_at) & RING_MASK);
                out[o++] = (unsigned char)(position & 0xFF);
                out[o++] = (unsigned char)((position >> 4 & 0xF0) | (unsigned)(best_len - MIN_MATCH));
                pos += best_len;
            } else {
                flags |= 1u << bit;
                out[o++] = src[pos++];
            }
        }
        out[flag_at] = (unsigned char)flags;
    }
    return o;
}

static PyObject *py_compress_greedy(PyObject *self, PyObject *args)
{
    Py_buffer buf;
    unsigned char *out;
    int32_t *head, *prev;
    Py_ssize_t n;
    PyObject *result;

    if (!PyArg_ParseTuple(args, "y*", &buf))
        return NULL;
    if (buf.len > INT32_MAX) {
        PyBuffer_Release(&buf);
        PyErr_SetString(PyExc_OverflowError, "data too large");
        return NULL;
    }
    out = (unsigned char *)malloc((size_t)max_compressed(buf.len) + 1);
    head = (int32_t *)malloc(sizeof(int32_t) * HASH_SIZE);
    prev = (int32_t *)malloc(sizeof(int32_t) * ((size_t)buf.len + 1));
    if (!out || !head || !prev) {
        free(out);
        free(head);
        free(prev);
        PyBuffer_Release(&buf);
        return PyErr_NoMemory();
    }
    Py_BEGIN_ALLOW_THREADS
    n = compress_greedy((const unsigned char *)buf.buf, buf.len, out, head, prev);
    Py_END_ALLOW_THREADS
    PyBuffer_Release(&buf);
    result = PyBytes_FromStringAndSize((const char *)out, n);
    free(out);
    free(head);
    free(prev);
    return result;
}

/* ------------------------------------------------------------------------ */
/* Okumura binary-tree encoder (AI6WIN)                                     */
/* ------------------------------------------------------------------------ */

/*
 * A port of Haruhiko Okumura's LZSS.C (1989), kept as close to the original
 * as the stream-to-buffer interface allows; ai6win/lzss.py explains which of
 * its quirks matter.  N, F and THRESHOLD are the original names.
 */

#define N RING_SIZE
#define F MAX_MATCH
#define THRESHOLD 2
#define NIL N

typedef struct {
    unsigned char text[N + F - 1];
    int lson[N + 1], rson[N + 257], dad[N + 1];
    int match_position, match_length;
} okumura_state;

/* Every link starts as NIL, as in the Python version.  (LZSS.C's InitTree
 * only sets the roots and dad[]; the rest are written before being read.) */
static void init_tree(okumura_state *st)
{
    int i;
    for (i = 0; i < N + 1; i++)
        st->lson[i] = st->dad[i] = NIL;
    for (i = 0; i < N + 257; i++)
        st->rson[i] = NIL;
}

static void insert_node(okumura_state *st, int r)
{
    int i, p, cmp = 1;
    const unsigned char *key = &st->text[r];

    p = N + 1 + key[0];
    st->rson[r] = st->lson[r] = NIL;
    st->match_length = 0;
    for (;;) {
        if (cmp >= 0) {
            if (st->rson[p] != NIL)
                p = st->rson[p];
            else {
                st->rson[p] = r;
                st->dad[r] = p;
                return;
            }
        } else {
            if (st->lson[p] != NIL)
                p = st->lson[p];
            else {
                st->lson[p] = r;
                st->dad[r] = p;
                return;
            }
        }
        for (i = 1; i < F; i++)
            if ((cmp = key[i] - st->text[p + i]) != 0)
                break;
        if (i > st->match_length) {
            st->match_position = p;
            if ((st->match_length = i) >= F)
                break;
        }
    }
    st->dad[r] = st->dad[p];
    st->lson[r] = st->lson[p];
    st->rson[r] = st->rson[p];
    st->dad[st->lson[p]] = r;
    st->dad[st->rson[p]] = r;
    if (st->rson[st->dad[p]] == p)
        st->rson[st->dad[p]] = r;
    else
        st->lson[st->dad[p]] = r;
    st->dad[p] = NIL;
}

static void delete_node(okumura_state *st, int p)
{
    int q;

    if (st->dad[p] == NIL)
        return;
    if (st->rson[p] == NIL)
        q = st->lson[p];
    else if (st->lson[p] == NIL)
        q = st->rson[p];
    else {
        q = st->lson[p];
        if (st->rson[q] != NIL) {
            do {
                q = st->rson[q];
            } while (st->rson[q] != NIL);
            st->rson[st->dad[q]] = st->lson[q];
            st->dad[st->lson[q]] = st->dad[q];
            st->lson[q] = st->lson[p];
            st->dad[st->lson[p]] = q;
        }
        st->rson[q] = st->rson[p];
        st->dad[st->rson[p]] = q;
    }
    st->dad[q] = st->dad[p];
    if (st->rson[st->dad[p]] == p)
        st->rson[st->dad[p]] = q;
    else
        st->lson[st->dad[p]] = q;
    st->dad[p] = NIL;
}

static Py_ssize_t compress_okumura(okumura_state *st, const unsigned char *src, Py_ssize_t end,
                                   unsigned char *out)
{
    int i, len, r, s, last_match_length, code_buf_ptr;
    unsigned char code_buf[17], mask;
    Py_ssize_t pos = 0, o = 0;

    if (!end)
        return 0;
    init_tree(st);
    memset(st->text, 0, sizeof st->text); /* the ring starts zero-filled */
    st->match_position = st->match_length = 0;

    code_buf[0] = 0;
    code_buf_ptr = mask = 1;
    s = 0;
    r = N - F;
    for (len = 0; len < F && pos < end; len++)
        st->text[r + len] = src[pos++];
    for (i = 1; i <= F; i++)
        insert_node(st, r - i);
    insert_node(st, r);
    do {
        if (st->match_length > len)
            st->match_length = len;
        if (st->match_length <= THRESHOLD) {
            st->match_length = 1;
            code_buf[0] |= mask;
            code_buf[code_buf_ptr++] = st->text[r];
        } else {
            code_buf[code_buf_ptr++] = (unsigned char)st->match_position;
            code_buf[code_buf_ptr++] =
                (unsigned char)(((st->match_position >> 4) & 0xF0) | (st->match_length - (THRESHOLD + 1)));
        }
        if ((mask <<= 1) == 0) {
            memcpy(out + o, code_buf, (size_t)code_buf_ptr);
            o += code_buf_ptr;
            code_buf[0] = 0;
            code_buf_ptr = mask = 1;
        }
        last_match_length = st->match_length;
        for (i = 0; i < last_match_length && pos < end; i++) {
            unsigned char c = src[pos++];
            delete_node(st, s);
            st->text[s] = c;
            if (s < F - 1)
                st->text[s + N] = c;
            s = (s + 1) & (N - 1);
            r = (r + 1) & (N - 1);
            insert_node(st, r);
        }
        while (i++ < last_match_length) {
            delete_node(st, s);
            s = (s + 1) & (N - 1);
            r = (r + 1) & (N - 1);
            if (--len)
                insert_node(st, r);
        }
    } while (len > 0);
    if (code_buf_ptr > 1) {
        memcpy(out + o, code_buf, (size_t)code_buf_ptr);
        o += code_buf_ptr;
    }
    return o;
}

static PyObject *py_compress_okumura(PyObject *self, PyObject *args)
{
    Py_buffer buf;
    unsigned char *out;
    okumura_state *st;
    Py_ssize_t n;
    PyObject *result;

    if (!PyArg_ParseTuple(args, "y*", &buf))
        return NULL;
    out = (unsigned char *)malloc((size_t)max_compressed(buf.len) + 1);
    st = (okumura_state *)malloc(sizeof *st);
    if (!out || !st) {
        free(out);
        free(st);
        PyBuffer_Release(&buf);
        return PyErr_NoMemory();
    }
    Py_BEGIN_ALLOW_THREADS
    n = compress_okumura(st, (const unsigned char *)buf.buf, buf.len, out);
    Py_END_ALLOW_THREADS
    PyBuffer_Release(&buf);
    result = PyBytes_FromStringAndSize((const char *)out, n);
    free(out);
    free(st);
    return result;
}

/* ------------------------------------------------------------------------ */

static PyMethodDef methods[] = {
    {"decompress", py_decompress, METH_VARARGS,
     "decompress(data, size) -> bytes\n\nDecompress an LZSS stream to size bytes."},
    {"compress_greedy", py_compress_greedy, METH_VARARGS,
     "compress_greedy(data) -> bytes\n\nGreedy longest-match LZSS encoder (BlackRainbow)."},
    {"compress_okumura", py_compress_okumura, METH_VARARGS,
     "compress_okumura(data) -> bytes\n\nOkumura's binary-tree LZSS encoder (AI6WIN)."},
    {NULL, NULL, 0, NULL},
};

static struct PyModuleDef module = {
    PyModuleDef_HEAD_INIT, "_lzss_accel", "C accelerator for LZSS.", -1, methods,
};

PyMODINIT_FUNC PyInit__lzss_accel(void)
{
    return PyModule_Create(&module);
}
