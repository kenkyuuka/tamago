/*
 * _tlg_accel.c — C accelerator for TLG image decoding hot loops.
 *
 * Provides C implementations of _lzss_decompress, _decode_golomb_channel,
 * and _decode_scanline.  The pure-Python versions in tlg.py serve as the
 * reference implementation and fallback when this module is unavailable.
 */

#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <stdint.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* Constants                                                          */
/* ------------------------------------------------------------------ */

#define RING_SIZE      4096
#define RING_MASK      (RING_SIZE - 1)
#define MATCH_BASE_LEN 3
#define MATCH_EXT_THR  18

#define BLOCK_WIDTH    8
#define GOLOMB_PERIOD  4

/* ------------------------------------------------------------------ */
/* Golomb length table (lazy-initialized, matches Python _ensure_tables) */
/* ------------------------------------------------------------------ */

static int g_golomb_len[1024][GOLOMB_PERIOD];
static int g_golomb_ready = 0;

static void ensure_golomb_table(void)
{
    if (g_golomb_ready) return;

    static const int thr[4][9] = {
        {3, 7, 15, 27, 63, 108, 223, 448, 130},
        {3, 5, 13, 24, 51,  95, 192, 384, 257},
        {2, 5, 12, 21, 39,  86, 155, 320, 384},
        {2, 3,  9, 18, 33,  61, 129, 258, 511},
    };
    for (int p = 0; p < GOLOMB_PERIOD; p++) {
        int e = 0;
        for (int bl = 0; bl < 9; bl++)
            for (int j = 0; j < thr[p][bl]; j++)
                g_golomb_len[e++][p] = bl;
    }
    g_golomb_ready = 1;
}

/* ------------------------------------------------------------------ */
/* Color transform table                                              */
/* ------------------------------------------------------------------ */

static const int CT[16][3][3] = {
    {{1,0,0},{0,1,0},{0,0,1}}, {{1,1,0},{0,1,0},{0,1,1}},
    {{1,1,1},{0,1,1},{0,0,1}}, {{1,0,0},{1,1,0},{1,1,1}},
    {{2,1,1},{1,1,1},{1,0,1}}, {{1,0,0},{1,1,1},{1,0,1}},
    {{1,0,0},{0,1,0},{0,1,1}}, {{1,0,0},{0,1,1},{0,0,1}},
    {{1,1,0},{0,1,0},{0,0,1}}, {{1,0,1},{1,1,1},{1,1,2}},
    {{1,0,0},{1,1,0},{1,0,1}}, {{1,0,1},{0,1,1},{0,0,1}},
    {{1,0,1},{1,1,1},{0,0,1}}, {{1,1,1},{1,2,1},{0,1,1}},
    {{2,1,1},{1,1,0},{1,1,1}}, {{1,0,2},{0,1,2},{0,0,1}},
};

/* ------------------------------------------------------------------ */
/* Packed-byte arithmetic                                             */
/* ------------------------------------------------------------------ */

static inline uint32_t packed_add(uint32_t a, uint32_t b)
{
    uint32_t carry = (((a & b) << 1) + ((a ^ b) & 0xFEFEFEFEu)) & 0x01010100u;
    return a + b - carry;
}

static inline uint32_t packed_gt(uint32_t a, uint32_t b)
{
    uint32_t c = ~b;
    uint32_t h = ((a & c) + (((a ^ c) >> 1) & 0x7F7F7F7Fu)) & 0x80808080u;
    return ((h >> 7) + 0x7F7F7F7Fu) ^ 0x7F7F7F7Fu;
}

/* ------------------------------------------------------------------ */
/* Spatial predictors                                                 */
/* ------------------------------------------------------------------ */

static inline uint32_t pred_median(uint32_t left, uint32_t above,
                                   uint32_t ul, uint32_t delta)
{
    uint32_t gt   = packed_gt(left, above);
    uint32_t swap = (left ^ above) & gt;
    uint32_t lo   = swap ^ left;
    uint32_t hi   = swap ^ above;

    uint32_t use_lo = packed_gt(lo, ul);
    uint32_t use_hi = packed_gt(ul, hi);
    uint32_t use_mid = ~(use_lo | use_hi);

    uint32_t pred = (use_hi & lo)
                  | (use_lo & hi)
                  | (((hi & use_mid) - (ul & use_mid) + (lo & use_mid)));

    return packed_add(pred, delta);
}

static inline uint32_t pred_average(uint32_t left, uint32_t above,
                                    uint32_t ul, uint32_t delta)
{
    (void)ul;
    uint32_t x = left ^ above;
    uint32_t avg = (left & above) + ((x & 0xFEFEFEFEu) >> 1) + (x & 0x01010101u);
    return packed_add(avg, delta);
}

/* ------------------------------------------------------------------ */
/* Bit reader (for Golomb decoder)                                    */
/* ------------------------------------------------------------------ */

typedef struct {
    const uint8_t *buf;
    Py_ssize_t     len;
    Py_ssize_t     byte_pos;
    int            bit_pos;
} BitRdr;

static inline uint32_t br_peek32(const BitRdr *r)
{
    uint32_t v = 0;
    Py_ssize_t rem = r->len - r->byte_pos;
    if (rem >= 4)
        memcpy(&v, r->buf + r->byte_pos, 4);   /* assumes little-endian */
    else
        for (Py_ssize_t i = 0; i < rem; i++)
            v |= (uint32_t)r->buf[r->byte_pos + i] << (i * 8);
    return v;
}

static inline void br_skip(BitRdr *r, int bits)
{
    r->bit_pos += bits;
    r->byte_pos += r->bit_pos >> 3;
    r->bit_pos &= 7;
}

static inline int br_bit(BitRdr *r)
{
    int v = (r->buf[r->byte_pos] >> r->bit_pos) & 1;
    br_skip(r, 1);
    return v;
}

static inline uint32_t br_bits(BitRdr *r, int n)
{
    if (n == 0) return 0;
    uint32_t w = br_peek32(r) >> r->bit_pos;
    uint32_t v = w & ((1u << n) - 1);
    br_skip(r, n);
    return v;
}

/* Count trailing zeros, portable. */
static inline int ctz32(uint32_t x)
{
#if defined(__GNUC__) || defined(__clang__)
    return __builtin_ctz(x);
#else
    int n = 0;
    while (!(x & 1)) { x >>= 1; n++; }
    return n;
#endif
}

static int br_unary(BitRdr *r)
{
    int zc = 0;
    for (;;) {
        uint32_t w = (br_peek32(r) >> r->bit_pos) & 0xFFFu;
        if (w) {
            int lo = ctz32(w);
            zc += lo;
            br_skip(r, lo + 1);
            return zc;
        }
        zc += 12;
        br_skip(r, 12);
    }
}

static int br_unary_fb(BitRdr *r)
{
    uint32_t word = br_peek32(r) >> r->bit_pos;
    if (word) {
        int zc = 0;
        for (;;) {
            uint32_t w = word & 0xFFFu;
            if (w) {
                int lo = ctz32(w);
                zc += lo;
                br_skip(r, lo + 1);
                return zc;
            }
            zc += 12;
            br_skip(r, 12);
            word = br_peek32(r) >> r->bit_pos;
        }
    } else {
        r->byte_pos += 5;
        int zc = r->buf[r->byte_pos - 1];
        r->bit_pos = 0;
        return zc;
    }
}

/* ------------------------------------------------------------------ */
/* py_lzss_decompress                                                 */
/* ------------------------------------------------------------------ */

static PyObject *
py_lzss_decompress(PyObject *self, PyObject *args)
{
    Py_buffer src_b, dst_b, ring_b;
    int rp;

    if (!PyArg_ParseTuple(args, "y*w*w*i", &src_b, &dst_b, &ring_b, &rp))
        return NULL;

    const uint8_t *src = src_b.buf;
    uint8_t *dst       = dst_b.buf;
    uint8_t *ring      = ring_b.buf;
    Py_ssize_t slen    = src_b.len;
    Py_ssize_t dlen    = dst_b.len;
    Py_ssize_t si = 0, di = 0;

    while (si < slen && di < dlen) {
        uint8_t flag = src[si++];
        for (int bit = 0; bit < 8; bit++) {
            if (di >= dlen || si >= slen) goto done;
            if ((flag >> bit) & 1) {
                if (si + 1 >= slen) goto done;
                int lo = src[si], hi = src[si + 1];
                si += 2;
                int mpos = lo | ((hi & 0x0F) << 8);
                int mlen = (hi >> 4) + MATCH_BASE_LEN;
                if (mlen == MATCH_EXT_THR) {
                    if (si >= slen) goto done;
                    mlen += src[si++];
                }
                if (mlen > dlen - di) mlen = (int)(dlen - di);
                for (int j = 0; j < mlen; j++) {
                    uint8_t b = ring[(mpos + j) & RING_MASK];
                    dst[di++] = b;
                    ring[rp] = b;
                    rp = (rp + 1) & RING_MASK;
                }
            } else {
                uint8_t b = src[si++];
                dst[di++] = b;
                ring[rp] = b;
                rp = (rp + 1) & RING_MASK;
            }
        }
    }
done:
    PyBuffer_Release(&src_b);
    PyBuffer_Release(&dst_b);
    PyBuffer_Release(&ring_b);
    return PyLong_FromLong(rp);
}

/* ------------------------------------------------------------------ */
/* py_decode_golomb_channel                                           */
/* ------------------------------------------------------------------ */

static PyObject *
py_decode_golomb_channel(PyObject *self, PyObject *args)
{
    Py_buffer pix_b, pool_b;
    int ch_off, pix_count;

    if (!PyArg_ParseTuple(args, "w*iiy*", &pix_b, &ch_off, &pix_count, &pool_b))
        return NULL;

    ensure_golomb_table();

    uint8_t *pix = pix_b.buf;
    BitRdr   rdr = { pool_b.buf, pool_b.len, 0, 0 };

    int limit = pix_count * 4;
    int oi    = ch_off;
    int is_zero = (br_bit(&rdr) == 0);
    int asum  = 0;
    int pctr  = GOLOMB_PERIOD - 1;

    while (oi < limit) {
        int uv  = br_unary(&rdr);
        int rlen = (1 << uv) + (int)br_bits(&rdr, uv);

        if (is_zero) {
            for (int i = 0; i < rlen && oi < limit; i++) {
                pix[oi] = 0;
                oi += 4;
            }
        } else {
            for (int i = 0; i < rlen && oi < limit; i++) {
                int pz   = br_unary_fb(&rdr);
                int sbits = g_golomb_len[asum][pctr];
                uint32_t sfx = br_bits(&rdr, sbits);
                uint32_t enc = ((uint32_t)pz << sbits) + sfx;

                int sign = enc & 1;
                int mag  = enc >> 1;
                int smask = sign - 1;
                pix[oi] = (uint8_t)((mag ^ smask) + smask + 1);
                oi += 4;

                asum += mag;
                if (--pctr < 0) { asum >>= 1; pctr = GOLOMB_PERIOD - 1; }
            }
        }
        is_zero = !is_zero;
    }

    PyBuffer_Release(&pix_b);
    PyBuffer_Release(&pool_b);
    Py_RETURN_NONE;
}

/* ------------------------------------------------------------------ */
/* py_decode_scanline                                                 */
/* ------------------------------------------------------------------ */

static PyObject *
py_decode_scanline(PyObject *self, PyObject *args)
{
    PyObject *above_obj, *cur_obj;
    int img_w, fb, lb, brs;
    Py_buffer filt_b, delta_b;
    unsigned int init_px;
    int il_off, row_dir, ch_count;

    if (!PyArg_ParseTuple(args, "OOiiiw*iw*Iiii",
            &above_obj, &cur_obj,
            &img_w, &fb, &lb,
            &filt_b, &brs, &delta_b,
            &init_px, &il_off, &row_dir, &ch_count))
        return NULL;

    Py_buffer above_b, cur_b;
    if (PyObject_GetBuffer(above_obj, &above_b, PyBUF_WRITABLE) < 0) {
        PyBuffer_Release(&filt_b); PyBuffer_Release(&delta_b);
        return NULL;
    }
    if (PyObject_GetBuffer(cur_obj, &cur_b, PyBUF_WRITABLE) < 0) {
        PyBuffer_Release(&above_b); PyBuffer_Release(&filt_b);
        PyBuffer_Release(&delta_b);
        return NULL;
    }

    uint32_t       *above = above_b.buf;
    uint32_t       *cur   = cur_b.buf;
    const uint8_t  *filt  = filt_b.buf;
    const uint8_t  *dbuf  = delta_b.buf;

    int ai = 0, oi = 0;
    uint32_t lp, ulp;

    if (fb > 0) {
        ai  = fb * BLOCK_WIDTH;
        oi  = fb * BLOCK_WIDTH;
        ulp = above[ai - 1];
        lp  = cur[oi - 1];
    } else {
        lp  = init_px;
        ulp = init_px;
    }

    int di   = brs * fb * 4;
    int step = (row_dir & 1) ? 1 : -1;
    int step4 = step * 4;
    int opaque = (ch_count == 3);

    for (int bc = fb; bc < lb; bc++) {
        int bw = img_w - bc * BLOCK_WIDTH;
        if (bw > BLOCK_WIDTH) bw = BLOCK_WIDTH;

        if (step == -1) di += (bw - 1) * 4;
        if (bc & 1)     di += il_off * bw * 4;

        int fbyte = filt[bc];
        int use_avg = fbyte & 1;
        int tidx = fbyte >> 1;
        const int *cr = CT[tidx][0];
        const int *cg = CT[tidx][1];
        const int *cb = CT[tidx][2];
        int is_id = (tidx == 0);

        for (int px = 0; px < bw; px++) {
            uint8_t da = dbuf[di + 3];
            uint8_t dr = dbuf[di + 2];
            uint8_t dg = dbuf[di + 1];
            uint8_t db = dbuf[di];

            if (!is_id) {
                uint8_t r2 = (uint8_t)(cr[0]*dr + cr[1]*dg + cr[2]*db);
                uint8_t g2 = (uint8_t)(cg[0]*dr + cg[1]*dg + cg[2]*db);
                uint8_t b2 = (uint8_t)(cb[0]*dr + cb[1]*dg + cb[2]*db);
                dr = r2; dg = g2; db = b2;
            }

            uint32_t pd = ((uint32_t)db << 16) | ((uint32_t)dg << 8)
                        | dr | ((uint32_t)da << 24);

            uint32_t ap = above[ai];
            lp = use_avg ? pred_average(lp, ap, ulp, pd)
                         : pred_median(lp, ap, ulp, pd);

            if (opaque) lp |= 0xFF000000u;

            ulp = ap;
            cur[oi] = lp;
            oi++;
            ai++;
            di += step4;
        }

        di += (brs + (step == 1 ? -bw : 1)) * 4;
        if (bc & 1) di -= il_off * bw * 4;
    }

    PyBuffer_Release(&above_b);
    PyBuffer_Release(&cur_b);
    PyBuffer_Release(&filt_b);
    PyBuffer_Release(&delta_b);
    Py_RETURN_NONE;
}

/* ------------------------------------------------------------------ */
/* py_correlate_channels                                              */
/* ------------------------------------------------------------------ */

static PyObject *
py_correlate_channels(PyObject *self, PyObject *args)
{
    Py_buffer pix_b;
    int width, height, ch_count;

    if (!PyArg_ParseTuple(args, "w*iii", &pix_b, &width, &height, &ch_count))
        return NULL;

    uint8_t *px = pix_b.buf;
    int stride = width * 4;
    int opaque = (ch_count == 3);

    /* First row: no vertical delta */
    uint8_t hr = 0, hg = 0, hb = 0, ha = 0;
    for (int x = 0; x < width; x++) {
        int i = x * 4;
        uint8_t dr = px[i], dg = px[i+1], db = px[i+2], da = px[i+3];
        db = db + dg;  dr = dr + dg;
        hr += dr;  hg += dg;  hb += db;  ha += da;
        px[i] = hr;  px[i+1] = hg;  px[i+2] = hb;
        px[i+3] = opaque ? 0xFF : ha;
    }

    /* Remaining rows: with vertical delta */
    for (int y = 1; y < height; y++) {
        int row = y * stride;
        int above = row - stride;
        hr = hg = hb = ha = 0;
        for (int x = 0; x < width; x++) {
            int i = row + x * 4;
            int a = above + x * 4;
            uint8_t dr = px[i], dg = px[i+1], db = px[i+2], da = px[i+3];
            db = db + dg;  dr = dr + dg;
            hr += dr;  hg += dg;  hb += db;  ha += da;
            px[i]   = hr + px[a];
            px[i+1] = hg + px[a+1];
            px[i+2] = hb + px[a+2];
            px[i+3] = opaque ? 0xFF : (uint8_t)(ha + px[a+3]);
        }
    }

    PyBuffer_Release(&pix_b);
    Py_RETURN_NONE;
}

/* ------------------------------------------------------------------ */
/* Module definition                                                  */
/* ------------------------------------------------------------------ */

static PyMethodDef methods[] = {
    {"lzss_decompress",       py_lzss_decompress,       METH_VARARGS, NULL},
    {"decode_golomb_channel", py_decode_golomb_channel,  METH_VARARGS, NULL},
    {"decode_scanline",       py_decode_scanline,        METH_VARARGS, NULL},
    {"correlate_channels",    py_correlate_channels,     METH_VARARGS, NULL},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef module = {
    PyModuleDef_HEAD_INIT, "_tlg_accel",
    "C accelerator for TLG image decoding.", -1, methods
};

PyMODINIT_FUNC PyInit__tlg_accel(void)
{
    return PyModule_Create(&module);
}
