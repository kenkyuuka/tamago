/*
 * _murmur_accel.c — C accelerator for MurmurHash2.
 *
 * The pure-Python version in hashing.py is the reference implementation and
 * the fallback when this module is unavailable.
 */

#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <stdint.h>

static uint32_t murmur2(const unsigned char *data, Py_ssize_t len, uint32_t seed)
{
    const uint32_t m = 0x5BD1E995u;
    uint32_t h = seed ^ (uint32_t)len;

    while (len >= 4) {
        /* Assemble little-endian regardless of host order or alignment. */
        uint32_t k = (uint32_t)data[0] | ((uint32_t)data[1] << 8)
                   | ((uint32_t)data[2] << 16) | ((uint32_t)data[3] << 24);
        k *= m;
        k ^= k >> 24;
        k *= m;
        h *= m;
        h ^= k;
        data += 4;
        len -= 4;
    }
    switch (len) {
    case 3: h ^= (uint32_t)data[2] << 16; /* fall through */
    case 2: h ^= (uint32_t)data[1] << 8;  /* fall through */
    case 1: h ^= data[0]; h *= m;
    }
    h ^= h >> 13;
    h *= m;
    h ^= h >> 15;
    return h;
}

static PyObject *py_murmur2(PyObject *self, PyObject *args)
{
    Py_buffer buf;
    unsigned int seed = 0;
    uint32_t h;

    if (!PyArg_ParseTuple(args, "y*|I", &buf, &seed))
        return NULL;
    Py_BEGIN_ALLOW_THREADS
    h = murmur2((const unsigned char *)buf.buf, buf.len, (uint32_t)seed);
    Py_END_ALLOW_THREADS
    PyBuffer_Release(&buf);
    return PyLong_FromUnsignedLong(h);
}

static PyMethodDef methods[] = {
    {"murmur2", py_murmur2, METH_VARARGS, "murmur2(data, seed=0) -> int\n\n32-bit MurmurHash2 of data."},
    {NULL, NULL, 0, NULL},
};

static struct PyModuleDef module = {
    PyModuleDef_HEAD_INIT, "_murmur_accel", "C accelerator for MurmurHash2.", -1, methods,
};

PyMODINIT_FUNC PyInit__murmur_accel(void)
{
    return PyModule_Create(&module);
}
