#include "array_read.h"
PyObject* md5(PyObject* self, PyObject* args);
PyObject* sha1(PyObject* self, PyObject* args);
PyObject* sha224(PyObject* self, PyObject* args);
PyObject* sha256(PyObject* self, PyObject* args);
PyObject* sha384(PyObject* self, PyObject* args);
PyObject* sha512(PyObject* self, PyObject* args);
PyObject* sha512t(PyObject* self, PyObject* args);
PyObject* sha512_224(PyObject* self, PyObject* args);
PyObject* sha512_256(PyObject* self, PyObject* args);
PyObject* sha3_224(PyObject* self, PyObject* args);
PyObject* sha3_256(PyObject* self, PyObject* args);
PyObject* sha3_384(PyObject* self, PyObject* args);
PyObject* sha3_512(PyObject* self, PyObject* args);
PyObject* shake128(PyObject* self, PyObject* args);
PyObject* shake256(PyObject* self, PyObject* args);
PyObject* shake128l(PyObject* self, PyObject* args);
PyObject* shake256l(PyObject* self, PyObject* args);
PyObject* rawshake128l(PyObject* self, PyObject* args);
PyObject* rawshake256l(PyObject* self, PyObject* args);
PyObject* keccak_diy(PyObject* self, PyObject* args);

static PyMethodDef HashMethods[] = {
    {"md5", md5, METH_VARARGS, NULL},
    {"sha1", sha1, METH_VARARGS, NULL},
    {"sha224", sha224, METH_VARARGS, NULL},
    {"sha256", sha256, METH_VARARGS, NULL},
    {"sha384", sha384, METH_VARARGS, NULL},
    {"sha512", sha512, METH_VARARGS, NULL},
    {"sha512t", sha512t, METH_VARARGS, NULL},
    {"sha512_224", sha512_224, METH_VARARGS, NULL},
    {"sha512_256", sha512_256, METH_VARARGS, NULL},
    {"sha3_224", sha3_224, METH_VARARGS, NULL},
    {"sha3_256", sha3_256, METH_VARARGS, NULL},
    {"sha3_384", sha3_384, METH_VARARGS, NULL},
    {"sha3_512", sha3_512, METH_VARARGS, NULL},
    {"shake128", shake128, METH_VARARGS, NULL},
    {"shake256", shake256, METH_VARARGS, NULL},
    {"shake128l", shake128l, METH_VARARGS, NULL},
    {"shake256l", shake256l, METH_VARARGS, NULL},
    {"rawshake128l", rawshake128l, METH_VARARGS, NULL},
    {"rawshake256l", rawshake256l, METH_VARARGS, NULL},
    {"keccak_diy", keccak_diy, METH_VARARGS, NULL},
    {NULL, NULL, 0, NULL}};

static struct PyModuleDef hashmodule = {PyModuleDef_HEAD_INIT, "cryptohash",
                                        NULL, -1, HashMethods};

PyMODINIT_FUNC PyInit_cryptohash(void) { return PyModule_Create(&hashmodule); }
