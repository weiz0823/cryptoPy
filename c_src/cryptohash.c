#include "md5.c"
static PyMethodDef HashMethods[] = {{"md5", md5, METH_VARARGS, NULL},
                                    {NULL, NULL, 0, NULL}};

static struct PyModuleDef hashmodule = {PyModuleDef_HEAD_INIT, "cryptohash",
                                        NULL, -1, HashMethods};

PyMODINIT_FUNC PyInit_cryptohash(void) { return PyModule_Create(&hashmodule); }
