#include "array_read.h"
static const uint64_t rho_count[24] = {1,  3,  6,  10, 15, 21, 28, 36,
                                       45, 55, 2,  14, 27, 41, 56, 8,
                                       25, 43, 62, 18, 39, 61, 20, 44};
static const uint64_t rho_x[24] = {1, 0, 2, 1, 2, 3, 3, 0, 1, 3, 1, 4,
                                   4, 0, 3, 4, 3, 2, 2, 0, 4, 2, 4, 1};
static const uint64_t rho_y[24] = {0, 2, 1, 2, 3, 3, 0, 1, 3, 1, 4, 4,
                                   0, 3, 4, 3, 2, 2, 0, 4, 2, 4, 1, 1};
static const uint64_t pi_x[5][5] = {{0, 3, 1, 4, 2},
                                    {1, 4, 2, 0, 3},
                                    {2, 0, 3, 1, 4},
                                    {3, 1, 4, 2, 0},
                                    {4, 2, 0, 3, 1}};
static const uint64_t iota_rc[24] = {0x1,
                                     0x8082,
                                     0x800000000000808a,
                                     0x8000000080008000,
                                     0x808b,
                                     0x80000001,
                                     0x8000000080008081,
                                     0x8000000000008009,
                                     0x8a,
                                     0x88,
                                     0x80008009,
                                     0x8000000a,
                                     0x8000808b,
                                     0x800000000000008b,
                                     0x8000000000008089,
                                     0x8000000000008003,
                                     0x8000000000008002,
                                     0x8000000000000080,
                                     0x800a,
                                     0x800000008000000a,
                                     0x8000000080008081,
                                     0x8000000000008080,
                                     0x80000001,
                                     0x8000000080008008};
typedef struct {
    uint32_t CAP, RATE;
    uint8_t PAD;
    uint64_t a[5][5];
    uint64_t msg_len, chunk_len;
    size_t hlen;
    uint8_t msg[200];
} SHA3Object;

static size_t sha3_224_hlen = 28;
static size_t sha3_256_hlen = 32;
static size_t sha3_384_hlen = 48;
static size_t sha3_512_hlen = 64;
static size_t shake128_hlen = 32;
static size_t shake256_hlen = 64;
static uint8_t sha3_pad = 0x06;
static uint8_t shake_pad = 0x1f;
static uint8_t rawshake_pad = 0x07;

static void KeccakPermutation(uint64_t a[][5]) {
    // constants
    uint64_t c[5], d[5], pi[5][5];
    for (int r = 0; r < 24; ++r) {
        // step theta, xor parity
        for (uint8_t i = 0; i < 5; ++i)
            c[i] = a[i][0] ^ a[i][1] ^ a[i][2] ^ a[i][3] ^ a[i][4];
        d[0] = c[4] ^ LeftRotate64(c[1], 1);
        d[1] = c[0] ^ LeftRotate64(c[2], 1);
        d[2] = c[1] ^ LeftRotate64(c[3], 1);
        d[3] = c[2] ^ LeftRotate64(c[4], 1);
        d[4] = c[3] ^ LeftRotate64(c[0], 1);
        for (uint8_t i = 0; i < 5; ++i)
            for (uint8_t j = 0; j < 5; ++j) a[i][j] ^= d[i];
        // step rho, rotate, only a(0,0) is not rotated
        for (uint8_t i = 0; i < 24; ++i)
            a[rho_x[i]][rho_y[i]] =
                LeftRotate64(a[rho_x[i]][rho_y[i]], rho_count[i]);
        // step pi, permutation, diverge to array pi
        for (uint8_t i = 0; i < 5; ++i)
            for (uint8_t j = 0; j < 5; ++j) pi[i][j] = a[pi_x[i][j]][i];
        // step chi, non-linear, merge back to array a
        for (uint8_t i = 0; i < 5; ++i) {
            a[0][i] = pi[0][i] ^ (~pi[1][i] & pi[2][i]);
            a[1][i] = pi[1][i] ^ (~pi[2][i] & pi[3][i]);
            a[2][i] = pi[2][i] ^ (~pi[3][i] & pi[4][i]);
            a[3][i] = pi[3][i] ^ (~pi[4][i] & pi[0][i]);
            a[4][i] = pi[4][i] ^ (~pi[0][i] & pi[1][i]);
        }
        // step iota, xor a LSFR sequence to break symmetry
        a[0][0] ^= iota_rc[r];
    }
}

void SHA3_HashProcess(SHA3Object* self) {
    // xor into state array, column major
    for (uint32_t i = 0; i < (self->RATE >> 3); ++i)
        for (uint32_t j = 0; j < 8; ++j)
            self->a[i % 5][i / 5] ^=
                ((uint64_t)(self->msg[(i << 3) + j]) << (j << 3));
    KeccakPermutation(self->a);
}
void SHA3_GetHash(SHA3Object* self, uint8_t* dst) {
    uint64_t tmp;
    uint32_t offset = 0;
    uint32_t i;
    uint64_t hl = self->hlen >> 3;
    for (i = 0; i < hl; ++i) {
        if (i - offset == 25) {
            offset = i;
            KeccakPermutation(self->a);
        }
        tmp = self->a[(i - offset) % 5][(i - offset) / 5];
        for (uint8_t j = 0; j < 8; ++j) {
            dst[(i << 3) + j] = tmp & 0xff;
            tmp >>= 8;
        }
    }
    if (i - offset == 25) {
        offset = i;
        KeccakPermutation(self->a);
    }
    tmp = self->a[(i - offset) % 5][(i - offset) / 5];
    for (uint8_t j = 0; j < self->hlen - (i << 3); ++j) {
        dst[(i << 3) + j] = (tmp & 255);
        tmp >>= 8;
    }
}
/* Require CAP, PAD, hlen set */
void SHA3_CommonReset(SHA3Object* self) {
    self->RATE = 200 - (self->CAP << 1);
    memset(self->a, 0, sizeof(self->a));
    self->msg_len = 0;
    self->msg_len = 0;
    self->chunk_len = 0;
}
uint64_t SHA3_HashUpdate(SHA3Object* self, const uint8_t* src,
                         uint64_t bytelen) {
    if (!src) return self->msg_len;
    uint64_t old_chunk = self->chunk_len;
    const uint8_t* max_pos = src + bytelen;
    self->chunk_len = read_from_arr(self->msg + old_chunk,
                                    self->RATE - old_chunk, src, max_pos);
    src += self->chunk_len;
    self->msg_len += self->chunk_len << 3;
    if (old_chunk + self->chunk_len < self->RATE) return self->msg_len;
    do {
        SHA3_HashProcess(self);
        self->chunk_len = read_from_arr(self->msg, self->RATE, src, max_pos);
        src += self->chunk_len;
        self->msg_len += self->chunk_len << 3;
    } while (self->chunk_len >= self->RATE);
    return self->msg_len;
}
uint64_t SHA3_HashFinal(SHA3Object* self, uint8_t* dst) {
    if (self->chunk_len < self->RATE - 1) {
        self->msg[self->chunk_len] = self->PAD;
        memset(self->msg + self->chunk_len + 1, 0,
               self->RATE - 2 - self->chunk_len);
        self->msg[self->RATE - 1] = 0x80;
    } else {
        self->msg[self->chunk_len] = self->PAD | 0x80;
    }
    SHA3_HashProcess(self);
    SHA3_GetHash(self, dst);
    // reset
    uint64_t len_tmp = self->msg_len;
    SHA3_CommonReset(self);
    return len_tmp;
}

PyObject* sha3_224(PyObject* self, PyObject* args) {
    Py_buffer view;
    if (!PyArg_ParseTuple(args, "y*", &view)) return NULL;
    SHA3Object obj;
    obj.hlen = sha3_224_hlen;
    obj.PAD = sha3_pad;
    obj.CAP = sha3_224_hlen;
    SHA3_CommonReset(&obj);
    SHA3_HashUpdate(&obj, view.buf, view.len);
    char* dst = malloc(sha3_224_hlen);
    SHA3_HashFinal(&obj, (uint8_t*)(dst));
    PyObject* rv = Py_BuildValue("y#", dst, sha3_224_hlen);
    free(dst);
    PyBuffer_Release(&view);
    return rv;
}
PyObject* sha3_256(PyObject* self, PyObject* args) {
    Py_buffer view;
    if (!PyArg_ParseTuple(args, "y*", &view)) return NULL;
    SHA3Object obj;
    obj.hlen = sha3_256_hlen;
    obj.PAD = sha3_pad;
    obj.CAP = sha3_256_hlen;
    SHA3_CommonReset(&obj);
    SHA3_HashUpdate(&obj, view.buf, view.len);
    char* dst = malloc(sha3_256_hlen);
    SHA3_HashFinal(&obj, (uint8_t*)(dst));
    PyObject* rv = Py_BuildValue("y#", dst, sha3_256_hlen);
    free(dst);
    PyBuffer_Release(&view);
    return rv;
}
PyObject* sha3_384(PyObject* self, PyObject* args) {
    Py_buffer view;
    if (!PyArg_ParseTuple(args, "y*", &view)) return NULL;
    SHA3Object obj;
    obj.hlen = sha3_384_hlen;
    obj.PAD = sha3_pad;
    obj.CAP = sha3_384_hlen;
    SHA3_CommonReset(&obj);
    SHA3_HashUpdate(&obj, view.buf, view.len);
    char* dst = malloc(sha3_384_hlen);
    SHA3_HashFinal(&obj, (uint8_t*)(dst));
    PyObject* rv = Py_BuildValue("y#", dst, sha3_384_hlen);
    free(dst);
    PyBuffer_Release(&view);
    return rv;
}
PyObject* sha3_512(PyObject* self, PyObject* args) {
    Py_buffer view;
    if (!PyArg_ParseTuple(args, "y*", &view)) return NULL;
    SHA3Object obj;
    obj.hlen = sha3_512_hlen;
    obj.PAD = sha3_pad;
    obj.CAP = sha3_512_hlen;
    SHA3_CommonReset(&obj);
    SHA3_HashUpdate(&obj, view.buf, view.len);
    char* dst = malloc(sha3_512_hlen);
    SHA3_HashFinal(&obj, (uint8_t*)(dst));
    PyObject* rv = Py_BuildValue("y#", dst, sha3_512_hlen);
    free(dst);
    PyBuffer_Release(&view);
    return rv;
}
PyObject* shake128(PyObject* self, PyObject* args) {
    Py_buffer view;
    if (!PyArg_ParseTuple(args, "y*", &view)) return NULL;
    SHA3Object obj;
    obj.hlen = shake128_hlen;
    obj.PAD = shake_pad;
    // intended for this: shake double hlen but keep CAP
    obj.CAP = shake128_hlen >> 1;
    SHA3_CommonReset(&obj);
    SHA3_HashUpdate(&obj, view.buf, view.len);
    char* dst = malloc(shake128_hlen);
    SHA3_HashFinal(&obj, (uint8_t*)(dst));
    PyObject* rv = Py_BuildValue("y#", dst, shake128_hlen);
    free(dst);
    PyBuffer_Release(&view);
    return rv;
}
PyObject* shake256(PyObject* self, PyObject* args) {
    Py_buffer view;
    if (!PyArg_ParseTuple(args, "y*", &view)) return NULL;
    SHA3Object obj;
    obj.hlen = shake256_hlen;
    obj.PAD = shake_pad;
    obj.CAP = shake256_hlen >> 1;
    SHA3_CommonReset(&obj);
    SHA3_HashUpdate(&obj, view.buf, view.len);
    char* dst = malloc(shake256_hlen);
    SHA3_HashFinal(&obj, (uint8_t*)(dst));
    PyObject* rv = Py_BuildValue("y#", dst, shake256_hlen);
    free(dst);
    PyBuffer_Release(&view);
    return rv;
}
PyObject* shake128l(PyObject* self, PyObject* args) {
    Py_buffer view;
    SHA3Object obj;
    size_t hashbit;
    if (!PyArg_ParseTuple(args, "y*k", &view, &hashbit)) return NULL;
    obj.hlen = (hashbit + 7) >> 3;
    obj.PAD = shake_pad;
    obj.CAP = shake128_hlen >> 1;
    SHA3_CommonReset(&obj);
    SHA3_HashUpdate(&obj, view.buf, view.len);
    char* dst = malloc(obj.hlen);
    SHA3_HashFinal(&obj, (uint8_t*)(dst));
    PyObject* rv = Py_BuildValue("y#", dst, obj.hlen);
    free(dst);
    PyBuffer_Release(&view);
    return rv;
}
PyObject* shake256l(PyObject* self, PyObject* args) {
    Py_buffer view;
    SHA3Object obj;
    size_t hashbit;
    if (!PyArg_ParseTuple(args, "y*k", &view, &hashbit)) return NULL;
    obj.hlen = (hashbit + 7) >> 3;
    obj.PAD = shake_pad;
    obj.CAP = shake256_hlen >> 1;
    SHA3_CommonReset(&obj);
    SHA3_HashUpdate(&obj, view.buf, view.len);
    char* dst = malloc(obj.hlen);
    SHA3_HashFinal(&obj, (uint8_t*)(dst));
    PyObject* rv = Py_BuildValue("y#", dst, obj.hlen);
    free(dst);
    PyBuffer_Release(&view);
    return rv;
}
PyObject* rawshake128l(PyObject* self, PyObject* args) {
    Py_buffer view;
    SHA3Object obj;
    size_t hashbit;
    if (!PyArg_ParseTuple(args, "y*k", &view, &hashbit)) return NULL;
    obj.hlen = (hashbit + 7) >> 3;
    obj.PAD = rawshake_pad;
    obj.CAP = shake128_hlen >> 1;
    SHA3_CommonReset(&obj);
    SHA3_HashUpdate(&obj, view.buf, view.len);
    char* dst = malloc(obj.hlen);
    SHA3_HashFinal(&obj, (uint8_t*)(dst));
    PyObject* rv = Py_BuildValue("y#", dst, obj.hlen);
    free(dst);
    PyBuffer_Release(&view);
    return rv;
}
PyObject* rawshake256l(PyObject* self, PyObject* args) {
    Py_buffer view;
    SHA3Object obj;
    size_t hashbit;
    if (!PyArg_ParseTuple(args, "y*k", &view, &hashbit)) return NULL;
    obj.hlen = (hashbit + 7) >> 3;
    obj.PAD = rawshake_pad;
    obj.CAP = shake256_hlen >> 1;
    SHA3_CommonReset(&obj);
    SHA3_HashUpdate(&obj, view.buf, view.len);
    char* dst = malloc(obj.hlen);
    SHA3_HashFinal(&obj, (uint8_t*)(dst));
    PyObject* rv = Py_BuildValue("y#", dst, obj.hlen);
    free(dst);
    PyBuffer_Release(&view);
    return rv;
}

PyObject* keccak_diy(PyObject* self, PyObject* args) {
    Py_buffer view;
    SHA3Object obj;
    size_t hashbit;
    unsigned capbit;
    if (!PyArg_ParseTuple(args, "y*kIb", &view, &hashbit, &capbit, &obj.PAD))
        return NULL;
    obj.hlen = (hashbit + 7) >> 3;
    obj.CAP = (capbit + 7) >> 3;
    SHA3_CommonReset(&obj);
    SHA3_HashUpdate(&obj, view.buf, view.len);
    char* dst = malloc(obj.hlen);
    SHA3_HashFinal(&obj, (uint8_t*)(dst));
    PyObject* rv = Py_BuildValue("y#", dst, obj.hlen);
    free(dst);
    PyBuffer_Release(&view);
    return rv;
}
