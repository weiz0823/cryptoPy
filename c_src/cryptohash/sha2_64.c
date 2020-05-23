#include "array_read.h"
static const uint64_t K[80] = {
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f,
    0xe9b5dba58189dbbc, 0x3956c25bf348b538, 0x59f111f1b605d019,
    0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242,
    0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235,
    0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3,
    0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65, 0x2de92c6f592b0275,
    0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f,
    0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725,
    0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc,
    0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6,
    0x92722c851482353b, 0xa2bfe8a14cf10364, 0xa81a664bbc423001,
    0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218,
    0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99,
    0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb,
    0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc,
    0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915,
    0xc67178f2e372532b, 0xca273eceea26619c, 0xd186b8c721c0c207,
    0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba,
    0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a,
    0x5fcb6fab3ad6faec, 0x6c44198c4a475817};
static const uint64_t a0_iv_sha384[8] = {
    0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17,
    0x152fecd8f70e5939, 0x67332667ffc00b31, 0x8eb44a8768581511,
    0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4};
static const uint64_t a0_iv_sha512[8] = {
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1, 0x510e527fade682d1, 0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b, 0x5be0cd19137e2179};
static const uint64_t a0_iv_sha512t[8] = {
    0xcfac43c256196cad, 0x1ec20b20216f029e, 0x99cb56d75b315d8e,
    0x00ea509ffab89354, 0xf4abf7da08432774, 0x3ea0cd298e9bc9ba,
    0xba267c0e5ee418ce, 0xfe4568bcb6db84dc};
static const uint64_t a0_iv_sha512_224[8] = {
    0x8c3d37c819544da2, 0x73e1996689dcd4d6, 0x1dfab7ae32ff9c82,
    0x679dd514582f9fcf, 0xf6d2b697bd44da8,  0x77e36f7304c48942,
    0x3f9d85a86a1d36c8, 0x1112e6ad91d692a1};
static const uint64_t a0_iv_sha512_256[8] = {
    0x22312194fc2bf72c, 0x9f555fa3c84c64c2, 0x2393b86b6f53b151,
    0x963877195940eabd, 0x96283ee2a88effe3, 0xbe5e1e2553863992,
    0x2b0199fc2c85b8aa, 0xeb72ddc81c52ca2};

typedef __uint128_t uint128_t;
typedef struct {
    uint64_t a0[8];
    uint128_t msg_len;
    uint64_t chunk_len;
    uint8_t msg[128];
    // dynamic initial value for sha512/t
    uint64_t a0_iv[8];
    size_t t;
} SHA2_64Object;

static size_t sha384_hlen = 48;
static size_t sha512_hlen = 64;
static size_t sha512_224_hlen = 28;
static size_t sha512_256_hlen = 32;

void SHA2_64_HashProcess(SHA2_64Object* self) {
    uint64_t f1, f2;
    uint64_t w[80];
    uint64_t a[8];
    for (uint8_t i = 0; i < 8; ++i) a[i] = self->a0[i];
    for (uint8_t i = 0; i < 80; ++i) {
        if (i < 16) {
            w[i] = (uint64_t)(self->msg[8 * i]);
            for (uint8_t j = 1; j < 8; ++j) {
                w[i] <<= 8;
                w[i] += (uint64_t)(self->msg[8 * i + j]);
            }
        } else {
            w[i] = w[i - 16] + w[i - 7];
            w[i] += RightRotate64(w[i - 15], 1) ^ RightRotate64(w[i - 15], 8) ^
                    (w[i - 15] >> 7);
            w[i] += RightRotate64(w[i - 2], 19) ^ RightRotate64(w[i - 2], 61) ^
                    (w[i - 2] >> 6);
        }
        f1 = K[i] + w[i] + a[7];
        f1 += RightRotate64(a[4], 14) ^ RightRotate64(a[4], 18) ^
              RightRotate64(a[4], 41);
        f1 += (a[4] & a[5]) ^ (~a[4] & a[6]);
        f2 = RightRotate64(a[0], 28) ^ RightRotate64(a[0], 34) ^
             RightRotate64(a[0], 39);
        f2 += (a[0] & a[1]) ^ (a[0] & a[2]) ^ (a[1] & a[2]);
        for (uint8_t j = 7; j > 0; --j) a[j] = a[j - 1];
        a[4] += f1;
        a[0] = f1 + f2;
    }
    for (uint8_t i = 0; i < 8; ++i) self->a0[i] += a[i];
}
uint64_t SHA2_64_HashUpdate(SHA2_64Object* self, const uint8_t* src,
                            uint64_t bytelen) {
    if (!src) return self->msg_len;
    uint64_t old_chunk = self->chunk_len;
    const uint8_t* max_pos = src + bytelen;
    self->chunk_len =
        read_from_arr(self->msg + old_chunk, 128 - old_chunk, src, max_pos);
    src += self->chunk_len;
    self->msg_len += self->chunk_len << 3;
    if (old_chunk + self->chunk_len < 128) return self->msg_len;
    do {
        SHA2_64_HashProcess(self);
        self->chunk_len = read_from_arr(self->msg, 128, src, max_pos);
        src += self->chunk_len;
        self->msg_len += self->chunk_len << 3;
    } while (self->chunk_len >= 128);
    return self->msg_len;
}
uint64_t SHA2_64_HashFinal(SHA2_64Object* self, uint8_t* dst,
                           void (*get_hash)(SHA2_64Object*, uint8_t*),
                           void (*reset)(SHA2_64Object*)) {
    uint128_t len_tmp = 0;
    // padding
    if (self->chunk_len < 112) {
        self->msg[self->chunk_len] = 0x80;
        memset(self->msg + self->chunk_len + 1, 0, 111 - self->chunk_len);
        len_tmp = self->msg_len;
        for (uint8_t i = 127; i >= 112; --i) {
            self->msg[i] = len_tmp & 0xff;
            len_tmp >>= 8;
        }
        SHA2_64_HashProcess(self);
    } else {
        self->msg[self->chunk_len] = 0x80;
        memset(self->msg + self->chunk_len + 1, 0, 127 - self->chunk_len);
        self->chunk_len = 128;
        SHA2_64_HashProcess(self);
        // length information in next chunk
        memset(self->msg, 0, 112);
        len_tmp = self->msg_len;
        for (uint8_t i = 127; i >= 112; --i) {
            self->msg[i] = len_tmp & 0xff;
            len_tmp >>= 8;
        }
        SHA2_64_HashProcess(self);
    }
    get_hash(self, dst);
    len_tmp = self->msg_len;
    reset(self);
    return len_tmp;
}

void SHA384_GetHash(SHA2_64Object* self, uint8_t* dst) {
    for (int i = 0; i < 6; ++i)
        for (int j = 7; j >= 0; --j) {
            dst[8 * i + j] = self->a0[i] & 0xff;
            self->a0[i] >>= 8;
        }
}
void SHA384_Reset(SHA2_64Object* self) {
    for (uint8_t i = 0; i < 8; ++i) self->a0[i] = a0_iv_sha384[i];
    self->msg_len = 0;
    self->chunk_len = 0;
}

void SHA512_GetHash(SHA2_64Object* self, uint8_t* dst) {
    for (int i = 0; i < 8; ++i)
        for (int j = 7; j >= 0; --j) {
            dst[8 * i + j] = self->a0[i] & 0xff;
            self->a0[i] >>= 8;
        }
}
void SHA512_Reset(SHA2_64Object* self) {
    for (uint8_t i = 0; i < 8; ++i) self->a0[i] = a0_iv_sha512[i];
    self->msg_len = 0;
    self->chunk_len = 0;
}

void SHA512t_GetHash(SHA2_64Object* self, uint8_t* dst) {
    size_t hlen = (self->t + 7) >> 3;
    if (hlen > 64) hlen = 64;
    uint32_t i;
    for (i = 0; i < (hlen >> 3); ++i)
        for (uint8_t j = 7; j != (uint8_t)(-1); --j) {
            dst[(i << 3) + j] = self->a0[i] & 255;
            self->a0[i] >>= 8;
        }
    uint8_t j = 7;
    for (; j != (uint8_t)(hlen - 1 - (i << 3)); --j) self->a0[i] >>= 8;
    for (; j != (uint8_t)(-1); --j) {
        dst[(i << 3) + j] = self->a0[i] & 255;
        self->a0[i] >>= 8;
    }
}
void SHA512t_Reset(SHA2_64Object* self) {
    memcpy(self->a0, self->a0_iv, 64);
    self->msg_len = 0;
    self->chunk_len = 0;
}
void SHA512t_IVGen(SHA2_64Object* self) {
    // do a hash to calculate iv
    self->msg_len = 0;
    self->chunk_len = 0;
    for (uint8_t i = 0; i < 8; ++i) self->a0[i] = a0_iv_sha512t[i];
    char s[32];
    sprintf(s, "SHA-512/%lu", self->t);
    SHA2_64_HashUpdate(self, (uint8_t*)(s), strlen(s));
    // manual HashFinal so that value will not be reset
    self->msg[self->chunk_len] = 0x80;
    memset(self->msg + self->chunk_len + 1, 0, 111 - self->chunk_len);
    uint128_t len_tmp = self->msg_len;
    for (uint8_t i = 127; i >= 112; --i) {
        self->msg[i] = len_tmp & 0xff;
        len_tmp >>= 8;
    }
    SHA2_64_HashProcess(self);
    memcpy(self->a0_iv, self->a0, 64);
    self->msg_len = 0;
    self->chunk_len = 0;
}
void SHA512_224_GetHash(SHA2_64Object* self, uint8_t* dst) {
    for (int i = 0; i < 3; ++i)
        for (int j = 7; j >= 0; --j) {
            dst[8 * i + j] = self->a0[i] & 0xff;
            self->a0[i] >>= 8;
        }
    self->a0[3] >>= 32;
    for (int j = 3; j >= 0; --j) {
        dst[24 + j] = self->a0[3] & 0xff;
        self->a0[3] >>= 8;
    }
}
void SHA512_224_Reset(SHA2_64Object* self) {
    for (uint8_t i = 0; i < 8; ++i) self->a0[i] = a0_iv_sha512_224[i];
    self->msg_len = 0;
    self->chunk_len = 0;
}
void SHA512_256_GetHash(SHA2_64Object* self, uint8_t* dst) {
    for (int i = 0; i < 4; ++i)
        for (int j = 7; j >= 0; --j) {
            dst[8 * i + j] = self->a0[i] & 0xff;
            self->a0[i] >>= 8;
        }
}
void SHA512_256_Reset(SHA2_64Object* self) {
    for (uint8_t i = 0; i < 8; ++i) self->a0[i] = a0_iv_sha512_256[i];
    self->msg_len = 0;
    self->chunk_len = 0;
}

PyObject* sha384(PyObject* self, PyObject* args) {
    Py_buffer view;
    if (!PyArg_ParseTuple(args, "y*", &view)) return NULL;
    SHA2_64Object obj;
    SHA384_Reset(&obj);
    SHA2_64_HashUpdate(&obj, view.buf, view.len);
    char* dst = malloc(sha384_hlen);
    SHA2_64_HashFinal(&obj, (uint8_t*)(dst), SHA384_GetHash, SHA384_Reset);
    PyObject* rv = Py_BuildValue("y#", dst, sha384_hlen);
    free(dst);
    PyBuffer_Release(&view);
    return rv;
}
PyObject* sha512(PyObject* self, PyObject* args) {
    Py_buffer view;
    if (!PyArg_ParseTuple(args, "y*", &view)) return NULL;
    SHA2_64Object obj;
    SHA512_Reset(&obj);
    SHA2_64_HashUpdate(&obj, view.buf, view.len);
    char* dst = malloc(sha512_hlen);
    SHA2_64_HashFinal(&obj, (uint8_t*)(dst), SHA512_GetHash, SHA512_Reset);
    PyObject* rv = Py_BuildValue("y#", dst, sha512_hlen);
    free(dst);
    PyBuffer_Release(&view);
    return rv;
}
PyObject* sha512_224(PyObject* self, PyObject* args) {
    Py_buffer view;
    if (!PyArg_ParseTuple(args, "y*", &view)) return NULL;
    SHA2_64Object obj;
    SHA512_224_Reset(&obj);
    SHA2_64_HashUpdate(&obj, view.buf, view.len);
    char* dst = malloc(sha512_224_hlen);
    SHA2_64_HashFinal(&obj, (uint8_t*)(dst), SHA512_224_GetHash,
                      SHA512_224_Reset);
    PyObject* rv = Py_BuildValue("y#", dst, sha512_224_hlen);
    free(dst);
    PyBuffer_Release(&view);
    return rv;
}
PyObject* sha512_256(PyObject* self, PyObject* args) {
    Py_buffer view;
    if (!PyArg_ParseTuple(args, "y*", &view)) return NULL;
    SHA2_64Object obj;
    SHA512_256_Reset(&obj);
    SHA2_64_HashUpdate(&obj, view.buf, view.len);
    char* dst = malloc(sha512_256_hlen);
    SHA2_64_HashFinal(&obj, (uint8_t*)(dst), SHA512_256_GetHash,
                      SHA512_256_Reset);
    PyObject* rv = Py_BuildValue("y#", dst, sha512_256_hlen);
    free(dst);
    PyBuffer_Release(&view);
    return rv;
}

PyObject* sha512t(PyObject* self, PyObject* args) {
    Py_buffer view;
    size_t t;
    if (!PyArg_ParseTuple(args, "y*k", &view, &t)) return NULL;
    size_t hlen = (t + 7) >> 3;
    SHA2_64Object obj;
    obj.t = t;
    SHA512t_IVGen(&obj);
    SHA2_64_HashUpdate(&obj, view.buf, view.len);
    char* dst = malloc(hlen);
    SHA2_64_HashFinal(&obj, (uint8_t*)(dst), SHA512t_GetHash, SHA512t_Reset);
    PyObject* rv = Py_BuildValue("y#", dst, hlen);
    free(dst);
    PyBuffer_Release(&view);
    return rv;
}
