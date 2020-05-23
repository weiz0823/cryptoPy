#include "array_read.h"
static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
static const uint32_t a0_iv_sha224[8] = {0xc1059ed8, 0x367cd507, 0x3070dd17,
                                         0xf70e5939, 0xffc00b31, 0x68581511,
                                         0x64f98fa7, 0xbefa4fa4};
static const uint32_t a0_iv_sha256[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372,
                                         0xa54ff53a, 0x510e527f, 0x9b05688c,
                                         0x1f83d9ab, 0x5be0cd19};

typedef struct {
    uint32_t a0[8];
    uint64_t msg_len, chunk_len;
    uint8_t msg[64];
} SHA2_32Object;

static size_t sha224_hlen = 28;
static size_t sha256_hlen = 32;

void SHA2_32_HashProcess(SHA2_32Object* self) {
    uint32_t a[8];
    uint32_t w[64];
    uint32_t f1, f2;
    for (uint8_t i = 0; i < 8; ++i) a[i] = self->a0[i];
    for (uint8_t i = 0; i < 64; ++i) {
        if (i < 16) {
            w[i] = (uint32_t)(self->msg[4 * i + 3]) +
                   (uint32_t)(self->msg[4 * i + 2] << 8) +
                   (uint32_t)(self->msg[4 * i + 1] << 16) +
                   (uint32_t)(self->msg[4 * i] << 24);
        } else {
            w[i] = w[i - 16] + w[i - 7];
            w[i] += RightRotate32(w[i - 15], 7) ^ RightRotate32(w[i - 15], 18) ^
                    (w[i - 15] >> 3);
            w[i] += RightRotate32(w[i - 2], 17) ^ RightRotate32(w[i - 2], 19) ^
                    (w[i - 2] >> 10);
        }
        f1 = K[i] + w[i] + a[7];
        f1 += RightRotate32(a[4], 6) ^ RightRotate32(a[4], 11) ^
              RightRotate32(a[4], 25);
        f1 += (a[4] & a[5]) ^ (~a[4] & a[6]);
        f2 = RightRotate32(a[0], 2) ^ RightRotate32(a[0], 13) ^
             RightRotate32(a[0], 22);
        f2 += (a[0] & a[1]) ^ (a[0] & a[2]) ^ (a[1] & a[2]);
        for (uint8_t j = 7; j > 0; --j) a[j] = a[j - 1];
        a[4] += f1;
        a[0] = f1 + f2;
    }
    for (uint8_t i = 0; i < 8; ++i) self->a0[i] += a[i];
}
uint64_t SHA2_32_HashUpdate(SHA2_32Object* self, const uint8_t* src,
                            uint64_t bytelen) {
    if (!src) return self->msg_len;
    uint64_t old_chunk = self->chunk_len;
    const uint8_t* max_pos = src + bytelen;
    self->chunk_len =
        read_from_arr(self->msg + old_chunk, 64 - old_chunk, src, max_pos);
    src += self->chunk_len;
    self->msg_len += self->chunk_len << 3;
    if (old_chunk + self->chunk_len < 64) return self->msg_len;
    do {
        SHA2_32_HashProcess(self);
        self->chunk_len = read_from_arr(self->msg, 64, src, max_pos);
        src += self->chunk_len;
        self->msg_len += self->chunk_len << 3;
    } while (self->chunk_len >= 64);
    return self->msg_len;
}
uint64_t SHA2_32_HashFinal(SHA2_32Object* self, uint8_t* dst,
                           void (*get_hash)(SHA2_32Object*, uint8_t*),
                           void (*reset)(SHA2_32Object*)) {
    uint64_t len_tmp = 0;
    // padding
    if (self->chunk_len < 56) {
        self->msg[self->chunk_len] = 0x80;
        memset(self->msg + self->chunk_len + 1, 0, 55 - self->chunk_len);
        len_tmp = self->msg_len;
        for (uint8_t i = 63; i >= 56; --i) {
            self->msg[i] = len_tmp & 0xff;
            len_tmp >>= 8;
        }
        SHA2_32_HashProcess(self);
    } else {
        self->msg[self->chunk_len] = 0x80;
        memset(self->msg + self->chunk_len + 1, 0, 63 - self->chunk_len);
        self->chunk_len = 64;
        SHA2_32_HashProcess(self);
        // length information in next chunk
        memset(self->msg, 0, 56);
        len_tmp = self->msg_len;
        for (uint8_t i = 63; i >= 56; --i) {
            self->msg[i] = len_tmp & 0xff;
            len_tmp >>= 8;
        }
        SHA2_32_HashProcess(self);
    }
    get_hash(self, dst);
    len_tmp = self->msg_len;
    reset(self);
    return len_tmp;
}
void SHA224_GetHash(SHA2_32Object* self, uint8_t* dst) {
    // discard last
    for (int i = 0; i < 7; ++i)
        for (int j = 3; j >= 0; --j) {
            dst[4 * i + j] = self->a0[i] & 0xff;
            self->a0[i] >>= 8;
        }
}
void SHA224_Reset(SHA2_32Object* self) {
    for (uint8_t i = 0; i < 8; ++i) self->a0[i] = a0_iv_sha224[i];
    self->msg_len = 0;
    self->chunk_len = 0;
}

void SHA256_GetHash(SHA2_32Object* self, uint8_t* dst) {
    for (int i = 0; i < 8; ++i)
        for (int j = 3; j >= 0; --j) {
            dst[4 * i + j] = self->a0[i] & 0xff;
            self->a0[i] >>= 8;
        }
}
void SHA256_Reset(SHA2_32Object* self) {
    for (uint8_t i = 0; i < 8; ++i) self->a0[i] = a0_iv_sha256[i];
    self->msg_len = 0;
    self->chunk_len = 0;
}

PyObject* sha224(PyObject* self, PyObject* args) {
    Py_buffer view;
    if (!PyArg_ParseTuple(args, "y*", &view)) return NULL;
    SHA2_32Object obj;
    SHA224_Reset(&obj);
    SHA2_32_HashUpdate(&obj, view.buf, view.len);
    char* dst = malloc(sha224_hlen);
    SHA2_32_HashFinal(&obj, (uint8_t*)(dst), SHA224_GetHash, SHA224_Reset);
    PyObject* rv = Py_BuildValue("y#", dst, sha224_hlen);
    free(dst);
    PyBuffer_Release(&view);
    return rv;
}
PyObject* sha256(PyObject* self, PyObject* args) {
    Py_buffer view;
    if (!PyArg_ParseTuple(args, "y*", &view)) return NULL;
    SHA2_32Object obj;
    SHA256_Reset(&obj);
    SHA2_32_HashUpdate(&obj, view.buf, view.len);
    char* dst = malloc(sha256_hlen);
    SHA2_32_HashFinal(&obj, (uint8_t*)(dst), SHA256_GetHash, SHA256_Reset);
    PyObject* rv = Py_BuildValue("y#", dst, sha256_hlen);
    free(dst);
    PyBuffer_Release(&view);
    return rv;
}
