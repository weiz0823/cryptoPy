#include "array_read.h"
// precomputed constants
static const uint8_t S[64] = {
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5, 9,  14, 20, 5, 9,  14, 20, 5, 9,  14, 20, 5, 9,  14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21};
static const uint32_t K[64] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a,
    0xa8304613, 0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340,
    0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8,
    0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
    0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92,
    0xffeff47d, 0x85845dd1, 0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391};
static const uint32_t a0_iv = 0x67452301;
static const uint32_t b0_iv = 0xefcdab89;
static const uint32_t c0_iv = 0x98badcfe;
static const uint32_t d0_iv = 0x10325476;

typedef struct {
    // state array
    uint32_t a0;
    uint32_t b0;
    uint32_t c0;
    uint32_t d0;
    // temporary save
    uint64_t msg_len, chunk_len;
    // 512 bits per block
    uint8_t msg[64];
} MD5Object;

static const size_t md5_hlen = 16;

void MD5_HashProcess(MD5Object* self) {
    uint32_t a, b, c, d;
    a = self->a0;
    b = self->b0;
    c = self->c0;
    d = self->d0;
    uint32_t f;
    uint32_t j;
    for (uint8_t i = 0; i < 64; ++i) {
        if (i < 16) {
            f = (b & c) | (~b & d);
            j = i;
        } else if (i < 32) {
            f = (d & b) | (~d & c);
            j = (uint32_t)(i << 2) + i + 1;
        } else if (i < 48) {
            f = b ^ c ^ d;
            j = i + i + i + 5;
        } else {
            f = c ^ (b | ~d);
            j = (uint32_t)(i << 3) - i;
        }
        j = (j & 15) << 2;
        f += a + self->msg[j] + (uint32_t)(self->msg[j + 1] << 8) +
             (uint32_t)(self->msg[j + 2] << 16) + (uint32_t)(self->msg[j + 3] << 24) +
             K[i];
        a = d;
        d = c;
        c = b;
        b += (f << S[i]) | (f >> (32 - S[i]));
    }
    self->a0 += a;
    self->b0 += b;
    self->c0 += c;
    self->d0 += d;
}
uint64_t MD5_HashUpdate(MD5Object* self, const uint8_t* src, uint64_t bytelen) {
    if (!src) return self->msg_len;
    uint64_t old_chunk = self->chunk_len;
    const uint8_t* max_pos = src + bytelen;
    self->chunk_len =
        read_from_arr(self->msg + old_chunk, 64 - old_chunk, src, max_pos);
    src += self->chunk_len;
    self->msg_len += self->chunk_len << 3;
    if (old_chunk + self->chunk_len < 64) return self->msg_len;
    do {
        MD5_HashProcess(self);
        self->chunk_len = read_from_arr(self->msg, 64, src, max_pos);
        src += self->chunk_len;
        self->msg_len += self->chunk_len << 3;
    } while (self->chunk_len >= 64);
    return self->msg_len;
}
uint64_t MD5_HashFinal(MD5Object* self, uint8_t* dst) {
    uint64_t len_tmp = 0;
    // padding
    if (self->chunk_len < 56) {
        self->msg[self->chunk_len] = 0x80;
        memset(self->msg + self->chunk_len + 1, 0, 55 - self->chunk_len);
        len_tmp = self->msg_len;
        for (uint8_t i = 56; i < 64; ++i) {
            self->msg[i] = len_tmp & 0xff;
            len_tmp >>= 8;
        }
        MD5_HashProcess(self);
    } else {
        self->msg[self->chunk_len] = 0x80;
        memset(self->msg + self->chunk_len + 1, 0, 63 - self->chunk_len);
        self->chunk_len = 64;
        MD5_HashProcess(self);
        // length information in next chunk
        memset(self->msg, 0, 56);
        len_tmp = self->msg_len;
        for (uint8_t i = 56; i < 64; ++i) {
            self->msg[i] = len_tmp & 0xff;
            len_tmp >>= 8;
        }
        MD5_HashProcess(self);
    }
    // convert state vector to octet string
    for (uint8_t i = 0; i < 4; ++i) {
        dst[i] = self->a0 & 0xff;
        dst[i + 4] = self->b0 & 0xff;
        dst[i + 8] = self->c0 & 0xff;
        dst[i + 12] = self->d0 & 0xff;
        self->a0 >>= 8;
        self->b0 >>= 8;
        self->c0 >>= 8;
        self->d0 >>= 8;
    }
    // reset to default state
    self->a0 = a0_iv;
    self->b0 = b0_iv;
    self->c0 = c0_iv;
    self->d0 = d0_iv;
    len_tmp = self->msg_len;
    self->msg_len = self->chunk_len = 0;
    // self->msg no need to reset
    return len_tmp;
}

PyObject* md5(PyObject* self, PyObject* args) {
    Py_buffer view;
    if (!PyArg_ParseTuple(args, "y*", &view)) return NULL;
    MD5Object obj = {a0_iv, b0_iv, c0_iv, d0_iv, 0, 0, {0}};
    MD5_HashUpdate(&obj, view.buf, view.len);
    char* dst = malloc(md5_hlen);
    MD5_HashFinal(&obj, (uint8_t*)(dst));
    PyObject* rv = Py_BuildValue("y#", dst, md5_hlen);
    free(dst);
    PyBuffer_Release(&view);
    return rv;
}
