#include "array_read.h"
static const uint32_t a0_iv = 0x67452301;
static const uint32_t b0_iv = 0xefcdab89;
static const uint32_t c0_iv = 0x98badcfe;
static const uint32_t d0_iv = 0x10325476;
static const uint32_t e0_iv = 0xc3d2e1f0;

typedef struct {
    // state array
    uint32_t a0;
    uint32_t b0;
    uint32_t c0;
    uint32_t d0;
    uint32_t e0;
    // temporary save
    uint64_t msg_len, chunk_len;
    // 512 bits per block
    uint8_t msg[64];
} SHA1Object;

static const size_t sha1_hlen = 20;

void SHA1_HashProcess(SHA1Object* self) {
    uint32_t a, b, c, d, e;
    uint32_t f;
    uint32_t j;
    uint32_t w[80];
    a = self->a0;
    b = self->b0;
    c = self->c0;
    d = self->d0;
    e = self->e0;
    for (uint8_t i = 0; i < 80; ++i) {
        if (i < 16) {
            w[i] = (uint32_t)(self->msg[4 * i + 3]) +
                   (uint32_t)(self->msg[4 * i + 2] << 8) +
                   (uint32_t)(self->msg[4 * i + 1] << 16) +
                   (uint32_t)(self->msg[4 * i] << 24);
        } else {
            w[i] = LeftRotate32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
        }
        if (i < 20) {
            f = (b & c) | (~b & d);
            j = 0x5A827999;
        } else if (i < 40) {
            f = b ^ c ^ d;
            j = 0x6ED9EBA1;
        } else if (i < 60) {
            f = (b & c) | (b & d) | (c & d);
            j = 0x8F1BBCDC;
        } else {
            f = b ^ c ^ d;
            j = 0xCA62C1D6;
        }
        f += e + LeftRotate32(a, 5) + j + w[i];
        e = d;
        d = c;
        c = LeftRotate32(b, 30);
        b = a;
        a = f;
    }
    self->a0 += a;
    self->b0 += b;
    self->c0 += c;
    self->d0 += d;
    self->e0 += e;
}
uint64_t SHA1_HashUpdate(SHA1Object* self, const uint8_t* src,
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
        SHA1_HashProcess(self);
        self->chunk_len = read_from_arr(self->msg, 64, src, max_pos);
        src += self->chunk_len;
        self->msg_len += self->chunk_len << 3;
    } while (self->chunk_len >= 64);
    return self->msg_len;
}
uint64_t SHA1_HashFinal(SHA1Object* self, uint8_t* dst) {
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
        SHA1_HashProcess(self);
    } else {
        self->msg[self->chunk_len] = 0x80;
        memset(self->msg + self->chunk_len + 1, 0, 63 - self->chunk_len);
        self->chunk_len = 64;
        SHA1_HashProcess(self);
        // length information in next chunk
        memset(self->msg, 0, 56);
        len_tmp = self->msg_len;
        for (uint8_t i = 63; i >= 56; --i) {
            self->msg[i] = len_tmp & 0xff;
            len_tmp >>= 8;
        }
        SHA1_HashProcess(self);
    }
    for (uint8_t i = 3; i != (uint8_t)(-1); --i) {
        dst[i] = self->a0 & 0xff;
        dst[i + 4] = self->b0 & 0xff;
        dst[i + 8] = self->c0 & 0xff;
        dst[i + 12] = self->d0 & 0xff;
        dst[i + 16] = self->e0 & 0xff;
        self->a0 >>= 8;
        self->b0 >>= 8;
        self->c0 >>= 8;
        self->d0 >>= 8;
        self->e0 >>= 8;
    }
    self->a0 = a0_iv;
    self->b0 = b0_iv;
    self->c0 = c0_iv;
    self->d0 = d0_iv;
    self->e0 = e0_iv;
    len_tmp = self->msg_len;
    self->msg_len = 0;
    self->chunk_len = 0;
    return len_tmp;
}

PyObject* sha1(PyObject* self, PyObject* args) {
    Py_buffer view;
    if (!PyArg_ParseTuple(args, "y*", &view)) return NULL;
    SHA1Object obj = {a0_iv, b0_iv, c0_iv, d0_iv, e0_iv, 0, 0, {0}};
    SHA1_HashUpdate(&obj, view.buf, view.len);
    char* dst = malloc(sha1_hlen);
    SHA1_HashFinal(&obj, (uint8_t*)(dst));
    PyObject* rv = Py_BuildValue("y#", dst, sha1_hlen);
    free(dst);
    PyBuffer_Release(&view);
    return rv;
}
