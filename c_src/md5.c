#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <stdint.h>
#include <stdlib.h>
#include "array_read.h"
// state array
static uint32_t a0_ = 0x67452301;
static uint32_t b0_ = 0xefcdab89;
static uint32_t c0_ = 0x98badcfe;
static uint32_t d0_ = 0x10325476;
// temporary save
static uint64_t msg_len_ = 0, chunk_len_ = 0;
// 512 bits
static uint8_t msg_[64];
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

static const size_t md5_hlen = 16;

void MD5_HashProcess() {
    uint32_t a, b, c, d;
    a = a0_;
    b = b0_;
    c = c0_;
    d = d0_;
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
        f += a + msg_[j] + (uint32_t)(msg_[j + 1] << 8) +
             (uint32_t)(msg_[j + 2] << 16) + (uint32_t)(msg_[j + 3] << 24) +
             K[i];
        a = d;
        d = c;
        c = b;
        b += (f << S[i]) | (f >> (32 - S[i]));
    }
    a0_ += a;
    b0_ += b;
    c0_ += c;
    d0_ += d;
}
uint64_t MD5_HashUpdate(const uint8_t* src, uint64_t bytelen) {
    if (!src) return msg_len_;
    uint64_t old_chunk = chunk_len_;
    const uint8_t* max_pos = src + bytelen;
    chunk_len_ = read_from_arr(msg_ + old_chunk, 64 - old_chunk, src, max_pos);
    src += chunk_len_;
    msg_len_ += chunk_len_ << 3;
    if (old_chunk + chunk_len_ < 64) return msg_len_;
    do {
        MD5_HashProcess();
        chunk_len_ = read_from_arr(msg_, 64, src, max_pos);
        src += chunk_len_;
        msg_len_ += chunk_len_ << 3;
    } while (chunk_len_ >= 64);
    return msg_len_;
}
uint64_t MD5_HashFinal(uint8_t* dst) {
    uint64_t len_tmp = 0;
    // padding
    if (chunk_len_ < 56) {
        msg_[chunk_len_] = 0x80;
        memset(msg_ + chunk_len_ + 1, 0, 55 - chunk_len_);
        len_tmp = msg_len_;
        for (uint8_t i = 56; i < 64; ++i) {
            msg_[i] = len_tmp & 0xff;
            len_tmp >>= 8;
        }
        MD5_HashProcess();
    } else {
        msg_[chunk_len_] = 0x80;
        memset(msg_ + chunk_len_ + 1, 0, 63 - chunk_len_);
        chunk_len_ = 64;
        MD5_HashProcess();
        // length information in next chunk
        memset(msg_, 0, 56);
        len_tmp = msg_len_;
        for (uint8_t i = 56; i < 64; ++i) {
            msg_[i] = len_tmp & 0xff;
            len_tmp >>= 8;
        }
        MD5_HashProcess();
    }
    // convert state vector to octet string
    for (uint8_t i = 0; i < 4; ++i) {
        dst[i] = a0_ & 0xff;
        dst[i + 4] = b0_ & 0xff;
        dst[i + 8] = c0_ & 0xff;
        dst[i + 12] = d0_ & 0xff;
        a0_ >>= 8;
        b0_ >>= 8;
        c0_ >>= 8;
        d0_ >>= 8;
    }
    // reset to default state
    a0_ = 0x67452301;
    b0_ = 0xefcdab89;
    c0_ = 0x98badcfe;
    d0_ = 0x10325476;
    len_tmp = msg_len_;
    msg_len_ = chunk_len_ = 0;
    // msg_ no need to reset
    return len_tmp;
}

PyObject* md5(PyObject* self, PyObject* args) {
    Py_buffer view;
    if (!PyArg_ParseTuple(args, "y*", &view)) return NULL;
    MD5_HashUpdate(view.buf, view.len);
    char* dst = malloc(md5_hlen);
    MD5_HashFinal((uint8_t*)(dst));
    PyObject* rv = Py_BuildValue("y#", dst, md5_hlen);
    free(dst);
    PyBuffer_Release(&view);
    return rv;
}
