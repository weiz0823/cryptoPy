#ifndef ARRAY_READ_H
#define ARRAY_READ_H
#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

inline uint64_t read_from_arr(uint8_t* buf, uint64_t count, const uint8_t* src,
                              const uint8_t* max_pos) {
    if (src >= max_pos || count == 0) {
        return 0;
    } else if (src + count > max_pos) {
        count = max_pos - src;
    }
    memcpy(buf, src, count);
    return count;
}
inline uint32_t LeftRotate32(uint32_t x, uint32_t n) {
    return (x << n) | (x >> (32 - n));
}
inline uint32_t RightRotate32(uint32_t x, uint32_t n) {
    return (x >> n) | (x << (32 - n));
}
inline uint64_t LeftRotate64(uint64_t x, uint64_t n) {
    return (x << n) | (x >> (64 - n));
}
inline uint64_t RightRotate64(uint64_t x, uint64_t n) {
    return (x >> n) | (x << (64 - n));
}
#endif /* ifndef ARRAY_READ_H */
