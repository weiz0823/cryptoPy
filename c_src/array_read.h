#ifndef ARRAY_READ_H
#define ARRAY_READ_H
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
#endif /* ifndef ARRAY_READ_H */
