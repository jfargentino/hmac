#ifndef SHA32_H
#define SHA32_H

#include <stdint.h>
#include <assert.h>

static inline uint32_t rotl32(uint32_t x, unsigned int w) {
    assert (w < sizeof(uint32_t)*8);
    return (x << w) | (x >> (sizeof(uint32_t)*8-w));
}

static inline uint32_t rotr32(uint32_t x, unsigned int w) {
    assert (w < sizeof(uint32_t)*8);
    return (x >> w) | (x << (sizeof(uint32_t)*8-w));
}

static inline uint32_t Ch32(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (~x & z);
}

static inline uint32_t Maj32(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

static inline uint32_t Parity32(uint32_t x, uint32_t y, uint32_t z) {
    return x ^ y ^ z;
}

static inline void uint32_to_bytes(uint32_t x, uint8_t y[sizeof(uint32_t)]) {
	y[0] = x >> 24;
	y[1] = x >> 16;
	y[2] = x >> 8;
	y[3] = x;
}

static inline uint32_t bytes_to_uint32(uint8_t const y[sizeof(uint32_t)]) {
    return ((uint32_t)y[0] << 24) | ((uint32_t)y[1] << 16)
                                  | ((uint32_t)y[2] << 8)
                                  | ((uint32_t)y[3]);
}

static inline void uint64_to_bytes(uint64_t x, uint8_t y[sizeof(uint64_t)]) {
	y[0] = x >> 56;
	y[1] = x >> 48;
	y[2] = x >> 40;
	y[3] = x >> 32;
	y[4] = x >> 24;
	y[5] = x >> 16;
	y[6] = x >> 8;
	y[7] = x;
}

static inline uint64_t bytes_to_uint64(uint8_t const y[sizeof(uint64_t)]) {
    return ((uint64_t)y[0] << 56) | ((uint64_t)y[1] << 48) 
                                  | ((uint64_t)y[2] << 40)
                                  | ((uint64_t)y[3] << 32)
                                  | ((uint64_t)y[4] << 24)
                                  | ((uint64_t)y[5] << 16)
                                  | ((uint64_t)y[6] << 8)
                                  | ((uint64_t)y[7]);
}

#endif

