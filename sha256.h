#ifndef SHA256_H
#define SHA256_H

/* public domain sha256 implementation based on fips180-3 */
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

// msg size < 2^64 bits,  block size 512 bits, word size 32 bits
// msg size < 2^61 bytes, block size 64 bytes, word size 4 bytes
// msg size < 2^59 int32, block size 16 int32, word size 1 int32

enum sha32_block_length_t {
        SHA1_BLOCK_LENGTH   = 512/8,
        SHA224_BLOCK_LENGTH = 512/8,
        SHA256_BLOCK_LENGTH = 512/8,
};

enum sha32_digest_length_t {
        SHA1_DIGEST_LENGTH   = 160/8,
        SHA224_DIGEST_LENGTH = 224/8,
        SHA256_DIGEST_LENGTH = 256/8,
};

ssize_t sha256_block (uint8_t const * msg,
                      size_t msg_sz,
                      uint8_t digest[SHA256_BLOCK_LENGTH]);

ssize_t sha256_pipe (FILE * in, FILE * out, FILE * dbg);

ssize_t hmac_sha256 (uint8_t const * key,
                     size_t key_sz,
                     FILE * input,
                     uint8_t digest[SHA256_BLOCK_LENGTH]);

// low level interfaces ///////////////////////////////////////////////////////
void sha256_update(uint32_t      H[SHA256_DIGEST_LENGTH/sizeof(uint32_t)],
                   uint32_t      W[SHA256_BLOCK_LENGTH],
                   uint8_t const M[SHA256_BLOCK_LENGTH]);

#endif

