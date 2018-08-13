#include <stdlib.h>
#include <string.h>
#include "sha32.h"
#include "sha256.h"

#define SIGMA_256_0(x)      (rotr32(x, 2) ^ rotr32(x,13) ^ rotr32(x,22))
#define SIGMA_256_1(x)      (rotr32(x, 6) ^ rotr32(x,11) ^ rotr32(x,25))
#define sigma_256_0(x)      (rotr32(x, 7) ^ rotr32(x,18) ^ (x>>3))
#define sigma_256_1(x)      (rotr32(x,17) ^ rotr32(x,19) ^ (x>>10))

static const uint32_t K256[SHA256_BLOCK_LENGTH] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

void sha256_update(uint32_t      H[SHA256_DIGEST_LENGTH/sizeof(uint32_t)],
                   uint32_t      W[SHA256_BLOCK_LENGTH],
                   uint8_t const M[SHA256_BLOCK_LENGTH]) {

    // 1. prepare message schedule
	for ( size_t t = 0;
                 t < SHA256_BLOCK_LENGTH/sizeof(uint32_t);
                 t ++ ) {
		W[t]  = (uint32_t)M[4*t+0] << 24;
		W[t] |= (uint32_t)M[4*t+1] << 16;
		W[t] |= (uint32_t)M[4*t+2] <<  8;
		W[t] |= (uint32_t)M[4*t+3] <<  0;
	}
	for ( size_t t = SHA256_BLOCK_LENGTH/sizeof(uint32_t);
                 t < SHA256_BLOCK_LENGTH;
                 t ++ ) {
		W[t]  = sigma_256_1(W[t-2]);
		W[t] += W[t-7];
		W[t] += sigma_256_0(W[t-15]);
		W[t] += W[t-16];
    }

    // 2. initialize working variables with previous hash
    uint32_t a, b, c, d, e, f, g, h;
	a = H[0];
	b = H[1];
	c = H[2];
	d = H[3];
	e = H[4];
	f = H[5];
	g = H[6];
	h = H[7];

    // 3.
	for ( size_t t = 0;
                 t < SHA256_BLOCK_LENGTH;
                 t ++ ) {
		uint32_t T1 = h + SIGMA_256_1(e) + Ch32(e,f,g) + K256[t] + W[t];
		uint32_t T2 = SIGMA_256_0(a) + Maj32(a,b,c);
		h = g;
		g = f;
		f = e;
		e = d + T1;
		d = c;
		c = b;
		b = a;
		a = T1 + T2;
	}

    // 4. compute the intermediate hash
	H[0] += a;
	H[1] += b;
	H[2] += c;
	H[3] += d;
	H[4] += e;
	H[5] += f;
	H[6] += g;
	H[7] += h;
}

static inline ssize_t fdump256 (FILE* out, uint8_t const * m) {
    if (out == NULL) {
        return 0;
    }
    if (fwrite (m, 1, SHA256_BLOCK_LENGTH, out) < SHA256_BLOCK_LENGTH) {
        exit (EXIT_FAILURE);
    }
    return SHA256_BLOCK_LENGTH;
}

struct sha256_t {
    // nb of bytes hashed
    uint64_t l;
    // the current hash as an array of 8 words
    uint32_t H[SHA256_DIGEST_LENGTH/sizeof(uint32_t)];
};

// FIPS-180-4 5.3.3
static void sha256_init (struct sha256_t * hasher) {
    hasher->l = 0;
    // Initial hash for SHA-256 is obtained by taking
    // the 1st 32bits of the fractional part of the
    // square root of 1st 8 primes.
    hasher->H[0] = 0x6a09e667;
	hasher->H[1] = 0xbb67ae85;
    hasher->H[2] = 0x3c6ef372;
	hasher->H[3] = 0xa54ff53a;
    hasher->H[4] = 0x510e527f;
	hasher->H[5] = 0x9b05688c;
    hasher->H[6] = 0x1f83d9ab;
	hasher->H[7] = 0x5be0cd19;
}

// FIPS-180-4 6.2.2
// M is one block of the input message to hash, 512 bits (64 bytes) 
// 4*64bytes allocated on stack
static void sha256_run (struct sha256_t * hasher,
                        uint8_t const M[SHA256_BLOCK_LENGTH]) {
    // a working buffer of 64 words
    uint32_t W[SHA256_BLOCK_LENGTH] = { 0 };
    sha256_update(hasher->H, W, M);
    hasher->l += SHA256_BLOCK_LENGTH;
}

// FIPS-180-4 5.1.1
// M is the last block of the input message to hash
// M_sz in the last block size, strictly less than 64 bytes 
// 5*64bytes allocated on stack
static void sha256_end (struct sha256_t * hasher,
                        uint8_t const M[SHA256_BLOCK_LENGTH],
                        size_t M_sz) {
    // a working buffer of 64 words
    uint32_t W[SHA256_BLOCK_LENGTH] = { 0 };
    // Needed for const correctness (64 bytes)
    uint8_t m[SHA256_BLOCK_LENGTH] = { 0 };

    assert (M_sz < SHA256_BLOCK_LENGTH);
    assert (M_sz < UINT64_MAX - hasher->l);
   
    hasher->l += M_sz;
    memcpy (m, M, M_sz);
    m[M_sz] = 0x80;
    M_sz ++;
    
    // length
    if (SHA256_BLOCK_LENGTH - M_sz < sizeof(uint64_t)) {
        // not enough room to write the length
        memset (&m[M_sz], 0, SHA256_BLOCK_LENGTH - M_sz);
        sha256_update(hasher->H, W, m);
        M_sz = 0;
    }
    assert (SHA256_BLOCK_LENGTH >= M_sz + sizeof(uint64_t));
    assert (hasher->l < UINT64_MAX / 8);
    memset (&m[M_sz], 0, 
            SHA256_BLOCK_LENGTH - M_sz - sizeof(uint64_t));
	hasher->l *= 8;
    uint64_to_bytes(hasher->l, &(m[56]));
	sha256_update(hasher->H, W, m);
	hasher->l /= 8;
}

// get the hash out of the struct
static void sha256_sum (struct sha256_t * hasher,
                        uint8_t digest[SHA256_BLOCK_LENGTH]) {
	for ( size_t t = 0;
          t < SHA256_DIGEST_LENGTH/sizeof(uint32_t);
          t++ ) {
        uint32_to_bytes (hasher->H[t], &digest[4*t]);
    }
}

ssize_t sha256_block (uint8_t const * msg,
                      size_t msg_sz,
                      uint8_t digest[SHA256_BLOCK_LENGTH]) {
    struct sha256_t hasher = { 0 };
    sha256_init (&hasher);
    while (msg_sz >= SHA256_BLOCK_LENGTH) {
        sha256_run (&hasher, msg);
        msg += SHA256_BLOCK_LENGTH;
        msg_sz -= SHA256_BLOCK_LENGTH;
    }
    sha256_end (&hasher, msg, msg_sz);
    sha256_sum (&hasher, digest);
    return hasher.l;
}

ssize_t sha256_pipe (FILE * in, FILE * out, FILE * dbg) {
    struct sha256_t hasher = { 0 };
    // one block of the input message, 512 bits (64 bytes) 
    uint8_t  M[SHA256_BLOCK_LENGTH] = { 0 };
    sha256_init (&hasher);
    size_t n = fread (M, 1, SHA256_BLOCK_LENGTH, in);
    while (n == SHA256_BLOCK_LENGTH) {
        fdump256 (dbg, M);
        sha256_run (&hasher, M);
        n = fread (M, 1, SHA256_BLOCK_LENGTH, in);
    }
    fdump256 (dbg, M);
    sha256_end (&hasher, M, n);
    uint8_t md[SHA256_DIGEST_LENGTH];
    sha256_sum (&hasher, md);
    if (fwrite (md, 1, SHA256_DIGEST_LENGTH, out) < SHA256_DIGEST_LENGTH) {
        return -1;
    }
    return hasher.l;
}

ssize_t hmac_sha256 (uint8_t const * key,
                     size_t key_sz,
                     FILE * input,
                     uint8_t digest[SHA256_BLOCK_LENGTH]) {
    // 1st normalize key:
    uint8_t  M[SHA256_BLOCK_LENGTH] = { 0 };
    if (key_sz <= SHA256_BLOCK_LENGTH) {
        memcpy(M, key, key_sz);   
    } else {
        sha256_block(key, key_sz, M);
    }
    // 2nd inner and outer keys:
    uint8_t okey[SHA256_BLOCK_LENGTH] = { 0 };
    for (size_t k = 0; k < SHA256_BLOCK_LENGTH; k ++) {
        okey[k] = M[k] ^ 0x5c;
        M[k] = M[k] ^ 0x36;
    }
    // inner hash
    struct sha256_t hasher = { 0 };
    sha256_init (&hasher);
    sha256_run (&hasher, M);
    size_t n = fread (M, 1, SHA256_BLOCK_LENGTH, input);
    while (n == SHA256_BLOCK_LENGTH) {
        sha256_run (&hasher, M);
        n = fread (M, 1, SHA256_BLOCK_LENGTH, input);
    }
    sha256_end (&hasher, M, n);
    uint8_t ihash[SHA256_DIGEST_LENGTH];
    sha256_sum (&hasher, ihash);
    // outer hash
    sha256_init (&hasher);
    sha256_run (&hasher, okey);
    sha256_end (&hasher, ihash, SHA256_DIGEST_LENGTH);
    sha256_sum (&hasher, digest);
    return n;
}

#if defined TEST_SHA256
int main (int argc, char** argv) {
    if (argc < 2) {
        sha256_pipe (stdin, stdout, stdout);
    } else {
        for (int k = 1; k < argc; k ++) {
            FILE * in = fopen (argv[k], "rb");
            if (in != NULL) {
                sha256_pipe (in, stdout, stderr);
                fclose (in);
            } else {
                fprintf (stderr, "can not open file %s\n", argv[k]);
            }
        }
    }
    return 0;
}
#elif defined TEST_HMAC_SHA256
int main (int argc, char** argv) {
    if (argc <= 1) {
    } else if (argc == 2) {
        uint8_t digest[SHA256_BLOCK_LENGTH] = { 0 };
        hmac_sha256 (argv[1], strlen(argv[1]), stdin, digest);
        for(size_t n = 0; n < SHA256_DIGEST_LENGTH; n++ ) {
            printf( "%02x", digest[n] );
        }
        putchar( '\n' );
    } else for (int k = 2; k < argc; k ++) {
        FILE * in = fopen (argv[k], "rb");
        if (in == NULL) {
        } else {
            uint8_t digest[SHA256_BLOCK_LENGTH] = { 0 };
            hmac_sha256 (argv[1], strlen(argv[1]), in, digest);
            fclose (in);
            for(size_t n = 0; n < SHA256_DIGEST_LENGTH; n++ ) {
		        printf( "%02x", digest[n] );
            }
            putchar( '\n' );
        }
    }
    return 0;
}
#endif
