// AES-128 (FIPS-197) for the CryptoCPU.
//
// A 128-bit block is held as four 32-bit words in big-endian byte order:
// word 0 holds bytes 0..3 of the block, most significant byte first. This
// matches the FIPS-197 test vectors written as hex strings.
//
// The key schedule is expanded once (at reset in hardware) and reused for
// every block, so the per-block cost is only the ten rounds.
#ifndef CRYPTOCPU_AES128_H
#define CRYPTOCPU_AES128_H

#include <stdint.h>

struct AesRoundKeys {
    uint8_t rk[11][16];  // round keys, byte i of the state in column-major order
};

void aes128_expand_key(const uint32_t key[4], AesRoundKeys *out);
void aes128_encrypt(const AesRoundKeys *k, const uint32_t in[4], uint32_t out[4]);
void aes128_decrypt(const AesRoundKeys *k, const uint32_t in[4], uint32_t out[4]);

#endif
