// AES-XEX memory encryption, tweaked by the block address.
//
//   T = AES_Enc(K_tweak, nonce0 || nonce1 || 0 || block_index)
//   C = AES_Enc(K_code, P xor T) xor T
//   P = AES_Dec(K_code, C xor T) xor T
//
// Compared with ECB, identical instruction blocks at different addresses give
// different ciphertexts, and a block moved to another address decrypts to
// unrelated data. Compared with CTR, a flipped ciphertext bit does not flip a
// chosen plaintext bit: the whole block decrypts to unpredictable data.
// T depends on the nonce and block index. Overlapping its calculation with a
// memory read is an implementation choice, not a timing guarantee of this model.
#include "cryptocpu.h"

void xex_tweak(const AesRoundKeys *k_tweak, const uint32_t nonce[2], uint32_t block_index,
               uint32_t tweak[4]) {
    uint32_t in[4] = {nonce[0], nonce[1], 0u, block_index};
    aes128_encrypt(k_tweak, in, tweak);
}

void xex_encrypt_block(const AesRoundKeys *k_code, const AesRoundKeys *k_tweak,
                       const uint32_t nonce[2], uint32_t block_index,
                       const uint32_t plain[4], uint32_t cipher[4]) {
    uint32_t t[4], x[4], y[4];
    xex_tweak(k_tweak, nonce, block_index, t);
    for (int i = 0; i < 4; i++) x[i] = plain[i] ^ t[i];
    aes128_encrypt(k_code, x, y);
    for (int i = 0; i < 4; i++) cipher[i] = y[i] ^ t[i];
}

void xex_decrypt_block(const AesRoundKeys *k_code, const AesRoundKeys *k_tweak,
                       const uint32_t nonce[2], uint32_t block_index,
                       const uint32_t cipher[4], uint32_t plain[4]) {
    uint32_t t[4], x[4], y[4];
    xex_tweak(k_tweak, nonce, block_index, t);
    for (int i = 0; i < 4; i++) x[i] = cipher[i] ^ t[i];
    aes128_decrypt(k_code, x, y);
    for (int i = 0; i < 4; i++) plain[i] = y[i] ^ t[i];
}
