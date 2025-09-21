#ifndef HEADER_H
#define HEADER_H

#define MEM_SIZE 256
#define INSTRS_PER_BLOCK 4

#ifdef __cplusplus
extern "C" {
#endif

extern uint32_t memory[MEM_SIZE];

void create_large_block_with_key(uint32_t key[4]);
void extract_key_from_large_block(uint32_t key[4]);
void aes_encrypt_block(uint32_t in[4], uint32_t key[4], uint32_t out[4]);
void aes_decrypt_block(uint32_t in[4], uint32_t key[4], uint32_t out[4]);

#ifdef __cplusplus
}
#endif

#endif
