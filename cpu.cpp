#include <stdint.h>
#include "header.h"
#include <stdlib.h>
#include <cstdint>
#include <stdio.h>
// ============================================================================
// ================  ΠΑΡΑΜΕΤΡΟΙ / ΟΡΙΣΜΟΙ  =====================================
// ============================================================================

#define AES_BLOCK_SIZE   16
#define NUM_REGS         32
#define MEM_SIZE         256
#define INSTRS_PER_BLOCK 4
#define ICACHE_LINES     4
#define DCACHE_LINES     4

enum OPCODES {
    NOP     = 0,
    ADD     = 1,
    SUB     = 2,
    LW      = 3,
    SW      = 4,
    AES_ENC = 5,
    AES_DEC = 6,
    AND_    = 7,
    OR_     = 8,
    XOR_    = 9,
    SLL     = 10,
    SRL     = 11,
    MULT    = 12,
    BEQ     = 13,
    BNE     = 14,
    J       = 15
};

typedef union {
    uint32_t raw;
    struct {
        uint32_t opcode : 6;
        uint32_t rs     : 5;
        uint32_t rt     : 5;
        uint32_t rd     : 5;
        uint32_t shamt  : 5;
        uint32_t funct  : 6;
    } r_type;
    struct {
        uint32_t opcode : 6;
        uint32_t rs     : 5;
        uint32_t rt     : 5;
        uint32_t imm    : 16;
    } i_type;
    struct {
        uint32_t opcode : 6;
        uint32_t target : 26;
    } j_type;
} InstructionUnion;

// ============================================================================
// ================  ΚΑΘΟΛΙΚΕΣ ΔΟΜΕΣ - REGISTERS - MEMORY  =====================
// ============================================================================

uint32_t memory[MEM_SIZE];
uint32_t reg_file[NUM_REGS];

static const uint32_t EXPECTED_AES_KEY[4] = {
    0x12345678, 0x9ABCDEF0, 0xFEDCBA98, 0x76543210
};
static bool key_check_failed = false;
static uint32_t aes_key[4];
static bool     key_valid = false;
static uint32_t copro_reg[4];

static int secret[128] = {
    849, 171, 458, 347, 306, 11, 1023, 282, 
    948, 361, 329, 145, 456, 499, 334, 535,
    633, 416, 924, 50, 670, 73, 20, 906,
    680, 673, 108, 491, 900, 552, 419, 121,
    182, 421, 824, 479, 796, 628, 135, 124,
    604, 147, 157, 693, 515, 821, 90, 784,
    138, 269, 66, 732, 823, 1011, 53, 118,
    711, 684, 117, 753, 195, 496, 97, 898,
    651, 418, 695, 713, 122, 591, 556, 669,
    265, 346, 634, 630, 1003, 790, 144, 384,
    657, 636, 1002, 493, 55, 873, 475, 861,
    573, 537, 782, 601, 471, 595, 1000, 915,
    596, 3, 714, 632, 311, 649, 660, 150,
    706, 372, 724, 923, 485, 609, 363, 336,
    41, 85, 451, 249, 587, 956, 79, 480,
    743, 198, 500, 447, 996, 908, 351, 380
};

// ============================================================================
// ================  iCACHE (Instruction Cache)  ==============================
// ============================================================================

static uint32_t iCache_data[ICACHE_LINES][INSTRS_PER_BLOCK];
static uint32_t iCache_tag[ICACHE_LINES];
static bool     iCache_valid[ICACHE_LINES];

static void icache_get_index_tag(uint32_t block_addr, uint32_t &index, uint32_t &tag) {
#pragma HLS INLINE
    index = block_addr % ICACHE_LINES;
    tag   = block_addr / ICACHE_LINES;
}

static void icache_fetch_block_from_mem(uint32_t block_addr, uint32_t out_block[INSTRS_PER_BLOCK]) {
#pragma HLS INLINE off
    const uint32_t max_blocks = MEM_SIZE / INSTRS_PER_BLOCK;
    if (block_addr >= max_blocks) {
        // Εκτός των διαθέσιμων blocks → γεμίζουμε με NOPs
        for (int i = 0; i < INSTRS_PER_BLOCK; i++) {
            out_block[i] = 0;
        }
    } else {
        uint32_t base = block_addr * INSTRS_PER_BLOCK;
        for (int i = 0; i < INSTRS_PER_BLOCK; i++) {
            out_block[i] = memory[base + i];
        }
    }
}

static void icache_read_block(uint32_t block_addr, uint32_t out_block[INSTRS_PER_BLOCK]) {
#pragma HLS INLINE off
    uint32_t index, tag;
    icache_get_index_tag(block_addr, index, tag);
    if (!iCache_valid[index] || iCache_tag[index] != tag) {
        icache_fetch_block_from_mem(block_addr, iCache_data[index]);
        iCache_tag[index]   = tag;
        iCache_valid[index] = true;
    }
    for (int i = 0; i < INSTRS_PER_BLOCK; i++) {
        out_block[i] = iCache_data[index][i];
    }
}

// ============================================================================
// ================  dCACHE (Data Cache)  =====================================
// ============================================================================

static uint32_t dcache_data[DCACHE_LINES];
static uint32_t dcache_tag[DCACHE_LINES];
static bool     dcache_valid[DCACHE_LINES];

static void dcache_get_index_tag(uint32_t addr, uint32_t &index, uint32_t &tag) {
#pragma HLS INLINE
    index = addr % DCACHE_LINES;
    tag   = addr / DCACHE_LINES;
}

static uint32_t dcache_read(uint32_t addr) {
#pragma HLS INLINE off
    uint32_t index, tag;
    dcache_get_index_tag(addr, index, tag);
    if (!dcache_valid[index] || dcache_tag[index] != tag) {
        dcache_data[index]  = memory[addr];
        dcache_tag[index]   = tag;
        dcache_valid[index] = true;
    }
    return dcache_data[index];
}

static void dcache_write(uint32_t addr, uint32_t value) {
#pragma HLS INLINE off
    uint32_t index, tag;
    dcache_get_index_tag(addr, index, tag);
    dcache_data[index]  = value;
    dcache_tag[index]   = tag;
    dcache_valid[index] = true;
    memory[addr]        = value;
}

// ============================================================================
// ================  Συναρτήσεις για Εξαγωγή και Δημιουργία Κλειδιού  =========
// ============================================================================

void extract_key_from_large_block(uint32_t key[4]) {
    for (int i = 0; i < 4; i++) key[i] = 0;

    for (int i = 0; i < 128; i++) {
        int bit_pos    = secret[i];
        int word_index = bit_pos / 32;
        int bit_in_word = bit_pos % 32;

        uint32_t bit_val = (memory[word_index] >> bit_in_word) & 1;

        int key_word = i / 32;
        int key_bit  = i % 32;

        key[key_word] |= (bit_val << key_bit);
    }
}

void create_large_block_with_key(uint32_t key[4]) {
    for (int i = 0; i < 32; i++) memory[i] = 0xDEADBEEF;

    for (int i = 0; i < 128; i++) {
        int bit_pos    = secret[i];
        int word_index = bit_pos / 32;
        int bit_in_word = bit_pos % 32;

        int key_word = i / 32;
        int key_bit  = i % 32;

        uint32_t bit_val = (key[key_word] >> key_bit) & 1;

        memory[word_index] &= ~(1u << bit_in_word);
        memory[word_index] |= (bit_val << bit_in_word);
    }
}

// ============================================================================
// ================  ΚΩΔΙΚΑΣ AES (Encrypt / Decrypt)  =========================
// ============================================================================

static const uint8_t sbox[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

static const uint8_t inv_sbox[256] = {
    0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
    0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
    0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
    0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
    0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
    0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
    0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
    0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
    0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
    0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
    0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
    0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
    0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
    0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
    0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
};

static const uint8_t Rcon[11] = {
    0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36
};

static uint8_t galois_mul(uint8_t a, uint8_t b) {
#pragma HLS INLINE
    uint8_t p = 0, hi;
    for (int i = 0; i < 8; i++) {
        if (b & 1) p ^= a;
        hi = a & 0x80;
        a <<= 1;
        if (hi) a ^= 0x1b;
        b >>= 1;
    }
    return p;
}

static void add_round_key(uint8_t state[4][4], uint8_t rk[4][4]) {
#pragma HLS INLINE
    for (int i = 0; i < 4; i++) {
#pragma HLS UNROLL
        for (int j = 0; j < 4; j++) {
#pragma HLS UNROLL
            state[i][j] ^= rk[i][j];
        }
    }
}

static void sub_bytes(uint8_t state[4][4]) {
    for (int i = 0; i < 4; i++) {
#pragma HLS UNROLL
        for (int j = 0; j < 4; j++) {
#pragma HLS UNROLL
            state[i][j] = sbox[state[i][j]];
        }
    }
}

static void inv_sub_bytes(uint8_t state[4][4]) {
    for (int i = 0; i < 4; i++) {
#pragma HLS UNROLL
        for (int j = 0; j < 4; j++) {
#pragma HLS UNROLL
            state[i][j] = inv_sbox[state[i][j]];
        }
    }
}

static void shift_rows(uint8_t state[4][4]) {
    uint8_t tmp;
    tmp = state[1][0]; state[1][0]=state[1][1]; state[1][1]=state[1][2]; state[1][2]=state[1][3]; state[1][3]=tmp;
    tmp = state[2][0]; state[2][0]=state[2][2]; state[2][2]=tmp;
    tmp = state[2][1]; state[2][1]=state[2][3]; state[2][3]=tmp;
    tmp = state[3][3]; state[3][3]=state[3][2]; state[3][2]=state[3][1]; state[3][1]=state[3][0]; state[3][0]=tmp;
}

static void inv_shift_rows(uint8_t state[4][4]) {
    uint8_t tmp;
    tmp = state[1][3]; state[1][3]=state[1][2]; state[1][2]=state[1][1]; state[1][1]=state[1][0]; state[1][0]=tmp;
    tmp = state[2][0]; state[2][0]=state[2][2]; state[2][2]=tmp;
    tmp = state[2][1]; state[2][1]=state[2][3]; state[2][3]=tmp;
    tmp = state[3][0]; state[3][0]=state[3][1]; state[3][1]=state[3][2]; state[3][2]=state[3][3]; state[3][3]=tmp;
}

static void mix_columns(uint8_t state[4][4]) {
    for (int i = 0; i < 4; i++) {
#pragma HLS UNROLL
        uint8_t a0 = state[0][i], a1 = state[1][i], a2 = state[2][i], a3 = state[3][i];
        state[0][i] = galois_mul(a0,2) ^ galois_mul(a1,3) ^ a2 ^ a3;
        state[1][i] = a0 ^ galois_mul(a1,2) ^ galois_mul(a2,3) ^ a3;
        state[2][i] = a0 ^ a1 ^ galois_mul(a2,2) ^ galois_mul(a3,3);
        state[3][i] = galois_mul(a0,3) ^ a1 ^ a2 ^ galois_mul(a3,2);
    }
}

static void inv_mix_columns(uint8_t state[4][4]) {
    for (int i = 0; i < 4; i++) {
#pragma HLS UNROLL
        uint8_t a0 = state[0][i], a1 = state[1][i], a2 = state[2][i], a3 = state[3][i];
        state[0][i] = galois_mul(a0,0x0e) ^ galois_mul(a1,0x0b) ^ galois_mul(a2,0x0d) ^ galois_mul(a3,0x09);
        state[1][i] = galois_mul(a0,0x09) ^ galois_mul(a1,0x0e) ^ galois_mul(a2,0x0b) ^ galois_mul(a3,0x0d);
        state[2][i] = galois_mul(a0,0x0d) ^ galois_mul(a1,0x09) ^ galois_mul(a2,0x0e) ^ galois_mul(a3,0x0b);
        state[3][i] = galois_mul(a0,0x0b) ^ galois_mul(a1,0x0d) ^ galois_mul(a2,0x09) ^ galois_mul(a3,0x0e);
    }
}

static void key_expansion(uint8_t key[4][4], uint8_t round_keys[11][4][4]) {
#pragma HLS INLINE off
    uint32_t w[44], temp;
    for (int i = 0; i < 4; i++) {
#pragma HLS UNROLL
        w[i] = ((uint32_t)key[0][i]<<24) | ((uint32_t)key[1][i]<<16)
             | ((uint32_t)key[2][i]<<8 ) |  key[3][i];
    }
    for (int i = 4; i < 44; i++) {
#pragma HLS PIPELINE II=1
        temp = w[i-1];
        if (i % 4 == 0) {
            temp = (temp<<8)|(temp>>24);
            temp = ((uint32_t)sbox[(temp>>24)&0xFF]<<24)
                 | ((uint32_t)sbox[(temp>>16)&0xFF]<<16)
                 | ((uint32_t)sbox[(temp>>8 )&0xFF]<<8 )
                 |  sbox[temp&0xFF];
            temp ^= ((uint32_t)Rcon[i/4]<<24);
        }
        w[i] = w[i-4] ^ temp;
    }
    for (int r = 0; r < 11; r++) {
#pragma HLS UNROLL
        for (int c = 0; c < 4; c++) {
#pragma HLS UNROLL
            uint32_t word = w[r*4 + c];
            round_keys[r][0][c] = (word>>24)&0xFF;
            round_keys[r][1][c] = (word>>16)&0xFF;
            round_keys[r][2][c] = (word>>8 )&0xFF;
            round_keys[r][3][c] =  word    &0xFF;
        }
    }
}

extern "C" void aes_encrypt_block(uint32_t input[4], uint32_t key[4], uint32_t output[4]) {
#pragma HLS INLINE off
    uint8_t state[4][4], ks[4][4], round_keys[11][4][4];
    // --- FIX: Proper mapping from input[4] to state[4][4] (column-major, big-endian) ---
    for (int c = 0; c < 4; c++) {
        state[0][c] = (input[c] >> 24) & 0xFF;
        state[1][c] = (input[c] >> 16) & 0xFF;
        state[2][c] = (input[c] >> 8 ) & 0xFF;
        state[3][c] =  input[c]        & 0xFF;
        ks[0][c]    = (key[c] >> 24) & 0xFF;
        ks[1][c]    = (key[c] >> 16) & 0xFF;
        ks[2][c]    = (key[c] >> 8 ) & 0xFF;
        ks[3][c]    =  key[c]        & 0xFF;
    }
    key_expansion(ks, round_keys);
    add_round_key(state, round_keys[0]);
    for (int round = 1; round <= 9; round++) {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, round_keys[round]);
    }
    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, round_keys[10]);
    for (int c = 0; c < 4; c++) {
        output[c] = (state[0][c]<<24) | (state[1][c]<<16) | (state[2][c]<<8) | state[3][c];
    }
}

void aes_decrypt_block(uint32_t input[4], uint32_t key[4], uint32_t output[4]) {
#pragma HLS INLINE off
    uint8_t state[4][4], ks[4][4], round_keys[11][4][4];
    // --- FIX: Proper mapping from input[4] to state[4][4] (column-major, big-endian) ---
    for (int c = 0; c < 4; c++) {
        state[0][c] = (input[c] >> 24) & 0xFF;
        state[1][c] = (input[c] >> 16) & 0xFF;
        state[2][c] = (input[c] >> 8 ) & 0xFF;
        state[3][c] =  input[c]        & 0xFF;
        ks[0][c]    = (key[c] >> 24) & 0xFF;
        ks[1][c]    = (key[c] >> 16) & 0xFF;
        ks[2][c]    = (key[c] >> 8 ) & 0xFF;
        ks[3][c]    =  key[c]        & 0xFF;
    }
    key_expansion(ks, round_keys);
    add_round_key(state, round_keys[10]);
    for (int round = 9; round >= 1; round--) {
        inv_shift_rows(state);
        inv_sub_bytes(state);
        add_round_key(state, round_keys[round]);
        inv_mix_columns(state);
    }
    inv_shift_rows(state);
    inv_sub_bytes(state);
    add_round_key(state, round_keys[0]);
    for (int c = 0; c < 4; c++) {
        output[c] = (state[0][c]<<24) | (state[1][c]<<16) | (state[2][c]<<8) | state[3][c];
    }
}

// ============================================================================
// ================  Pipeline Stages  =========================================
// ============================================================================

struct FetchReg  { bool valid; uint32_t block_addr; uint32_t block_data[4]; };
struct DecryptReg{ bool valid; uint32_t decr_block[4]; int instr_index; };
struct DecodeReg { bool valid; uint32_t instr, rs_val, rt_val; uint8_t a_sel, b_sel; };
struct ExecReg   { bool valid; uint32_t alu_result, instr; bool taken_branch; uint32_t new_block_addr; };
struct MemReg    { bool valid; uint32_t alu_result, instr, mem_read_val; };
struct WbReg     { bool valid; uint32_t final_val, instr; };

static FetchReg   fetch_reg;
static DecryptReg decr_reg;
static DecodeReg  decode_reg;
static ExecReg    exec_reg;
static MemReg     mem_reg;
static WbReg      wb_reg;

static bool isWriteInstruction(uint32_t instr) {
#pragma HLS INLINE
    InstructionUnion u; u.raw = instr;
    switch(u.r_type.opcode) {
        case ADD: case SUB: case AND_: case OR_: case XOR_:
        case SLL: case SRL: case MULT:
        case LW: case AES_ENC: case AES_DEC:
            return true;
        default:
            return false;
    }
}

static uint32_t getDestReg(uint32_t instr) {
#pragma HLS INLINE
    InstructionUnion u; u.raw = instr;
    switch(u.r_type.opcode) {
        case ADD: case SUB: case AND_: case OR_: case XOR_:
        case SLL: case SRL: case MULT:
            return u.r_type.rd;
        case LW: case AES_ENC: case AES_DEC:
            return u.i_type.rt;
        default:
            return 0;
    }
}

static void getSourceRegs(uint32_t instr, uint32_t &rs, uint32_t &rt) {
#pragma HLS INLINE
    InstructionUnion u; u.raw = instr;
    rs = u.i_type.rs; rt = u.i_type.rt;
}

static bool checkDataHazard(uint32_t decode_instr,
                            uint32_t exec_instr,
                            uint32_t mem_instr,
                            uint8_t &a_sel,
                            uint8_t &b_sel) {
#pragma HLS INLINE off
    uint32_t d_rs, d_rt;
    getSourceRegs(decode_instr, d_rs, d_rt);
    a_sel = b_sel = 0;
    if (exec_reg.valid && isWriteInstruction(exec_instr)) {
        uint32_t exd = getDestReg(exec_instr);
        if (exd && d_rs == exd) a_sel = 1;
        if (exd && d_rt == exd) b_sel = 1;
    }
    if (mem_reg.valid && isWriteInstruction(mem_instr)) {
        uint32_t md = getDestReg(mem_instr);
        if (md && !a_sel && d_rs == md) a_sel = 2;
        if (md && !b_sel && d_rt == md) b_sel = 2;
    }
    return (a_sel||b_sel);
}

static void stage_fetch() {
#pragma HLS INLINE off
    if (!fetch_reg.valid) {
        if (!key_valid) {
            extract_key_from_large_block(aes_key);

            // === KEY VALIDATION ===
            bool match = true;
            for (int i = 0; i < 4; i++) {
                if (aes_key[i] != EXPECTED_AES_KEY[i]) {
                    match = false;
                }
            }

#ifndef __SYNTHESIS__
            if (!match) {
                printf("[ERROR] Invalid AES key in block 0! Aborting.\n");
                printf("Expected key:\n");
                for (int i = 0; i < 4; i++) printf("  0x%08X\n", EXPECTED_AES_KEY[i]);
                printf("Extracted key:\n");
                for (int i = 0; i < 4; i++) printf("  0x%08X\n", aes_key[i]);
                exit(1);
            }
#endif

            key_check_failed = !match;
            key_valid = match;
            if (!match) return;
        }

        uint32_t block[INSTRS_PER_BLOCK];
        icache_read_block(fetch_reg.block_addr, block);
        for (int i = 0; i < INSTRS_PER_BLOCK; i++) {
            fetch_reg.block_data[i] = block[i];
        }
        fetch_reg.valid = true;
    }
}

static void stage_decrypt(uint32_t aes_key[4]) {
#pragma HLS INLINE off
    if (fetch_reg.valid && !decr_reg.valid) {
        uint32_t out[4];
        // Decrypt μόνο αν είμαστε σε .text section (block 8+)
        if (fetch_reg.block_addr >= 8) {
            aes_decrypt_block(fetch_reg.block_data, aes_key, out);
            // --- ΝΕΟ: Γράψε το αποκρυπτογραφημένο block πίσω στη μνήμη ΜΟΝΟ αν εντός ορίων ---
            int mem_base = fetch_reg.block_addr * INSTRS_PER_BLOCK;
            for (int i = 0; i < 4; i++) {
                if ((mem_base + i) >= 0 && (mem_base + i) < MEM_SIZE) {
                    memory[mem_base + i] = out[i];
                }
            }
        } else {
            for (int i = 0; i < 4; i++) out[i] = fetch_reg.block_data[i];
        }
        for (int i = 0; i < 4; i++) {
            decr_reg.decr_block[i] = out[i];
        }
        decr_reg.valid       = true;
        decr_reg.instr_index = 0;
        fetch_reg.valid      = false;
        fetch_reg.block_addr++;
    }
}

static void stage_decode(bool stall) {
#pragma HLS INLINE off
    if (!stall && decr_reg.valid && !decode_reg.valid) {
        uint32_t instr = decr_reg.decr_block[decr_reg.instr_index];
        uint32_t rs, rt; getSourceRegs(instr, rs, rt);
        uint8_t a_sel, b_sel;
        checkDataHazard(instr, exec_reg.instr, mem_reg.instr, a_sel, b_sel);
        decode_reg.valid  = true;
        decode_reg.instr  = instr;
        decode_reg.rs_val = reg_file[rs];
        decode_reg.rt_val = reg_file[rt];
        decode_reg.a_sel  = a_sel;
        decode_reg.b_sel  = b_sel;
        decr_reg.instr_index++;
        if (decr_reg.instr_index >= INSTRS_PER_BLOCK) {
            decr_reg.valid = false;
        }
    }
}

static void stage_execute() {
#pragma HLS INLINE off
    if (decode_reg.valid && !exec_reg.valid) {
        InstructionUnion u; u.raw = decode_reg.instr;
        uint32_t opcode = u.r_type.opcode;
        uint32_t rs_val = (decode_reg.a_sel == 1) ? exec_reg.alu_result
                        : (decode_reg.a_sel == 2) ? mem_reg.mem_read_val
                        : decode_reg.rs_val;
        uint32_t rt_val = (decode_reg.b_sel == 1) ? exec_reg.alu_result
                        : (decode_reg.b_sel == 2) ? mem_reg.mem_read_val
                        : decode_reg.rt_val;
        uint32_t alu_res = 0;
        bool     br      = false;
        uint32_t nb      = 0;
        switch(opcode) {
            case NOP:   break;
            case ADD:   alu_res = rs_val + rt_val; break;
            case SUB:   alu_res = rs_val - rt_val; break;
            case LW:    alu_res = rs_val + (int16_t)u.i_type.imm; break;
            case SW:    alu_res = rs_val + (int16_t)u.i_type.imm; break;
            case AES_ENC:
                if (!key_valid) {
                    // Error: Key must be extracted from memory before AES_ENC
                    // You can use assert or return error code, e.g.:
                    // #include <cassert>
                    // assert(key_valid && "AES key not initialized from memory!");
                    return; // Abort execution if key is not valid
                }
                {
                    uint32_t inb[4] = { rs_val, rt_val, 0, 0 };
                    aes_encrypt_block(inb, aes_key, copro_reg);
                    alu_res = copro_reg[0];
                }
                break;
            case AES_DEC:
                if (!key_valid) {
                    extract_key_from_large_block(aes_key);
                    key_valid = true;
                }
                {
                    uint32_t inb[4] = { rs_val, rt_val, 0, 0 };
                    aes_decrypt_block(inb, aes_key, copro_reg);
                    alu_res = copro_reg[0];
                }
                break;
            case AND_:  alu_res = rs_val & rt_val; break;
            case OR_:   alu_res = rs_val | rt_val; break;
            case XOR_:  alu_res = rs_val ^ rt_val; break;
            case SLL:   alu_res = rs_val << (rt_val & 0x1F); break;
            case SRL:   alu_res = rs_val >> (rt_val & 0x1F); break;
            case MULT:  alu_res = rs_val * rt_val; break;
            case BEQ:
                if (rs_val == rt_val) {
                    br = true;
                    nb = fetch_reg.block_addr + (int16_t)u.i_type.imm;
                }
                break;
            case BNE:
                if (rs_val != rt_val) {
                    br = true;
                    nb = fetch_reg.block_addr + (int16_t)u.i_type.imm;
                }
                break;
            case J:
                br = true;
                nb = u.j_type.target;
                break;
            default:
                break;
        }
        exec_reg.valid         = true;
        exec_reg.alu_result    = alu_res;
        exec_reg.instr         = decode_reg.instr;
        exec_reg.taken_branch  = br;
        exec_reg.new_block_addr= nb;
        decode_reg.valid       = false;
    }
}

static void stage_memory() {
#pragma HLS INLINE off
    if (exec_reg.valid && !mem_reg.valid) {
        InstructionUnion u; u.raw = exec_reg.instr;
        uint32_t opcode = u.r_type.opcode;
        uint32_t rt     = u.i_type.rt;
        uint32_t val    = 0;
        uint32_t addr   = exec_reg.alu_result;
        switch(opcode) {
            case LW:
                if (addr < MEM_SIZE) val = dcache_read(addr);
                break;
            case SW:
                if (addr < MEM_SIZE) dcache_write(addr, reg_file[rt]);
                break;
            case AES_ENC:
            case AES_DEC:
                val = copro_reg[0];
                break;
            default: break;
        }
        mem_reg.valid        = true;
        mem_reg.alu_result   = exec_reg.alu_result;
        mem_reg.instr        = exec_reg.instr;
        mem_reg.mem_read_val = val;
        exec_reg.valid       = false;
    }
}

static void stage_writeback() {
#pragma HLS INLINE off
    if (mem_reg.valid && !wb_reg.valid) {
        InstructionUnion u; u.raw = mem_reg.instr;
        uint32_t opcode = u.r_type.opcode;
        uint32_t rd     = u.r_type.rd;
        uint32_t rt     = u.i_type.rt;
        uint32_t fv     = 0;
        switch(opcode) {
            case LW:
                fv = mem_reg.mem_read_val;
                reg_file[rt] = fv;
                break;
            case ADD: case SUB: case AND_: case OR_: case XOR_:
            case SLL: case SRL: case MULT:
                fv = mem_reg.alu_result;
                reg_file[rd] = fv;
                break;
            case AES_ENC: case AES_DEC:
                fv = mem_reg.mem_read_val;
                reg_file[rt] = fv;
                break;
            default: break;
        }
        wb_reg.valid    = true;
        wb_reg.final_val= fv;
        wb_reg.instr    = mem_reg.instr;
        mem_reg.valid   = false;
    }
}

// ============================================================================
// ================  Top Function για HLS  =====================================
// ============================================================================


extern "C" void CryptoCPU_top()
{
    const uint32_t start_block = 8;     
    const uint32_t num_cycles  = 2000;  
 
    static bool init_done = false;
    if (!init_done) {
        // Initialize registers and caches; memory[] left untouched
        for (int r = 0; r < NUM_REGS; r++) {
            reg_file[r] = 0;
        }
        for (int i = 0; i < ICACHE_LINES; i++) {
            iCache_valid[i] = false;
            iCache_tag[i]   = 0;
        }
        for (int i = 0; i < DCACHE_LINES; i++) {
            dcache_valid[i] = false;
            dcache_tag[i]   = 0;
        }
        init_done = true;
    }

    // Reset pipeline registers
    fetch_reg.valid      = false;
    fetch_reg.block_addr = start_block;
    decr_reg.valid       = false;
    decode_reg.valid     = false;
    exec_reg.valid       = false;
    mem_reg.valid        = false;
    wb_reg.valid         = false;

    // Reset validation flag every time simulation loads new .hex
    key_valid = false;
    key_check_failed = false;

    // Main execution loop
    for (uint32_t cycle = 0; cycle < num_cycles; cycle++) {
#pragma HLS PIPELINE II=1

        if (key_check_failed) {
            break;
        }
        if (wb_reg.valid)       wb_reg.valid = false;
        if (mem_reg.valid)      stage_writeback();
        if (exec_reg.valid) {
            if (exec_reg.taken_branch) {
                // flush pipeline on branch
                decr_reg.valid       = false;
                decode_reg.valid     = false;
                fetch_reg.valid      = false;
                fetch_reg.block_addr = exec_reg.new_block_addr;
            }
            stage_memory();
        }
        if (decode_reg.valid)   stage_execute();
        if (decr_reg.valid) {
            uint32_t next_instr = decr_reg.decr_block[decr_reg.instr_index];
            uint8_t a_sel, b_sel;
            if (!checkDataHazard(next_instr, exec_reg.instr, mem_reg.instr, a_sel, b_sel)) {
                stage_decode(false);
            }
        } else {
            stage_decrypt(aes_key);
        }
        if (!fetch_reg.valid)   stage_fetch();
    }

#ifndef __SYNTHESIS__
    printf("=== POST-EXECUTION DECRYPTED .TEXT DUMP ===\n");
    for (int i = 32; i < MEM_SIZE; i++) {
        if (memory[i] != 0x00000000) {
            printf("memory[%03X] = 0x%08X\n", i, memory[i]);
        }
    }
#endif
}