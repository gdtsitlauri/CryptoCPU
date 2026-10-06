// CryptoCPU v2: a MIPS32-subset processor that executes only encrypted programs.
//
// Instruction memory holds the program encrypted block by block with AES-128 in
// XEX mode, tweaked by the block address. Blocks are decrypted inside the core
// (Decrypt stage) into an on-chip decrypted-instruction cache; plaintext
// instructions never leave the core. Keys live in on-chip key registers, loaded
// through the key port (eFUSE/BBRAM on an FPGA), never in instruction or data memory.
#ifndef CRYPTOCPU_H
#define CRYPTOCPU_H

#include <stdint.h>
#include "aes128.h"

// ---------------------------------------------------------------------------
// Memory map (MARS default layout, so MARS-assembled programs run unchanged)
// ---------------------------------------------------------------------------
#define TEXT_BASE      0x00400000u
#define DATA_BASE      0x10010000u
#define IMEM_WORDS     4096                 // 16 KiB of encrypted instructions
#define DMEM_WORDS     4096                 // 16 KiB of data (stack at the top)
#define BLOCK_WORDS    4                    // one AES block = 4 instructions
#define IMEM_BLOCKS    (IMEM_WORDS / BLOCK_WORDS)
#define STACK_TOP      (DATA_BASE + 4u * DMEM_WORDS)
#define ICACHE_MAX_LINES 64

// ---------------------------------------------------------------------------
// Custom instructions (opcodes unused by MIPS32)
//   aesenc $rt, $rs : M[GPR[rt] .. +15] = AES_Enc(Kdata, M[GPR[rs] .. +15])
//   aesdec $rt, $rs : M[GPR[rt] .. +15] = AES_Dec(Kdata, M[GPR[rs] .. +15])
// ---------------------------------------------------------------------------
#define OP_AESENC 0x3A
#define OP_AESDEC 0x3B

enum CpuStatus {
    ST_RUNNING = 0,
    ST_HALT = 1,          // syscall 10 / 17 reached write-back
    ST_TRAP_ILLEGAL = 2,  // undefined instruction reached execute
    ST_TRAP_MEM = 3,      // misaligned or out-of-range data access
    ST_TRAP_FETCH = 4,    // PC outside instruction memory reached execute
    ST_TRAP_OVERFLOW = 5, // signed overflow in add / addi / sub
    ST_TRAP_BREAK = 6,    // break instruction
    ST_TIMEOUT = 7        // cycle budget exhausted
};

// On-chip key registers (written once through the key port).
struct KeyRegisters {
    uint32_t k_code[4];   // decrypts instruction blocks
    uint32_t k_tweak[4];  // derives the per-block XEX tweak
    uint32_t k_data[4];   // used by aesenc / aesdec
    uint32_t nonce[2];    // public image nonce, part of every tweak
};

// Micro-architecture parameters. The defaults model the design point used in
// the paper; the testbench varies them for the sensitivity study.
struct CpuConfig {
    int icache_lines;   // decrypted-instruction cache lines (power of two, <= 64)
    int mem_latency;    // cycles to read one 16-byte block from instruction memory
    int aes_latency;    // cycles of the iterative AES unit (one round per cycle = 11)
    int encrypted;      // 0: plaintext image, no decryption (baseline for overhead)
    uint64_t max_cycles;
};

struct CpuStats {
    uint64_t cycles;
    uint64_t retired;
    uint64_t icache_hits;
    uint64_t icache_misses;     // misses started (including wrong-path ones)
    uint64_t misses_cancelled;  // wrong-path misses abandoned on a redirect
    uint64_t blocks_decrypted;
    uint64_t stall_fetch;     // cycles the front end waited for a block
    uint64_t stall_load_use;  // bubbles inserted for load-use hazards
    uint64_t stall_mem_aes;   // cycles the MEM stage was busy with aesenc/aesdec
    uint64_t flushes;         // redirects (taken branches, jumps)
    uint64_t flushed_instrs;  // wrong-path instructions squashed
};

struct CpuState {
    uint32_t regs[32];
    uint32_t hi, lo;
    uint32_t pc;              // PC of the instruction that ended the run
    int status;
};

void cpu_default_config(CpuConfig *cfg);

// Top-level function (HLS top). imem is read-only: the core has no path that
// writes decrypted instructions back to memory.
void cryptocpu_top(const uint32_t imem[IMEM_WORDS],
                   uint32_t dmem[DMEM_WORDS],
                   const KeyRegisters *keys,
                   const CpuConfig *cfg,
                   CpuState *state,
                   CpuStats *stats);

// Memory encryption used by the image tool and by the Decrypt stage.
void xex_tweak(const AesRoundKeys *k_tweak, const uint32_t nonce[2], uint32_t block_index,
               uint32_t tweak[4]);
void xex_encrypt_block(const AesRoundKeys *k_code, const AesRoundKeys *k_tweak,
                       const uint32_t nonce[2], uint32_t block_index,
                       const uint32_t plain[4], uint32_t cipher[4]);
void xex_decrypt_block(const AesRoundKeys *k_code, const AesRoundKeys *k_tweak,
                       const uint32_t nonce[2], uint32_t block_index,
                       const uint32_t cipher[4], uint32_t plain[4]);

const char *cpu_status_name(int status);

#endif
