// Golden reference: an instruction-set interpreter for the CryptoCPU ISA.
//
// It runs the plaintext program one instruction at a time, with no pipeline,
// no caches and no encryption. It is written independently of the core (its
// own decoder and semantics) so that a mistake in one is unlikely to be
// repeated in the other. The testbench compares the core against it.
#ifndef CRYPTOCPU_ISA_REF_H
#define CRYPTOCPU_ISA_REF_H

#include <stdint.h>

struct RefResult {
    uint32_t regs[32];
    uint32_t hi, lo;
    uint32_t pc;        // PC of the instruction that ended the run
    int status;         // same codes as CpuStatus
    uint64_t retired;
};

// text: plaintext instruction words starting at TEXT_BASE (n words).
// dmem: data memory, updated in place.
void ref_run(const uint32_t *text, int n, uint32_t *dmem, const uint32_t k_data[4],
             uint64_t max_steps, RefResult *out);

#endif
