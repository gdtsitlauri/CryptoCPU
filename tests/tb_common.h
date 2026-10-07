// Helpers shared by the testbenches: hex loading, image building, test keys.
#ifndef CRYPTOCPU_TB_COMMON_H
#define CRYPTOCPU_TB_COMMON_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <vector>
#include "../src/cryptocpu.h"
#include "../ref/isa_ref.h"

// Fixed test keys. k_data is the FIPS-197 Appendix C.1 key so that programs can
// check aesenc against the published ciphertext.
static const KeyRegisters TEST_KEYS = {
    {0x2b7e1516u, 0x28aed2a6u, 0xabf71588u, 0x09cf4f3cu},  // k_code
    {0x603deb10u, 0x15ca71beu, 0x2b73aef0u, 0x857d7781u},  // k_tweak
    {0x00010203u, 0x04050607u, 0x08090a0bu, 0x0c0d0e0fu},  // k_data
    {0x43727970u, 0x746f4350u}                             // nonce "CryptoCP"
};

static inline bool load_hex(const std::string &path, std::vector<uint32_t> &out) {
    FILE *f = fopen(path.c_str(), "r");
    if (!f) return false;
    char line[128];
    while (fgets(line, sizeof line, f)) {
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '\n' || *p == '\r' || *p == 0 || *p == '#') continue;
        out.push_back((uint32_t)strtoul(p, nullptr, 16));
    }
    fclose(f);
    return true;
}

// Builds the instruction-memory image: every block of IMEM (program padded
// with nops) is encrypted with AES-XEX under the block's own tweak.
static inline void build_image(const std::vector<uint32_t> &text, const KeyRegisters &k,
                               bool encrypt, std::vector<uint32_t> &imem) {
    imem.assign(IMEM_WORDS, 0u);
    for (size_t i = 0; i < text.size() && i < (size_t)IMEM_WORDS; i++) imem[i] = text[i];
    if (!encrypt) return;
    AesRoundKeys kc, kt;
    aes128_expand_key(k.k_code, &kc);
    aes128_expand_key(k.k_tweak, &kt);
    for (uint32_t b = 0; b < (uint32_t)IMEM_BLOCKS; b++) {
        uint32_t p[4], c[4];
        for (int i = 0; i < 4; i++) p[i] = imem[b * 4 + i];
        xex_encrypt_block(&kc, &kt, k.nonce, b, p, c);
        for (int i = 0; i < 4; i++) imem[b * 4 + i] = c[i];
    }
}

static inline void init_dmem(const std::vector<uint32_t> &data, std::vector<uint32_t> &dmem) {
    dmem.assign(DMEM_WORDS, 0u);
    for (size_t i = 0; i < data.size() && i < (size_t)DMEM_WORDS; i++) dmem[i] = data[i];
}

struct RunOutcome {
    CpuState cpu;
    CpuStats stats;
    RefResult ref;
    std::vector<uint32_t> dmem_cpu, dmem_ref;
};

static inline void run_both(const std::vector<uint32_t> &text, const std::vector<uint32_t> &data,
                            const std::vector<uint32_t> &imem, const KeyRegisters &keys,
                            const CpuConfig &cfg, RunOutcome &o) {
    init_dmem(data, o.dmem_cpu);
    init_dmem(data, o.dmem_ref);
    cryptocpu_top(imem.data(), o.dmem_cpu.data(), &keys, &cfg, &o.cpu, &o.stats);
    std::vector<uint32_t> padded(text);
    ref_run(padded.data(), (int)padded.size(), o.dmem_ref.data(), keys.k_data,
            cfg.max_cycles, &o.ref);
}

// Returns an empty string when the core and the reference agree.
static inline std::string compare(const RunOutcome &o) {
    char buf[256];
    if (o.cpu.status != o.ref.status) {
        snprintf(buf, sizeof buf, "status %s vs reference %s", cpu_status_name(o.cpu.status),
                 cpu_status_name(o.ref.status));
        return buf;
    }
    if (o.cpu.pc != o.ref.pc) {
        snprintf(buf, sizeof buf, "end pc %08x vs reference %08x", o.cpu.pc, o.ref.pc);
        return buf;
    }
    if (o.stats.retired != o.ref.retired) {
        snprintf(buf, sizeof buf, "retired %llu vs reference %llu",
                 (unsigned long long)o.stats.retired, (unsigned long long)o.ref.retired);
        return buf;
    }
    for (int i = 0; i < 32; i++)
        if (o.cpu.regs[i] != o.ref.regs[i]) {
            snprintf(buf, sizeof buf, "reg $%d = %08x vs reference %08x", i, o.cpu.regs[i], o.ref.regs[i]);
            return buf;
        }
    if (o.cpu.hi != o.ref.hi || o.cpu.lo != o.ref.lo) return "HI/LO differ";
    for (int i = 0; i < DMEM_WORDS; i++)
        if (o.dmem_cpu[i] != o.dmem_ref[i]) {
            snprintf(buf, sizeof buf, "dmem[%08x] = %08x vs reference %08x", DATA_BASE + 4 * i,
                     o.dmem_cpu[i], o.dmem_ref[i]);
            return buf;
        }
    return "";
}

#endif
