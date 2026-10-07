// Classification shared by the tampering experiment and its regression tests.
#ifndef CRYPTOCPU_SECURITY_COMMON_H
#define CRYPTOCPU_SECURITY_COMMON_H

#include "tb_common.h"

enum SecurityOutcome { SEC_TRAP, SEC_CORRUPT, SEC_SAME, SEC_TIMEOUT };

static inline bool same_state(const CpuState &a, const std::vector<uint32_t> &ma,
                              const CpuState &b, const std::vector<uint32_t> &mb) {
    if (a.status != b.status || a.pc != b.pc || a.hi != b.hi || a.lo != b.lo) return false;
    for (int i = 0; i < 32; i++)
        if (a.regs[i] != b.regs[i]) return false;
    return ma == mb;
}

static inline SecurityOutcome classify(const std::vector<uint32_t> &imem,
                                        const std::vector<uint32_t> &data,
                                        const KeyRegisters &keys, const CpuConfig &cfg,
                                        const CpuState &ref_state,
                                        const std::vector<uint32_t> &ref_mem) {
    std::vector<uint32_t> dmem;
    init_dmem(data, dmem);
    CpuState s;
    CpuStats st;
    cryptocpu_top(imem.data(), dmem.data(), &keys, &cfg, &s, &st);
    if (s.status == ST_TIMEOUT) return SEC_TIMEOUT;
    if (s.status != ST_HALT) return SEC_TRAP;
    return same_state(s, dmem, ref_state, ref_mem) ? SEC_SAME : SEC_CORRUPT;
}

#endif
