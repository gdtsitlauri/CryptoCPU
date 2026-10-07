// Execute encrypted programs whose final states differ in only HI, LO or PC.
// The tampering classifier must not report these changes as "same".
#include "security_common.h"

int main() {
    const std::vector<uint32_t> program = {
        0x24080007u,  // addiu $t0, $zero, 7
        0x00000011u,  // mthi $zero
        0x00000013u,  // mtlo $zero
        0x2402000au,  // addiu $v0, $zero, 10
        0x0000000cu   // syscall
    };
    const std::vector<uint32_t> data;
    CpuConfig cfg;
    cpu_default_config(&cfg);
    cfg.max_cycles = 1000;
    std::vector<uint32_t> image, memory;
    build_image(program, TEST_KEYS, true, image);
    init_dmem(data, memory);
    CpuState baseline;
    CpuStats stats;
    cryptocpu_top(image.data(), memory.data(), &TEST_KEYS, &cfg, &baseline, &stats);
    if (baseline.status != ST_HALT || baseline.hi != 0 || baseline.lo != 0 ||
        baseline.regs[8] != 7 || baseline.pc != TEXT_BASE + 16) {
        fprintf(stderr, "FAIL: invalid regression baseline\n");
        return 1;
    }

    int failures = 0, checks = 0;
    auto check = [&](const char *name, const std::vector<uint32_t> &code,
                     SecurityOutcome expected, const std::vector<uint32_t> &initial_data = std::vector<uint32_t>{}) {
        build_image(code, TEST_KEYS, true, image);
        const SecurityOutcome actual = classify(image, initial_data, TEST_KEYS, cfg, baseline, memory);
        checks++;
        printf("%-28s %s\n", name, actual == expected ? "PASS" : "FAIL");
        if (actual != expected) failures++;
    };
    check("unchanged final state", program, SEC_SAME);
    auto changed = program;
    changed[1] = 0x01000011u;  // mthi $t0; only final HI changes
    check("HI-only change", changed, SEC_CORRUPT);
    changed = program;
    changed[2] = 0x01000013u;  // mtlo $t0; only final LO changes
    check("LO-only change", changed, SEC_CORRUPT);
    changed = program;
    changed.back() = 0;       // nop, then halt at the next instruction
    changed.push_back(0x0000000cu);
    check("end-PC-only change", changed, SEC_CORRUPT);
    changed = program;
    changed[0] = 0x24080008u;  // addiu $t0, $zero, 8
    check("general register change", changed, SEC_CORRUPT);
    check("data-memory-only change", program, SEC_CORRUPT, {1});
    check("illegal instruction", {0xffffffffu}, SEC_TRAP);
    check("nonterminating program", {0x08100000u}, SEC_TIMEOUT);  // j TEXT_BASE
    printf("\n%d/%d security regressions passed\n", checks - failures, checks);
    return failures ? 1 : 0;
}
