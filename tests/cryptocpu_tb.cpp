// Functional testbench (C simulation of the HLS top).
//
//   cryptocpu_tb <prog_dir> [--icache N] [--mem N] [--aes N] [--plain] [--dump file]
//
// Loads <prog_dir>/text.hex and data.hex (from tools/asm.py), builds the
// AES-XEX encrypted image, runs the core and the golden reference, and checks
// that status, end PC, retired count, all registers, HI/LO and the whole data
// memory agree. It also checks that no plaintext instruction block of the
// program appears in instruction or data memory. Prints one result line and,
// with --dump, writes the final state for the expectation checks.
#include <stdlib.h>
#include <set>
#include "tb_common.h"

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <prog_dir> [--icache N] [--mem N] [--aes N] [--plain] [--dump file]\n", argv[0]);
        return 2;
    }
    std::string dir = argv[1];
    CpuConfig cfg;
    cpu_default_config(&cfg);
    std::string dump;
    for (int i = 2; i < argc; i++) {
        std::string a = argv[i];
        if (a == "--icache" && i + 1 < argc) cfg.icache_lines = atoi(argv[++i]);
        else if (a == "--mem" && i + 1 < argc) cfg.mem_latency = atoi(argv[++i]);
        else if (a == "--aes" && i + 1 < argc) cfg.aes_latency = atoi(argv[++i]);
        else if (a == "--plain") cfg.encrypted = 0;
        else if (a == "--dump" && i + 1 < argc) dump = argv[++i];
        else { fprintf(stderr, "unknown option %s\n", a.c_str()); return 2; }
    }
    std::vector<uint32_t> text, data, imem;
    if (!load_hex(dir + "/text.hex", text) || !load_hex(dir + "/data.hex", data)) {
        fprintf(stderr, "cannot read %s/text.hex or data.hex\n", dir.c_str());
        return 2;
    }
    build_image(text, TEST_KEYS, cfg.encrypted != 0, imem);

    RunOutcome o;
    run_both(text, data, imem, TEST_KEYS, cfg, o);
    std::string diff = compare(o);

    // Confidentiality check: no 16-byte plaintext block of the program may appear
    // in instruction memory (the image) or in data memory after the run.
    int leaks = 0;
    if (cfg.encrypted) {
        std::set<std::vector<uint32_t>> blocks;
        for (size_t b = 0; b + 4 <= text.size(); b += 4) {
            std::vector<uint32_t> blk(text.begin() + b, text.begin() + b + 4);
            bool all_zero = blk[0] == 0 && blk[1] == 0 && blk[2] == 0 && blk[3] == 0;
            if (!all_zero) blocks.insert(blk);
        }
        auto scan = [&](const std::vector<uint32_t> &mem) {
            for (size_t i = 0; i + 4 <= mem.size(); i++) {
                std::vector<uint32_t> w(mem.begin() + i, mem.begin() + i + 4);
                if (blocks.count(w)) leaks++;
            }
        };
        scan(imem);
        scan(o.dmem_cpu);
    }

    const CpuStats &s = o.stats;
    std::string name = dir.substr(dir.find_last_of("/\\") + 1);
    double cpi = s.retired ? (double)s.cycles / (double)s.retired : 0.0;
    printf("%-16s %-4s status=%-13s retired=%-8llu cycles=%-9llu cpi=%.3f ic_hit=%llu ic_miss=%llu "
           "cancelled=%llu decrypted=%llu leaks=%d%s%s\n",
           name.c_str(), (diff.empty() && leaks == 0) ? "PASS" : "FAIL", cpu_status_name(o.cpu.status),
           (unsigned long long)s.retired, (unsigned long long)s.cycles, cpi,
           (unsigned long long)s.icache_hits, (unsigned long long)s.icache_misses,
           (unsigned long long)s.misses_cancelled, (unsigned long long)s.blocks_decrypted, leaks, diff.empty() ? "" : "  MISMATCH: ",
           diff.c_str());

    if (!dump.empty()) {
        FILE *f = fopen(dump.c_str(), "w");
        if (f) {
            fprintf(f, "status %s\npc %08x\nretired %llu\ncycles %llu\n", cpu_status_name(o.cpu.status),
                    o.cpu.pc, (unsigned long long)s.retired, (unsigned long long)s.cycles);
            fprintf(f, "icache_hits %llu\nicache_misses %llu\nblocks_decrypted %llu\nstall_fetch %llu\n"
                       "stall_load_use %llu\nstall_mem_aes %llu\nflushes %llu\nflushed_instrs %llu\n"
                       "misses_cancelled %llu\n",
                    (unsigned long long)s.icache_hits, (unsigned long long)s.icache_misses,
                    (unsigned long long)s.blocks_decrypted, (unsigned long long)s.stall_fetch,
                    (unsigned long long)s.stall_load_use, (unsigned long long)s.stall_mem_aes,
                    (unsigned long long)s.flushes, (unsigned long long)s.flushed_instrs,
                    (unsigned long long)s.misses_cancelled);
            for (int i = 0; i < 32; i++) fprintf(f, "reg %d %08x\n", i, o.cpu.regs[i]);
            fprintf(f, "hi %08x\nlo %08x\n", o.cpu.hi, o.cpu.lo);
            for (int i = 0; i < DMEM_WORDS; i++)
                if (o.dmem_cpu[i]) fprintf(f, "mem %08x %08x\n", DATA_BASE + 4 * i, o.dmem_cpu[i]);
            fclose(f);
        }
    }
    return (diff.empty() && leaks == 0) ? 0 : 1;
}
