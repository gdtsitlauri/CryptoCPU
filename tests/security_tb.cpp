// Security experiments on encrypted images.
//
//   security_tb <prog_dir>... [--flips N] [--seed S]
//
// For every program:
//   E1  image patterns: distinct ciphertext blocks under XEX vs. under ECB
//   E2  wrong code key: what the core does with a correctly built image
//   E3  ciphertext tampering: N random single-bit flips inside code blocks
//   E4  block relocation: two code blocks swapped in memory
// Outcomes are classified against the untampered run:
//   trap      - the core stopped with an exception (illegal instruction, bad fetch, ...)
//   corrupt   - the run halted normally but the final state differs (silent corruption)
//   same      - the run halted with the same final state (the flip was never executed)
//   timeout   - no halt within 20x the normal cycle count
#include <stdlib.h>
#include <map>
#include <set>
#include "tb_common.h"

struct Tally {
    int trap = 0, corrupt = 0, same = 0, timeout = 0;
    void add(int c) { (c == 0 ? trap : c == 1 ? corrupt : c == 2 ? same : timeout)++; }
    int total() const { return trap + corrupt + same + timeout; }
};

static bool same_state(const CpuState &a, const std::vector<uint32_t> &ma, const CpuState &b,
                       const std::vector<uint32_t> &mb) {
    if (a.status != b.status) return false;
    for (int i = 0; i < 32; i++)
        if (a.regs[i] != b.regs[i]) return false;
    return ma == mb;
}

static int classify(const std::vector<uint32_t> &imem, const std::vector<uint32_t> &data, const KeyRegisters &keys,
                    const CpuConfig &cfg, const CpuState &ref_state, const std::vector<uint32_t> &ref_mem) {
    std::vector<uint32_t> dmem;
    init_dmem(data, dmem);
    CpuState s;
    CpuStats st;
    cryptocpu_top(imem.data(), dmem.data(), &keys, &cfg, &s, &st);
    if (s.status == ST_TIMEOUT) return 3;
    if (s.status != ST_HALT) return 0;
    return same_state(s, dmem, ref_state, ref_mem) ? 2 : 1;
}

static int distinct_blocks(const std::vector<uint32_t> &img) {
    std::set<std::vector<uint32_t>> s;
    for (size_t b = 0; b + 4 <= img.size(); b += 4) s.insert(std::vector<uint32_t>(img.begin() + b, img.begin() + b + 4));
    return (int)s.size();
}

int main(int argc, char **argv) {
    std::vector<std::string> dirs;
    int flips = 500;
    unsigned seed = 1;
    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        if (a == "--flips" && i + 1 < argc) flips = atoi(argv[++i]);
        else if (a == "--seed" && i + 1 < argc) seed = (unsigned)atoi(argv[++i]);
        else dirs.push_back(a);
    }
    if (dirs.empty()) {
        fprintf(stderr, "usage: %s <prog_dir>... [--flips N] [--seed S]\n", argv[0]);
        return 2;
    }
    srand(seed);
    Tally all_flip, all_wrongkey, all_swap;
    printf("%-12s %6s | %-24s | %-10s | %-34s | %-26s\n", "program", "blocks", "E1 distinct blocks", "E2 wrong key",
           "E3 bit flips: trap/corrupt/same/TO", "E4 swaps: trap/corrupt/same/TO");
    for (const std::string &dir : dirs) {
        std::vector<uint32_t> text, data, img, img_plain;
        if (!load_hex(dir + "/text.hex", text) || !load_hex(dir + "/data.hex", data)) {
            fprintf(stderr, "cannot read %s\n", dir.c_str());
            return 2;
        }
        CpuConfig cfg;
        cpu_default_config(&cfg);
        build_image(text, TEST_KEYS, true, img);

        // Untampered run
        std::vector<uint32_t> ref_mem;
        init_dmem(data, ref_mem);
        CpuState ref_state;
        CpuStats ref_stats;
        cryptocpu_top(img.data(), ref_mem.data(), &TEST_KEYS, &cfg, &ref_state, &ref_stats);
        cfg.max_cycles = ref_stats.cycles * 20 + 1000;
        const int code_blocks = (int)((text.size() + 3) / 4);

        // E1: ECB image for comparison (same key, no tweak)
        AesRoundKeys kc;
        aes128_expand_key(TEST_KEYS.k_code, &kc);
        std::vector<uint32_t> ecb(IMEM_WORDS, 0u), plainimg(IMEM_WORDS, 0u);
        for (size_t i = 0; i < text.size(); i++) plainimg[i] = text[i];
        for (int b = 0; b < IMEM_BLOCKS; b++) aes128_encrypt(&kc, &plainimg[4 * b], &ecb[4 * b]);
        char e1[64];
        snprintf(e1, sizeof e1, "plain %d, ECB %d, XEX %d", distinct_blocks(plainimg), distinct_blocks(ecb),
                 distinct_blocks(img));

        // E2: wrong code key
        KeyRegisters wrong = TEST_KEYS;
        wrong.k_code[0] ^= 1u;
        int wk = classify(img, data, wrong, cfg, ref_state, ref_mem);
        all_wrongkey.add(wk);
        static const char *names[4] = {"trap", "corrupt", "same", "timeout"};

        // E3: single-bit flips in code blocks
        Tally tf;
        for (int t = 0; t < flips; t++) {
            std::vector<uint32_t> m = img;
            int w = rand() % (code_blocks * 4);
            m[w] ^= 1u << (rand() % 32);
            int c = classify(m, data, TEST_KEYS, cfg, ref_state, ref_mem);
            tf.add(c);
            all_flip.add(c);
        }

        // E4: swap two distinct code blocks
        Tally ts;
        int pairs = 0;
        for (int a = 0; a < code_blocks && pairs < 50; a++)
            for (int b = a + 1; b < code_blocks && pairs < 50; b++, pairs++) {
                std::vector<uint32_t> m = img;
                for (int i = 0; i < 4; i++) std::swap(m[4 * a + i], m[4 * b + i]);
                int c = classify(m, data, TEST_KEYS, cfg, ref_state, ref_mem);
                ts.add(c);
                all_swap.add(c);
            }

        std::string name = dir.substr(dir.find_last_of("/\\") + 1);
        printf("%-12s %6d | %-24s | %-10s | %5d / %5d / %5d / %5d       | %4d / %4d / %4d / %4d\n", name.c_str(),
               code_blocks, e1, names[wk], tf.trap, tf.corrupt, tf.same, tf.timeout, ts.trap, ts.corrupt, ts.same,
               ts.timeout);
    }
    auto pct = [](int x, int n) { return n ? 100.0 * x / n : 0.0; };
    printf("\nTOTAL wrong key (%d programs): trap %d, corrupt %d, same %d, timeout %d\n", all_wrongkey.total(),
           all_wrongkey.trap, all_wrongkey.corrupt, all_wrongkey.same, all_wrongkey.timeout);
    printf("TOTAL bit flips (%d): trap %.1f%%, silent corruption %.1f%%, no effect %.1f%%, timeout %.1f%%\n",
           all_flip.total(), pct(all_flip.trap, all_flip.total()), pct(all_flip.corrupt, all_flip.total()),
           pct(all_flip.same, all_flip.total()), pct(all_flip.timeout, all_flip.total()));
    printf("TOTAL block swaps (%d): trap %.1f%%, silent corruption %.1f%%, no effect %.1f%%, timeout %.1f%%\n",
           all_swap.total(), pct(all_swap.trap, all_swap.total()), pct(all_swap.corrupt, all_swap.total()),
           pct(all_swap.same, all_swap.total()), pct(all_swap.timeout, all_swap.total()));
    return 0;
}
