// Image tool: builds and inspects encrypted instruction-memory images.
//
//   image_tool encrypt <text.hex> <image.hex> [--keys keys.txt]
//   image_tool decrypt <image.hex> <plain.hex> [--keys keys.txt]
//
// The image covers the whole instruction memory (IMEM_WORDS words): the
// program is padded with nops and every 16-byte block is encrypted with
// AES-XEX under its own address tweak. keys.txt has four lines:
//   k_code  <32 hex digits>
//   k_tweak <32 hex digits>
//   k_data  <32 hex digits>
//   nonce   <16 hex digits>
// Without --keys the fixed test keys of the testbench are used.
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <fstream>
#include <sstream>
#include "../tests/tb_common.h"

static bool parse_words(const char *hex, uint32_t *out, int n) {
    if ((int)strlen(hex) != 8 * n) return false;
    for (int i = 0; i < 8 * n; i++)
        if (!isxdigit((unsigned char)hex[i])) return false;
    for (int i = 0; i < n; i++) {
        char buf[9];
        memcpy(buf, hex + 8 * i, 8);
        buf[8] = 0;
        char *end;
        out[i] = (uint32_t)strtoul(buf, &end, 16);
        if (*end) return false;
    }
    return true;
}

static bool load_keys(const char *path, KeyRegisters *k) {
    std::ifstream f(path);
    if (!f) return false;
    KeyRegisters parsed = {};
    unsigned seen = 0;
    std::string line;
    while (std::getline(f, line)) {
        std::istringstream fields(line);
        std::string name, val, extra;
        if (!(fields >> name)) continue;  // blank lines are harmless
        if (!(fields >> val) || (fields >> extra)) return false;
        unsigned bit;
        uint32_t *dest;
        int words = 4;
        if (name == "k_code") { bit = 1; dest = parsed.k_code; }
        else if (name == "k_tweak") { bit = 2; dest = parsed.k_tweak; }
        else if (name == "k_data") { bit = 4; dest = parsed.k_data; }
        else if (name == "nonce") { bit = 8; dest = parsed.nonce; words = 2; }
        else return false;
        if ((seen & bit) || !parse_words(val.c_str(), dest, words)) return false;
        seen |= bit;
    }
    if (f.bad() || seen != 15) return false;
    *k = parsed;  // commit only after all four distinct fields passed validation
    return true;
}

static bool write_hex(const char *path, const std::vector<uint32_t> &w) {
    FILE *f = fopen(path, "w");
    if (!f) return false;
    for (uint32_t x : w) fprintf(f, "%08x\n", x);
    fclose(f);
    return true;
}

int main(int argc, char **argv) {
    if ((argc != 4 && argc != 6) || (argc == 6 && strcmp(argv[4], "--keys"))) {
        fprintf(stderr, "usage: %s encrypt|decrypt <in.hex> <out.hex> [--keys keys.txt]\n", argv[0]);
        return 2;
    }
    KeyRegisters keys = TEST_KEYS;
    if (argc == 6 && !load_keys(argv[5], &keys)) {
        fprintf(stderr, "cannot read keys from %s\n", argv[5]);
        return 2;
    }
    std::vector<uint32_t> in, out;
    if (!load_hex(argv[2], in)) {
        fprintf(stderr, "cannot read %s\n", argv[2]);
        return 2;
    }
    if (!strcmp(argv[1], "encrypt")) {
        build_image(in, keys, true, out);
    } else if (!strcmp(argv[1], "decrypt")) {
        AesRoundKeys kc, kt;
        aes128_expand_key(keys.k_code, &kc);
        aes128_expand_key(keys.k_tweak, &kt);
        in.resize(IMEM_WORDS, 0u);
        out.assign(IMEM_WORDS, 0u);
        for (uint32_t b = 0; b < (uint32_t)IMEM_BLOCKS; b++)
            xex_decrypt_block(&kc, &kt, keys.nonce, b, &in[4 * b], &out[4 * b]);
    } else {
        fprintf(stderr, "unknown command %s\n", argv[1]);
        return 2;
    }
    if (!write_hex(argv[3], out)) {
        fprintf(stderr, "cannot write %s\n", argv[3]);
        return 2;
    }
    printf("%s: %zu words written to %s\n", argv[1], out.size(), argv[3]);
    return 0;
}
