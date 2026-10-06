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
#include "../tests/tb_common.h"

static bool parse_words(const char *hex, uint32_t *out, int n) {
    if ((int)strlen(hex) != 8 * n) return false;
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
    FILE *f = fopen(path, "r");
    if (!f) return false;
    char name[32], val[80];
    int got = 0;
    while (fscanf(f, "%31s %79s", name, val) == 2) {
        if (!strcmp(name, "k_code")) got += parse_words(val, k->k_code, 4);
        else if (!strcmp(name, "k_tweak")) got += parse_words(val, k->k_tweak, 4);
        else if (!strcmp(name, "k_data")) got += parse_words(val, k->k_data, 4);
        else if (!strcmp(name, "nonce")) got += parse_words(val, k->nonce, 2);
    }
    fclose(f);
    return got == 4;
}

static bool write_hex(const char *path, const std::vector<uint32_t> &w) {
    FILE *f = fopen(path, "w");
    if (!f) return false;
    for (uint32_t x : w) fprintf(f, "%08x\n", x);
    fclose(f);
    return true;
}

int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "usage: %s encrypt|decrypt <in.hex> <out.hex> [--keys keys.txt]\n", argv[0]);
        return 2;
    }
    KeyRegisters keys = TEST_KEYS;
    if (argc >= 6 && !strcmp(argv[4], "--keys") && !load_keys(argv[5], &keys)) {
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
