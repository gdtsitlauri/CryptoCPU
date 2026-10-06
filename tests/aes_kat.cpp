// Known-answer tests for the AES-128 core and the XEX layer.
//   - FIPS-197 Appendix B and C.1 vectors (encrypt and decrypt)
//   - NIST SP 800-38A F.1.1 ECB-AES128 (four blocks)
//   - XEX: decrypt(encrypt(x)) == x for random blocks and addresses, and the
//     same plaintext at two addresses gives two different ciphertexts.
#include <stdio.h>
#include <stdlib.h>
#include "../src/cryptocpu.h"

static int failures = 0;

static void check(const char *name, const uint32_t got[4], const uint32_t want[4]) {
    bool ok = true;
    for (int i = 0; i < 4; i++) ok = ok && got[i] == want[i];
    printf("%-34s %s\n", name, ok ? "PASS" : "FAIL");
    if (!ok) {
        failures++;
        printf("    got  %08x%08x%08x%08x\n    want %08x%08x%08x%08x\n", got[0], got[1], got[2], got[3],
               want[0], want[1], want[2], want[3]);
    }
}

static void kat(const char *name, const uint32_t key[4], const uint32_t pt[4], const uint32_t ct[4]) {
    AesRoundKeys k;
    aes128_expand_key(key, &k);
    uint32_t out[4], back[4];
    aes128_encrypt(&k, pt, out);
    char buf[64];
    snprintf(buf, sizeof buf, "%s encrypt", name);
    check(buf, out, ct);
    aes128_decrypt(&k, ct, back);
    snprintf(buf, sizeof buf, "%s decrypt", name);
    check(buf, back, pt);
}

int main() {
    {
        const uint32_t key[4] = {0x2b7e1516, 0x28aed2a6, 0xabf71588, 0x09cf4f3c};
        const uint32_t pt[4] = {0x3243f6a8, 0x885a308d, 0x313198a2, 0xe0370734};
        const uint32_t ct[4] = {0x3925841d, 0x02dc09fb, 0xdc118597, 0x196a0b32};
        kat("FIPS-197 Appendix B", key, pt, ct);
    }
    {
        const uint32_t key[4] = {0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f};
        const uint32_t pt[4] = {0x00112233, 0x44556677, 0x8899aabb, 0xccddeeff};
        const uint32_t ct[4] = {0x69c4e0d8, 0x6a7b0430, 0xd8cdb780, 0x70b4c55a};
        kat("FIPS-197 Appendix C.1", key, pt, ct);
    }
    {
        const uint32_t key[4] = {0x2b7e1516, 0x28aed2a6, 0xabf71588, 0x09cf4f3c};
        const uint32_t pts[4][4] = {{0x6bc1bee2, 0x2e409f96, 0xe93d7e11, 0x7393172a},
                                    {0xae2d8a57, 0x1e03ac9c, 0x9eb76fac, 0x45af8e51},
                                    {0x30c81c46, 0xa35ce411, 0xe5fbc119, 0x1a0a52ef},
                                    {0xf69f2445, 0xdf4f9b17, 0xad2b417b, 0xe66c3710}};
        const uint32_t cts[4][4] = {{0x3ad77bb4, 0x0d7a3660, 0xa89ecaf3, 0x2466ef97},
                                    {0xf5d3d585, 0x03b9699d, 0xe785895a, 0x96fdbaaf},
                                    {0x43b1cd7f, 0x598ece23, 0x881b00e3, 0xed030688},
                                    {0x7b0c785e, 0x27e8ad3f, 0x82232071, 0x04725dd4}};
        for (int i = 0; i < 4; i++) {
            char name[48];
            snprintf(name, sizeof name, "SP 800-38A F.1.1 block %d", i + 1);
            kat(name, key, pts[i], cts[i]);
        }
    }
    {
        AesRoundKeys kc, kt;
        const uint32_t k1[4] = {1, 2, 3, 4}, k2[4] = {5, 6, 7, 8}, nonce[2] = {0xabcdef01, 0x23456789};
        aes128_expand_key(k1, &kc);
        aes128_expand_key(k2, &kt);
        srand(1);
        int bad = 0;
        for (int t = 0; t < 10000; t++) {
            uint32_t p[4], c[4], q[4];
            for (int i = 0; i < 4; i++) p[i] = ((uint32_t)rand() << 16) ^ (uint32_t)rand();
            uint32_t blk = (uint32_t)rand() % IMEM_BLOCKS;
            xex_encrypt_block(&kc, &kt, nonce, blk, p, c);
            xex_decrypt_block(&kc, &kt, nonce, blk, c, q);
            for (int i = 0; i < 4; i++) bad += q[i] != p[i];
        }
        printf("%-34s %s\n", "XEX round trip (10000 blocks)", bad ? "FAIL" : "PASS");
        failures += bad != 0;
        uint32_t p[4] = {0, 0, 0, 0}, c0[4], c1[4];
        xex_encrypt_block(&kc, &kt, nonce, 0, p, c0);
        xex_encrypt_block(&kc, &kt, nonce, 1, p, c1);
        bool differ = c0[0] != c1[0] || c0[1] != c1[1] || c0[2] != c1[2] || c0[3] != c1[3];
        printf("%-34s %s\n", "XEX same block, two addresses", differ ? "PASS" : "FAIL");
        failures += !differ;
    }
    printf("\n%s\n", failures ? "AES KNOWN-ANSWER TESTS FAILED" : "all AES known-answer tests passed");
    return failures ? 1 : 0;
}
