# CryptoCPU v1 (BSc thesis version)

These are the files of the first version of CryptoCPU, as described in the BSc thesis
(`docs/thesis/CryptoCPU_BSc_Thesis.docx`). They are kept unchanged for reference. The
current design is in `src/`; see the main README.

A review of v1 in October 2026 found five problems, which v2 fixes:

| v1 behaviour | consequence | v2 |
| --- | --- | --- |
| `stage_decrypt` wrote every decrypted block back into `memory[]` | after a run, plaintext instructions were in memory, against the design goal | decrypted blocks live only in an on-chip cache; instruction memory is read-only to the core |
| the opcode was read from bits 5..0, while MARS places it in bits 31..26 | MARS-assembled programs were decoded as different instructions | standard MIPS32 encodings |
| `test.cpp` checked `memory[156] == 0x15`, a value already present in `demo.hex` (computed by MARS) | the test passed even when the core did not execute the program | the testbench compares the whole architectural state with an independent reference interpreter |
| AES-128 in ECB mode, one block per 4 instructions | equal instruction blocks gave equal ciphertexts; blocks could be moved | AES-XEX with the block address as tweak |
| the key was hidden at secret bit positions in memory block 0 | the key was stored in the same memory as the program | on-chip key registers loaded through a key port |

The AES-128 implementation of v1 was correct (it matches the FIPS-197 vectors) and is
the basis of `src/aes128.cpp`.

The three v1 tools compile with any C++ compiler:

```bash
g++ test.cpp cpu.cpp -o testbench && ./testbench demo.hex
g++ encryptor.cpp cpu.cpp -o encryptor
g++ decryptor.cpp cpu.cpp -o decryptor
```
