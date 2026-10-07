# Original CryptoCPU work — 2025

The sources, assembly, memory images and thesis of the 2025 BSc thesis, unchanged.

- [Thesis (PDF)](thesis/Thesis.pdf) and [Word document](thesis/CryptoCPU_BSc_Thesis.docx)
- [SHA-256 checksums](SHA256SUMS.txt)

| file | role |
| --- | --- |
| `cpu.cpp`, `header.h` | the processor, with the AES-128 Decrypt stage, for Vitis HLS |
| `test.cpp` | the testbench used in C simulation and C/RTL co-simulation |
| `encryptor.cpp`, `decryptor.cpp` | encrypt the program and check the decryption offline |
| `demo.asm` | the demonstration program (MARS) |
| `text.hex`, `data.hex` | MARS output: instructions and data |
| `text_encrypted.hex`, `text_decrypted.hex` | the encrypted instructions and their offline decryption |
| `demo.hex` | the memory image loaded into the processor |
