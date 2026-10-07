# Original CryptoCPU work — 2025

The sources, assembly and memory images of the 2025 BSc thesis, unchanged;
[SHA256SUMS.txt](SHA256SUMS.txt) records their hashes.

| file | role |
| --- | --- |
| `cpu.cpp`, `header.h` | the processor, with the AES-128 Decrypt stage, for Vitis HLS |
| `test.cpp` | the testbench used in C simulation and C/RTL co-simulation |
| `encryptor.cpp`, `decryptor.cpp` | encrypt the program and check the decryption offline |
| `demo.asm` | the demonstration program (MARS) |
| `text.hex`, `data.hex` | MARS output: instructions and data |
| `text_encrypted.hex`, `text_decrypted.hex` | the encrypted instructions and their offline decryption |
| `demo.hex` | the memory image loaded into the processor |
