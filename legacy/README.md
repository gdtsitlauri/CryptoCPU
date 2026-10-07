# CryptoCPU 2025

[original-2025/](original-2025/) holds the CryptoCPU work as submitted for the
BSc thesis in 2025: the C++ sources (`cpu.cpp`, `encryptor.cpp`,
`decryptor.cpp`, `test.cpp`) and the MARS assembly program and its memory images.

These are the files of the prototype that went through Vitis HLS and Vivado and
ran on the Artix-7 board. They are kept byte for byte;
[SHA256SUMS.txt](original-2025/SHA256SUMS.txt) records their hashes. The
maintained sources and their verification are in `src/`, `tests/` and
`results/host/` at the repository root.

[CHANGES.md](CHANGES.md) explains what differs between the 2025 implementation and the
present one, and why.
