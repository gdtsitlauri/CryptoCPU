# CryptoCPU

**Can a processor run programs that exist only in encrypted form, outside its own chip, at a small cost in performance?**

CryptoCPU is a pipelined processor for the MIPS32 instruction set that executes only encrypted
programs. Instruction memory holds the program encrypted with AES-128; blocks are decrypted inside
the core, in a dedicated Decrypt stage, into an on-chip cache of decrypted instructions. Plaintext
instructions never appear in instruction memory, in data memory or on the memory bus. It is the
BSc thesis project of George David Tsitlauri (University of Thessaly), revised in 2026 as version 2.

The core is written in C++ for Vitis HLS (HLS pragmas, fixed-size arrays, no dynamic memory) and is
evaluated with a cycle-level C simulation, an independent reference interpreter and a set of
security experiments. The design background is in the thesis (`docs/thesis/`).

| part | what it does |
| --- | --- |
| ISA | MIPS32 subset in standard encodings (ALU, shifts, multiply/divide with HI/LO, byte/half/word loads and stores, branches, jumps, calls), so MARS output runs unchanged; two extra instructions, `aesenc` and `aesdec`, encrypt and decrypt 16-byte data blocks |
| pipeline | six stages: IF, DC (Decrypt), ID, EX, MEM, WB; forwarding, load-use stalls, branches resolved in EX, precise exceptions |
| memory encryption | AES-128 in XEX mode with the block address as tweak: equal instruction blocks give different ciphertexts, and a block moved to another address decrypts to garbage |
| keys | three on-chip key registers (code, tweak, data) loaded through a key port, as with eFUSE/BBRAM keys on an FPGA; never stored in memory |
| decrypted-instruction cache | direct-mapped, 8 lines of 4 instructions; a hit needs no decryption, so loops pay for AES once |

## Main results

All numbers come from the commands in "Building and running"; the logs are in `results/`.

1. **AES-128 is correct.** The core passes the FIPS-197 Appendix B and C.1 vectors and the four
   NIST SP 800-38A ECB-AES128 blocks, in both directions. XEX decryption inverts encryption on
   10,000 random blocks and addresses (`results/aes_kat.txt`).
2. **The core executes encrypted programs correctly.** 13 directed programs (arithmetic, loops,
   recursion, sorting, strings, multiply/divide, `aesenc`/`aesdec`, hazards, sieve, matrix
   multiply, and three exception cases) run from encrypted images. For every one, the final
   status, end PC, retired-instruction count, all 32 registers, HI/LO and the whole data memory
   equal those of the reference interpreter, and every expected value written in the program
   holds (`results/functional_tests.txt`).
3. **Random programs agree with the reference too.** 1,000 random programs with dense register
   dependencies, branches, loops, calls and `aesenc`/`aesdec`, each under five configurations
   (5,000 runs, 545 of them ending in exceptions), match the reference exactly
   (`results/fuzz.txt`). The checks are sensitive: three deliberately injected pipeline bugs
   (no forwarding, no load-use stall, no squash after a taken branch) were each caught in
   81-100% of the runs (`results/mutation.txt`).
4. **No plaintext leaves the core.** No 16-byte plaintext block of any test program appears in the
   instruction image or in data memory after the run. Instruction memory is read-only to the core,
   so decrypted instructions have no path back to memory.
5. **The image hides program structure.** For the ten halting programs, the 1,024-block image has
   1,024 distinct blocks under XEX, while ECB with the same key keeps the 4-11 distinct blocks of
   the plaintext (equal blocks, such as padding, stay equal).
6. **Wrong keys and tampering stop the core.** With a wrong code key, all ten programs end in an
   exception. Of 5,000 random single-bit flips in code blocks, 99.9% end in an
   exception and 0.1% in a timeout; none produced a silently wrong result. All 208 swaps of two
   code blocks end in an exception (`results/security.txt`).
7. **The decrypted-instruction cache hides the cost of AES.** At the design point (8 lines,
   11-cycle AES, 4-cycle block read), encryption adds +0.2% to +7.6% cycles to the programs with
   loops (fib, sieve, bubble sort, loop sum, matrix multiply) and +1.5% over all programs together.
   Short straight-line programs pay more (up to +134%), because every block is a first-time miss.
   With a single cache line, the CPI of the programs with loops rises from 1.4-1.9 to 5.9-9.1
   (`results/perf.md`).

## Limitations (reported as such)

- XEX gives confidentiality, not integrity. Tampering garbles a whole block, and in the experiments
  this almost always ended in an exception, but nothing guarantees it: a garbled block can decode to
  valid instructions. Authenticated memory is the subject of the follow-up project
  [Crypto3DStackCPU](https://github.com/gdtsitlauri/Crypto3DStackCPU).
- Side channels (power, timing, electromagnetic) are outside the threat model.
- The cycle counts come from a cycle-level model of the pipeline; multiply and divide take one cycle,
  and memory latencies are parameters.
- `aesenc` and `aesdec` use a separate data key; they cannot decrypt instruction blocks.

## Folder map

```
CryptoCPU/
  README.md, CMakeLists.txt
  src/          aes128.cpp (AES-128), xex.cpp (memory encryption), cryptocpu.cpp (pipeline, HLS top)
  ref/          isa_ref.cpp: independent reference interpreter (golden model)
  tests/        cryptocpu_tb.cpp (core vs. reference), security_tb.cpp, aes_kat.cpp,
                programs/*.s (13 directed programs with EXPECT lines)
  tools/        asm.py (assembler, MARS syntax), image_tool.cpp (encrypt/decrypt images),
                run_tests.py, fuzz.py, mutate.py, sweep.py
  results/      logs of every experiment in this README
  docs/thesis/  the BSc thesis (v1)
  legacy/v1/    the v1 sources and what changed
```

## Building and running

Requirements: a C++17 compiler (g++, clang++ or MSVC) and Python 3; CMake is optional.

```bash
cmake -S . -B build && cmake --build build          # or: g++ -std=c++17 -O2 ... (see below)
./build/aes_kat                                     # AES known-answer tests
python tools/run_tests.py                           # 13 programs, core vs. reference
python tools/fuzz.py --count 1000 --seed 2026       # random differential testing
python tools/run_tests.py >/dev/null && ./build/security_tb build/progs/{signature,loop_sum,fib,bubble,strings,muldiv,aes,hazards,sieve,matmul}
python tools/mutate.py                              # injected bugs must be caught
python tools/sweep.py                               # performance tables
```

Without CMake, each tool is one command, for example:

```bash
g++ -std=c++17 -O2 src/aes128.cpp src/xex.cpp src/cryptocpu.cpp ref/isa_ref.cpp tests/cryptocpu_tb.cpp -o build/cryptocpu_tb
```

Writing and running your own program:

```bash
python tools/asm.py myprog.s -o build/myprog       # text.hex, data.hex, symbols.txt
./build/cryptocpu_tb build/myprog                   # encrypts, runs, compares with the reference
./build/image_tool encrypt build/myprog/text.hex image.hex --keys keys.txt
```

For Vitis HLS, the top function is `cryptocpu_top` in `src/cryptocpu.cpp`; `tests/cryptocpu_tb.cpp`
is the C-simulation testbench.

## Citation and license

George David Tsitlauri, *CryptoCPU: Design and Implementation of an Encrypted Instruction Set
Processor on FPGA*, BSc thesis, Department of Informatics and Telecommunications, University of
Thessaly, supervisor Prof. G. Dimitriou. Provided for academic and research use; please cite the
thesis when you use it.
