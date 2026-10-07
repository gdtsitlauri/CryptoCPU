# CryptoCPU

**Design and implementation of an encrypted instruction set processor on FPGA**

George David Tsitlauri · **BSc thesis, 2025** · University of Thessaly

**Can a processor run programs that exist only in encrypted form, outside its own
chip, at a small cost in performance?**

CryptoCPU models a pipelined processor for a MIPS32 subset that executes encrypted
programs. Instruction memory holds the program encrypted with AES-128; blocks are
decrypted inside the core, in a dedicated Decrypt stage, into an internal cache
of decrypted instructions. The model keeps instruction memory read-only and does
not write decrypted instruction blocks to data memory. The original idea remains:
keep stored instructions encrypted, decrypt them inside the processor, and reuse
cached instructions to reduce the cost of AES.

The core is written in C++ for Vitis HLS, with HLS pragmas, fixed-size arrays and
no dynamic memory in the core. It is evaluated with a cycle-level C simulation,
a sequential reference interpreter and a set of security experiments. Read the
[paper](paper/cryptocpu.pdf), its [LaTeX source](paper/cryptocpu.tex), the
[architecture](docs/architecture.md), and the
[Vitis / Vivado integration flow](docs/hardware-flow.md). The
[original thesis and sources](legacy/README.md) are preserved in `legacy/`.

All reported numbers come from the host checks described below. The
[recorded run](results/host/README.md) contains the logs; its
[manifest](results/host/manifest.json) records commands, actual run timestamps,
tool versions and source/binary hashes.

## Main results

1. **AES-128 passes the known-answer checks.** The core passes the FIPS-197
   Appendix B and C.1 vectors and the four NIST SP 800-38A ECB-AES128 blocks,
   in both directions. XEX decryption inverts encryption on 10,000 random blocks
   and addresses ([AES log](results/host/aes_kat.txt)).

2. **Directed programs agree with the reference.** Fourteen programs cover
   arithmetic, loops, recursion, sorting, strings, multiply/divide, `aesenc` and
   `aesdec`, hazards, sieve, matrix multiplication, data alignment and three
   exception cases. Every program runs from an encrypted image. Final status,
   end PC, retired-instruction count, all 32 registers, HI/LO and the complete
   data memory match the reference interpreter; the programs' fixed expected
   values also hold ([functional log](results/host/functional_tests.txt)).

3. **Random programs agree with the reference too.** One thousand random
   programs with register dependencies, branches, loops, calls and AES data
   instructions run under five configurations: 5,000 runs, including 545 that
   end in exceptions, with zero mismatches ([fuzz log](results/host/fuzz.txt)).
   Three deliberately injected pipeline bugs—missing forwarding, a missing
   load-use stall and missing branch squashing—are each detected in 81–100% of
   runs ([mutation log](results/host/mutation.txt)).

4. **No tested plaintext instruction blocks appear in the final memory images.**
   The scan finds no complete, nonzero 16-byte instruction blocks in either the
   encrypted image or final data memory. Instruction memory is read-only to the
   core, so decrypted blocks have no write path back through that interface.
   The scan checks those complete blocks; it does not establish absence of
   fragments, transient leakage or physical side channels.

5. **XEX removes repeated-block patterns in the tested images.** Each of the ten
   benchmark images contains 1,024 distinct ciphertext blocks under XEX. ECB
   preserves the 4–11 distinct plaintext patterns, including repeated padding
   ([security log](results/host/security.txt)).

6. **Wrong keys and tampering produce observable execution failures in these
   experiments.** All ten wrong-code-key cases end in an exception. Of 5,000
   random single-bit flips, 4,995 end in an exception and five in a timeout;
   none produces a silently changed result. All 208 swaps of two code blocks
   end in an exception. These observations do not guarantee detection of
   arbitrary tampering ([security log](results/host/security.txt)).

7. **The decrypted-instruction cache reduces the modeled cost of AES.** At the
   design point—eight active lines, eleven-cycle AES service and a four-cycle
   block read—encryption adds 0.2–7.6% to the cycles of the loop-oriented
   benchmarks. Across all ten benchmarks, total cycles rise from 46,068 to
   46,773, or 1.5%. This aggregate is weighted by execution cycles; individual
   overhead reaches 133.8% for a short program. Reducing the cache to one line
   raises loop-oriented CPI from 1.356–1.855 to 5.911–9.130
   ([performance tables](results/host/perf.md)).

8. **The tooling and outcome checks have targeted regressions.** Six Python test
   methods cover data-label alignment and strict key-file/command-line handling,
   including invalid-input subcases. Eight encrypted-program cases check
   security classification, including differences confined to HI, LO or end PC
   ([tooling log](results/host/tooling_regression.txt),
   [classification log](results/host/security_regression.txt)).

9. **The thesis prototype ran on an Artix-7 FPGA.** It went through the full
   Vitis HLS and Vivado flow (C simulation, synthesis, C/RTL co-simulation, IP
   packaging, block design and implementation) on an AMD Artix-7 XC7A200T
   (AC701 board). Timing closed at 75 MHz with about 15% of the LUTs, 10% of the
   flip-flops, 12% of the block RAM and 5% of the DSP slices, and the board ran
   the encrypted program, signalling completion on an LED. The paper gives these
   measurements together with resource estimates for the present configuration
   ([paper](paper/cryptocpu.pdf), Section V).

## Scope and limits

- XEX encrypts instructions without an authentication tag. Modified ciphertext
  may decode into valid instructions, so an exception is not an integrity check.
  [Crypto3DStackCPU](https://github.com/gdtsitlauri/Crypto3DStackCPU) continues this
  research direction with a four-tier memory model, encrypted and authenticated
  program images, and protected transfers between tiers. It has its own
  implementation and validation.
- Power, electromagnetic and other physical side channels are outside the
  evaluated threat model. Separate key inputs define an interface boundary;
  hardware provisioning and access control define physical key protection.
- Cycle counts come from the pipeline model. Multiply/divide take one modeled
  cycle, memory and AES delays are parameters, and setup/key expansion precede
  cycle accounting. The FPGA figures are those of the thesis prototype; for the
  present configuration the paper gives estimates. The
  [integration flow](docs/hardware-flow.md) describes the Vitis / Vivado steps.
- `aesenc` and `aesdec` use a separate data key. They do not expose decryption
  under the code key; ordinary data memory is otherwise unencrypted.

See the [verification notes](docs/validation.md) for exact methods and coverage.

## Folder map

```text
CryptoCPU/
  README.md, CMakeLists.txt
  src/          AES-128, AES-XEX and the six-stage CPU; HLS top: cryptocpu_top
  ref/          sequential reference ISA interpreter
  tests/        CPU, AES, security and tooling checks; programs/*.s (14 programs)
  tools/        assembler, image tool, fuzzing, mutation, sweep and verification runners
  paper/        IEEE-style paper: PDF, LaTeX source and bibliography
  docs/         architecture, verification and Vitis / Vivado integration
  results/
    host/       recorded logs, performance data and verification manifest
  legacy/
    original-2025/     the 2025 sources, memory images and thesis (PDF/Word)
```

`build/`, `_build/` and `results/local/` hold ignored local outputs and tools.
Instructions for rebuilding the paper are in [paper/README.md](paper/README.md).

## Building and running

Requirements: Python 3 and a C++17 compiler. The complete host runner uses
GCC/Clang; CMake also supports MSVC. Vitis, Vivado and third-party Python packages
are unnecessary for these host checks.

Build and reproduce the complete suite with one command:

```text
python tools/verify.py --cxx g++
```

This builds five executables in `build/`, then runs AES checks, directed programs,
targeted regressions, randomized tests, tampering experiments, pipeline mutation
tests and performance sweeps. Fresh logs go to `results/local/`, leaving the
bundled results intact. Use `--out /path/to/report` to select another directory
and `--cxx /path/to/compiler` to select a compiler. On Windows, use MinGW
GCC/Clang for this runner; the [verification notes](docs/validation.md) also
show the portable-tool command available in this workspace.

For a CMake build and the four fast CTest checks:

```text
cmake -S . -B build
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

CMake must find Python to register the tooling and directed-program checks.
For individual experiments after building:

```text
build/aes_kat
python tools/run_tests.py
python tools/fuzz.py --count 1000 --seed 2026
python tools/mutate.py --cxx g++
python tools/sweep.py
```

The standalone sweep writes to `results/local/performance/`. Use the executable
directory selected by your CMake generator; MSVC normally places Release
executables in `build/Release/`.

Assembling and running a program:

```text
python tools/asm.py tests/programs/signature.s -o build/progs/signature
build/cryptocpu_tb build/progs/signature
build/image_tool encrypt build/progs/signature/text.hex build/image.hex --keys keys.txt
```

The assembler writes `text.hex`, `data.hex` and `symbols.txt`. The testbench
loads these files, encrypts instructions, executes the core and compares the
result with the reference. The image tool prepares a separate ciphertext file.

A supplied key file contains `k_code`, `k_tweak`, `k_data` (32 hexadecimal digits
each) and `nonce` (16 digits), each exactly once. For example:

```text
k_code 000102030405060708090a0b0c0d0e0f
k_tweak 101112131415161718191a1b1c1d1e1f
k_data 202122232425262728292a2b2c2d2e2f
nonce 3031323334353637
```

These values are public demonstration keys. Omitting `--keys` selects the
public built-in test keys. Malformed fields or command-line options are rejected
before an output image is written.

For Vitis HLS, select `cryptocpu_top` in `src/cryptocpu.cpp` as the top function
and `tests/cryptocpu_tb.cpp` as the C-simulation testbench. Follow the
[hardware flow](docs/hardware-flow.md) for the design sources, testbench arguments,
interfaces, co-simulation and board result checks.

## Citation

George David Tsitlauri, *Design and implementation of an encrypted instruction
set processor on FPGA*, BSc thesis, Department of Informatics and
Telecommunications, University of Thessaly, 2025. Supervisor: Georgios Dimitriou.
Please cite the thesis when referring to this work.

The [original thesis PDF](legacy/original-2025/thesis/Thesis.pdf) and
[Word document](legacy/original-2025/thesis/CryptoCPU_BSc_Thesis.docx) are preserved
in the archive.
