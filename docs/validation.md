# Verification

The [recorded report](../results/host/README.md) is the evidence behind the paper
and main README. Its [manifest](../results/host/manifest.json) records actual
execution timestamps, commands, compiler/Python versions and SHA-256 hashes of
the source files and binaries. The thesis year is 2025; verification timestamps
identify when a particular source snapshot was checked.

## Reproduce the complete run

Use Python 3 and a GCC/Clang C++17 compiler from the project root:

```text
python tools/verify.py --cxx g++
```

The default output is `results/local/`, leaving the bundled `results/host/`
report intact. `--out` selects a different report directory and `--cxx` accepts
an absolute compiler path. The runner builds five executables, records each
step's exit status and stops on failure. A report is successful only when its
manifest says `passed` and the sources stayed unchanged throughout the run.

This workspace also contains ignored portable tools. In PowerShell:

```powershell
& .\_build\toolchain\python\python.exe tools\verify.py --cxx .\_build\toolchain\llvm-mingw-20260908-ucrt-x86_64\bin\clang++.exe
```

A normal clone can use locally installed Python and a compiler instead.

## Coverage and interpretation

| Experiment | Inputs and comparison | Evidence |
| --- | --- | --- |
| AES known answers | FIPS-197 examples and four SP 800-38A AES-128 blocks, encryption and decryption | [AES log](../results/host/aes_kat.txt) |
| XEX inversion | 10,000 randomized block/address round trips | [AES log](../results/host/aes_kat.txt) |
| Directed programs | 14 programs, including three exception cases and a data-alignment regression | [Functional log](../results/host/functional_tests.txt) |
| Random differential checks | 1,000 programs × five configurations, seed 2026 | [Fuzz log](../results/host/fuzz.txt) |
| Mutation sensitivity | Three injected forwarding/stall/branch bugs; 100 programs × five configurations per mutant, seed 7 | [Mutation log](../results/host/mutation.txt) |
| Tooling regression | Six Python test methods, including invalid-input subcases and preservation of output on rejection | [Tooling log](../results/host/tooling_regression.txt) |
| Outcome classification | Eight encrypted-program cases, including differences confined to HI, LO or end PC | [Classification log](../results/host/security_regression.txt) |
| Ciphertext experiment | Ten programs; one wrong code key per program, 500 random bit flips per program and 208 block swaps; seed 1 | [Security log](../results/host/security.txt) |
| Performance | Ten benchmarks; encrypted/plaintext baselines, cache sizes 1–64 and AES service latencies 1–44 | [Tables](../results/host/perf.md), [CSV](../results/host/perf.csv) |

The CPU testbench compares final status, end PC, retired count, all 32 general
registers, HI/LO and the complete data memory against the reference interpreter.
Directed programs also contain fixed expected values. The interpreter has its
own sequential decode/execute flow, but shares the AES implementation; NIST
known-answer tests provide the separate cryptographic check.

The 5,000 random runs have zero mismatches, including 430 memory traps and 115
overflow traps. The three mutants are caught in 500/500, 405/500 and 495/500
runs respectively. This demonstrates sensitivity to those injected faults,
rather than exhaustive correctness of every possible program.

## Security experiment

Outcomes are compared with each program's untampered CPU run. A trap, timeout,
normal halt with changed state, and normal halt with unchanged state are
separate outcomes. The state comparison includes status, PC, HI/LO, all general
registers and data memory. The timeout budget is twenty times the baseline
modeled cycles plus 1,000 cycles. A normally halted unchanged state does not
establish whether modified instructions executed.

The recorded experiment observes 4,995 traps and five timeouts in 5,000 bit
flips, ten traps with wrong code keys, and 208 traps after block swaps. No
silently changed final result was observed. Since XEX is unauthenticated,
these counts do not establish arbitrary-tamper detection. The C runtime's
`rand()` implementation can change the sample sequence across platforms even
with the same seed.

The plaintext scan searches for complete, nonzero 16-byte instruction blocks
in the encrypted image and final data memory. It found none in the directed
checks. It does not cover fragments, transient values, debug ports or physical
leakage. The pattern experiment finds 1,024 distinct XEX blocks in each complete
instruction image, compared with 4–11 distinct ECB blocks for these programs.

## Performance and hardware scope

At eight active cache lines, four-cycle block reads and eleven-cycle AES
service, the ten benchmarks total 46,068 plaintext cycles and 46,773 encrypted
cycles. The +1.5% figure is a ratio of summed cycles, not the mean overhead of
ten equally weighted workloads. Fibonacci accounts for most of the execution;
short programs show much larger cold-cache overhead.

The cycle model excludes setup/key expansion and uses parameterized service
delays. FPGA scheduling, frequency, resources and power follow the
[hardware integration procedure](hardware-flow.md). Host success does not
establish those physical quantities.

## Fast CMake checks

```text
cmake -S . -B build
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

With Python found, CTest registers four tests: AES, security classification,
tooling regression and directed programs. The [recorded CTest log](../results/host/ctest.txt)
contains the outcome of the separate CMake build. Earlier logs and historical
review notes are preserved in [legacy](../legacy/README.md).
