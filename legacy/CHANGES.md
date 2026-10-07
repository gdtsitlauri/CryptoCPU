# From the 2025 implementation to the present one

The idea is the same as in the 2025 thesis: instructions stay encrypted in memory, a
Decrypt stage between Fetch and Decode recovers them inside the processor, a cache keeps
the decrypted instructions so that loops do not pay for AES again, and the pipeline has six
stages over a MIPS instruction set. What changed is how the implementation carries the idea
out. The 2025 files are in [original-2025/](original-2025/), unchanged.

| | 2025 (`original-2025/cpu.cpp`) | Present (`src/`) |
| --- | --- | --- |
| Instruction encryption | AES-128 in ECB mode | AES-128 in XEX mode, with a tweak derived from an image nonce and the block address |
| Decrypted instructions | written back to memory | kept only inside the processor (cache and pipeline) |
| Key | hidden in the first 32 words of memory, among `0xDEADBEEF` patterns | supplied separately; separate keys for code, tweak and data operations |
| Memory | one 256-word (1 KiB) memory for code and data | separate 16 KiB instruction and 16 KiB data memories |
| Instruction cache | four lines, holding encrypted blocks | eight lines by default (one to 64), holding decrypted blocks |
| Instruction set | 16 project-specific opcodes (`ADD = 1`, `SUB = 2`, ...) | standard MIPS32 encodings for a subset of about 50 instructions, including divide, HI/LO, byte/halfword access and calls |
| Verification | one signature check (`memory[156] == 0x15`) | a reference interpreter, 14 directed programs, 5,000 random-program runs, injected-fault (mutation) checks and ciphertext-tampering experiments |
| Toolchain | MARS, `encryptor.cpp`, `decryptor.cpp` | an assembler and an image tool in `tools/`, no MARS needed |

## Why

**Decrypted instructions stay inside the processor.** The thesis states that no instruction
ever appears in plaintext in memory, but the 2025 Decrypt stage wrote each decrypted block back
to memory, to let the testbench print and check it. That left the whole program readable in
memory after a run. It could also break execution: the cache held encrypted blocks, so a block
evicted and fetched again was read back from memory, already in plaintext, and decrypted a
second time. The demonstration program was short enough not to reach that case. Checking the
decryption now happens outside the processor, as `decryptor.cpp` already did.

**The key is no longer stored next to the program.** Hiding the key among the `0xDEADBEEF`
words of the first memory block meant that anyone able to read the memory image could recover
it. A separate key input keeps it out of the image; separate data and code keys also stop the
`aesenc`/`aesdec` instructions from being used to decrypt the program.

**XEX instead of ECB.** In ECB, equal instruction blocks, such as repeated code or padding,
encrypt to equal ciphertext, a weakness the thesis itself notes, proposing other modes as future
work. XEX makes every block's encryption depend on its address. In the ten benchmark images every
16 KiB image has 1,024 distinct ciphertext blocks under XEX, where ECB keeps the 4 to 11 repeated
plaintext patterns.

**Separate, larger memories and a cache of decrypted instructions.** Keeping instructions and
data apart matches the Harvard organisation the thesis describes and lets instruction memory be
read-only. Caching decrypted rather than encrypted blocks is what lets loops reuse instructions
without running AES again: with eight lines, encryption adds 0.2-7.6% to the cycles of the
loop-oriented benchmarks.

**Standard encodings and stronger verification.** Standard MIPS32 encodings let ordinary MIPS
assembly run without a custom opcode table. A single signature value shows that one program
finished, not that the processor is correct, so the present version compares every program's
full final state with an independent reference interpreter and checks that deliberately
injected pipeline bugs are caught.

## FPGA results

The 2025 prototype went through the Vitis HLS and Vivado flow and ran on the Artix-7 board, as
the thesis describes. The [paper](../paper/cryptocpu.pdf) (Section V) gives those measured
results, and resource estimates for the present configuration based on these differences.
