# CryptoCPU Project
**Note:** The repository also includes the full paper (`paper.docx`) describing the project in detail.

This repository contains the implementation and testing framework of **CryptoCPU**, a MIPS-like processor with an integrated AES-128 decryption stage in the pipeline.  
The goal of CryptoCPU is to execute **only encrypted programs**, ensuring that no plaintext instructions ever appear in memory or on FPGA buses.

---

## 📂 Repository Structure

- **cpu.cpp**  
  Core implementation of the CryptoCPU processor (pipeline, AES integration, instruction execution).

- **data.hex**  
  Plaintext data section generated from MARS (`.data` segment).

- **decryptor.cpp**  
  Offline AES decryption tool. Used to verify that encrypted instructions can be correctly decrypted back to their original form.

- **demo.asm**  
  Example MIPS-like assembly program used for testing.

- **demo.hex**  
  Unified memory image containing:
  - Encrypted instructions (`.text`)  
  - Plaintext data (`.data`)  
  - AES key embedding at block 0  

- **encryptor.cpp**  
  Offline AES encryption tool. Takes `text.hex` and generates `text_encrypted.hex`.

- **header.h**  
  Header file containing AES declarations, constants, and function prototypes.

- **test.cpp**  
  Testbench used in C Simulation (Vitis HLS). Loads `demo.hex`, executes CryptoCPU, and checks final results/signature.

- **text.hex**  
  Instruction section in plaintext, generated from MARS (`.text` segment).

- **text_encrypted.hex**  
  AES-encrypted version of `text.hex` (input for CryptoCPU execution).

- **text_decrypted.hex**  
  Decrypted output (for validation). Used to compare with the original `text.hex`.

---

## 🚀 Workflow

1. Write program in **demo.asm** (MIPS-like assembly).
2. Export `.text.hex` and `.data.hex` using **MARS**.
3. Encrypt `.text.hex` with **encryptor.cpp** → produces `text_encrypted.hex`.
4. Merge encrypted `.text` and plaintext `.data` into **demo.hex**.
5. Run **test.cpp** (C Simulation) or synthesize with **Vitis/Vivado** to execute on FPGA.
6. (Optional) Use **decryptor.cpp** to verify correctness of AES decryption.

---

## ✅ Features

- Six-stage pipeline: `Fetch → Decrypt → Decode → Execute → Memory → Write-Back`.
- On-the-fly AES-128 decryption at the `Decrypt` stage.
- No plaintext instructions are ever stored in memory.
- Testbench validation with digital signature check (`0x15` at `memory[156]`).
- Compatible with Xilinx Vitis HLS and Vivado for FPGA implementation.

---

## 🔧 Requirements

- **MARS** (MIPS Assembler and Runtime Simulator)  
- **g++ / clang++** for compiling the C++ tools  
- **Xilinx Vitis HLS** and **Vivado Design Suite** (for synthesis and FPGA implementation)  

---

## 🧪 Example Run

```bash
# Compile encryption/decryption tools
g++ encryptor.cpp cpu.cpp -o encryptor
g++ decryptor.cpp cpu.cpp -o decryptor
g++ test.cpp cpu.cpp -o testbench

# Encrypt instructions
./encryptor text.hex text_encrypted.hex

# Decrypt for verification
./decryptor text_encrypted.hex text_decrypted.hex

# Run testbench
./testbench
```

If successful, the output will confirm execution with:

```
Signature check PASSED
```

---

## 📜 License

This project is provided for academic and research purposes.
Use it freely with proper citation of the original work.

---
