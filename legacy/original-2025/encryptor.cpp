#include <iostream>
#include <fstream>
#include <iomanip>
#include <cstdint>
#include "header.h"

int main(int argc, char **argv) {
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " input.hex encrypted.hex\n";
        return 1;
    }

    std::string input_file = argv[1];
    std::string output_file = argv[2];

    // -------------------------------------------------------------------------
    // 1. Load input.hex
    // -------------------------------------------------------------------------
    std::ifstream fin(input_file);
    if (!fin) {
        std::cerr << "[ERROR] Cannot open input file: " << input_file << "\n";
        return 1;
    }

    for (int i = 0; i < MEM_SIZE; i++) {
        std::string line;
        if (!std::getline(fin, line) || line.empty()) {
            memory[i] = 0x00000000;
        } else {
            try {
                memory[i] = std::stoul(line, nullptr, 16);
            } catch (...) {
                memory[i] = 0x00000000;
            }
        }
    }
    fin.close();
    std::cout << "[INFO] Loaded input file: " << input_file << std::endl;

    // --- Count input lines for output size ---
    std::ifstream fin_count(input_file);
    int input_lines = 0;
    std::string dummy_line;
    while (std::getline(fin_count, dummy_line)) input_lines++;
    fin_count.close();
    std::cout << "[DEBUG] input_lines = " << input_lines << std::endl;

    // -------------------------------------------------------------------------
    // 2. Detect TEXT region (skip block 0)
    // -------------------------------------------------------------------------
    int TEXT_START_ADDR = 32;
    int TEXT_END_ADDR = 32;
    for (int i = 32; i < MEM_SIZE; i++) {
        if (memory[i] != 0) {
            TEXT_END_ADDR = i + 1;
        }
    }
    std::cout << "[INFO] Detected TEXT_START_ADDR = " << TEXT_START_ADDR << std::endl;
    std::cout << "[INFO] Detected TEXT_END_ADDR = " << TEXT_END_ADDR << std::endl;

    // Align to 4-word blocks
    if (TEXT_END_ADDR % INSTRS_PER_BLOCK != 0) {
        TEXT_END_ADDR += (INSTRS_PER_BLOCK - (TEXT_END_ADDR % INSTRS_PER_BLOCK));
    }
    if (TEXT_END_ADDR > MEM_SIZE) TEXT_END_ADDR = MEM_SIZE;

    std::cout << "[INFO] Aligned TEXT_END_ADDR = " << TEXT_END_ADDR << std::endl;

    // -------------------------------------------------------------------------
    // 3. Use FIXED AES key
    // -------------------------------------------------------------------------
    uint32_t aes_key[4] = {
        0x12345678,
        0x9ABCDEF0,
        0xFEDCBA98,
        0x76543210
    };

    std::cout << "[INFO] Using FIXED AES Key:" << std::endl;
    for (int i = 0; i < 4; i++) {
        std::cout << "  0x"
                  << std::hex << std::uppercase << std::setw(8) << std::setfill('0')
                  << aes_key[i] << std::endl;
    }

    // -------------------------------------------------------------------------
    // 4. Encrypt *all* of .text (even zero blocks)
    // -------------------------------------------------------------------------
    int start_block = TEXT_START_ADDR / INSTRS_PER_BLOCK;
    int end_block   = TEXT_END_ADDR / INSTRS_PER_BLOCK;

    for (int block = start_block; block < end_block; block++) {
        int block_start_addr = block * INSTRS_PER_BLOCK;

        uint32_t plaintext[INSTRS_PER_BLOCK];
        for (int i = 0; i < INSTRS_PER_BLOCK; i++) {
            plaintext[i] = memory[block_start_addr + i];
        }

        uint32_t ciphertext[INSTRS_PER_BLOCK];
        aes_encrypt_block(plaintext, aes_key, ciphertext);

        for (int i = 0; i < INSTRS_PER_BLOCK; i++) {
            memory[block_start_addr + i] = ciphertext[i];
        }
    }

    // -------------------------------------------------------------------------
    // 5. Hide key in block 0 (for joining)
    // -------------------------------------------------------------------------
    for (int i = 0; i < 32; i++) memory[i] = 0xDEADBEEF;
    create_large_block_with_key(aes_key);
    std::cout << "[INFO] Key hidden in block 0 for joining." << std::endl;

    // -------------------------------------------------------------------------
    // 6. Write block 0 + encrypted .text (output with padding to next multiple of 4)
    // -------------------------------------------------------------------------
    // Calculate padded output lines (block 0 + .text section)
    int padded_lines = input_lines;
    if (padded_lines % INSTRS_PER_BLOCK != 0) {
        padded_lines += (INSTRS_PER_BLOCK - (padded_lines % INSTRS_PER_BLOCK));
    }
    std::ofstream fout(output_file);
    if (!fout) {
        std::cerr << "[ERROR] Cannot write to " << output_file << "\n";
        return 1;
    }
    for (int i = 0; i < padded_lines; i++) {
        fout << std::hex << std::uppercase << std::setw(8) << std::setfill('0')
             << memory[i] << "\n";
    }
    fout.close();

    std::cout << "[INFO] Encryption complete. Written " << padded_lines
              << " lines to " << output_file << std::endl;

    return 0;
}
