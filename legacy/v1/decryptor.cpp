#include <iostream>
#include <fstream>
#include <iomanip>
#include <string>
#include <cstdint>
#include "header.h"

int main(int argc, char **argv) {
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " encrypted.hex decrypted.hex\n";
        return 1;
    }

    std::string input_file = argv[1];
    std::string output_file = argv[2];

    // -------------------------------------------------------------------------
    // 1. Load encrypted .text (skip block 0, starts at offset 32)
    // -------------------------------------------------------------------------
    std::ifstream fin(input_file);
    if (!fin) {
        std::cerr << "[ERROR] Cannot open input file: " << input_file << std::endl;
        return 1;
    }

    // Clear memory
    for (int i = 0; i < MEM_SIZE; i++) memory[i] = 0;

    // Load encrypted.hex (block 0 + encrypted .text) directly into memory[0..N]
    int lines_loaded = 0;
    std::string line;
    while (std::getline(fin, line) && lines_loaded < MEM_SIZE) {
        if (!line.empty()) {
            try {
                memory[lines_loaded] = std::stoul(line, nullptr, 16);
            } catch (...) {
                memory[lines_loaded] = 0x00000000;
            }
        } else {
            memory[lines_loaded] = 0x00000000;
        }
        lines_loaded++;
    }
    fin.close();

    int text_start_addr = 32;
    int TEXT_END_ADDR = lines_loaded;
    if (TEXT_END_ADDR % INSTRS_PER_BLOCK != 0) {
        TEXT_END_ADDR += (INSTRS_PER_BLOCK - (TEXT_END_ADDR % INSTRS_PER_BLOCK));
    }
    if (TEXT_END_ADDR > MEM_SIZE) TEXT_END_ADDR = MEM_SIZE;

    std::cout << "[INFO] Loaded " << lines_loaded << " lines from encrypted.hex" << std::endl;
    std::cout << "[INFO] Aligned TEXT_END_ADDR = " << TEXT_END_ADDR << std::endl;

    // -------------------------------------------------------------------------
    // 2. Insert block 0 with *known* key bits for extraction
    // -------------------------------------------------------------------------
    for (int i = 0; i < 32; i++) memory[i] = 0xDEADBEEF;

    uint32_t aes_key[4] = {
        0x12345678,
        0x9ABCDEF0,
        0xFEDCBA98,
        0x76543210
    };
    create_large_block_with_key(aes_key);
    std::cout << "[INFO] Inserted block 0 with key-hiding for extraction." << std::endl;

    // -------------------------------------------------------------------------
    // 3. Extract AES key
    // -------------------------------------------------------------------------
    extract_key_from_large_block(aes_key);
    std::cout << "[INFO] Extracted AES Key:" << std::endl;
    for (int i = 0; i < 4; i++) {
        std::cout << "  0x"
                  << std::hex << std::uppercase << std::setw(8) << std::setfill('0')
                  << aes_key[i] << std::endl;
    }

    // -------------------------------------------------------------------------
    // 4. Decrypt only the actual .text region (no extra padding!)
    // -------------------------------------------------------------------------
    int start_block = text_start_addr / INSTRS_PER_BLOCK;
    int end_block   = (lines_loaded + INSTRS_PER_BLOCK - 1) / INSTRS_PER_BLOCK;

    for (int block = start_block; block < end_block; block++) {
        int block_start_addr = block * INSTRS_PER_BLOCK;

        uint32_t ciphertext[INSTRS_PER_BLOCK];
        for (int i = 0; i < INSTRS_PER_BLOCK; i++) {
            ciphertext[i] = memory[block_start_addr + i];
        }

        uint32_t plaintext[INSTRS_PER_BLOCK];
        aes_decrypt_block(ciphertext, aes_key, plaintext);

        int valid_words = INSTRS_PER_BLOCK;
        if (block == end_block - 1) {
            valid_words = lines_loaded - block_start_addr;
            if (valid_words > INSTRS_PER_BLOCK) valid_words = INSTRS_PER_BLOCK;
        }
        for (int i = 0; i < INSTRS_PER_BLOCK; i++) {
            if (block != end_block - 1 || i < valid_words) {
                memory[block_start_addr + i] = plaintext[i];
            } // else: keep original (encrypted) value for padding
        }
    }

    // -------------------------------------------------------------------------
    // 5. Write back *including block 0* + decrypted .text
    // -------------------------------------------------------------------------
    std::ofstream fout(output_file);
    if (!fout) {
        std::cerr << "[ERROR] Cannot write to: " << output_file << std::endl;
        return 1;
    }

    // Count lines in original text.hex
    std::ifstream fin_orig("text.hex");
    int orig_lines = 0;
    std::string dummy;
    while (std::getline(fin_orig, dummy)) orig_lines++;
    fin_orig.close();

    // Write exactly as many lines as the original text.hex
    for (int i = 0; i < orig_lines; i++) {
        fout << std::hex << std::uppercase << std::setw(8) << std::setfill('0')
             << memory[i] << "\n";
    }
    fout.close();

    std::cout << "[INFO] Decryption complete. Written " << orig_lines
              << " lines to " << output_file << std::endl;

    return 0;
}
