#include <iostream>
#include <fstream>
#include <cstdint>
#include <iomanip>
#include <string>

// Μέγεθος μνήμης και register file (να ταιριάζει με το CPU.cpp)
#define MEM_SIZE   256
#define NUM_REGS   32

// Από το joiner
#define SIGNATURE_ADDR 156
#define EXPECTED_SIGNATURE 0x00000015

// Εκκίνηση .text
#define TEXT_START_ADDR 32

extern "C" {
    void     CryptoCPU_top();
    extern   uint32_t memory[MEM_SIZE];
    extern   uint32_t reg_file[NUM_REGS];
}

int main(int argc, char **argv) {
    // 1. Διαβάζει αρχείο .hex
    std::string hex_file = (argc > 1) ? argv[1] : "demo.hex";
    std::cout << "[INFO] Using input file: " << hex_file << std::endl;

    std::ifstream fin(hex_file);
    if (!fin) {
        std::cerr << "[ERROR] Cannot open file: " << hex_file << std::endl;
        return 1;
    }

    int lines_loaded = 0;
    for (int i = 0; i < MEM_SIZE; i++) {
        std::string line;
        if (!std::getline(fin, line)) {
            std::cerr << "[ERROR] Unexpected EOF at line " << i << std::endl;
            return 1;
        }
        try {
            memory[i] = std::stoul(line, nullptr, 16);
            lines_loaded++;
        } catch (...) {
            std::cerr << "[ERROR] Invalid hex at line " << i << ": " << line << std::endl;
            return 1;
        }
    }
    fin.close();

    std::cout << "[INFO] Loaded " << lines_loaded << " words into memory." << std::endl;

    // 2. Τρέχει το CryptoCPU
    std::cout << "[INFO] Starting CryptoCPU_top()..." << std::endl;
    CryptoCPU_top();
    std::cout << "[INFO] CryptoCPU execution complete." << std::endl;

    // 3. Dump όλων των registers
    std::cout << "\n=== REGISTER FILE DUMP ===" << std::endl;
    for (int i = 0; i < NUM_REGS; i++) {
        std::cout << "reg[" << std::setw(2) << i << "] = 0x"
                  << std::hex << std::uppercase << std::setw(8) << std::setfill('0')
                  << reg_file[i] << std::endl;
    }

    // 4. Dump πρώτων 64 θέσεων μνήμης
    std::cout << "\n=== MEMORY DUMP (first 64 words) ===" << std::endl;
    for (int i = 0; i < 64; i++) {
        std::cout << "memory[" << std::setw(3) << i << "] = 0x"
                  << std::hex << std::uppercase << std::setw(8) << std::setfill('0')
                  << memory[i] << std::endl;
    }

    // 5. Έλεγχος υπογραφής
    std::cout << "\n=== SIGNATURE CHECK ===" << std::endl;
    uint32_t signature = memory[SIGNATURE_ADDR];
    std::cout << "Signature at address " << SIGNATURE_ADDR << " = 0x"
              << std::hex << std::uppercase << std::setw(8) << std::setfill('0')
              << signature << std::endl;

    if (signature == EXPECTED_SIGNATURE) {
        std::cout << "[✅] SUCCESS: Signature matches expected value " << EXPECTED_SIGNATURE << std::endl;
    } else {
        std::cout << "[❌] ERROR: Signature mismatch. Expected "
                  << EXPECTED_SIGNATURE << ", got " << signature << std::endl;
    }

    // 6. EXTRA: Dump αποκρυπτογραφημένου .text section
    std::cout << "\n=== POST-EXECUTION DECRYPTED .TEXT DUMP ===" << std::endl;
    int TEXT_END_ADDR = SIGNATURE_ADDR;  // ή ό,τι έχεις από το joiner
    for (int i = TEXT_START_ADDR; i < TEXT_END_ADDR; i++) {
        std::cout << "memory[" << std::setw(3) << i << "] = 0x"
                  << std::hex << std::uppercase << std::setw(8) << std::setfill('0')
                  << memory[i] << std::endl;
    }

    return 0;
}
