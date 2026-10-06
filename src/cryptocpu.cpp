// CryptoCPU v2 core: six-stage in-order pipeline
//
//   IF  - PC generation, ciphertext block request
//   DC  - decrypted-line lookup; on a miss the AES-XEX unit decrypts the block
//         and fills the on-chip decrypted-instruction cache
//   ID  - decode, load-use hazard detection
//   EX  - ALU, multiply/divide, branch and jump resolution, forwarding
//   MEM - data memory, aesenc / aesdec (multi-cycle)
//   WB  - register write-back, retirement, precise halt and traps
//
// The model is cycle-level: every iteration of the main loop is one clock.
// Branches are predicted not taken and resolved in EX (3-cycle penalty); there
// are no delay slots (MARS default). Exceptions are precise: an instruction
// that faults is marked, younger instructions are squashed, and the run ends
// when the marker reaches WB, after all older instructions have retired.
#include "cryptocpu.h"

// ---------------------------------------------------------------------------
// Decoding
// ---------------------------------------------------------------------------
enum Op {
    OP_NONE = 0, OP_ILLEGAL,
    OP_SLL, OP_SRL, OP_SRA, OP_SLLV, OP_SRLV, OP_SRAV,
    OP_JR, OP_JALR, OP_SYSCALL, OP_BREAK,
    OP_MFHI, OP_MTHI, OP_MFLO, OP_MTLO, OP_MULT, OP_MULTU, OP_DIV, OP_DIVU,
    OP_ADD, OP_ADDU, OP_SUB, OP_SUBU, OP_AND, OP_OR, OP_XOR, OP_NOR, OP_SLT, OP_SLTU,
    OP_MUL,
    OP_BLTZ, OP_BGEZ, OP_J, OP_JAL, OP_BEQ, OP_BNE, OP_BLEZ, OP_BGTZ,
    OP_ADDI, OP_ADDIU, OP_SLTI, OP_SLTIU, OP_ANDI, OP_ORI, OP_XORI, OP_LUI,
    OP_LB, OP_LH, OP_LW, OP_LBU, OP_LHU, OP_SB, OP_SH, OP_SW,
    I_AESENC, I_AESDEC
};

struct Decoded {
    uint8_t op;
    uint8_t src_a, src_b;  // registers read (0 = none, $zero reads as 0 anyway)
    uint8_t dest;          // register written (0 = none)
    uint8_t shamt;
    uint32_t imm;          // already sign- or zero-extended
    uint32_t target;       // jump index field
    bool is_load;
};

static Decoded decode(uint32_t ins) {
    Decoded d = {OP_ILLEGAL, 0, 0, 0, 0, 0, 0, false};
    const uint32_t op = ins >> 26, rs = (ins >> 21) & 31, rt = (ins >> 16) & 31;
    const uint32_t rd = (ins >> 11) & 31, sh = (ins >> 6) & 31, fn = ins & 63;
    const uint32_t imm16 = ins & 0xffff;
    const uint32_t simm = (uint32_t)(int32_t)(int16_t)imm16;
    d.shamt = (uint8_t)sh;
    switch (op) {
    case 0x00:
        switch (fn) {
        case 0x00: if (rs == 0) { d.op = OP_SLL; d.src_b = rt; d.dest = rd; } break;
        case 0x02: if (rs == 0) { d.op = OP_SRL; d.src_b = rt; d.dest = rd; } break;
        case 0x03: if (rs == 0) { d.op = OP_SRA; d.src_b = rt; d.dest = rd; } break;
        case 0x04: if (sh == 0) { d.op = OP_SLLV; d.src_a = rs; d.src_b = rt; d.dest = rd; } break;
        case 0x06: if (sh == 0) { d.op = OP_SRLV; d.src_a = rs; d.src_b = rt; d.dest = rd; } break;
        case 0x07: if (sh == 0) { d.op = OP_SRAV; d.src_a = rs; d.src_b = rt; d.dest = rd; } break;
        case 0x08: if (rt == 0 && rd == 0 && sh == 0) { d.op = OP_JR; d.src_a = rs; } break;
        case 0x09: if (rt == 0 && sh == 0) { d.op = OP_JALR; d.src_a = rs; d.dest = rd; } break;
        case 0x0C: d.op = OP_SYSCALL; d.src_a = 2; break;  // service number in $v0
        case 0x0D: d.op = OP_BREAK; break;
        case 0x10: if (rs == 0 && rt == 0 && sh == 0) { d.op = OP_MFHI; d.dest = rd; } break;
        case 0x11: if (rt == 0 && rd == 0 && sh == 0) { d.op = OP_MTHI; d.src_a = rs; } break;
        case 0x12: if (rs == 0 && rt == 0 && sh == 0) { d.op = OP_MFLO; d.dest = rd; } break;
        case 0x13: if (rt == 0 && rd == 0 && sh == 0) { d.op = OP_MTLO; d.src_a = rs; } break;
        case 0x18: if (rd == 0 && sh == 0) { d.op = OP_MULT; d.src_a = rs; d.src_b = rt; } break;
        case 0x19: if (rd == 0 && sh == 0) { d.op = OP_MULTU; d.src_a = rs; d.src_b = rt; } break;
        case 0x1A: if (rd == 0 && sh == 0) { d.op = OP_DIV; d.src_a = rs; d.src_b = rt; } break;
        case 0x1B: if (rd == 0 && sh == 0) { d.op = OP_DIVU; d.src_a = rs; d.src_b = rt; } break;
        case 0x20: case 0x21: case 0x22: case 0x23: case 0x24: case 0x25: case 0x26: case 0x27:
        case 0x2A: case 0x2B:
            if (sh == 0) {
                static const uint8_t ops[12] = {OP_ADD, OP_ADDU, OP_SUB, OP_SUBU, OP_AND, OP_OR,
                                                OP_XOR, OP_NOR, OP_ILLEGAL, OP_ILLEGAL, OP_SLT, OP_SLTU};
                d.op = ops[fn - 0x20]; d.src_a = rs; d.src_b = rt; d.dest = rd;
            }
            break;
        default: break;
        }
        break;
    case 0x01:
        if (rt == 0) { d.op = OP_BLTZ; d.src_a = rs; d.imm = simm; }
        else if (rt == 1) { d.op = OP_BGEZ; d.src_a = rs; d.imm = simm; }
        break;
    case 0x02: d.op = OP_J; d.target = ins & 0x03ffffff; break;
    case 0x03: d.op = OP_JAL; d.target = ins & 0x03ffffff; d.dest = 31; break;
    case 0x04: d.op = OP_BEQ; d.src_a = rs; d.src_b = rt; d.imm = simm; break;
    case 0x05: d.op = OP_BNE; d.src_a = rs; d.src_b = rt; d.imm = simm; break;
    case 0x06: if (rt == 0) { d.op = OP_BLEZ; d.src_a = rs; d.imm = simm; } break;
    case 0x07: if (rt == 0) { d.op = OP_BGTZ; d.src_a = rs; d.imm = simm; } break;
    case 0x08: d.op = OP_ADDI;  d.src_a = rs; d.dest = rt; d.imm = simm; break;
    case 0x09: d.op = OP_ADDIU; d.src_a = rs; d.dest = rt; d.imm = simm; break;
    case 0x0A: d.op = OP_SLTI;  d.src_a = rs; d.dest = rt; d.imm = simm; break;
    case 0x0B: d.op = OP_SLTIU; d.src_a = rs; d.dest = rt; d.imm = simm; break;
    case 0x0C: d.op = OP_ANDI;  d.src_a = rs; d.dest = rt; d.imm = imm16; break;
    case 0x0D: d.op = OP_ORI;   d.src_a = rs; d.dest = rt; d.imm = imm16; break;
    case 0x0E: d.op = OP_XORI;  d.src_a = rs; d.dest = rt; d.imm = imm16; break;
    case 0x0F: if (rs == 0) { d.op = OP_LUI; d.dest = rt; d.imm = imm16 << 16; } break;
    case 0x1C: if (fn == 0x02 && sh == 0) { d.op = OP_MUL; d.src_a = rs; d.src_b = rt; d.dest = rd; } break;
    case 0x20: d.op = OP_LB;  d.src_a = rs; d.dest = rt; d.imm = simm; d.is_load = true; break;
    case 0x21: d.op = OP_LH;  d.src_a = rs; d.dest = rt; d.imm = simm; d.is_load = true; break;
    case 0x23: d.op = OP_LW;  d.src_a = rs; d.dest = rt; d.imm = simm; d.is_load = true; break;
    case 0x24: d.op = OP_LBU; d.src_a = rs; d.dest = rt; d.imm = simm; d.is_load = true; break;
    case 0x25: d.op = OP_LHU; d.src_a = rs; d.dest = rt; d.imm = simm; d.is_load = true; break;
    case 0x28: d.op = OP_SB; d.src_a = rs; d.src_b = rt; d.imm = simm; break;
    case 0x29: d.op = OP_SH; d.src_a = rs; d.src_b = rt; d.imm = simm; break;
    case 0x2B: d.op = OP_SW; d.src_a = rs; d.src_b = rt; d.imm = simm; break;
    case OP_AESENC: if (imm16 == 0) { d.op = I_AESENC; d.src_a = rs; d.src_b = rt; } break;
    case OP_AESDEC: if (imm16 == 0) { d.op = I_AESDEC; d.src_a = rs; d.src_b = rt; } break;
    default: break;
    }
    if (d.op == OP_ILLEGAL) { d.src_a = d.src_b = d.dest = 0; d.is_load = false; }
    return d;
}

// ---------------------------------------------------------------------------
// Pipeline registers
// ---------------------------------------------------------------------------
struct RegIfDc { bool v; uint32_t pc; };
struct RegDcId { bool v; uint32_t pc; uint32_t ins; uint8_t fault; };
struct RegIdEx { bool v; uint32_t pc; Decoded d; uint8_t fault; };
struct RegExMem { bool v; uint32_t pc; Decoded d; uint32_t res; uint32_t addr; uint32_t sdata;
                  uint8_t trap; bool halt; };
struct RegMemWb { bool v; uint32_t pc; uint8_t dest; uint32_t val; uint8_t trap; bool halt; };

void cpu_default_config(CpuConfig *cfg) {
    cfg->icache_lines = 8;
    cfg->mem_latency = 4;
    cfg->aes_latency = 11;
    cfg->encrypted = 1;
    cfg->max_cycles = 50000000ull;
}

const char *cpu_status_name(int s) {
    switch (s) {
    case ST_RUNNING: return "running";
    case ST_HALT: return "halt";
    case ST_TRAP_ILLEGAL: return "trap-illegal";
    case ST_TRAP_MEM: return "trap-mem";
    case ST_TRAP_FETCH: return "trap-fetch";
    case ST_TRAP_OVERFLOW: return "trap-overflow";
    case ST_TRAP_BREAK: return "trap-break";
    case ST_TIMEOUT: return "timeout";
    default: return "?";
    }
}

static inline bool dmem_index(uint32_t addr, uint32_t align, uint32_t *idx) {
    if (addr & (align - 1)) return false;
    if (addr < DATA_BASE || addr - DATA_BASE >= 4u * DMEM_WORDS) return false;
    *idx = (addr - DATA_BASE) >> 2;
    return true;
}

// ---------------------------------------------------------------------------
// Top
// ---------------------------------------------------------------------------
void cryptocpu_top(const uint32_t imem[IMEM_WORDS], uint32_t dmem[DMEM_WORDS],
                   const KeyRegisters *keys, const CpuConfig *cfg, CpuState *state,
                   CpuStats *stats) {
#pragma HLS INTERFACE mode=bram port=imem
#pragma HLS INTERFACE mode=bram port=dmem
#pragma HLS INTERFACE mode=s_axilite port=keys
#pragma HLS INTERFACE mode=s_axilite port=cfg
#pragma HLS INTERFACE mode=s_axilite port=state
#pragma HLS INTERFACE mode=s_axilite port=stats
#pragma HLS INTERFACE mode=s_axilite port=return

    // Key schedules are expanded once at reset and kept on chip.
    AesRoundKeys rk_code, rk_tweak, rk_data;
    aes128_expand_key(keys->k_code, &rk_code);
    aes128_expand_key(keys->k_tweak, &rk_tweak);
    aes128_expand_key(keys->k_data, &rk_data);

    uint32_t regs[32];
#pragma HLS ARRAY_PARTITION variable=regs complete
    for (int i = 0; i < 32; i++) regs[i] = 0;
    regs[29] = STACK_TOP;
    uint32_t hi = 0, lo = 0;

    // Decrypted-instruction cache: the only place plaintext instructions exist.
    bool ic_valid[ICACHE_MAX_LINES];
    uint32_t ic_tag[ICACHE_MAX_LINES];
    uint32_t ic_data[ICACHE_MAX_LINES][BLOCK_WORDS];
    int lines = cfg->icache_lines;
    if (lines < 1) lines = 1;
    if (lines > ICACHE_MAX_LINES) lines = ICACHE_MAX_LINES;
    for (int i = 0; i < ICACHE_MAX_LINES; i++) ic_valid[i] = false;

    const int miss_penalty = cfg->mem_latency + (cfg->encrypted ? cfg->aes_latency : 0);

    CpuStats st = {};
    RegIfDc r_ifdc = {false, 0};
    RegDcId r_dcid = {};
    RegIdEx r_idex = {};
    RegExMem r_exmem = {};
    RegMemWb r_memwb = {};
    uint32_t fetch_pc = TEXT_BASE;
    bool fetch_stop = false;
    int dc_busy = 0;            // cycles left on the current miss
    uint32_t dc_block = 0;      // block being fetched and decrypted
    int mem_hold = -1;          // aesenc/aesdec occupancy of the MEM stage
    int status = ST_TIMEOUT;
    uint32_t end_pc = 0;

    for (uint64_t cycle = 0; cycle < cfg->max_cycles; cycle++) {
        st.cycles++;

        // ------------------------------ WB ------------------------------
        if (r_memwb.v) {
            if (r_memwb.trap) { status = r_memwb.trap; end_pc = r_memwb.pc; break; }
            if (r_memwb.dest) regs[r_memwb.dest] = r_memwb.val;
            st.retired++;
            if (r_memwb.halt) { status = ST_HALT; end_pc = r_memwb.pc; break; }
        }
        regs[0] = 0;

        // ------------------------------ MEM -----------------------------
        RegMemWb n_memwb = {};
        bool stall_mem = false;
        bool kill_younger = false;
        if (r_exmem.v) {
            const RegExMem &m = r_exmem;
            n_memwb.v = true; n_memwb.pc = m.pc; n_memwb.dest = m.d.dest; n_memwb.val = m.res;
            n_memwb.trap = m.trap; n_memwb.halt = m.halt;
            if (!m.trap && !m.halt) {
                uint32_t idx;
                const uint32_t a = m.addr;
                switch (m.d.op) {
                case OP_LW:
                    if (dmem_index(a, 4, &idx)) n_memwb.val = dmem[idx]; else n_memwb.trap = ST_TRAP_MEM;
                    break;
                case OP_LH: case OP_LHU:
                    if (dmem_index(a & ~3u, 4, &idx) && !(a & 1)) {
                        uint32_t h = (dmem[idx] >> (8 * (a & 2))) & 0xffff;
                        n_memwb.val = (m.d.op == OP_LH) ? (uint32_t)(int32_t)(int16_t)h : h;
                    } else n_memwb.trap = ST_TRAP_MEM;
                    break;
                case OP_LB: case OP_LBU:
                    if (dmem_index(a & ~3u, 4, &idx)) {
                        uint32_t b = (dmem[idx] >> (8 * (a & 3))) & 0xff;
                        n_memwb.val = (m.d.op == OP_LB) ? (uint32_t)(int32_t)(int8_t)b : b;
                    } else n_memwb.trap = ST_TRAP_MEM;
                    break;
                case OP_SW:
                    if (dmem_index(a, 4, &idx)) dmem[idx] = m.sdata; else n_memwb.trap = ST_TRAP_MEM;
                    break;
                case OP_SH:
                    if (dmem_index(a & ~3u, 4, &idx) && !(a & 1)) {
                        uint32_t s = 8 * (a & 2);
                        dmem[idx] = (dmem[idx] & ~(0xffffu << s)) | ((m.sdata & 0xffff) << s);
                    } else n_memwb.trap = ST_TRAP_MEM;
                    break;
                case OP_SB:
                    if (dmem_index(a & ~3u, 4, &idx)) {
                        uint32_t s = 8 * (a & 3);
                        dmem[idx] = (dmem[idx] & ~(0xffu << s)) | ((m.sdata & 0xff) << s);
                    } else n_memwb.trap = ST_TRAP_MEM;
                    break;
                case I_AESENC: case I_AESDEC:
                    if (mem_hold < 0) {
                        uint32_t is, id;
                        // source = GPR[rs] (addr), destination = GPR[rt] (sdata); 16-byte blocks
                        if (dmem_index(a, 4, &is) && dmem_index(m.sdata, 4, &id) &&
                            is + 3 < DMEM_WORDS && id + 3 < DMEM_WORDS) {
                            uint32_t in[4], out[4];
                            for (int i = 0; i < 4; i++) in[i] = dmem[is + i];
                            if (m.d.op == I_AESENC) aes128_encrypt(&rk_data, in, out);
                            else aes128_decrypt(&rk_data, in, out);
                            for (int i = 0; i < 4; i++) dmem[id + i] = out[i];
                            mem_hold = cfg->aes_latency < 1 ? 1 : cfg->aes_latency;
                        } else {
                            n_memwb.trap = ST_TRAP_MEM;
                        }
                    }
                    if (!n_memwb.trap) {
                        if (mem_hold > 1) {
                            mem_hold--;
                            stall_mem = true;
                            st.stall_mem_aes++;
                            n_memwb.v = false;
                        } else {
                            mem_hold = -1;
                        }
                    }
                    break;
                default: break;
                }
            }
            if (n_memwb.trap || n_memwb.halt) kill_younger = true;
        }

        // ------------------------------ EX ------------------------------
        RegExMem n_exmem = {};
        bool ex_consumed = false;
        bool redirect = false;
        uint32_t redirect_pc = 0;
        if (stall_mem) {
            n_exmem = r_exmem;  // MEM holds its instruction
        } else if (kill_younger) {
            if (r_idex.v) st.flushed_instrs++;
            ex_consumed = true;
        } else {
            ex_consumed = true;
            if (r_idex.v) {
                const Decoded &d = r_idex.d;
                // Operand read with forwarding. The register file already holds
                // every value written by retired instructions (WB ran first), so
                // only the instruction now in MEM needs a bypass.
                uint32_t va = regs[d.src_a], vb = regs[d.src_b];
                if (r_exmem.v && !r_exmem.trap && r_exmem.d.dest && !r_exmem.d.is_load) {
                    if (d.src_a && r_exmem.d.dest == d.src_a) va = r_exmem.res;
                    if (d.src_b && r_exmem.d.dest == d.src_b) vb = r_exmem.res;
                }
                if (d.src_a == 0) va = 0;
                if (d.src_b == 0) vb = 0;

                RegExMem &x = n_exmem;
                x.v = true; x.pc = r_idex.pc; x.d = d; x.trap = 0; x.halt = false;
                const uint32_t pc4 = r_idex.pc + 4;
                uint32_t res = 0;
                bool taken = false;
                uint32_t tgt = 0;
                int32_t sa = (int32_t)va, sb = (int32_t)vb;
                switch (d.op) {
                case OP_SLL:  res = vb << d.shamt; break;
                case OP_SRL:  res = vb >> d.shamt; break;
                case OP_SRA:  res = (uint32_t)(sb >> d.shamt); break;
                case OP_SLLV: res = vb << (va & 31); break;
                case OP_SRLV: res = vb >> (va & 31); break;
                case OP_SRAV: res = (uint32_t)(sb >> (va & 31)); break;
                case OP_ADD: case OP_ADDI: {
                    uint32_t b2 = (d.op == OP_ADD) ? vb : d.imm;
                    res = va + b2;
                    if (((va ^ res) & (b2 ^ res)) >> 31) x.trap = ST_TRAP_OVERFLOW;
                    break;
                }
                case OP_ADDU: res = va + vb; break;
                case OP_ADDIU: res = va + d.imm; break;
                case OP_SUB:
                    res = va - vb;
                    if (((va ^ vb) & (va ^ res)) >> 31) x.trap = ST_TRAP_OVERFLOW;
                    break;
                case OP_SUBU: res = va - vb; break;
                case OP_AND:  res = va & vb; break;
                case OP_OR:   res = va | vb; break;
                case OP_XOR:  res = va ^ vb; break;
                case OP_NOR:  res = ~(va | vb); break;
                case OP_SLT:  res = sa < sb; break;
                case OP_SLTU: res = va < vb; break;
                case OP_SLTI: res = sa < (int32_t)d.imm; break;
                case OP_SLTIU: res = va < d.imm; break;
                case OP_ANDI: res = va & d.imm; break;
                case OP_ORI:  res = va | d.imm; break;
                case OP_XORI: res = va ^ d.imm; break;
                case OP_LUI:  res = d.imm; break;
                case OP_MUL:  res = (uint32_t)((int64_t)sa * (int64_t)sb); break;
                case OP_MULT: { int64_t p = (int64_t)sa * (int64_t)sb; lo = (uint32_t)p; hi = (uint32_t)((uint64_t)p >> 32); break; }
                case OP_MULTU: { uint64_t p = (uint64_t)va * (uint64_t)vb; lo = (uint32_t)p; hi = (uint32_t)(p >> 32); break; }
                case OP_DIV:
                    if (vb != 0 && !(va == 0x80000000u && vb == 0xffffffffu)) {
                        lo = (uint32_t)(sa / sb); hi = (uint32_t)(sa % sb);
                    } else if (vb != 0) { lo = 0x80000000u; hi = 0; }
                    break;  // division by zero leaves HI/LO unchanged
                case OP_DIVU: if (vb != 0) { lo = va / vb; hi = va % vb; } break;
                case OP_MFHI: res = hi; break;
                case OP_MFLO: res = lo; break;
                case OP_MTHI: hi = va; break;
                case OP_MTLO: lo = va; break;
                case OP_BEQ:  taken = va == vb; tgt = pc4 + (d.imm << 2); break;
                case OP_BNE:  taken = va != vb; tgt = pc4 + (d.imm << 2); break;
                case OP_BLEZ: taken = sa <= 0; tgt = pc4 + (d.imm << 2); break;
                case OP_BGTZ: taken = sa > 0;  tgt = pc4 + (d.imm << 2); break;
                case OP_BLTZ: taken = sa < 0;  tgt = pc4 + (d.imm << 2); break;
                case OP_BGEZ: taken = sa >= 0; tgt = pc4 + (d.imm << 2); break;
                case OP_J:    taken = true; tgt = (pc4 & 0xf0000000u) | (d.target << 2); break;
                case OP_JAL:  taken = true; tgt = (pc4 & 0xf0000000u) | (d.target << 2); res = pc4; break;
                case OP_JR:   taken = true; tgt = va; break;
                case OP_JALR: taken = true; tgt = va; res = pc4; break;
                case OP_LB: case OP_LH: case OP_LW: case OP_LBU: case OP_LHU:
                case OP_SB: case OP_SH: case OP_SW:
                    x.addr = va + d.imm; x.sdata = vb; break;
                case I_AESENC: case I_AESDEC:
                    x.addr = va; x.sdata = vb; break;
                case OP_SYSCALL:
                    if (va == 10 || va == 17) x.halt = true;  // MARS exit services
                    break;
                case OP_BREAK: x.trap = ST_TRAP_BREAK; break;
                case OP_ILLEGAL: default:
                    x.trap = r_idex.fault ? r_idex.fault : ST_TRAP_ILLEGAL; break;
                }
                if (r_idex.fault) x.trap = r_idex.fault;
                x.res = res;
                if (x.trap || x.halt) {
                    x.d.dest = 0;
                    kill_younger = true;
                } else if (taken) {
                    // Predicted not taken: redirect only if the next fetched PC differs.
                    redirect = true;
                    redirect_pc = tgt;
                }
            }
        }

        // ------------------------------ ID ------------------------------
        RegIdEx n_idex = r_idex;
        bool id_consumed = false;
        if (stall_mem) {
            // hold
        } else if (kill_younger) {
            n_idex.v = false;
            if (r_dcid.v) st.flushed_instrs++;
            id_consumed = true;
        } else {
            n_idex.v = false;
            if (r_dcid.v) {
                Decoded d = decode(r_dcid.ins);
                // Load-use hazard: the instruction now in EX is a load whose result
                // this instruction needs; insert one bubble.
                bool hazard = r_idex.v && r_idex.d.is_load && r_idex.d.dest &&
                              (r_idex.d.dest == d.src_a || r_idex.d.dest == d.src_b);
                if (hazard) {
                    st.stall_load_use++;
                } else {
                    n_idex.v = true; n_idex.pc = r_dcid.pc; n_idex.d = d; n_idex.fault = r_dcid.fault;
                    id_consumed = true;
                }
            } else {
                id_consumed = true;
            }
        }

        // ------------------------------ DC ------------------------------
        RegDcId n_dcid = r_dcid;
        bool dc_consumed = false;
        if (dc_busy > 0) {
            dc_busy--;
            st.stall_fetch++;
            if (dc_busy == 0) {
                // Fill the line: read the ciphertext block and decrypt it on chip.
                const uint32_t base = dc_block * BLOCK_WORDS;
                uint32_t blk[4];
                if (cfg->encrypted) {
                    uint32_t c[4] = {imem[base], imem[base + 1], imem[base + 2], imem[base + 3]};
                    xex_decrypt_block(&rk_code, &rk_tweak, keys->nonce, dc_block, c, blk);
                    st.blocks_decrypted++;
                } else {
                    for (int i = 0; i < 4; i++) blk[i] = imem[base + i];
                }
                const int line = (int)(dc_block & (uint32_t)(lines - 1));
                for (int i = 0; i < 4; i++) ic_data[line][i] = blk[i];
                ic_tag[line] = dc_block;
                ic_valid[line] = true;
            }
        }
        if (!stall_mem && !kill_younger && id_consumed) {
            n_dcid.v = false;
            if (r_ifdc.v && dc_busy == 0) {
                const uint32_t pc = r_ifdc.pc;
                if ((pc & 3) || pc < TEXT_BASE || pc - TEXT_BASE >= 4u * IMEM_WORDS) {
                    n_dcid.v = true; n_dcid.pc = pc; n_dcid.ins = 0; n_dcid.fault = ST_TRAP_FETCH;
                    dc_consumed = true;
                } else {
                    const uint32_t widx = (pc - TEXT_BASE) >> 2;
                    const uint32_t blk = widx / BLOCK_WORDS;
                    const int line = (int)(blk & (uint32_t)(lines - 1));
                    if (ic_valid[line] && ic_tag[line] == blk) {
                        st.icache_hits++;
                        n_dcid.v = true; n_dcid.pc = pc;
                        n_dcid.ins = ic_data[line][widx % BLOCK_WORDS]; n_dcid.fault = 0;
                        dc_consumed = true;
                    } else {
                        st.icache_misses++;
                        dc_block = blk;
                        dc_busy = miss_penalty;
                        if (dc_busy == 0) dc_busy = 1;  // at least one cycle to fill
                    }
                }
            } else if (!r_ifdc.v) {
                dc_consumed = true;
            }
        } else if (kill_younger) {
            if (r_ifdc.v) st.flushed_instrs++;
            n_dcid.v = false;
        }

        // ------------------------------ IF ------------------------------
        RegIfDc n_ifdc = r_ifdc;
        if (kill_younger) {
            n_ifdc.v = false;
            fetch_stop = true;
            if (dc_busy > 0) st.misses_cancelled++;
            dc_busy = 0;
        } else if (!stall_mem && dc_consumed) {
            n_ifdc.v = false;
            if (!fetch_stop) {
                n_ifdc.v = true;
                n_ifdc.pc = fetch_pc;
                fetch_pc += 4;
            }
        }

        // --------------------------- redirect ---------------------------
        if (redirect && !kill_younger) {
            st.flushes++;
            if (n_idex.v) st.flushed_instrs++;
            if (n_dcid.v) st.flushed_instrs++;
            if (n_ifdc.v) st.flushed_instrs++;
            n_idex.v = false;
            n_dcid.v = false;
            n_ifdc.v = false;
            fetch_pc = redirect_pc;
            if (dc_busy > 0) st.misses_cancelled++;
            dc_busy = 0;  // abandon a wrong-path miss
        }
        (void)ex_consumed;

        r_memwb = n_memwb;
        r_exmem = n_exmem;
        r_idex = n_idex;
        r_dcid = n_dcid;
        r_ifdc = n_ifdc;
    }

    for (int i = 0; i < 32; i++) state->regs[i] = regs[i];
    state->hi = hi;
    state->lo = lo;
    state->pc = end_pc;
    state->status = status;
    *stats = st;
}
