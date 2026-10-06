// Golden reference interpreter (see isa_ref.h). Deliberately simple: fetch,
// decode by opcode/funct, execute, repeat.
#include "isa_ref.h"
#include "../src/cryptocpu.h"

namespace {

struct Machine {
    uint32_t r[32];
    uint32_t hi, lo, pc;
    uint32_t *mem;
};

bool word_index(uint32_t addr, uint32_t *i) {
    if (addr % 4 != 0) return false;
    if (addr < DATA_BASE) return false;
    uint32_t off = addr - DATA_BASE;
    if (off >= 4u * DMEM_WORDS) return false;
    *i = off / 4;
    return true;
}

int32_t sext16(uint32_t v) { return (int32_t)(int16_t)(v & 0xffff); }

}  // namespace

void ref_run(const uint32_t *text, int n, uint32_t *dmem, const uint32_t k_data[4],
             uint64_t max_steps, RefResult *out) {
    Machine m = {};
    m.r[29] = STACK_TOP;
    m.pc = TEXT_BASE;
    m.mem = dmem;
    AesRoundKeys kd;
    aes128_expand_key(k_data, &kd);
    int status = ST_TIMEOUT;
    uint64_t retired = 0;
    uint32_t end_pc = 0;

    for (uint64_t step = 0; step < max_steps; step++) {
        const uint32_t pc = m.pc;
        if (pc % 4 != 0 || pc < TEXT_BASE || (pc - TEXT_BASE) / 4 >= (uint32_t)IMEM_WORDS) {
            status = ST_TRAP_FETCH; end_pc = pc; break;
        }
        const uint32_t idx = (pc - TEXT_BASE) / 4;
        const uint32_t ins = idx < (uint32_t)n ? text[idx] : 0u;  // unused memory reads as nop
        const uint32_t op = ins >> 26, rs = (ins >> 21) & 31, rt = (ins >> 16) & 31;
        const uint32_t rd = (ins >> 11) & 31, sh = (ins >> 6) & 31, fn = ins & 63;
        const uint32_t imm = ins & 0xffff;
        const uint32_t A = m.r[rs], B = m.r[rt];
        uint32_t next = pc + 4;
        int fault = 0;
        bool halt = false;
        // destination register and value, written at the end if no fault
        int wreg = -1;
        uint32_t wval = 0;

        if (op == 0) {
            if (fn == 0 && rs == 0) { wreg = rd; wval = B << sh; }
            else if (fn == 2 && rs == 0) { wreg = rd; wval = B >> sh; }
            else if (fn == 3 && rs == 0) { wreg = rd; wval = (uint32_t)((int32_t)B >> sh); }
            else if (fn == 4 && sh == 0) { wreg = rd; wval = B << (A % 32); }
            else if (fn == 6 && sh == 0) { wreg = rd; wval = B >> (A % 32); }
            else if (fn == 7 && sh == 0) { wreg = rd; wval = (uint32_t)((int32_t)B >> (A % 32)); }
            else if (fn == 8 && rt == 0 && rd == 0 && sh == 0) { next = A; }
            else if (fn == 9 && rt == 0 && sh == 0) { wreg = rd; wval = pc + 4; next = A; }
            else if (fn == 12) { if (m.r[2] == 10 || m.r[2] == 17) halt = true; }
            else if (fn == 13) { fault = ST_TRAP_BREAK; }
            else if (fn == 16 && rs == 0 && rt == 0 && sh == 0) { wreg = rd; wval = m.hi; }
            else if (fn == 17 && rt == 0 && rd == 0 && sh == 0) { m.hi = A; }
            else if (fn == 18 && rs == 0 && rt == 0 && sh == 0) { wreg = rd; wval = m.lo; }
            else if (fn == 19 && rt == 0 && rd == 0 && sh == 0) { m.lo = A; }
            else if (fn == 24 && rd == 0 && sh == 0) {
                int64_t p = (int64_t)(int32_t)A * (int64_t)(int32_t)B;
                m.lo = (uint32_t)(p & 0xffffffff); m.hi = (uint32_t)((p >> 32) & 0xffffffff);
            } else if (fn == 25 && rd == 0 && sh == 0) {
                uint64_t p = (uint64_t)A * (uint64_t)B;
                m.lo = (uint32_t)p; m.hi = (uint32_t)(p >> 32);
            } else if (fn == 26 && rd == 0 && sh == 0) {
                if (B != 0) {
                    int64_t q = (int64_t)(int32_t)A / (int64_t)(int32_t)B;  // 64-bit avoids overflow
                    int64_t rr = (int64_t)(int32_t)A % (int64_t)(int32_t)B;
                    m.lo = (uint32_t)q; m.hi = (uint32_t)rr;
                }
            } else if (fn == 27 && rd == 0 && sh == 0) {
                if (B != 0) { m.lo = A / B; m.hi = A % B; }
            } else if (sh == 0 && fn == 32) {
                uint32_t s = A + B;
                if ((int64_t)(int32_t)A + (int64_t)(int32_t)B != (int64_t)(int32_t)s) fault = ST_TRAP_OVERFLOW;
                wreg = rd; wval = s;
            } else if (sh == 0 && fn == 33) { wreg = rd; wval = A + B; }
            else if (sh == 0 && fn == 34) {
                uint32_t s = A - B;
                if ((int64_t)(int32_t)A - (int64_t)(int32_t)B != (int64_t)(int32_t)s) fault = ST_TRAP_OVERFLOW;
                wreg = rd; wval = s;
            } else if (sh == 0 && fn == 35) { wreg = rd; wval = A - B; }
            else if (sh == 0 && fn == 36) { wreg = rd; wval = A & B; }
            else if (sh == 0 && fn == 37) { wreg = rd; wval = A | B; }
            else if (sh == 0 && fn == 38) { wreg = rd; wval = A ^ B; }
            else if (sh == 0 && fn == 39) { wreg = rd; wval = ~(A | B); }
            else if (sh == 0 && fn == 42) { wreg = rd; wval = (int32_t)A < (int32_t)B ? 1 : 0; }
            else if (sh == 0 && fn == 43) { wreg = rd; wval = A < B ? 1 : 0; }
            else fault = ST_TRAP_ILLEGAL;
        } else if (op == 1 && (rt == 0 || rt == 1)) {
            bool t = (rt == 0) ? ((int32_t)A < 0) : ((int32_t)A >= 0);
            if (t) next = pc + 4 + (uint32_t)(sext16(imm) * 4);
        } else if (op == 2 || op == 3) {
            if (op == 3) { wreg = 31; wval = pc + 4; }
            next = ((pc + 4) & 0xf0000000u) | ((ins & 0x03ffffff) << 2);
        } else if (op == 4 || op == 5) {
            bool eq = (A == B);
            if ((op == 4) == eq) next = pc + 4 + (uint32_t)(sext16(imm) * 4);
        } else if ((op == 6 || op == 7) && rt == 0) {
            bool t = (op == 6) ? ((int32_t)A <= 0) : ((int32_t)A > 0);
            if (t) next = pc + 4 + (uint32_t)(sext16(imm) * 4);
        } else if (op == 8) {
            uint32_t s = A + (uint32_t)sext16(imm);
            if ((int64_t)(int32_t)A + sext16(imm) != (int64_t)(int32_t)s) fault = ST_TRAP_OVERFLOW;
            wreg = rt; wval = s;
        } else if (op == 9) { wreg = rt; wval = A + (uint32_t)sext16(imm); }
        else if (op == 10) { wreg = rt; wval = (int32_t)A < sext16(imm) ? 1 : 0; }
        else if (op == 11) { wreg = rt; wval = A < (uint32_t)sext16(imm) ? 1 : 0; }
        else if (op == 12) { wreg = rt; wval = A & imm; }
        else if (op == 13) { wreg = rt; wval = A | imm; }
        else if (op == 14) { wreg = rt; wval = A ^ imm; }
        else if (op == 15 && rs == 0) { wreg = rt; wval = imm << 16; }
        else if (op == 28 && fn == 2 && sh == 0) {
            wreg = rd; wval = (uint32_t)((int64_t)(int32_t)A * (int64_t)(int32_t)B);
        } else if (op == 32 || op == 33 || op == 35 || op == 36 || op == 37) {
            uint32_t addr = A + (uint32_t)sext16(imm), wi;
            uint32_t size = (op == 35) ? 4 : (op == 33 || op == 37) ? 2 : 1;
            if (addr % size != 0 || !word_index(addr - addr % 4, &wi)) {
                fault = ST_TRAP_MEM;
            } else {
                uint32_t w = m.mem[wi], shift = 8 * (addr % 4);
                uint32_t v;
                if (size == 4) v = w;
                else if (size == 2) v = (w >> shift) & 0xffff;
                else v = (w >> shift) & 0xff;
                if (op == 32) v = (uint32_t)(int32_t)(int8_t)v;
                if (op == 33) v = (uint32_t)(int32_t)(int16_t)v;
                wreg = rt; wval = v;
            }
        } else if (op == 40 || op == 41 || op == 43) {
            uint32_t addr = A + (uint32_t)sext16(imm), wi;
            uint32_t size = (op == 43) ? 4 : (op == 41) ? 2 : 1;
            if (addr % size != 0 || !word_index(addr - addr % 4, &wi)) {
                fault = ST_TRAP_MEM;
            } else if (size == 4) {
                m.mem[wi] = B;
            } else {
                uint32_t shift = 8 * (addr % 4);
                uint32_t mask = (size == 2 ? 0xffffu : 0xffu) << shift;
                m.mem[wi] = (m.mem[wi] & ~mask) | ((B << shift) & mask);
            }
        } else if ((op == OP_AESENC || op == OP_AESDEC) && imm == 0) {
            uint32_t s, d;
            if (!word_index(A, &s) || !word_index(B, &d) || s + 3 >= (uint32_t)DMEM_WORDS ||
                d + 3 >= (uint32_t)DMEM_WORDS) {
                fault = ST_TRAP_MEM;
            } else {
                uint32_t in[4] = {m.mem[s], m.mem[s + 1], m.mem[s + 2], m.mem[s + 3]}, o[4];
                if (op == OP_AESENC) aes128_encrypt(&kd, in, o); else aes128_decrypt(&kd, in, o);
                for (int i = 0; i < 4; i++) m.mem[d + i] = o[i];
            }
        } else {
            fault = ST_TRAP_ILLEGAL;
        }

        if (fault) { status = fault; end_pc = pc; break; }
        if (wreg > 0) m.r[wreg] = wval;
        retired++;
        if (halt) { status = ST_HALT; end_pc = pc; break; }
        m.pc = next;
    }

    for (int i = 0; i < 32; i++) out->regs[i] = m.r[i];
    out->hi = m.hi;
    out->lo = m.lo;
    out->pc = end_pc;
    out->status = status;
    out->retired = retired;
}
