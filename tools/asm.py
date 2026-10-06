#!/usr/bin/env python3
"""Two-pass assembler for the CryptoCPU ISA (a MIPS32 subset in MARS syntax).

Produces standard MIPS32 encodings with the MARS default memory map
(.text at 0x00400000, .data at 0x10010000), so the same source also assembles
and runs in MARS. Branches have no delay slot (MARS default).

    python tools/asm.py prog.s -o out_dir

writes out_dir/text.hex (plaintext instructions, one word per line),
out_dir/data.hex (initial data memory) and out_dir/symbols.txt.
"""
import argparse
import re
import sys
from pathlib import Path

TEXT_BASE = 0x00400000
DATA_BASE = 0x10010000

REG_NAMES = ["zero", "at", "v0", "v1", "a0", "a1", "a2", "a3",
             "t0", "t1", "t2", "t3", "t4", "t5", "t6", "t7",
             "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7",
             "t8", "t9", "k0", "k1", "gp", "sp", "fp", "ra"]
REGS = {f"${n}": i for i, n in enumerate(REG_NAMES)}
REGS.update({f"${i}": i for i in range(32)})
REGS["$s8"] = 30

R_ALU = {"add": 0x20, "addu": 0x21, "sub": 0x22, "subu": 0x23, "and": 0x24, "or": 0x25,
         "xor": 0x26, "nor": 0x27, "slt": 0x2A, "sltu": 0x2B}
SHIFT_IMM = {"sll": 0x00, "srl": 0x02, "sra": 0x03}
SHIFT_VAR = {"sllv": 0x04, "srlv": 0x06, "srav": 0x07}
MULDIV = {"mult": 0x18, "multu": 0x19, "div": 0x1A, "divu": 0x1B}
I_ALU = {"addi": 0x08, "addiu": 0x09, "slti": 0x0A, "sltiu": 0x0B, "andi": 0x0C, "ori": 0x0D,
         "xori": 0x0E}
ZERO_EXT = {"andi", "ori", "xori"}
MEMOPS = {"lb": 0x20, "lh": 0x21, "lw": 0x23, "lbu": 0x24, "lhu": 0x25, "sb": 0x28, "sh": 0x29,
          "sw": 0x2B}
CUSTOM = {"aesenc": 0x3A, "aesdec": 0x3B}


class AsmError(Exception):
    pass


def parse_int(tok):
    tok = tok.strip()
    if len(tok) == 3 and tok[0] == tok[2] == "'":
        return ord(tok[1])
    return int(tok, 0)


def is_int(tok):
    try:
        parse_int(tok)
        return True
    except ValueError:
        return False


def reg(tok, line):
    tok = tok.strip()
    if tok not in REGS:
        raise AsmError(f"line {line}: bad register '{tok}'")
    return REGS[tok]


def split_operands(s):
    return [p.strip() for p in s.split(",")] if s.strip() else []


def strip_comment(s):
    out, in_str = [], False
    for ch in s:
        if ch == '"':
            in_str = not in_str
        if ch == "#" and not in_str:
            break
        out.append(ch)
    return "".join(out)


def r_type(rs, rt, rd, sh, fn):
    return (rs << 21) | (rt << 16) | (rd << 11) | (sh << 6) | fn


def i_type(op, rs, rt, imm):
    return (op << 26) | (rs << 21) | (rt << 16) | (imm & 0xFFFF)


def fits_s16(v):
    return -32768 <= v <= 32767


def fits_u16(v):
    return 0 <= v <= 0xFFFF


def expand(mn, ops, line, value_of):
    """Return a list of (mnemonic, operands) real instructions.

    value_of(tok) resolves an integer or a label; during pass 1 labels resolve
    to None and only the instruction count matters.
    """
    if mn == "nop":
        return [("sll", ["$zero", "$zero", "0"])]
    if mn == "move":
        return [("addu", [ops[0], ops[1], "$zero"])]
    if mn == "li":
        v = parse_int(ops[1])
        if fits_s16(v):
            return [("addiu", [ops[0], "$zero", str(v)])]
        if fits_u16(v):
            return [("ori", [ops[0], "$zero", str(v)])]
        v &= 0xFFFFFFFF
        return [("lui", [ops[0], str(v >> 16)]), ("ori", [ops[0], ops[0], str(v & 0xFFFF)])]
    if mn == "la":
        return [("lui", [ops[0], f"%hi({ops[1]})"]), ("ori", [ops[0], ops[0], f"%lo({ops[1]})"])]
    if mn == "b":
        return [("beq", ["$zero", "$zero", ops[0]])]
    if mn == "beqz":
        return [("beq", [ops[0], "$zero", ops[1]])]
    if mn == "bnez":
        return [("bne", [ops[0], "$zero", ops[1]])]
    if mn in ("blt", "bge", "bgt", "ble", "bltu", "bgeu", "bgtu", "bleu"):
        a, b, lab = ops
        unsigned = mn.endswith("u")
        base = mn[:-1] if unsigned else mn
        slt = "sltu" if unsigned else "slt"
        if base in ("blt", "bge"):
            cmp_ = (slt, ["$at", a, b])
        else:
            cmp_ = (slt, ["$at", b, a])
        br = "bne" if base in ("blt", "bgt") else "beq"
        return [cmp_, (br, ["$at", "$zero", lab])]
    if mn == "neg":
        return [("sub", [ops[0], "$zero", ops[1]])]
    if mn == "negu":
        return [("subu", [ops[0], "$zero", ops[1]])]
    if mn == "not":
        return [("nor", [ops[0], ops[1], "$zero"])]
    if mn == "subi":
        return [("addi", [ops[0], ops[1], str(-parse_int(ops[2]))])]
    if mn == "mul" and len(ops) == 3 and not ops[2].startswith("$"):
        raise AsmError(f"line {line}: mul with an immediate is not supported")
    return [(mn, ops)]


def assemble(src):
    lines = src.splitlines()
    # ---- pass 1: sizes and labels --------------------------------------
    labels = {}
    seg = "text"
    text_items, data_bytes = [], bytearray()
    pc = TEXT_BASE
    for ln, raw in enumerate(lines, 1):
        s = strip_comment(raw).strip()
        while True:
            mlab = re.match(r"^([A-Za-z_.$][\w.$]*)\s*:\s*(.*)$", s)
            if not mlab:
                break
            name = mlab.group(1)
            if name in labels:
                raise AsmError(f"line {ln}: duplicate label '{name}'")
            labels[name] = pc if seg == "text" else DATA_BASE + len(data_bytes)
            s = mlab.group(2).strip()
        if not s:
            continue
        if s.startswith("."):
            parts = s.split(None, 1)
            d, rest = parts[0], parts[1] if len(parts) > 1 else ""
            if d == ".text":
                seg = "text"
            elif d == ".data":
                seg = "data"
            elif d in (".globl", ".globl", ".global", ".extern", ".ent", ".end", ".set"):
                pass
            elif seg != "data":
                raise AsmError(f"line {ln}: directive {d} only allowed in .data")
            elif d == ".align":
                a = 1 << parse_int(rest)
                while len(data_bytes) % a:
                    data_bytes.append(0)
            elif d == ".space":
                data_bytes.extend(b"\0" * parse_int(rest))
            elif d in (".word", ".half", ".byte"):
                size = {".word": 4, ".half": 2, ".byte": 1}[d]
                while len(data_bytes) % size:
                    data_bytes.append(0)
                for tok in split_operands(rest):
                    if ":" in tok and is_int(tok.split(":")[0]):
                        v, cnt = tok.split(":")
                        items = [v] * parse_int(cnt)
                    else:
                        items = [tok]
                    for it in items:
                        data_bytes.extend(b"\0" * size)
                        text_items.append(("data", len(data_bytes) - size, size, it, ln))
            elif d in (".asciiz", ".ascii"):
                m = re.match(r'^"(.*)"$', rest.strip())
                if not m:
                    raise AsmError(f"line {ln}: bad string")
                bs = bytes(m.group(1), "utf-8").decode("unicode_escape").encode("latin-1")
                data_bytes.extend(bs + (b"\0" if d == ".asciiz" else b""))
            else:
                raise AsmError(f"line {ln}: unknown directive {d}")
            continue
        if seg != "text":
            raise AsmError(f"line {ln}: instruction in .data")
        parts = s.split(None, 1)
        mn = parts[0].lower()
        ops = split_operands(parts[1] if len(parts) > 1 else "")
        for real in expand(mn, ops, ln, None):
            text_items.append(("ins", pc, real[0], real[1], ln))
            pc += 4

    def value(tok, ln):
        tok = tok.strip()
        m = re.match(r"^%(hi|lo)\((.+)\)$", tok)
        if m:
            v = value(m.group(2), ln) & 0xFFFFFFFF
            return (v >> 16) if m.group(1) == "hi" else (v & 0xFFFF)
        m = re.match(r"^([A-Za-z_.$][\w.$]*)\s*([+-]\s*\w+)?$", tok)
        if m and m.group(1) in labels:
            off = parse_int(m.group(2).replace(" ", "")) if m.group(2) else 0
            return labels[m.group(1)] + off
        if is_int(tok):
            return parse_int(tok)
        raise AsmError(f"line {ln}: unknown symbol '{tok}'")

    # ---- pass 2: encode -------------------------------------------------
    words = []
    for item in text_items:
        if item[0] == "data":
            _, off, size, tok, ln = item
            v = value(tok, ln) & ((1 << (8 * size)) - 1)
            data_bytes[off:off + size] = v.to_bytes(size, "little")
            continue
        _, pc, mn, ops, ln = item
        words.append(encode(mn, ops, pc, ln, value))
    while len(data_bytes) % 4:
        data_bytes.append(0)
    data_words = [int.from_bytes(data_bytes[i:i + 4], "little") for i in range(0, len(data_bytes), 4)]
    return words, data_words, labels


def encode(mn, ops, pc, ln, value):
    def need(n):
        if len(ops) != n:
            raise AsmError(f"line {ln}: '{mn}' expects {n} operands")

    def imm16(tok, signed=True):
        v = value(tok, ln)
        if signed and not fits_s16(v) and not fits_u16(v):
            raise AsmError(f"line {ln}: immediate {v} out of range")
        if not signed and not fits_u16(v) and not fits_s16(v):
            raise AsmError(f"line {ln}: immediate {v} out of range")
        return v & 0xFFFF

    def branch_off(tok):
        tgt = value(tok, ln)
        off = (tgt - (pc + 4)) >> 2
        if not fits_s16(off):
            raise AsmError(f"line {ln}: branch target too far")
        return off & 0xFFFF

    if mn in R_ALU:
        need(3)
        return r_type(reg(ops[1], ln), reg(ops[2], ln), reg(ops[0], ln), 0, R_ALU[mn])
    if mn in SHIFT_IMM:
        need(3)
        sh = value(ops[2], ln)
        if not 0 <= sh < 32:
            raise AsmError(f"line {ln}: shift amount out of range")
        return r_type(0, reg(ops[1], ln), reg(ops[0], ln), sh, SHIFT_IMM[mn])
    if mn in SHIFT_VAR:
        need(3)
        return r_type(reg(ops[2], ln), reg(ops[1], ln), reg(ops[0], ln), 0, SHIFT_VAR[mn])
    if mn in MULDIV:
        need(2)
        return r_type(reg(ops[0], ln), reg(ops[1], ln), 0, 0, MULDIV[mn])
    if mn == "mul":
        need(3)
        return (0x1C << 26) | r_type(reg(ops[1], ln), reg(ops[2], ln), reg(ops[0], ln), 0, 0x02)
    if mn in ("mfhi", "mflo"):
        need(1)
        return r_type(0, 0, reg(ops[0], ln), 0, 0x10 if mn == "mfhi" else 0x12)
    if mn in ("mthi", "mtlo"):
        need(1)
        return r_type(reg(ops[0], ln), 0, 0, 0, 0x11 if mn == "mthi" else 0x13)
    if mn == "jr":
        need(1)
        return r_type(reg(ops[0], ln), 0, 0, 0, 0x08)
    if mn == "jalr":
        if len(ops) == 1:
            return r_type(reg(ops[0], ln), 0, 31, 0, 0x09)
        need(2)
        return r_type(reg(ops[1], ln), 0, reg(ops[0], ln), 0, 0x09)
    if mn == "syscall":
        return 0x0000000C
    if mn == "break":
        return 0x0000000D
    if mn in I_ALU:
        need(3)
        return i_type(I_ALU[mn], reg(ops[1], ln), reg(ops[0], ln), imm16(ops[2], mn not in ZERO_EXT))
    if mn == "lui":
        need(2)
        return i_type(0x0F, 0, reg(ops[0], ln), imm16(ops[1], False))
    if mn in MEMOPS:
        need(2)
        m = re.match(r"^(.*)\((\$\w+)\)$", ops[1].replace(" ", ""))
        if m:
            off = value(m.group(1), ln) if m.group(1) else 0
            base = reg(m.group(2), ln)
        else:
            raise AsmError(f"line {ln}: expected offset($reg)")
        if not fits_s16(off):
            raise AsmError(f"line {ln}: offset out of range")
        return i_type(MEMOPS[mn], base, reg(ops[0], ln), off)
    if mn in ("beq", "bne"):
        need(3)
        return i_type(0x04 if mn == "beq" else 0x05, reg(ops[0], ln), reg(ops[1], ln), branch_off(ops[2]))
    if mn in ("blez", "bgtz"):
        need(2)
        return i_type(0x06 if mn == "blez" else 0x07, reg(ops[0], ln), 0, branch_off(ops[1]))
    if mn in ("bltz", "bgez"):
        need(2)
        return i_type(0x01, reg(ops[0], ln), 0 if mn == "bltz" else 1, branch_off(ops[1]))
    if mn in ("j", "jal"):
        need(1)
        tgt = value(ops[0], ln)
        if (tgt & 0xF0000000) != ((pc + 4) & 0xF0000000):
            raise AsmError(f"line {ln}: jump target outside the 256 MiB region")
        return ((0x02 if mn == "j" else 0x03) << 26) | ((tgt >> 2) & 0x03FFFFFF)
    if mn in CUSTOM:
        need(2)  # aesenc $rt(dst addr), $rs(src addr)
        return i_type(CUSTOM[mn], reg(ops[1], ln), reg(ops[0], ln), 0)
    raise AsmError(f"line {ln}: unknown instruction '{mn}'")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("source")
    ap.add_argument("-o", "--out", required=True, help="output directory")
    a = ap.parse_args()
    try:
        words, data, labels = assemble(Path(a.source).read_text(encoding="utf-8"))
    except AsmError as e:
        sys.exit(f"{a.source}: {e}")
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "text.hex").write_text("".join(f"{w:08x}\n" for w in words))
    (out / "data.hex").write_text("".join(f"{w:08x}\n" for w in data))
    (out / "symbols.txt").write_text("".join(f"{k} {v:08x}\n" for k, v in sorted(labels.items(), key=lambda x: x[1])))
    print(f"{a.source}: {len(words)} instructions, {len(data)} data words")


if __name__ == "__main__":
    main()
