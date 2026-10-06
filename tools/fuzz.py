#!/usr/bin/env python3
"""Random differential testing of the core against the golden reference.

Generates random programs that mix every instruction class (ALU, shifts,
multiply/divide with HI/LO, byte/half/word loads and stores, forward
branches, counted loops, calls to leaf functions, aesenc/aesdec), with dense
register dependencies so that forwarding, load-use stalls and flushes are
exercised. A small fraction of programs trap (overflow, misaligned access),
which checks precise exceptions. Every program runs under several
micro-architecture configurations; each run must match the reference exactly.

    python tools/fuzz.py --count 300 --seed 1
"""
import argparse
import random
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import asm  # noqa: E402
from run_tests import find_tb  # noqa: E402

POOL = ["$t0", "$t1", "$t2", "$t3", "$t4", "$t5", "$t6", "$t7", "$t8", "$t9",
        "$s0", "$s1", "$s2", "$s3", "$s4", "$s5", "$s6", "$v1", "$a0", "$a1"]
CONFIGS = [
    [],                                   # paper design point
    ["--icache", "1"],                    # one decrypted line: constant misses
    ["--aes", "1", "--mem", "1"],         # minimal latencies
    ["--plain"],                          # no encryption
    ["--icache", "64", "--aes", "20", "--mem", "9"],
]


class Gen:
    def __init__(self, rng, allow_traps):
        self.r = rng
        self.allow_traps = allow_traps
        self.lines = []
        self.label_id = 0

    def reg(self):
        return self.r.choice(POOL)

    def label(self):
        self.label_id += 1
        return f"L{self.label_id}"

    def emit(self, s):
        self.lines.append("        " + s)

    def op(self):
        r = self.r
        k = r.random()
        d, a, b = self.reg(), self.reg(), self.reg()
        if k < 0.30:
            mn = r.choice(["addu", "subu", "and", "or", "xor", "nor", "slt", "sltu", "sllv", "srlv", "srav"])
            if self.allow_traps and r.random() < 0.02:
                mn = r.choice(["add", "sub"])
            self.emit(f"{mn} {d}, {a}, {b}")
        elif k < 0.40:
            self.emit(f"{r.choice(['sll', 'srl', 'sra'])} {d}, {a}, {r.randrange(32)}")
        elif k < 0.55:
            mn = r.choice(["addiu", "andi", "ori", "xori", "slti", "sltiu", "lui"])
            if mn == "lui":
                self.emit(f"lui {d}, {r.randrange(65536)}")
            elif mn in ("andi", "ori", "xori"):
                self.emit(f"{mn} {d}, {a}, {r.randrange(65536)}")
            else:
                if self.allow_traps and r.random() < 0.02:
                    mn = "addi"
                self.emit(f"{mn} {d}, {a}, {r.randrange(-32768, 32768)}")
        elif k < 0.62:
            c = r.random()
            if c < 0.3:
                self.emit(f"mul {d}, {a}, {b}")
            elif c < 0.8:
                self.emit(f"{r.choice(['mult', 'multu', 'div', 'divu'])} {a}, {b}")
                self.emit(f"{r.choice(['mfhi', 'mflo'])} {d}")
            else:
                self.emit(f"{r.choice(['mthi', 'mtlo'])} {a}")
        elif k < 0.80:
            self.mem(d, a)
        elif k < 0.88:
            self.branch()
        elif k < 0.92:
            self.emit(f"jal leaf{r.randrange(3)}")
        elif k < 0.95:
            off = 16 * r.randrange(32)
            off2 = 16 * r.randrange(32)
            self.emit(f"addiu $a2, $s7, {off}")
            self.emit(f"addiu $at, $s7, {off2}")
            self.emit(f"{r.choice(['aesenc', 'aesdec'])} $a2, $at")
        else:
            self.loop()

    def mem(self, d, a):
        r = self.r
        kind = r.choice(["lw", "sw", "lb", "lbu", "sb", "lh", "lhu", "sh"])
        size = {"lw": 4, "sw": 4, "lh": 2, "lhu": 2, "sh": 2}.get(kind, 1)
        off = r.randrange(0, 512 // size) * size
        if self.allow_traps and size > 1 and r.random() < 0.03:
            off += 1  # misaligned: traps in MEM
        self.emit(f"{kind} {d}, {off}($s7)")
        if kind.startswith("l") and r.random() < 0.5:
            self.emit(f"addu {self.reg()}, {d}, {self.reg()}")  # immediate use: load-use stall

    def branch(self):
        r = self.r
        lab = self.label()
        a, b = self.reg(), self.reg()
        mn = r.choice(["beq", "bne", "blez", "bgtz", "bltz", "bgez"])
        if mn in ("beq", "bne"):
            self.emit(f"{mn} {a}, {b}, {lab}")
        else:
            self.emit(f"{mn} {a}, {lab}")
        for _ in range(r.randrange(0, 5)):
            self.simple()
        self.lines.append(f"{lab}:")

    def simple(self):
        r = self.r
        d, a, b = self.reg(), self.reg(), self.reg()
        if r.random() < 0.5:
            self.emit(f"{r.choice(['addu', 'xor', 'or', 'subu'])} {d}, {a}, {b}")
        else:
            self.emit(f"lw {d}, {4 * r.randrange(128)}($s7)")

    def loop(self):
        r = self.r
        lab = self.label()
        self.emit(f"li $a3, {r.randrange(1, 9)}")
        self.lines.append(f"{lab}:")
        for _ in range(r.randrange(1, 6)):
            self.simple()
        self.emit("addiu $a3, $a3, -1")
        self.emit(f"bgtz $a3, {lab}")

    def program(self, n_ops):
        r = self.r
        self.lines = ["        .data", "buf:"]
        for _ in range(128):
            self.lines.append(f"        .word {r.randrange(1 << 32):#010x}")
        self.lines += ["        .text", "main:"]
        self.emit("la $s7, buf")
        for reg in POOL:
            self.emit(f"li {reg}, {r.randrange(-(1 << 31), 1 << 31)}")
        for _ in range(n_ops):
            self.op()
        self.emit("li $v0, 10")
        self.emit("syscall")
        for i in range(3):
            self.lines.append(f"leaf{i}:")
            for _ in range(r.randrange(1, 5)):
                d, a, b = self.reg(), self.reg(), self.reg()
                self.emit(f"{r.choice(['addu', 'xor', 'and', 'or', 'sltu'])} {d}, {a}, {b}")
            self.emit("jr $ra")
        return "\n".join(self.lines) + "\n"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--count", type=int, default=300)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--ops", type=int, default=120)
    ap.add_argument("--bin")
    a = ap.parse_args()
    tb = find_tb(a.bin)
    rng = random.Random(a.seed)
    out_root = ROOT / "build" / "fuzz"
    runs = fails = 0
    statuses = {}
    for i in range(a.count):
        gen = Gen(rng, allow_traps=(i % 4 == 3))
        src = gen.program(rng.randrange(a.ops // 2, a.ops * 2))
        d = out_root / f"p{i:04d}"
        d.mkdir(parents=True, exist_ok=True)
        (d / "prog.s").write_text(src)
        words, data, labels = asm.assemble(src)
        (d / "text.hex").write_text("".join(f"{w:08x}\n" for w in words))
        (d / "data.hex").write_text("".join(f"{w:08x}\n" for w in data))
        for cfg in CONFIGS:
            r = subprocess.run([str(tb), str(d)] + cfg, capture_output=True, text=True)
            runs += 1
            line = r.stdout.strip()
            st = line.split("status=")[1].split()[0] if "status=" in line else "?"
            statuses[st] = statuses.get(st, 0) + 1
            if r.returncode != 0:
                fails += 1
                print(f"FAIL p{i:04d} {' '.join(cfg)}\n  {line}")
    print(f"{runs} runs over {a.count} random programs, {fails} mismatches")
    print("final status of runs: " + ", ".join(f"{k} {v}" for k, v in sorted(statuses.items())))
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
