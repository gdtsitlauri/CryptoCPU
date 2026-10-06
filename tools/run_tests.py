#!/usr/bin/env python3
"""Assemble every program in tests/programs, run it on the core and on the
golden reference (cryptocpu_tb), and check the EXPECT lines of each source.

    python tools/run_tests.py [--bin build/cryptocpu_tb] [extra tb options]

A program passes when the core agrees with the reference on the whole
architectural state, no plaintext block leaks into memory, and every
'# EXPECT status|mem|reg ...' line in the source holds.
"""
import argparse
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
from asm import REGS  # noqa: E402


def find_tb(explicit):
    if explicit:
        return Path(explicit)
    for cand in ("build/cryptocpu_tb", "build/cryptocpu_tb.exe", "build/Release/cryptocpu_tb.exe"):
        p = ROOT / cand
        if p.exists():
            return p
    sys.exit("cryptocpu_tb not found: build it first (see README)")


def parse_dump(path):
    st = {"mem": {}, "reg": {}}
    for line in path.read_text().splitlines():
        parts = line.split()
        if parts[0] == "mem":
            st["mem"][int(parts[1], 16)] = int(parts[2], 16)
        elif parts[0] == "reg":
            st["reg"][int(parts[1])] = int(parts[2], 16)
        else:
            st[parts[0]] = parts[1]
    return st


def check_expect(src, symbols, st):
    errors = []
    for line in src.splitlines():
        m = re.match(r"^\s*#\s*EXPECT\s+(\w+)\s+(\S+)(?:\s+(\S+))?", line)
        if not m:
            continue
        kind, a, b = m.groups()
        if kind == "status":
            if st["status"] != a:
                errors.append(f"status {st['status']} != {a}")
            continue
        want = int(b, 0) & 0xFFFFFFFF
        if kind == "mem":
            lab, _, off = a.partition("+")
            addr = symbols[lab] + (int(off, 0) if off else 0)
            got = st["mem"].get(addr, 0)
            if got != want:
                errors.append(f"mem {a} = {got:#010x} != {want:#010x}")
        elif kind == "reg":
            got = st["reg"][REGS[a]]
            if got != want:
                errors.append(f"reg {a} = {got:#010x} != {want:#010x}")
    return errors


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bin")
    ap.add_argument("--programs", default=str(ROOT / "tests" / "programs"))
    args, extra = ap.parse_known_args()
    tb = find_tb(args.bin)
    build = ROOT / "build" / "progs"
    failures = 0
    progs = sorted(Path(args.programs).glob("*.s"))
    for prog in progs:
        out = build / prog.stem
        r = subprocess.run([sys.executable, str(ROOT / "tools" / "asm.py"), str(prog), "-o", str(out)],
                           capture_output=True, text=True)
        if r.returncode:
            print(f"{prog.name}: assembly failed\n{r.stderr}")
            failures += 1
            continue
        symbols = {}
        for line in (out / "symbols.txt").read_text().splitlines():
            name, addr = line.split()
            symbols[name] = int(addr, 16)
        dump = out / "final_state.txt"
        r = subprocess.run([str(tb), str(out), "--dump", str(dump)] + extra, capture_output=True, text=True)
        print(r.stdout.rstrip())
        if r.returncode:
            failures += 1
            continue
        errors = check_expect(prog.read_text(encoding="utf-8"), symbols, parse_dump(dump))
        if errors:
            failures += 1
            for e in errors:
                print(f"    EXPECT FAILED: {e}")
    print(f"\n{len(progs) - failures}/{len(progs)} programs passed")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
