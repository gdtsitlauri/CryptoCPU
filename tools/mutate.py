#!/usr/bin/env python3
"""Mutation test of the verification: inject known pipeline bugs into a copy of
the core and check that random differential testing catches them.

    python tools/mutate.py [--cxx "g++"] [--count 100]

A mutant is caught when at least one run disagrees with the reference.
"""
import argparse
import shlex
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

MUTANTS = {
    "no forwarding from EX/MEM (operand a)": (
        "if (d.src_a && r_exmem.d.dest == d.src_a) va = r_exmem.res;", "/* mutated */"),
    "no load-use stall": (
        "bool hazard = r_idex.v && r_idex.d.is_load", "bool hazard = false && r_idex.v && r_idex.d.is_load"),
    "no squash of the instruction behind a taken branch": (
        "            n_idex.v = false;\n            n_dcid.v = false;\n            n_ifdc.v = false;\n"
        "            fetch_pc = redirect_pc;",
        "            n_dcid.v = false;\n            n_ifdc.v = false;\n            fetch_pc = redirect_pc;"),
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cxx", default="g++")
    ap.add_argument("--count", type=int, default=100)
    ap.add_argument("--seed", type=int, default=7)
    a = ap.parse_args()
    src = (ROOT / "src" / "cryptocpu.cpp").read_text(encoding="utf-8")
    out = ROOT / "build" / "mut"
    out.mkdir(parents=True, exist_ok=True)
    caught = 0
    for i, (name, (old, new)) in enumerate(MUTANTS.items()):
        if src.count(old) != 1:
            sys.exit(f"mutant '{name}': pattern not found in src/cryptocpu.cpp")
        (out / "cryptocpu.cpp").write_text(src.replace(old, new), encoding="utf-8")
        exe = out / f"m{i}.exe"
        cmd = shlex.split(a.cxx) + ["-std=c++17", "-O2", "-Wno-unknown-pragmas", f"-I{ROOT / 'src'}",
                                     str(ROOT / "src" / "aes128.cpp"), str(ROOT / "src" / "xex.cpp"),
                                     str(out / "cryptocpu.cpp"), str(ROOT / "ref" / "isa_ref.cpp"),
                                     str(ROOT / "tests" / "cryptocpu_tb.cpp"), "-o", str(exe)]
        subprocess.run(cmd, check=True, capture_output=True)
        r = subprocess.run([sys.executable, str(ROOT / "tools" / "fuzz.py"), "--count", str(a.count),
                            "--seed", str(a.seed), "--bin", str(exe)], capture_output=True, text=True)
        summary = [l for l in r.stdout.splitlines() if "runs over" in l][0]
        runs, fails = int(summary.split()[0]), int(summary.split(",")[1].split()[0])
        caught += fails > 0
        print(f"{name:55s} caught in {fails}/{runs} runs ({100 * fails / runs:.0f}%)")
    print(f"\n{caught}/{len(MUTANTS)} mutants caught")
    sys.exit(0 if caught == len(MUTANTS) else 1)


if __name__ == "__main__":
    main()
