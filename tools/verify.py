#!/usr/bin/env python3
"""Build and reproduce the host verification suite; no FPGA tools required.

    python tools/verify.py --cxx g++ --out results/local

Requires a GCC/Clang C++17 compiler and Python's standard library. Writes fresh
logs, source/binary hashes, tool versions and a summary to a separate directory.
The security experiment records outcomes; it does not prove code integrity.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parent.parent
PROGRAMS = ["signature", "loop_sum", "fib", "bubble", "strings", "muldiv",
            "aes", "hazards", "sieve", "matmul"]
TARGETS = {
    "cryptocpu_tb": "tests/cryptocpu_tb.cpp",
    "security_tb": "tests/security_tb.cpp",
    "aes_kat": "tests/aes_kat.cpp",
    "image_tool": "tools/image_tool.cpp",
    "security_regression": "tests/security_regression.cpp",
}


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_hashes():
    paths = [ROOT / "CMakeLists.txt"]
    for folder in ("src", "ref", "tests", "tools"):
        paths.extend(p for p in (ROOT / folder).rglob("*")
                     if p.suffix in (".cpp", ".h", ".py", ".s"))
    return {p.relative_to(ROOT).as_posix(): sha256(p) for p in sorted(paths)}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--cxx", default="g++", help="GCC/Clang executable or path")
    ap.add_argument("--bin-dir", type=Path, default=ROOT / "build")
    ap.add_argument("--out", type=Path, default=ROOT / "results" / "local")
    ap.add_argument("--skip-build", action="store_true", help="use existing binaries; mutants still compile")
    args = ap.parse_args()
    compiler = shutil.which(args.cxx)
    if compiler is None:
        ap.error(f"C++ compiler not found: {args.cxx}")
    compiler = str(Path(compiler).resolve())
    out, bin_dir = args.out.resolve(), args.bin_dir.resolve()
    out.mkdir(parents=True, exist_ok=True)
    bin_dir.mkdir(parents=True, exist_ok=True)
    suffix = ".exe" if os.name == "nt" else ""
    binaries = {name: str(bin_dir / (name + suffix)) for name in TARGETS}
    compiler_version = subprocess.check_output([compiler, "--version"], text=True).strip()
    report = {
        "status": "running", "started_utc": datetime.now(timezone.utc).isoformat(),
        "command": [sys.executable, *sys.argv], "platform": platform.platform(),
        "python": sys.version, "compiler": compiler_version,
        "sources_sha256": source_hashes(), "binaries_sha256": {}, "steps": [],
        "hardware_validation": "not assessed by this host run",
    }

    def save_report():
        (out / "manifest.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        lines = ["# Host verification", "", f"Status: **{report['status']}**", "",
                 f"Started (UTC): {report['started_utc']}", "",
                 f"Platform: {report['platform']}", "",
                 f"Python: {sys.version.split()[0]}; compiler: {compiler_version.splitlines()[0]}", "",
                 "| Step | Result | Seconds | Log |", "| --- | --- | ---: | --- |"]
        for step in report["steps"]:
            lines.append(f"| {step['name']} | {'PASS' if step['returncode'] == 0 else 'FAIL'} | "
                         f"{step['seconds']:.2f} | [{step['log']}]({step['log']}) |")
        lines += ["", "Commands, tool versions and SHA-256 hashes are in [manifest.json](manifest.json).", "",
                  "Security PASS means the experiment completed, not authenticated memory or a proof of security.",
                  "Its rand() sequence can differ across C runtimes; use the recorded platform and seed when comparing logs.",
                  "Performance figures are cycle-model results, not measured FPGA timing or resource usage.",
                  "The FPGA integration and measurement procedure is documented in docs/hardware-flow.md."]
        if "error" in report:
            lines += ["", "Error: " + report["error"]]
        (out / "README.md").write_text("\n".join(lines) + "\n", encoding="utf-8")

    def run(name, command, log_name=None):
        command = list(map(str, command))
        log_name = log_name or name + ".txt"
        print(f"Running {name}...", flush=True)
        started = time.monotonic()
        result = subprocess.run(command, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, encoding="utf-8", errors="replace")
        (out / log_name).write_text(result.stdout, encoding="utf-8")
        report["steps"].append({"name": name, "command": command, "log": log_name,
                                "returncode": result.returncode,
                                "seconds": round(time.monotonic() - started, 3)})
        save_report()
        if result.returncode:
            print(result.stdout[-6000:], flush=True)
            raise RuntimeError(f"{name} failed with exit code {result.returncode}; see {out / log_name}")
        print(f"PASS {name}", flush=True)

    save_report()
    try:
        if not args.skip_build:
            objects_dir = bin_dir / "host_objects"
            objects_dir.mkdir(exist_ok=True)
            common = ["-std=c++17", "-O2", "-Wall", "-Wextra", "-Wno-unknown-pragmas",
                      "-Isrc", "-Iref"]
            objects = []
            for source in ("src/aes128.cpp", "src/xex.cpp", "src/cryptocpu.cpp", "ref/isa_ref.cpp"):
                obj = objects_dir / (Path(source).stem + ".o")
                run("compile_" + obj.stem, [compiler, *common, "-c", source, "-o", obj])
                objects.append(obj)
            for name, source in TARGETS.items():
                static = ["-static"] if os.name == "nt" else []
                run("build_" + name, [compiler, *common, source, *objects, *static, "-o", binaries[name]])
        report["binaries_sha256"] = {name: sha256(Path(path)) for name, path in binaries.items()}
        py = sys.executable
        run("aes_kat", [binaries["aes_kat"]])
        run("tooling_regression", [py, "tests/tooling_regression.py", "--image-tool", binaries["image_tool"], "-v"])
        run("security_regression", [binaries["security_regression"]])
        run("functional_tests", [py, "tools/run_tests.py", "--bin", binaries["cryptocpu_tb"]])
        run("fuzz", [py, "tools/fuzz.py", "--count", "1000", "--seed", "2026", "--bin", binaries["cryptocpu_tb"]])
        run("security", [binaries["security_tb"], *[ROOT / "build" / "progs" / p for p in PROGRAMS],
                         "--flips", "500", "--seed", "1"])
        run("mutation", [py, "tools/mutate.py", "--cxx", compiler, "--count", "100", "--seed", "7"])
        run("performance", [py, "tools/sweep.py", "--bin", binaries["cryptocpu_tb"], "--out", out])
        if source_hashes() != report["sources_sha256"]:
            raise RuntimeError("Source files changed during verification; rerun against a fixed revision")
        report["status"] = "passed"
    except (OSError, subprocess.SubprocessError, RuntimeError) as exc:
        report["status"] = "failed"
        report["error"] = str(exc)
    finally:
        report["finished_utc"] = datetime.now(timezone.utc).isoformat()
        save_report()
    print(f"\nVerification {report['status']}: {out / 'README.md'}")
    if "error" in report:
        print(report["error"], file=sys.stderr)
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
