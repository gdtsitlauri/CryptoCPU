# Results

[host/README.md](host/README.md) is the recorded verification used by the paper.
It links every stage log; [host/manifest.json](host/manifest.json) records the
exact commands, timestamps, source hashes and tool versions.

- [Performance tables](host/perf.md) and [machine-readable data](host/perf.csv).
- [CMake / CTest result](host/ctest.txt).
- [Verification methods and interpretation](../docs/validation.md).

Running `python tools/verify.py --cxx g++` writes new local results to the
ignored `results/local/` directory. Running `python tools/sweep.py` by itself
writes to `results/local/performance/`.

All performance values here are cycle-model results.
