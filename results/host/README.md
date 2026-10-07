# Host verification

Status: **passed**

Started (UTC): 2026-10-06T13:06:59.423141+00:00

Platform: Windows-11-10.0.22631-SP0

Python: 3.13.16; compiler: clang version 23.1.1 (https://github.com/llvm/llvm-project.git 6dfe1677ab8dffbc6ec13d53a1e0215d75147689)

| Step | Result | Seconds | Log |
| --- | --- | ---: | --- |
| compile_aes128 | PASS | 0.11 | [compile_aes128.txt](compile_aes128.txt) |
| compile_xex | PASS | 0.06 | [compile_xex.txt](compile_xex.txt) |
| compile_cryptocpu | PASS | 0.14 | [compile_cryptocpu.txt](compile_cryptocpu.txt) |
| compile_isa_ref | PASS | 0.07 | [compile_isa_ref.txt](compile_isa_ref.txt) |
| build_cryptocpu_tb | PASS | 0.59 | [build_cryptocpu_tb.txt](build_cryptocpu_tb.txt) |
| build_security_tb | PASS | 0.62 | [build_security_tb.txt](build_security_tb.txt) |
| build_aes_kat | PASS | 0.12 | [build_aes_kat.txt](build_aes_kat.txt) |
| build_image_tool | PASS | 0.67 | [build_image_tool.txt](build_image_tool.txt) |
| build_security_regression | PASS | 0.40 | [build_security_regression.txt](build_security_regression.txt) |
| aes_kat | PASS | 0.02 | [aes_kat.txt](aes_kat.txt) |
| tooling_regression | PASS | 0.17 | [tooling_regression.txt](tooling_regression.txt) |
| security_regression | PASS | 0.01 | [security_regression.txt](security_regression.txt) |
| functional_tests | PASS | 0.83 | [functional_tests.txt](functional_tests.txt) |
| fuzz | PASS | 26.43 | [fuzz.txt](fuzz.txt) |
| security | PASS | 0.08 | [security.txt](security.txt) |
| mutation | PASS | 74.50 | [mutation.txt](mutation.txt) |
| performance | PASS | 0.68 | [performance.txt](performance.txt) |

Commands, tool versions and SHA-256 hashes are in [manifest.json](manifest.json).

Security PASS means the experiment completed, not authenticated memory or a proof of security.
Its rand() sequence can differ across C runtimes; use the recorded platform and seed when comparing logs.
Performance figures are cycle-model results, not measured FPGA timing or resource usage.
The FPGA integration and measurement procedure is documented in docs/hardware-flow.md.
