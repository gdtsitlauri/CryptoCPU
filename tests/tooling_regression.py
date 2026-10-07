"""Regression tests for data-label alignment and image-tool key loading."""
import argparse
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import asm

IMAGE_TOOL = None


class AlignmentTests(unittest.TestCase):
    def test_inline_word_and_half_labels(self):
        _, words, labels = asm.assemble("""
            .data
            byte: .byte 0xaa
            half: .half 0x1234
            next: .byte 0xbb
            word: .word 0x12345678
        """)
        self.assertEqual(labels["byte"], asm.DATA_BASE)
        self.assertEqual(labels["half"], asm.DATA_BASE + 2)
        self.assertEqual(labels["next"], asm.DATA_BASE + 4)
        self.assertEqual(labels["word"], asm.DATA_BASE + 8)
        self.assertEqual(words, [0x123400AA, 0xBB, 0x12345678])

    def test_standalone_labels_and_forward_reference(self):
        _, words, labels = asm.assemble("""
            .data
            pointer: .word target
            .byte 1
            alias:
            # Both labels refer to the next aligned word.
            target:
            .word 0x11223344
        """)
        self.assertEqual(labels["alias"], asm.DATA_BASE + 8)
        self.assertEqual(labels["target"], asm.DATA_BASE + 8)
        self.assertEqual(words, [asm.DATA_BASE + 8, 1, 0x11223344])

    def test_explicit_alignment_moves_labels_at_the_cursor(self):
        _, words, labels = asm.assemble("""
            .data
            first: .byte 1
            alias:
            aligned: .align 4
            .word 9
        """)
        self.assertEqual(labels["first"], asm.DATA_BASE)
        self.assertEqual(labels["alias"], asm.DATA_BASE + 16)
        self.assertEqual(labels["aligned"], asm.DATA_BASE + 16)
        self.assertEqual(words, [1, 0, 0, 0, 9])


class KeyLoadingTests(unittest.TestCase):
    FIELDS = [
        "k_code 00112233445566778899aabbccddeeff",
        "k_tweak ffeeddccbbaa99887766554433221100",
        "k_data 0123456789abcdef0123456789abcdef",
        "nonce 0102030405060708",
    ]

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)
        self.source = self.folder / "text.hex"
        self.source.write_text("2402000a\n0000000c\n12345678\nabcdef01\n")
        self.output = self.folder / "image.hex"
        self.keys = self.folder / "keys.txt"

    def run_tool(self, *extra, command="encrypt", source=None, output=None):
        return subprocess.run(
            [str(IMAGE_TOOL), command, str(source or self.source),
             str(output or self.output), *map(str, extra)],
            capture_output=True, text=True, timeout=20)

    def test_custom_keys_round_trip_and_differ_from_defaults(self):
        self.assertEqual(self.run_tool().returncode, 0)
        default_image = self.output.read_bytes()
        # Fields may be reordered; blank lines and CRLF are accepted.
        self.keys.write_bytes(("\r\n" + "\r\n".join(reversed(self.FIELDS)) + "\r\n").encode())
        result = self.run_tool("--keys", self.keys)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotEqual(self.output.read_bytes(), default_image)
        plain = self.folder / "plain.hex"
        result = self.run_tool("--keys", self.keys, command="decrypt",
                               source=self.output, output=plain)
        self.assertEqual(result.returncode, 0, result.stderr)
        words = plain.read_text().splitlines()
        self.assertEqual(words[:4], self.source.read_text().splitlines())
        self.assertTrue(all(word == "00000000" for word in words[4:]))

    def test_invalid_key_files_are_rejected_without_overwriting_output(self):
        cases = {
            "repeated nonce with missing keys": [self.FIELDS[3]] * 4,
            "duplicate replacing nonce": self.FIELDS[:3] + [self.FIELDS[0]],
            "duplicate after complete keys": self.FIELDS + [self.FIELDS[0]],
            "missing nonce": self.FIELDS[:3],
            "unknown field": self.FIELDS + ["unknown 00000000"],
            "dangling field": self.FIELDS + ["nonce"],
            "extra token": self.FIELDS[:3] + [self.FIELDS[3] + " extra"],
            "short key": ["k_code 1234"] + self.FIELDS[1:],
            "non-hex key": ["k_code " + "g" * 32] + self.FIELDS[1:],
            "signed key": ["k_code +" + "0" * 31] + self.FIELDS[1:],
            "hex prefix": ["k_code 0x" + "0" * 30] + self.FIELDS[1:],
            "empty file": [],
        }
        for name, lines in cases.items():
            with self.subTest(name=name):
                self.keys.write_text("\n".join(lines) + "\n")
                self.output.write_text("existing output\n")
                result = self.run_tool("--keys", self.keys)
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertEqual(self.output.read_text(), "existing output\n")

    def test_invalid_cli_never_falls_back_to_test_keys(self):
        self.keys.write_text("\n".join(self.FIELDS) + "\n")
        for extra in [("--keys",), ("--key", str(self.keys)),
                      ("--keys", str(self.keys), "unexpected"),
                      ("--keys", str(self.folder / "missing.txt"))]:
            with self.subTest(extra=extra):
                self.output.unlink(missing_ok=True)
                result = self.run_tool(*extra)
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertFalse(self.output.exists())


if __name__ == "__main__":
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--image-tool", type=Path, required=True)
    args, remaining = parser.parse_known_args()
    IMAGE_TOOL = args.image_tool.resolve()
    unittest.main(argv=[sys.argv[0], *remaining])
