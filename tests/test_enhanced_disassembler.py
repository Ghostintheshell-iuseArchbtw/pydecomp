import json
import types
import unittest
from pathlib import Path

from enhanced_disassembler import (
    AnalysisResult,
    EnhancedBinaryAnalyzer,
    ImportEntry,
    Section,
    StringMatch,
    calculate_entropy,
    collect_strings,
    format_summary,
    identify_section_purpose,
)


class FakeSection:
    def __init__(self, name: str, data: bytes, va: int = 0x1000, raw_size: int = 0x200, virt_size: int = 0x300,
                 characteristics: int = 0x60000020):
        self.Name = name.encode("ascii") + b"\x00" * max(0, 8 - len(name))
        self._data = data
        self.VirtualAddress = va
        self.Misc_VirtualSize = virt_size
        self.SizeOfRawData = raw_size
        self.Characteristics = characteristics

    def get_data(self) -> bytes:
        return self._data


class EnhancedDisassemblerTests(unittest.TestCase):
    def test_identify_section_purpose_uses_name_and_flags(self) -> None:
        self.assertEqual(identify_section_purpose(".text", 0), "executable_code")
        self.assertEqual(identify_section_purpose("mydata", 0x80000000), "writable_data")
        self.assertEqual(identify_section_purpose("unknown", 0), "unknown")

    def test_calculate_entropy_handles_simple_cases(self) -> None:
        self.assertAlmostEqual(calculate_entropy(b"\x00" * 32), 0.0)
        high_entropy = calculate_entropy(bytes(range(256)))
        self.assertGreater(high_entropy, 7.5)

    def test_collect_strings_combines_ascii_and_unicode(self) -> None:
        data = b"Hello World\x00H\x00i\x00"  # contains ASCII and UTF-16LE
        matches = collect_strings(".text", data, min_length=2)
        values = {(match.value, match.encoding) for match in matches}
        self.assertIn(("Hello World", "ascii"), values)
        self.assertIn(("Hi", "utf-16le"), values)

    def test_analyze_with_fake_pe(self) -> None:
        sections = [
            FakeSection(".text", b"Hello!\x00H\x00i\x00"),
            FakeSection(".rsrc", b"", characteristics=0x40000040),
        ]
        import_entry = types.SimpleNamespace(
            dll=b"KERNEL32.dll",
            imports=[
                types.SimpleNamespace(name=b"CreateFileA", ordinal=1, address=0x2000),
                types.SimpleNamespace(name=None, ordinal=2, address=0x2004),
            ],
        )
        export_symbols = [types.SimpleNamespace(name=b"ExportedFunc", ordinal=7, address=0x3000)]
        fake_pe = types.SimpleNamespace(
            FILE_HEADER=types.SimpleNamespace(Machine=0x8664),
            OPTIONAL_HEADER=types.SimpleNamespace(ImageBase=0x140000000, AddressOfEntryPoint=0x1000),
            sections=sections,
            DIRECTORY_ENTRY_IMPORT=[import_entry],
            DIRECTORY_ENTRY_EXPORT=types.SimpleNamespace(symbols=export_symbols),
        )

        analyzer = EnhancedBinaryAnalyzer("dummy.bin", pe=fake_pe, string_min_length=3)
        result = analyzer.analyze(include_strings=True)

        self.assertEqual(result.architecture, "x64")
        self.assertEqual(result.image_base, 0x140000000)
        self.assertEqual(result.entry_point, 0x140001000)
        self.assertEqual(len(result.sections), 2)
        self.assertTrue(any(s.purpose == "resources" for s in result.sections))
        self.assertEqual(len(result.imports), 2)
        self.assertEqual(result.imports[0].signature, "HANDLE CreateFileA(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE)")
        self.assertEqual(len(result.exports), 1)
        self.assertTrue(any(match.value == "Hello!" for match in result.strings))

        summary = format_summary(result, include_strings=True, max_strings=5)
        self.assertIn("Architecture : x64", summary)
        self.assertIn("KERNEL32.dll", summary)
        self.assertIn("ExportedFunc", summary)

        # JSON serialisation should not raise and should contain key fields.
        payload = json.dumps(result.to_dict())
        self.assertIn("\"architecture\": \"x64\"", payload)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
