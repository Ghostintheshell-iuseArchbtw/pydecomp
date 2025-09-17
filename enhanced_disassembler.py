#!/usr/bin/env python3
"""High level helpers for inspecting Windows PE binaries.

The original project shipped an extremely ambitious "enhanced" disassembler
that attempted to stitch together several missing modules.  In practice the
script failed before it could do any meaningful work.  This rewrite focuses on
reliable, well tested building blocks that expose the information most users
need when quickly triaging a binary:

* section metadata with a best-effort purpose guess and entropy calculation
* import/export listings with a curated table of Windows API signatures
* string extraction (ASCII and UTF-16LE) with configurable limits

The public API centres around :class:`EnhancedBinaryAnalyzer`.  The class hides
all interactions with :mod:`pefile`, allowing the rest of the code base – and
our unit tests – to provide light-weight stand-ins.  Results are represented by
simple dataclasses that can easily be converted to JSON or formatted for human
consumption via :func:`format_summary`.

Running the module as a script exposes a small CLI.  By default it prints a
human readable report; passing ``--json`` writes the structured analysis to a
file, making the tool easy to integrate with other automation.
"""

from __future__ import annotations

import argparse
import json
import math
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence

try:  # pragma: no cover - import guard only exercised when the dependency is missing
    import pefile  # type: ignore
except ImportError:  # pragma: no cover - surfaced as a runtime error during loading
    pefile = None  # type: ignore[assignment]


# -- Data models -----------------------------------------------------------------


@dataclass(frozen=True)
class Section:
    """Description of a section inside a PE binary."""

    name: str
    virtual_address: int
    virtual_size: int
    raw_size: int
    characteristics: int
    entropy: float
    purpose: str


@dataclass(frozen=True)
class ImportEntry:
    """Information about a single imported function."""

    dll: str
    name: Optional[str]
    ordinal: Optional[int]
    address: Optional[int]
    signature: Optional[str]


@dataclass(frozen=True)
class ExportEntry:
    """Information about a single exported function."""

    name: str
    ordinal: Optional[int]
    address: Optional[int]


@dataclass(frozen=True)
class StringMatch:
    """A string extracted from a section."""

    value: str
    offset: int
    section: str
    encoding: str  # ``"ascii"`` or ``"utf-16le"``


@dataclass(frozen=True)
class AnalysisResult:
    """Aggregated information produced by :class:`EnhancedBinaryAnalyzer`."""

    binary_path: Path
    architecture: str
    image_base: int
    entry_point: int
    sections: Sequence[Section] = field(default_factory=list)
    imports: Sequence[ImportEntry] = field(default_factory=list)
    exports: Sequence[ExportEntry] = field(default_factory=list)
    strings: Sequence[StringMatch] = field(default_factory=list)

    def to_dict(self) -> Dict[str, object]:
        """Return a JSON-serialisable representation of the analysis result."""

        data = asdict(self)
        data["binary_path"] = str(self.binary_path)
        return data


# -- Helper utilities ------------------------------------------------------------


_MACHINE_TO_ARCH = {
    0x8664: "x64",  # IMAGE_FILE_MACHINE_AMD64
    0x14C: "x86",  # IMAGE_FILE_MACHINE_I386
}

# A curated subset of signatures for common Win32 APIs.  The list is intentionally
# small – it is meant to provide helpful hints rather than exhaustive coverage.
_KNOWN_API_SIGNATURES: Dict[str, str] = {
    "CreateFileA": "HANDLE CreateFileA(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE)",
    "CreateFileW": "HANDLE CreateFileW(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE)",
    "ReadFile": "BOOL ReadFile(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED)",
    "WriteFile": "BOOL WriteFile(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED)",
    "CloseHandle": "BOOL CloseHandle(HANDLE)",
    "VirtualAlloc": "LPVOID VirtualAlloc(LPVOID, SIZE_T, DWORD, DWORD)",
    "VirtualFree": "BOOL VirtualFree(LPVOID, SIZE_T, DWORD)",
    "GetProcAddress": "FARPROC GetProcAddress(HMODULE, LPCSTR)",
    "LoadLibraryA": "HMODULE LoadLibraryA(LPCSTR)",
    "LoadLibraryW": "HMODULE LoadLibraryW(LPCWSTR)",
    "ExitProcess": "void ExitProcess(UINT)",
    "Sleep": "void Sleep(DWORD)",
    "MessageBoxA": "int MessageBoxA(HWND, LPCSTR, LPCSTR, UINT)",
    "MessageBoxW": "int MessageBoxW(HWND, LPCWSTR, LPCWSTR, UINT)",
    "malloc": "void* malloc(size_t)",
    "free": "void free(void*)",
    "printf": "int printf(const char*, ...)",
    "sprintf": "int sprintf(char*, const char*, ...)",
    "strlen": "size_t strlen(const char*)",
    "strcpy": "char* strcpy(char*, const char*)",
    "strcmp": "int strcmp(const char*, const char*)",
}


def infer_architecture(machine_value: int) -> str:
    """Translate the ``Machine`` value from a PE header into a human label."""

    try:
        return _MACHINE_TO_ARCH[machine_value]
    except KeyError:  # pragma: no cover - defensive, depends on input file
        raise ValueError(f"Unsupported architecture value: 0x{machine_value:X}") from None


_SECTION_PURPOSES = {
    ".text": "executable_code",
    ".data": "initialized_data",
    ".bss": "uninitialized_data",
    ".rdata": "read_only_data",
    ".rodata": "read_only_data",
    ".rsrc": "resources",
    ".reloc": "relocations",
    ".idata": "import_data",
    ".edata": "export_data",
    ".pdata": "exception_data",
    ".debug": "debug_info",
}


def identify_section_purpose(name: str, characteristics: int) -> str:
    """Best effort guess of a PE section's role.

    The function first checks the canonical section names.  If no direct match is
    found it falls back to interpreting the ``Characteristics`` flags.
    """

    normalized = name.lower()
    for key, purpose in _SECTION_PURPOSES.items():
        if key in normalized:
            return purpose

    # Interpret a subset of IMAGE_SCN_* flags; we only rely on the numerical
    # values to avoid importing the massive Windows headers.
    if characteristics & 0x20000000:  # IMAGE_SCN_MEM_EXECUTE
        return "executable_code"
    if characteristics & 0x80000000:  # IMAGE_SCN_MEM_WRITE
        return "writable_data"
    if characteristics & 0x40000000:  # IMAGE_SCN_MEM_READ
        return "read_only_data"
    return "unknown"


def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy for ``data``.

    An empty byte-string naturally has zero entropy.
    """

    if not data:
        return 0.0

    counts = [0] * 256
    for value in data:
        counts[value] += 1

    entropy = 0.0
    data_len = float(len(data))
    for count in counts:
        if count:
            probability = count / data_len
            entropy -= probability * math.log2(probability)
    return entropy


def _iter_ascii_strings(data: bytes, min_length: int) -> Iterable[StringMatch]:
    pattern = re.compile(rb"[ -~]{%d,}" % max(min_length, 1))
    for match in pattern.finditer(data):
        try:
            text = match.group().decode("ascii")
        except UnicodeDecodeError:  # pragma: no cover - the regex already filters this out
            continue
        yield match.start(), text


def _iter_utf16le_strings(data: bytes, min_length: int) -> Iterable[StringMatch]:
    min_length = max(min_length, 1)
    run_start: Optional[int] = None
    code_units = 0

    for index in range(0, len(data) - 1, 2):
        code_unit = data[index] | (data[index + 1] << 8)
        if 0x20 <= code_unit <= 0x7E:
            if run_start is None:
                if index == 0 or data[index - 1] == 0:
                    run_start = index
                    code_units = 0
                else:
                    continue
            code_units += 1
        else:
            if run_start is not None and code_units >= min_length:
                end = index
                try:
                    yield run_start, data[run_start:end].decode("utf-16le")
                except UnicodeDecodeError:  # pragma: no cover - defensive
                    pass
            run_start = None
            code_units = 0

    if run_start is not None and code_units >= min_length:
        try:
            yield run_start, data[run_start:run_start + code_units * 2].decode("utf-16le")
        except UnicodeDecodeError:  # pragma: no cover - defensive
            pass


def collect_strings(section_name: str, data: bytes, min_length: int) -> List[StringMatch]:
    """Extract ASCII and UTF-16LE strings from a section."""

    matches: List[StringMatch] = []
    for offset, text in _iter_ascii_strings(data, min_length):
        matches.append(StringMatch(text, offset, section_name, "ascii"))
    for offset, text in _iter_utf16le_strings(data, min_length):
        matches.append(StringMatch(text, offset, section_name, "utf-16le"))
    matches.sort(key=lambda item: (item.offset, item.encoding))
    return matches


# -- Core analyser ----------------------------------------------------------------


class EnhancedBinaryAnalyzer:
    """Analyse a PE binary using :mod:`pefile`.

    Parameters
    ----------
    binary_path:
        Path to the binary to analyse.  The path is resolved lazily – only
        :meth:`load_binary` performs any IO.
    pe:
        Optional pre-constructed ``pefile.PE`` compatible object.  Supplying a
        fake object greatly simplifies testing because no actual binary has to be
        parsed.
    string_min_length:
        Minimum length for strings extracted from sections.
    """

    def __init__(self, binary_path: Path | str, *, pe: Optional[object] = None, string_min_length: int = 4):
        self.binary_path = Path(binary_path)
        self._pe = pe
        self._arch: Optional[str] = None
        self._string_min_length = max(1, string_min_length)

    # -- public API --------------------------------------------------------------

    def load_binary(self) -> None:
        """Load the binary from disk using :mod:`pefile`.

        The method populates ``self._pe`` and infers the architecture.  It is
        safe to call multiple times – the expensive work is only carried out once.
        """

        if self._pe is not None:
            return
        if pefile is None:  # pragma: no cover - depends on runtime environment
            raise RuntimeError("pefile is required to load binaries")
        if not self.binary_path.exists():
            raise FileNotFoundError(self.binary_path)

        pe = pefile.PE(str(self.binary_path))  # type: ignore[call-arg]
        self._pe = pe
        self._arch = infer_architecture(int(pe.FILE_HEADER.Machine))

    def analyze(
        self,
        *,
        include_strings: bool = False,
        max_strings: Optional[int] = None,
    ) -> AnalysisResult:
        """Perform the analysis and return structured results."""

        if self._pe is None:
            self.load_binary()
        assert self._pe is not None  # mypy hint

        arch = self._arch
        if arch is None:
            arch = infer_architecture(int(self._pe.FILE_HEADER.Machine))
            self._arch = arch

        image_base = int(getattr(self._pe.OPTIONAL_HEADER, "ImageBase", 0))
        entry_rva = int(getattr(self._pe.OPTIONAL_HEADER, "AddressOfEntryPoint", 0))
        entry_point = image_base + entry_rva

        sections = self._collect_sections()
        imports = self._collect_imports()
        exports = self._collect_exports()

        strings: List[StringMatch] = []
        if include_strings:
            for section in self._pe.sections:
                name = _decode_section_name(getattr(section, "Name", b""))
                data = bytes(section.get_data()) if hasattr(section, "get_data") else b""
                strings.extend(collect_strings(name, data, self._string_min_length))
            if max_strings is not None:
                strings = strings[:max_strings]

        return AnalysisResult(
            binary_path=self.binary_path,
            architecture=arch,
            image_base=image_base,
            entry_point=entry_point,
            sections=sections,
            imports=imports,
            exports=exports,
            strings=strings,
        )

    # -- internal helpers --------------------------------------------------------

    def _collect_sections(self) -> List[Section]:
        results: List[Section] = []
        for section in getattr(self._pe, "sections", []):
            name = _decode_section_name(getattr(section, "Name", b""))
            data = bytes(section.get_data()) if hasattr(section, "get_data") else b""
            section_info = Section(
                name=name or "<unnamed>",
                virtual_address=int(getattr(section, "VirtualAddress", 0)),
                virtual_size=int(getattr(section, "Misc_VirtualSize", 0)),
                raw_size=int(getattr(section, "SizeOfRawData", 0)),
                characteristics=int(getattr(section, "Characteristics", 0)),
                entropy=calculate_entropy(data),
                purpose=identify_section_purpose(name, int(getattr(section, "Characteristics", 0))),
            )
            results.append(section_info)
        return results

    def _collect_imports(self) -> List[ImportEntry]:
        entries: List[ImportEntry] = []
        directory = getattr(self._pe, "DIRECTORY_ENTRY_IMPORT", None)
        if not directory:
            return entries

        for dll_entry in directory:
            dll_name = _decode_bytes(getattr(dll_entry, "dll", b""))
            for imported in getattr(dll_entry, "imports", []) or []:
                name = _decode_bytes(getattr(imported, "name", None))
                ordinal = getattr(imported, "ordinal", None)
                address = getattr(imported, "address", None)
                signature = _KNOWN_API_SIGNATURES.get(name) if name else None

                entries.append(
                    ImportEntry(
                        dll=dll_name,
                        name=name,
                        ordinal=int(ordinal) if ordinal is not None else None,
                        address=int(address) if isinstance(address, (int, float)) else None,
                        signature=signature,
                    )
                )
        return entries

    def _collect_exports(self) -> List[ExportEntry]:
        entries: List[ExportEntry] = []
        directory = getattr(self._pe, "DIRECTORY_ENTRY_EXPORT", None)
        symbols = getattr(directory, "symbols", []) if directory else []
        for symbol in symbols or []:
            name = _decode_bytes(getattr(symbol, "name", None)) or f"ordinal_{getattr(symbol, 'ordinal', 'unknown')}"
            ordinal = getattr(symbol, "ordinal", None)
            address = getattr(symbol, "address", None)
            entries.append(
                ExportEntry(
                    name=name,
                    ordinal=int(ordinal) if ordinal is not None else None,
                    address=int(address) if isinstance(address, (int, float)) else None,
                )
            )
        return entries


def _decode_bytes(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="ignore")
    return str(value)


def _decode_section_name(value: bytes) -> str:
    if not isinstance(value, (bytes, bytearray)):
        return str(value)
    return value.decode("utf-8", errors="ignore").rstrip("\x00")


# -- Reporting -------------------------------------------------------------------


def format_summary(
    result: AnalysisResult,
    *,
    include_strings: bool = False,
    max_strings: int = 10,
) -> str:
    """Create a human readable summary for ``result``."""

    lines: List[str] = []
    lines.append(f"Analysis summary for {result.binary_path}")
    lines.append("=" * (len(lines[0])))
    lines.append(f"Architecture : {result.architecture}")
    lines.append(f"Image base   : 0x{result.image_base:X}")
    lines.append(f"Entry point  : 0x{result.entry_point:X}")
    lines.append("")

    lines.append("Sections:")
    if result.sections:
        for section in result.sections:
            lines.append(
                "  - {name} @ 0x{va:X} (raw={raw} bytes, virtual={virt} bytes, "
                "entropy={entropy:.2f}, purpose={purpose})".format(
                    name=section.name,
                    va=section.virtual_address,
                    raw=section.raw_size,
                    virt=section.virtual_size,
                    entropy=section.entropy,
                    purpose=section.purpose,
                )
            )
    else:
        lines.append("  (no sections found)")
    lines.append("")

    lines.append(f"Imports ({len(result.imports)}):")
    if result.imports:
        grouped: Dict[str, List[ImportEntry]] = {}
        for entry in result.imports:
            grouped.setdefault(entry.dll, []).append(entry)
        for dll in sorted(grouped):
            names = ", ".join(
                entry.name or (f"ordinal #{entry.ordinal}" if entry.ordinal is not None else "<unknown>")
                for entry in grouped[dll]
            )
            lines.append(f"  - {dll}: {names}")
    else:
        lines.append("  (no imports found)")
    lines.append("")

    lines.append(f"Exports ({len(result.exports)}):")
    if result.exports:
        for entry in result.exports:
            ordinal = f" (ordinal {entry.ordinal})" if entry.ordinal is not None else ""
            address = f" @ 0x{entry.address:X}" if entry.address is not None else ""
            lines.append(f"  - {entry.name}{ordinal}{address}")
    else:
        lines.append("  (no exports found)")

    if include_strings:
        lines.append("")
        total_strings = len(result.strings)
        if total_strings:
            lines.append(
                f"Strings (showing up to {min(total_strings, max_strings)} of {total_strings}):"
            )
            for match in result.strings[:max_strings]:
                lines.append(
                    f"  - {match.section}+0x{match.offset:X} [{match.encoding}] {match.value!r}"
                )
        else:
            lines.append("Strings: none found")

    return "\n".join(lines)


# -- Command line interface ------------------------------------------------------


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Analyse a Windows PE binary and print a summary")
    parser.add_argument("binary", type=Path, help="Path to the PE file to analyse")
    parser.add_argument("--strings", action="store_true", help="Extract printable strings")
    parser.add_argument(
        "--min-string-length",
        type=int,
        default=4,
        help="Minimum string length when extracting strings (default: 4)",
    )
    parser.add_argument(
        "--max-strings",
        type=int,
        default=100,
        help="Limit the number of strings included in the output (default: 100)",
    )
    parser.add_argument(
        "--json",
        type=Path,
        help="Optional path to write the analysis result as JSON",
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = _build_arg_parser()
    args = parser.parse_args(argv)

    analyzer = EnhancedBinaryAnalyzer(args.binary, string_min_length=args.min_string_length)

    try:
        analyzer.load_binary()
    except FileNotFoundError:
        parser.error(f"Binary not found: {args.binary}")
    except Exception as exc:  # pragma: no cover - defensive, depends on runtime environment
        parser.error(str(exc))

    result = analyzer.analyze(include_strings=args.strings, max_strings=args.max_strings)

    if args.json:
        args.json.write_text(json.dumps(result.to_dict(), indent=2))

    print(
        format_summary(
            result,
            include_strings=args.strings,
            max_strings=args.max_strings,
        )
    )
    return 0


if __name__ == "__main__":  # pragma: no cover - manual execution
    raise SystemExit(main())
