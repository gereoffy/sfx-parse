# parseexe / parsearch

Executable and archive analysis in pure Python (Python 3.6+, standard library only).
Both modules take `bytes`: they don't open files, run anything, or extract anything. They only
read the structure. Malformed or malicious input does not raise exceptions either: any
anomalies found go into the `errors` list.

| File | What it does |
|---|---|
| `parseexe.py` | executable type, size (where the executable ends), dependencies, overlay and the location of an embedded archive |
| `parsearch.py` | archive detection, size, file listing, encryption, comment, SFX script |
| `bzip2dec.py` | pure Python bzip2 decompressor (standard and NSIS variant), used by `parsearch` |

`parseexe` imports `parsearch` (to locate archives), and `parsearch` imports `bzip2dec` (for NSIS
bzip2 only). All three files must be in the same directory.

## Quick start

```python
import parseexe, parsearch

data = open("something.exe", "rb").read()

r = parseexe.dump_exe(data)           # None if not an executable
if r:
    print(r["type"], r["size"], r["imports"])
    if r["archive"]:                   # SFX / installer / embedded archive
        s, n = r["archive_start"], r["archive_size"]
        a = parsearch.dump_archive(data[s:s + n])
        for name, size, packed, encrypted, method, offset in a["files"] or []:
            # stored, unencrypted file: its content can be sliced out directly -> recursion
            if method == "store" and not encrypted and offset is not None:
                inner = data[s + offset:s + offset + size]

a = parsearch.dump_archive(data)       # standalone archive (starting at offset 0)
```

## parseexe

`dump_exe(data)` → `None` if not a (parseable) executable, otherwise a dict.

**Supported formats:**
- MZ (DOS), including PKLITE, LZEXE and DIET packer hints;
- PE32/PE32+ (x86, x64, ARM64 and other machines), including .NET;
- NE (16-bit Windows/OS2), LE/LX (DOS extenders, OS/2, VxD);
- LC (DOS/32A compressed), DJGPP COFF;
- ELF (32/64-bit, little/big endian).

**Common fields:**

| Field | Meaning |
|---|---|
| `type` | `"MZ"` `"PE"` `"NE"` `"LE"` `"LX"` `"LC"` `"COFF"` `"ELF"` |
| `size` | the executable part from the start of the file (including signature, debug info, symbol table); anything after it is the overlay |
| `truncated` | the file is shorter than the headers say it should be |
| `overlay` | type of the data after the executable (`"ZIP"`, `"RAR"`, `"7z"`, `"NSIS"`, `"Inno Setup"`, `"MZ"`, `"zero padding"`, `"unknown"`...) or `None` |
| `imports` | dependencies: `[[dll, symbol, ...], ...]`, import by ordinal: `"#123"` |
| `archive`, `archive_start`, `archive_size` | type and location of the associated archive (`data[start:start+size]`) |
| `sfx_config`, `sfx_script` | 7-Zip SFX config between the executable and the archive, and the extracted commands (`RunProgram`, `ExecuteFile`...) |
| `errors` | parse errors and anomalies |

The archive search also handles SFX tricks: junk or a config block before the archive, a digital
signature after it, an archive embedded inside the executable (then `archive_start < size`), and
ZIPs adjusted with `zip -A`.

**PE:**
- basics: `bits`, `machine`, `subsystem`, `dll`;
- `delay_imports`, `exports` (`name`, `count`), `certificate` (`[offset, size]`);
- `packer` (hint: UPX, PECompact, ASPack...);
- `dotnet`: runtime version, own assembly, `assembly_refs` (name, version), `imports` (referenced types per assembly), `pinvoke` (native DLLs and their functions).

**ELF:**
- basics: `bits`, `endian`, `machine`, `os`, `elf_type`, `interpreter`, `soname`, `dll`, `packer`;
- `imports`: the `DT_NEEDED` libraries and imported symbols, assigned to libraries via symbol versioning. Unversioned symbols go into the `"*"` group.

**NE/LE/LX:** `bits`, `os`, `module`, `imports` (for NE, including imported functions taken from the relocations).

**LC:** `objects`, `oem`.

## parsearch

`dump_archive(data)`: `data` is an archive starting at offset 0. Returns `None` if there is no
valid archive there.

**Supported formats:**

| Format | What you get |
|---|---|
| ZIP | ZIP64 too; file listing; ZipCrypto/AES flag; comment; reports mismatches between local and central headers |
| RAR 1.5–4.x | file listing, Unicode names; encrypted files and headers; comment if stored |
| RAR5 | file listing; encrypted files and headers; comment; symlink/hardlink |
| RAR 1.3/1.4 (`RE~^`) | file listing (not supported by `7zz`, but supported by `unrar`) |
| 7z | file listing (header decompressed with LZMA/LZMA2), coder chain, AES, encrypted headers |
| CAB | file listing, method |
| NSIS | files of the installer script (zlib, bzip2, LZMA; solid and non-solid) and its commands |
| Inno Setup | detection, location and size only |

**Fields:**

| Field | Meaning |
|---|---|
| `type` | `"ZIP"` `"RAR"` `"RAR5"` `"RAR14"` `"7z"` `"CAB"` `"NSIS"` `"Inno Setup"` |
| `size` | size of the archive (anything after it, e.g. a signature, is not part of it) |
| `files` | `[[name, size, packed size, encrypted, method, offset], ...]` or `None` if not readable |
| `encrypted` | `False`, `True` (some files are password protected), `"headers"` (the listing itself is encrypted) |
| `comment` | the archive comment |
| `sfx_script` | WinRAR SFX commands from the comment (`Setup`, `Silent`, `TempMode`...); for NSIS, the script: `Exec`, `ShellExec`, `Plugin` (`dll::function`) |
| `truncated`, `errors` | same as in `parseexe` |

**File listing entries:**
- **`method`:**
  - `"store"` = uncompressed;
  - `"link"` = symlink/hardlink;
  - ZIP: `"deflate"`, `"bzip2"`, `"lzma"`...;
  - RAR: `"m1"`–`"m5"`;
  - 7z: the full coder chain, e.g. `"BCJ2+LZMA2+LZMA"` or `"LZMA2+AES"`;
  - CAB: `"MSZIP"`, `"LZX"`, `"Quantum"`.
- **`offset`:** start of the file's data from the beginning of the archive. For stored, unencrypted files, `data[offset:offset+size]` is the file itself.
- **`None` values:** in 7z solid folders and in CAB the packed size is `None`, because there is no per-file packed size there. The offset is only given where the data is contiguous: for 7z in stored, unencrypted folders, for CAB never.
- **Directories:** not included in the listing.

**Other functions:**
- `find_archive(data, lo, hi)`: searches for a valid archive within a range. ZIPs are found from the end, via the End of Central Directory record; the others by signature and header CRC.
- `detect_archive(data, pos)`: tells whether an archive starts at the given offset.
- `dump_file(data)`: an archive at offset 0, or an archive embedded in an executable (one level).
- `parse_winrar_script()`, `parse_7z_config()`: parsing of SFX scripts.

## bzip2dec

```python
import bzip2dec
bzip2dec.decompress(data, check_crc=True)    # standard bzip2 (multiple streams too)
bzip2dec.decompress_nsis(data, max_length)   # NSIS bzip2 (no header, no CRC)
bzip2dec.Bzip2Decompressor(), bzip2dec.NsisBzip2Decompressor()   # like the bz2/lzma decompressors
```

Speed is about 1.3 MB/s. Old "randomised" blocks (bzip2 before 0.9.0) are not supported.

## Command line

Both modules can also be run directly: they analyze the given files and directories
(recursively) one after another and print one line per file.

```bash
python3 parseexe.py [-v] [-e] [-x] [-s results.json] [-c results.json] files/directories...
python3 parsearch.py [-v] [-l] [-s results.json] [-c results.json] files/directories...
python3 bzip2dec.py file.bz2 > decompressed
```

- `-v` debug log
- `-e` print parse errors
- `-l` print the file listing
- `-x` save the data after the executable as `<file>.dump`
- `-s` save results to JSON
- `-c` compare with previously saved results (exit code 1 on mismatch)

## Limitations

- File contents are not extracted. Compressed files cannot be inspected recursively, only stored ones.
- Compressed RAR comments are not decoded (reported in `errors`).
- No file listing for Inno Setup.
- For ARM64EC/ARM64X PE files only the native view is parsed.
- Multi-volume archives are listed volume by volume.
