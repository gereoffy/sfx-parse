# parseexe / parsearch

Futtatható fájlok és archívumok elemzése tiszta Pythonban (Python 3.6+, csak a standard könyvtár).
Mindkét modul `bytes`-t kap, nem nyit fájlt, semmit nem futtat és nem csomagol ki, csak a
szerkezetet olvassa. Hibás vagy rosszindulatú bemenetre sem dob kivételt: a talált
anomáliák az `errors` listába kerülnek.

| Fájl | Mit csinál |
|---|---|
| `parseexe.py` | exe típus, méret (hol ér véget az exe), függőségek, overlay és a beágyazott archívum helye |
| `parsearch.py` | archívum felismerése, mérete, tartalomjegyzéke, titkosítása, kommentje, SFX szkriptje |
| `bzip2dec.py` | tiszta Python bzip2 kibontó (szabványos és NSIS változat), a `parsearch` használja |

A `parseexe` a `parsearch`-öt importálja (az archívum megkereséséhez), a `parsearch` a
`bzip2dec`-et (csak az NSIS bzip2-höz). A három fájlnak egy könyvtárban kell lennie.

## Gyors használat

```python
import parseexe, parsearch

data = open("valami.exe", "rb").read()

r = parseexe.dump_exe(data)           # None, ha nem exe
if r:
    print(r["type"], r["size"], r["imports"])
    if r["archive"]:                   # SFX / telepítő / beágyazott archívum
        s, n = r["archive_start"], r["archive_size"]
        a = parsearch.dump_archive(data[s:s + n])
        for name, size, packed, encrypted, method, offset in a["files"] or []:
            # tárolt, titkosítatlan fájl: a tartalma közvetlenül kivágható -> rekurzió
            if method == "store" and not encrypted and offset is not None:
                inner = data[s + offset:s + offset + size]

a = parsearch.dump_archive(data)       # önálló archívum (a 0. offseten kezdődik)
```

## parseexe

`dump_exe(data)` → `None`, ha nem (értelmezhető) exe, különben dict.

**Támogatott formátumok:**
- MZ (DOS), beleértve a PKLITE, LZEXE és DIET packer-tippeket;
- PE32/PE32+ (x86, x64, ARM64 és a többi gép), .NET is;
- NE (16 bites Windows/OS2), LE/LX (DOS extender, OS/2, VxD);
- LC (DOS/32A tömörített), DJGPP COFF;
- ELF (32/64 bit, little/big endian).

**Közös mezők:**

| Mező | Jelentés |
|---|---|
| `type` | `"MZ"` `"PE"` `"NE"` `"LE"` `"LX"` `"LC"` `"COFF"` `"ELF"` |
| `size` | az exe része a fájl elejétől (aláírással, debug infóval, szimbólumtáblával együtt); ami utána van, az overlay |
| `truncated` | a fájl rövidebb, mint amit a fejlécek szerint tartalmaznia kellene |
| `overlay` | az exe utáni adat típusa (`"ZIP"`, `"RAR"`, `"7z"`, `"NSIS"`, `"Inno Setup"`, `"MZ"`, `"zero padding"`, `"unknown"`...) vagy `None` |
| `imports` | függőségek: `[[dll, szimbólum, ...], ...]`, ordinális import: `"#123"` |
| `archive`, `archive_start`, `archive_size` | a hozzá tartozó archívum típusa és helye (`data[start:start+size]`) |
| `sfx_config`, `sfx_script` | 7-Zip SFX konfig az exe és az archívum között, és a kiolvasott parancsok (`RunProgram`, `ExecuteFile`...) |
| `errors` | elemzési hibák és anomáliák |

Az archívum-keresés az SFX-trükköket is kezeli: szemét vagy konfig az archívum előtt,
digitális aláírás utána, exe-be ágyazott archívum (ekkor `archive_start < size`), `zip -A`-val
igazított ZIP.

**PE:**
- alapadatok: `bits`, `machine`, `subsystem`, `dll`;
- `delay_imports`, `exports` (`name`, `count`), `certificate` (`[offset, size]`);
- `packer` (tipp: UPX, PECompact, ASPack...);
- `dotnet`: runtime verzió, saját assembly, `assembly_refs` (név, verzió), `imports` (hivatkozott típusok assembly-nként), `pinvoke` (natív DLL-ek és függvényeik).

**ELF:**
- alapadatok: `bits`, `endian`, `machine`, `os`, `elf_type`, `interpreter`, `soname`, `dll`, `packer`;
- `imports`: a `DT_NEEDED` könyvtárak és az importált szimbólumok, a symbol versioning alapján könyvtárakhoz rendelve. A verzió nélküli szimbólumok a `"*"` csoportba kerülnek.

**NE/LE/LX:** `bits`, `os`, `module`, `imports` (NE-nél a relokációkból az importált függvényekkel együtt).

**LC:** `objects`, `oem`.

## parsearch

`dump_archive(data)`: a `data` a 0. offseten kezdődő archívum. Ha ott nincs érvényes archívum,
`None`-t ad.

**Támogatott formátumok:**

| Formátum | Mit ad |
|---|---|
| ZIP | ZIP64 is; fájllista; ZipCrypto/AES jelzés; komment; a local és a central header eltérését jelzi |
| RAR 1.5–4.x | fájllista, unicode nevek; titkosított fájlok és fejlécek; komment, ha tárolt |
| RAR5 | fájllista; titkosított fájlok és fejlécek; komment; symlink/hardlink |
| RAR 1.3/1.4 (`RE~^`) | fájllista (a `7zz` nem ismeri, az `unrar` igen) |
| 7z | fájllista (a fejlécet LZMA/LZMA2-vel kibontva), kódolólánc, AES, titkosított fejléc |
| CAB | fájllista, módszer |
| NSIS | a telepítő szkript fájljai (zlib, bzip2, LZMA; solid és nem solid) és parancsai |
| Inno Setup | csak felismerés, hely és méret |

**Mezők:**

| Mező | Jelentés |
|---|---|
| `type` | `"ZIP"` `"RAR"` `"RAR5"` `"RAR14"` `"7z"` `"CAB"` `"NSIS"` `"Inno Setup"` |
| `size` | az archívum mérete (az utána lévő pl. aláírás nem része) |
| `files` | `[[név, méret, tömörített méret, titkosított, módszer, offset], ...]` vagy `None`, ha nem olvasható |
| `encrypted` | `False`, `True` (van jelszavas fájl), `"headers"` (a tartalomjegyzék is titkosított) |
| `comment` | az archívum kommentje |
| `sfx_script` | WinRAR SFX parancsok a kommentből (`Setup`, `Silent`, `TempMode`...), NSIS-nél a szkript: `Exec`, `ShellExec`, `Plugin` (`dll::függvény`) |
| `truncated`, `errors` | mint a `parseexe`-nél |

**A fájllista elemei:**
- **`módszer`:**
  - `"store"` = tömörítetlen;
  - `"link"` = symlink/hardlink;
  - ZIP: `"deflate"`, `"bzip2"`, `"lzma"`...;
  - RAR: `"m1"`–`"m5"`;
  - 7z: a teljes kódolólánc, pl. `"BCJ2+LZMA2+LZMA"` vagy `"LZMA2+AES"`;
  - CAB: `"MSZIP"`, `"LZX"`, `"Quantum"`.
- **`offset`:** a fájl adatának kezdete az archívum elejétől. Tárolt és titkosítatlan fájlnál `data[offset:offset+méret]` maga a fájl.
- **`None` értékek:** 7z solid folderben és CAB-ban a tömörített méret `None`, mert ott fájlszintű tömörített méret nincs. Az offset csak ott van, ahol az adat folytonos: 7z-nél tárolt, titkosítatlan folderben, CAB-nál soha.
- **Könyvtárak:** nincsenek a listában.

**További függvények:**
- `find_archive(data, lo, hi)`: érvényes archívumot keres egy tartományban. A ZIP-et a végéről, az End of Central Directory rekordból találja meg, a többit szignatúra és fejléc-CRC alapján.
- `detect_archive(data, pos)`: megmondja, kezdődik-e archívum az adott offseten.
- `dump_file(data)`: archívum a 0. offseten, vagy egy exe-be ágyazott archívum (egy szint).
- `parse_winrar_script()`, `parse_7z_config()`: az SFX szkriptek értelmezése.

## bzip2dec

```python
import bzip2dec
bzip2dec.decompress(data, check_crc=True)    # szabványos bzip2 (több stream is)
bzip2dec.decompress_nsis(data, max_length)   # NSIS bzip2 (nincs fejléc és CRC)
bzip2dec.Bzip2Decompressor(), bzip2dec.NsisBzip2Decompressor()   # mint a bz2/lzma decompressor
```

A sebessége kb. 1,3 MB/s. A régi „randomised” blokkokat (bzip2 0.9.0 előtt) nem támogatja.

## Parancssor

Mindkét modul futtatható is: a megadott fájlokat és könyvtárakat (rekurzívan) sorban elemzi,
és fájlonként egy sort ír ki.

```bash
python3 parseexe.py [-v] [-e] [-x] [-s eredmeny.json] [-c eredmeny.json] fájlok/könyvtárak...
python3 parsearch.py [-v] [-l] [-s eredmeny.json] [-c eredmeny.json] fájlok/könyvtárak...
python3 bzip2dec.py fájl.bz2 > kibontott
```

- `-v` debug log
- `-e` elemzési hibák kiírása
- `-l` fájllista kiírása
- `-x` az exe utáni adat mentése `<fájl>.dump` néven
- `-s` eredmények mentése JSON-ba
- `-c` összevetés egy korábban mentett eredménnyel (kilépési kód 1, ha eltér)

## Korlátok

- A fájlok tartalmát nem csomagolja ki. A tömörített fájlok nem vizsgálhatók rekurzívan, csak a tároltak.
- Tömörített RAR kommentet nem bont ki (az `errors` jelzi).
- Inno Setupnál nincs fájllista.
- ARM64EC/ARM64X PE-nél csak a natív nézetet látja.
- A több kötetes archívumokat kötetenként listázza.
