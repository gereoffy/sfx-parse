#!/usr/bin/env python3
"""
DOS/Windows futtathato fileok (MZ, PE, NE, LE/LX, LC, DJGPP COFF) es ELF (Linux/BSD/Solaris) elemzese.

dump_exe(data) -- data: a teljes file tartalma (bytes)
  None, ha nem (ertelmezheto) EXE, kulonben dict:
    type      "MZ" | "PE" | "NE" | "LE" | "LX" | "LC" | "BW" | "COFF" | "ELF"
    size      az exe resz merete a file elejetol; ami utana van, az overlay
              (SFX archiv, installer adat, stb.)
    overlay   az exe utani adat tipusa ("ZIP","RAR","7z","CAB","NSIS","Inno Setup",
              "MZ",...), "unknown", vagy None ha nincs utana semmi
    imports   fuggosegek: [[dllnev, szimbolum1, szimbolum2, ...], ...]
              (ordinal szerinti import: "#123"), None ha nincs import tabla
    archive   a hozza tartozo archivum / installer adat tipusa ("ZIP","RAR","RAR5","7z","CAB",
              "NSIS","Inno Setup") vagy None. Altalaban az exe utan van, de lehet elotte
              szemet (pl. 7-Zip SFX konfig), utana alairas, vagy lehet az exe-be agyazva
              (ekkor archive_start < size).
    archive_start, archive_size
              az archivum helye a fileban: data[archive_start:archive_start+archive_size]
    sfx_config
              7-Zip SFX konfig (";!@Install@!UTF-8!" ... ";!@InstallEnd@!") az exe es az archivum kozott
    sfx_script
              a 7-Zip SFX konfigbol kiolvasott parancsok: {parancs: [ertekek]}, pl. {"RunProgram": ["..."]}
              (az archivum tartalomjegyzeke, kommentje es a WinRAR SFX parancsok: parsearch.dump_archive())
    errors    elemzes kozben talalt hibak/anomaliak (lista, altalaban ures)
    truncated True, ha a file rovidebb, mint amit a fejlec szerint tartalmaznia kellene
  PE eseten meg:
    bits, machine, subsystem, dll, delay_imports (mint az imports),
    exports ({"name","count"} vagy None), certificate ([offset,size] vagy None),
    packer (tipp: "UPX","PECompact",... vagy None),
    dotnet: None, vagy {"version","runtime","flags","assembly","assembly_refs",
            "imports","pinvoke"}
      assembly_refs  [[nev, verzio], ...]
      imports        [[assembly, "Namespace.Tipus", ...], ...]   (TypeRef-ek)
      pinvoke        [[dll, fuggveny, ...], ...]                  (natív DllImport-ok)
  NE/LE/LX eseten meg: bits, os, module (modulnev)
  MZ eseten meg: packer (tipp), extender (ha maga a DOS program egy DOS extender stub/runtime)
  LE/LX eseten meg: extender (DOS extender a stub alapjan: "DOS/4GW","DOS/32A","PMODE/W",...,
    ilyenkor os="dos"), os_header (a fejlec OS mezoje, DOS extendereknel altalaban "os2")
  debug     a file vegere fuzott debug info formatuma ("DWARF","Watcom","CodeView NB09",...), ha van
            (ilyenkor a size ezt is tartalmazza)
  BW (DOS/16M, pl. a DOS/4GW kernel) eseten meg: bits, os, extender, images (a lancolt image-ek szama),
    bound_app (ha a lanc egy LE/LX alkalmazasba torkollik)
  LC (DOS/32A tomoritett) eseten meg: bits, os, packer, objects (objektumok szama), oem (OEM szoveg, ha van)
  ELF eseten meg: bits, endian, machine, os (EI_OSABI), elf_type ("EXEC","DYN","REL",...),
    interpreter (PT_INTERP), soname, dll (shared library), packer ("UPX"),
    imports: [[DT_NEEDED konyvtar, importalt szimbolumok...], ..., ["*", verzio nelkuli szimbolumok]]
      (a szimbolumokat a symbol versioning alapjan rendeli a konyvtarakhoz; ELF-ben nincs
      kotelezo szimbolum->konyvtar hozzarendeles, a verzio nelkuliek barhonnan johetnek)
"""

import struct

debug=False

def log(level,text):
    if level>0 or debug: print(level,text)

MAX_DLLS=4096      # vedelem a hibas/rosszindulatu fileok ellen
MAX_SYMS=65536
MAX_ERRORS=100     # ennyi hibauzenet kerul az errors listaba, a tobbit csak szamoljuk
MAX_BAD_IMPORT_NAMES=32   # ennyi egymas utani ervenytelen import nev utan feladjuk az adott DLL-t

def unpack(fmt,data,pos):
    if pos is None or pos<0:
        raise struct.error("invalid offset: %s"%(pos,))
    return struct.unpack_from(fmt,data,pos)

def u16(data,pos): return unpack("<H",data,pos)[0]
def u32(data,pos): return unpack("<I",data,pos)[0]

def cstr(data,pos,maxlen=1024,enc="latin-1"):
    """0-val lezart string (legfeljebb maxlen hosszu)."""
    if pos is None or pos<0 or pos>=len(data):
        raise struct.error("string offset out of range: %s"%(pos,))
    end=data.find(b"\0",pos,pos+maxlen)
    if end<0: end=min(len(data),pos+maxlen)
    return data[pos:end].decode(enc,"replace")

def pstr(data,pos):
    """Pascal string (hossz byte + szoveg)."""
    n=data[pos]
    return data[pos+1:pos+1+n].decode("latin-1")

def printable(b,minc=32,maxc=127):
    return "".join(chr(c) for c in b if minc<=c<maxc)

def align_up(x,a):
    return (x+a-1)//a*a if a>1 else x


#####################################################################
#   Overlay (exe utani adat) felismerese
#####################################################################

def detect_overlay(data,off):
    if off>=len(data): return None
    d=data[off:off+64]
    if d.startswith(b"PK\3\4") or d.startswith(b"PK\5\6"): return "ZIP"
    if d.startswith(b"Rar!\x1a\x07\x01\x00"): return "RAR5"
    if d.startswith(b"Rar!\x1a\x07"): return "RAR"
    if d.startswith(b"RE~^"): return "RAR14"
    if d.startswith(b"7z\xbc\xaf\x27\x1c"): return "7z"
    if d.startswith(b"MSCF"): return "CAB"
    if d.startswith(b"\xfd7zXZ\0"): return "XZ"
    if d.startswith(b"\x1f\x8b"): return "GZIP"
    if d.startswith(b"BZh"): return "BZIP2"
    if d[4:8]==b"\xef\xbe\xad\xde" and d[8:20]==b"NullsoftInst": return "NSIS"
    if d.startswith(b"zlb\x1a") or d.startswith(b"idska32\x1a"): return "Inno Setup"
    if d.startswith(b"MZ"): return "MZ"
    if d.startswith(b"\x7fELF"): return "ELF"
    if d.startswith(b"BW"): return "BW"
    if d.startswith(b"%PDF"): return "PDF"
    if d.startswith(b"FBOV"): return "Borland overlay"
    if len(d)>=10 and d[4:6]==b"\0\x02" and d[8:10]==b"\x30\x82": return "certificate"
    rest=data[off:]
    if rest.count(0)==len(rest): return "zero padding"
    return "unknown"


#####################################################################
#   Az exe-hez tartozo archivum helye (a listazas a parsearch.py dolga)
#####################################################################

import parsearch

def find_archive(data,r):
    """Az exe-hez tartozo archivum: eloszor az exe utan, ha ott nincs, akkor az exe-n belul."""
    lo=min(r["size"],len(data))
    hi=len(data)
    cert=r.get("certificate")
    if cert and lo<=cert[0]<hi:
        hi=cert[0]       # a vegen levo alairas nem az archivum resze
    a=parsearch.find_archive(data,lo,hi,inno=True)
    if a is None and lo>0:
        a=parsearch.find_archive(data,min(0x40,lo),lo)   # exe-be agyazva (pl. WinZip SFX, resource)
    res={"archive":None,"archive_start":None,"archive_size":None,"sfx_config":None,"sfx_script":None}
    if a is None:
        return res
    name,start,end=a
    res.update({"archive":name,"archive_start":start,"archive_size":end-start})
    # 7-Zip SFX konfig: az exe es az archivum kozott (7zSD, 7z.sfx)
    if start>r["size"]:
        gap=data[r["size"]:start]
        i=gap.find(b";!@Install@!UTF-8!")
        if i>=0:
            j=gap.find(b";!@InstallEnd@!",i)
            cfg=gap[i:j+15 if j>=0 else len(gap)].decode("utf-8","replace")
            res["sfx_config"]=cfg
            res["sfx_script"]=parsearch.parse_7z_config(cfg)
    return res



#####################################################################
#   PE
#####################################################################

PE_MACHINES={0x0:"unknown",0x14c:"i386",0x162:"R3000",0x166:"R4000",0x168:"R10000",0x169:"WCEMIPSV2",
    0x184:"ALPHA",0x1a2:"SH3",0x1a6:"SH4",0x1c0:"ARM",0x1c2:"THUMB",0x1c4:"ARMNT",0x1f0:"POWERPC",
    0x200:"IA64",0x266:"MIPS16",0x284:"ALPHA64",0xebc:"EBC",0x8664:"AMD64",0x9041:"M32R",0xaa64:"ARM64",
    0x5032:"RISCV32",0x5064:"RISCV64",0x6232:"LOONGARCH32",0x6264:"LOONGARCH64"}

PE_SUBSYSTEMS={1:"native",2:"windows",3:"console",5:"os2",7:"posix",8:"win9x-driver",9:"wince",
    10:"efi-app",11:"efi-boot",12:"efi-runtime",13:"efi-rom",14:"xbox",16:"boot-app"}

# szekcionev -> packer
PE_PACKER_SECTIONS={"UPX0":"UPX","UPX1":"UPX","UPX2":"UPX",".UPX0":"UPX",".UPX1":"UPX",
    "PEC2":"PECompact","PEC2TO":"PECompact","PEC2MO":"PECompact","pec1":"PECompact","pec2":"PECompact",
    ".aspack":"ASPack",".adata":"ASPack",".MPRESS1":"MPRESS",".MPRESS2":"MPRESS",
    ".petite":"Petite",".nsp0":"NsPack",".nsp1":"NsPack","nsp0":"NsPack",
    ".themida":"Themida",".winlice":"WinLicense",".vmp0":"VMProtect",".vmp1":"VMProtect",
    ".enigma1":"Enigma",".enigma2":"Enigma","MEW":"MEW",".packed":"RLPack",".RLPack":"RLPack",
    "kkrunchy":"kkrunchy",".yP":"Y0da",".y0da":"Y0da","PELOCKnt":"PELock",".perplex":"Perplex",
    "FSG!":"FSG",".spack":"SimplePack","ExeS":"EXE Stealth",".ccg":"CCG","_winzip_":"WinZip SFX"}

# a fejlec teruleten keresett packer-szovegek
PE_PACKER_STRINGS=((b"PECompact2","PECompact"),(b"UPX!","UPX"),(b"$Id: UPX","UPX"))

class PEParser:

    def __init__(self,data,pe_off):
        self.data=data
        self.pe_off=pe_off
        self.errors=[]
        self.suppressed=0

    def error(self,text):
        if len(self.errors)<MAX_ERRORS:
            log(0,"ERROR: "+text)
            self.errors.append(text)
        else:
            self.suppressed+=1

    def rva2off(self,rva):
        """RVA -> file offset, None ha nincs a fileban (pl. .bss, vagy ervenytelen)."""
        if rva is None: return None
        for name,vsize,va,rawsize,rawptr,rawptr_eff,flags in self.sections:
            span=max(vsize,rawsize) if vsize else rawsize
            if va<=rva<va+span:
                if rva-va>=rawsize or not rawptr: return None  # nem file-bol toltott (nullazott) resz
                off=rawptr_eff+(rva-va)
                return off if off<len(self.data) else None
        # fejlec terulet (az elso szekcio elott)
        if rva<self.first_va and rva<len(self.data):
            return rva
        return None

    def read_thunks(self,rva,namebase=0):
        """Import (lookup/address) tabla szimbolumai. namebase: a nev-pointerekbol levonando ertek (VA eseten)"""
        data=self.data
        off=self.rva2off(rva)
        if off is None:
            raise struct.error("thunk table RVA 0x%X not in file"%(rva))
        if self.bits==64: fmt,step,ordflag="<Q",8,1<<63
        else: fmt,step,ordflag="<I",4,1<<31
        syms=[]
        bad=0
        while len(syms)<MAX_SYMS:
            v,=unpack(fmt,data,off)
            off+=step
            if v==0: break
            if v&ordflag:
                syms.append("#%d"%(v&0xFFFF))
            else:
                o=self.rva2off((v-namebase)&0x7FFFFFFF)
                if o is None:
                    self.error("import name RVA 0x%X not in file"%(v))
                    syms.append("?0x%X"%(v))
                    bad+=1
                    if bad>=MAX_BAD_IMPORT_NAMES:
                        raise struct.error("too many invalid import names, thunk table is probably garbage")
                else:
                    syms.append(cstr(data,o+2)) # hint + nev
                    bad=0
        return syms

    def parse_imports(self,rva,size):
        data=self.data
        off=self.rva2off(rva)
        if off is None:
            self.error("import directory RVA 0x%X not in file"%(rva))
            return None
        dlls=[]
        try:
            for i in range(MAX_DLLS):
                oft,ts,fwd,name,ft=unpack("<5I",data,off+20*i)
                if name==0 or ft==0: break  # a Windows loader is igy all meg
                entry=[""]
                try:
                    entry[0]=cstr(data,self.rva2off(name),256)
                except struct.error:
                    self.error("import DLL name RVA 0x%X not in file"%(name))
                try:
                    thunk=oft if oft and self.rva2off(oft) is not None else ft
                    entry+=self.read_thunks(thunk)
                except struct.error as e:
                    self.error("error parsing imports of '%s': %s"%(entry[0],e))
                dlls.append(entry)
        except struct.error as e:
            self.error("import directory truncated: %s"%(e))
        return dlls

    def parse_delay_imports(self,rva,size):
        data=self.data
        off=self.rva2off(rva)
        if off is None:
            self.error("delay import directory RVA 0x%X not in file"%(rva))
            return None
        dlls=[]
        try:
            for i in range(MAX_DLLS):
                attrs,name,hmod,iat,int_,biat,uiat,ts=unpack("<8I",data,off+32*i)
                if name==0: break
                namebase=0
                if not attrs&1 and self.bits==32:
                    # regi (VC6/Delphi) formatum: VA-k RVA helyett
                    namebase=self.imagebase
                    name-=namebase; int_-=namebase
                entry=[""]
                try:
                    entry[0]=cstr(data,self.rva2off(name),256)
                except struct.error:
                    self.error("delay import DLL name RVA 0x%X not in file"%(name))
                try:
                    if int_: entry+=self.read_thunks(int_,namebase)
                except struct.error as e:
                    self.error("error parsing delay imports of '%s': %s"%(entry[0],e))
                dlls.append(entry)
        except struct.error as e:
            self.error("delay import directory truncated: %s"%(e))
        return dlls

    def parse_exports(self,rva,size):
        off=self.rva2off(rva)
        if off is None:
            self.error("export directory RVA 0x%X not in file"%(rva))
            return None
        try:
            flags,ts,vmaj,vmin,name,base,nfuncs,nnames=unpack("<IIHHIIII",self.data,off)
            o=self.rva2off(name)
            return {"name":cstr(self.data,o,256) if o is not None else None,"count":nfuncs}
        except struct.error as e:
            self.error("export directory truncated: %s"%(e))
            return None

    def parse(self):
        data=self.data
        r={"type":"PE"}
        machine,nsects,timedate,symptr,nsyms,ohsize,chars=unpack("<HHIIIHH",data,self.pe_off+4)
        oh=self.pe_off+24
        r["machine"]=PE_MACHINES.get(machine,"0x%X"%(machine))
        r["dll"]=bool(chars&0x2000)
        magic=u16(data,oh) if ohsize>=2 else 0
        if magic==0x10B:
            self.bits=32
            (magic,lmaj,lmin,size_code,size_data,size_bss,entry,base_code,base_data,imagebase,
             sect_align,file_align,osmaj,osmin,imgmaj,imgmin,submaj,submin,win32ver,
             image_size,header_size,checksum,subsys,dllchars,
             stack_res,stack_com,heap_res,heap_com,loader_flags,num_dirs)=unpack("<HBB9I6H4I2H6I",data,oh)
            dirs_off=oh+96
        elif magic==0x20B:
            self.bits=64
            (magic,lmaj,lmin,size_code,size_data,size_bss,entry,base_code,imagebase,
             sect_align,file_align,osmaj,osmin,imgmaj,imgmin,submaj,submin,win32ver,
             image_size,header_size,checksum,subsys,dllchars,
             stack_res,stack_com,heap_res,heap_com,loader_flags,num_dirs)=unpack("<HBB5IQ2I6H4I2H4Q2I",data,oh)
            dirs_off=oh+112
        else:
            # hibas/nullazott optional header: a Windows nem toltene be, de a szekciotabla
            # (SizeOfOptionalHeader utan) altalaban ertelmes, abbol meg a meret szamolhato
            self.error("bad PE optional header magic: 0x%X (size=%d)"%(magic,ohsize))
            self.bits=64 if machine in (0x8664,0xaa64,0x200) else 32
            imagebase=file_align=header_size=subsys=num_dirs=0
            dirs_off=oh
        r["bits"]=self.bits
        r["subsystem"]=PE_SUBSYSTEMS.get(subsys,str(subsys))
        self.imagebase=imagebase
        log(0,"PE%s machine=%s subsystem=%s dll=%s"%("32+" if self.bits==64 else "32",r["machine"],r["subsystem"],r["dll"]))
        if num_dirs>16:
            self.error("NumberOfRvaAndSizes=%d"%(num_dirs))
        dirs=[]
        for i in range(min(num_dirs,16)):
            try:
                dirs.append(unpack("<II",data,dirs_off+8*i))
            except struct.error:
                self.error("data directory %d truncated"%(i))
                break
        while len(dirs)<16: dirs.append((0,0))

        # SECTIONS
        self.sections=[]
        sect_off=oh+ohsize
        size=sect_off+40*nsects
        winzip=None
        for i in range(nsects):
            try:
                sname,vsize,va,rawsize,rawptr,relptr,lnptr,nrel,nln,flags=unpack("<8sIIIIIIHHI",data,sect_off+40*i)
            except struct.error:
                self.error("section table truncated (%d/%d)"%(i,nsects))
                break
            name=printable(sname.rstrip(b"\0"))
            # a loader 512-re lefele kerekiti a raw pointert
            rawptr_eff=rawptr&~0x1FF if file_align>=0x200 else rawptr
            self.sections.append((name,vsize,va,rawsize,rawptr,rawptr_eff,flags))
            log(0,"SECT: %-8s raw=0x%08X+0x%08X  va=0x%08X+0x%08X flags=%08X"%(name,rawptr,rawsize,va,vsize,flags))
            if rawptr and rawsize:
                size=max(size,rawptr+rawsize)
            if name=="_winzip_":
                p=data.find(b"PK\3\4",rawptr,rawptr+rawsize)
                winzip=p if p>=0 else rawptr+0x2f
                log(0,"WinZip SFX detected, ZIP file at 0x%08X" % (winzip))
        self.first_va=min([s[2] for s in self.sections] or [header_size])
        firstraw=min([s[4] for s in self.sections if s[4] and s[3]] or [header_size])
        size=max(size,min(header_size,firstraw))

        # az exe-hez tartozo, de szekcion kivuli adatok: debug info, COFF szimbolumtabla, digitalis alairas
        extra=[]
        rva,dsize=dirs[6]
        if rva and dsize:
            off=self.rva2off(rva)
            if off is None:
                self.error("debug directory RVA 0x%X not in file"%(rva))
            else:
                for i in range(min(dsize//28,64)):
                    try:
                        dch,dts,dmaj,dmin,dtype,dlen,drva,dptr=unpack("<IIHHIIII",data,off+28*i)
                    except struct.error:
                        break
                    if dptr and dlen: extra.append((dptr,dlen,"debug"))
        if symptr and nsyms:
            strtab=symptr+18*nsyms
            try:
                strlen=u32(data,strtab)
                if strlen<4: strlen=4
            except struct.error:
                strlen=0
            extra.append((symptr,18*nsyms+strlen,"symbols"))
        cert_off,cert_size=dirs[4]
        r["certificate"]=None
        if cert_off and cert_size:
            r["certificate"]=[cert_off,cert_size]
            if cert_off+cert_size>len(data):
                self.error("certificate table beyond end of file (0x%X+0x%X)"%(cert_off,cert_size))
            else:
                extra.append((cert_off,cert_size,"certificate"))
        for off,length,what in sorted(extra):
            if off+length<=size:                   # szekcion belul van
                if what=="certificate":
                    self.error("certificate table inside image (0x%X+0x%X)"%(off,length))
                continue
            if off>align_up(size,8):
                if what=="certificate":
                    # overlay utani alairas (pl. alairt installer)
                    log(0,"certificate after overlay at 0x%X"%(off))
                else:
                    self.error("%s data after gap at 0x%X+0x%X"%(what,off,length))
                continue
            log(0,"%s data at 0x%X+0x%X"%(what,off,length))
            size=off+length
        if winzip is not None:
            size=winzip
        r["size"]=size

        r["imports"]=None
        r["delay_imports"]=None
        r["exports"]=None
        if dirs[1][0] and dirs[1][1]:
            r["imports"]=self.parse_imports(*dirs[1])
        if dirs[13][0] and dirs[13][1]:
            r["delay_imports"]=self.parse_delay_imports(*dirs[13])
        if dirs[0][0] and dirs[0][1]:
            r["exports"]=self.parse_exports(*dirs[0])

        # packer tipp
        r["packer"]=None
        for s in self.sections:
            if s[0] in PE_PACKER_SECTIONS:
                r["packer"]=PE_PACKER_SECTIONS[s[0]]
                break
        else:
            hdr=data[:0x1000]
            for sig,name in PE_PACKER_STRINGS:
                if sig in hdr:
                    r["packer"]=name
                    break

        r["dotnet"]=None
        rva,dsize=dirs[14]
        if rva and dsize>=16:
            r["dotnet"]=self.parse_dotnet(rva)
        if self.suppressed:
            self.errors.append("... %d more errors suppressed"%(self.suppressed))
        r["errors"]=self.errors
        return r

    def parse_dotnet(self,rva):
        data=self.data
        off=self.rva2off(rva)
        net={"version":None}
        if off is None:
            self.error(".NET header RVA 0x%X not in file"%(rva))
            return net
        try:
            cb,rmaj,rmin,meta_rva,meta_size,flags=unpack("<IHHIII",data,off)
            net["runtime"]="%d.%d"%(rmaj,rmin)
            net["flags"]=flags
            meta_off=self.rva2off(meta_rva)
            log(0,".NET header: v%d.%d flags=0x%X  MetaData: fpos=0x%s len=%d"%(rmaj,rmin,flags,meta_off,meta_size))
            if meta_off is None:
                self.error(".NET metadata RVA 0x%X not in file"%(meta_rva))
                return net
            DotNetMeta(data,meta_off,meta_size,self.error).parse(net)
        except Exception as e:
            self.error(".NET parse error: %s"%(e))
            log(0,"exc:dotnet: %r"%(e))
        return net


#####################################################################
#   .NET metadata
#####################################################################

# coded index: (tag bitek szama, tablak)
DN_CODED={
    "TypeDefOrRef":(2,[2,1,0x1B]),
    "HasConstant":(2,[4,8,0x17]),
    "HasCustomAttribute":(5,[6,4,1,2,8,9,10,0,0x0E,0x17,0x14,0x11,0x1A,0x1B,0x20,0x23,0x26,0x27,0x28,0x2A,0x2C,0x2B]),
    "HasFieldMarshal":(1,[4,8]),
    "HasDeclSecurity":(2,[2,6,0x20]),
    "MemberRefParent":(3,[2,1,0x1A,6,0x1B]),
    "HasSemantics":(1,[0x14,0x17]),
    "MethodDefOrRef":(1,[6,0x0A]),
    "MemberForwarded":(1,[4,6]),
    "Implementation":(2,[0x26,0x23,0x27]),
    "CustomAttributeType":(3,[None,None,6,0x0A,None]),
    "ResolutionScope":(2,[0,0x1A,0x23,1]),
    "TypeOrMethodDef":(1,[2,6]),
}

# oszlopok: 1/2/4 = fix meretu, "S"/"G"/"B" = string/guid/blob heap index, int>=0x100: tabla index (0x100+tabla), str: coded index
T=lambda t: 0x100+t
DN_TABLES={
    0x00:("Module",[2,"S","G","G","G"]),
    0x01:("TypeRef",["ResolutionScope","S","S"]),
    0x02:("TypeDef",[4,"S","S","TypeDefOrRef",T(0x04),T(0x06)]),
    0x03:("FieldPtr",[T(0x04)]),
    0x04:("Field",[2,"S","B"]),
    0x05:("MethodPtr",[T(0x06)]),
    0x06:("MethodDef",[4,2,2,"S","B",T(0x08)]),
    0x07:("ParamPtr",[T(0x08)]),
    0x08:("Param",[2,2,"S"]),
    0x09:("InterfaceImpl",[T(0x02),"TypeDefOrRef"]),
    0x0A:("MemberRef",["MemberRefParent","S","B"]),
    0x0B:("Constant",[1,1,"HasConstant","B"]),
    0x0C:("CustomAttribute",["HasCustomAttribute","CustomAttributeType","B"]),
    0x0D:("FieldMarshal",["HasFieldMarshal","B"]),
    0x0E:("DeclSecurity",[2,"HasDeclSecurity","B"]),
    0x0F:("ClassLayout",[2,4,T(0x02)]),
    0x10:("FieldLayout",[4,T(0x04)]),
    0x11:("StandAloneSig",["B"]),
    0x12:("EventMap",[T(0x02),T(0x14)]),
    0x13:("EventPtr",[T(0x14)]),
    0x14:("Event",[2,"S","TypeDefOrRef"]),
    0x15:("PropertyMap",[T(0x02),T(0x17)]),
    0x16:("PropertyPtr",[T(0x17)]),
    0x17:("Property",[2,"S","B"]),
    0x18:("MethodSemantics",[2,T(0x06),"HasSemantics"]),
    0x19:("MethodImpl",[T(0x02),"MethodDefOrRef","MethodDefOrRef"]),
    0x1A:("ModuleRef",["S"]),
    0x1B:("TypeSpec",["B"]),
    0x1C:("ImplMap",[2,"MemberForwarded","S",T(0x1A)]),
    0x1D:("FieldRVA",[4,T(0x04)]),
    0x1E:("EncLog",[4,4]),
    0x1F:("EncMap",[4]),
    0x20:("Assembly",[4,2,2,2,2,4,"B","S","S"]),
    0x21:("AssemblyProcessor",[4]),
    0x22:("AssemblyOS",[4,4,4]),
    0x23:("AssemblyRef",[2,2,2,2,4,"B","S","S","B"]),
    0x24:("AssemblyRefProcessor",[4,T(0x23)]),
    0x25:("AssemblyRefOS",[4,4,4,T(0x23)]),
    0x26:("File",[4,"S","B"]),
    0x27:("ExportedType",[4,4,"S","S","Implementation"]),
    0x28:("ManifestResource",[4,4,"S","Implementation"]),
    0x29:("NestedClass",[T(0x02),T(0x02)]),
    0x2A:("GenericParam",[2,2,"TypeOrMethodDef","S"]),
    0x2B:("MethodSpec",["MethodDefOrRef","B"]),
    0x2C:("GenericParamConstraint",[T(0x2A),"TypeDefOrRef"]),
}
del T

class DotNetMeta:

    def __init__(self,data,pos,size,error):
        self.data=data
        self.pos=pos
        self.size=size
        self.error=error

    def string(self,idx):
        if idx>=len(self.strings):
            self.error(".NET string index out of range: %d"%(idx))
            return "?"
        end=self.strings.find(b"\0",idx)
        return self.strings[idx:end if end>=0 else len(self.strings)].decode("utf-8","replace")

    def parse(self,net):
        data=self.data
        pos=self.pos
        sig,vmaj,vmin,reserved,verlen=unpack("<IHHII",data,pos)
        if sig!=0x424A5342:
            self.error("bad .NET metadata signature: 0x%X"%(sig))
            return
        pos+=16
        net["version"]=printable(data[pos:pos+min(verlen,256)])
        pos+=verlen
        flags,nstreams=unpack("<HH",data,pos)
        pos+=4
        log(0,".NET Metadata %s streams=%d len=%d"%(net["version"],nstreams,self.size))
        streams={}
        for i in range(min(nstreams,64)):
            s_off,s_size=unpack("<II",data,pos)
            name=cstr(data,pos+8,32)
            pos=align_up(pos+8+len(name)+1,4)
            log(0,".NET stream: %08X %8d '%s'"%(s_off,s_size,name))
            if name not in streams:   # tobbszoros stream nev: az elso szamit
                streams[name]=(self.pos+s_off,s_size)
        if "#Strings" in streams:
            o,l=streams["#Strings"]
            self.strings=data[o:o+l]
        else:
            self.error(".NET #Strings stream missing")
            self.strings=b""
        tabstream=streams.get("#~") or streams.get("#-")
        if not tabstream:
            self.error(".NET metadata tables stream missing")
            return
        self.parse_tables(tabstream[0],tabstream[0]+tabstream[1],net)

    def parse_tables(self,pos,end,net):
        data=self.data
        reserved,tmaj,tmin,heapsizes,reserved2,valid,sorted_=unpack("<IBBBBQQ",data,pos)
        pos+=24
        rows={}
        for t in range(64):
            if valid&(1<<t):
                rows[t]=u32(data,pos)
                pos+=4
                log(0,"Table 0x%02X [%s]: %d"%(t,DN_TABLES.get(t,("?",))[0],rows[t]))
        if heapsizes&0x40:
            pos+=4  # extra data
        strsize=4 if heapsizes&1 else 2
        guidsize=4 if heapsizes&2 else 2
        blobsize=4 if heapsizes&4 else 2

        def colsize(c):
            if c in (1,2,4): return c
            if c=="S": return strsize
            if c=="G": return guidsize
            if c=="B": return blobsize
            if isinstance(c,int): return 2 if rows.get(c-0x100,0)<0x10000 else 4
            bits,tabs=DN_CODED[c]
            m=max(rows.get(t,0) for t in tabs if t is not None)
            return 2 if m<(1<<(16-bits)) else 4

        # tablak beolvasasa (csak ami kell, a tobbit atugorjuk)
        need=(0x01,0x1A,0x1C,0x20,0x23)
        tables={}
        for t in sorted(rows):
            if t not in DN_TABLES:
                self.error(".NET unknown metadata table 0x%02X"%(t))
                break
            cols=DN_TABLES[t][1]
            fmt="<"+"".join({1:"B",2:"H",4:"I"}[colsize(c)] for c in cols)
            rowlen=struct.calcsize(fmt)
            n=rows[t]
            if pos+n*rowlen>end:
                self.error(".NET metadata table 0x%02X exceeds stream"%(t))
                break
            if t in need:
                tables[t]=[struct.unpack_from(fmt,data,pos+i*rowlen) for i in range(n)]
            pos+=n*rowlen

        s=self.string
        ver=lambda r: "%d.%d.%d.%d"%(r[0],r[1],r[2],r[3])
        if tables.get(0x20):
            a=tables[0x20][0]
            net["assembly"]=[s(a[7]),ver(a[1:5])]
        else:
            net["assembly"]=None
        refs=tables.get(0x23,[])
        net["assembly_refs"]=[[s(r[6]),ver(r)] for r in refs]
        modrefs=[s(r[0]) for r in tables.get(0x1A,[])]

        # TypeRef-ek szetosztasa assembly-k (vagy modulok) szerint
        typerefs=tables.get(0x01,[])
        def tr_name(i,depth=0):
            scope,name,ns=typerefs[i]
            name=s(name)
            if ns: name=s(ns)+"."+name
            if scope&3==3 and 0<(scope>>2)<=len(typerefs) and depth<16:
                outer,owner=tr_name((scope>>2)-1,depth+1)
                return outer+"/"+name,owner
            return name,scope
        imports={}
        for i in range(len(typerefs)):
            name,scope=tr_name(i)
            tag,idx=scope&3,scope>>2
            if tag==2 and 0<idx<=len(refs): owner=net["assembly_refs"][idx-1][0]
            elif tag==1 and 0<idx<=len(modrefs): owner=modrefs[idx-1]
            elif tag==0: owner=""       # sajat modul
            else: owner="?"
            imports.setdefault(owner,[]).append(name)
        net["imports"]=[[a]+imports.pop(a) for a,v in net["assembly_refs"] if a in imports]
        net["imports"]+=[[a]+t for a,t in imports.items()]

        # P/Invoke (DllImport): natív DLL fuggosegek
        pinvoke={}
        for flags,member,name,scope in tables.get(0x1C,[]):
            mod=modrefs[scope-1] if 0<scope<=len(modrefs) else "?"
            pinvoke.setdefault(mod,[]).append(s(name))
        net["pinvoke"]=[[m]+f for m,f in pinvoke.items()]


#####################################################################
#   NE (16-bit Windows / OS/2)
#####################################################################

NE_OS={0:"unknown",1:"os2",2:"windows",3:"dos4",4:"win386",5:"boss"}

def dump_ne(data,ne):
    r={"type":"NE","bits":16,"errors":[]}
    (magic,lver,lrev,enttab,entlen,crc,flags,autodata,heap,stack,csip,sssp,nseg,nmod,nrnamsize,
     segtab,rsrctab,restab,modtab,imptab,nrnamtab,nmovent,shift,nres,os,flags2)=unpack("<HBBHHIHHHHIIHHHHHHHHIHHHBB",data,ne)
    r["os"]=NE_OS.get(os,str(os))
    if shift==0: shift=9
    size=ne+max(0x40,enttab+entlen,segtab+8*nseg,modtab+2*nmod,restab,imptab)
    if nrnamtab and nrnamsize:
        size=max(size,nrnamtab+nrnamsize)
    try:
        r["module"]=pstr(data,ne+restab)
    except IndexError:
        r["module"]=None
    # importalt modulok
    mods=[]
    for i in range(nmod):
        try:
            mods.append([pstr(data,ne+imptab+u16(data,ne+modtab+2*i))])
        except (IndexError,struct.error):
            r["errors"].append("NE module reference %d out of range"%(i))
            mods.append(["?"])
    # szegmensek (+ relokacios adatok, ezekbol jonnek az importalt fuggvenyek)
    for i in range(nseg):
        try:
            soff,slen,sflags,smin=unpack("<4H",data,ne+segtab+8*i)
        except struct.error:
            r["errors"].append("NE segment table truncated")
            break
        if not soff: continue
        start=soff<<shift
        end=start+(slen or 0x10000)
        if sflags&0x100:   # relokacios adat a szegmens utan
            try:
                nrel=u16(data,end)
                for j in range(nrel):
                    rtype,rflags,roff,a,b=unpack("<BBHHH",data,end+2+8*j)
                    if rflags&3 in (1,2) and 0<a<=len(mods):
                        if rflags&3==1: fn="#%d"%(b)
                        else: fn=pstr(data,ne+imptab+b)
                        if fn not in mods[a-1]: mods[a-1].append(fn)
                end+=2+8*nrel
            except (IndexError,struct.error):
                r["errors"].append("NE relocations of segment %d truncated"%(i+1))
        log(0,"NE SEG %d: 0x%X-0x%X flags=0x%X"%(i+1,start,end,sflags))
        size=max(size,end)
    # resource-ok
    if rsrctab!=restab:
        try:
            p=ne+rsrctab
            rshift=u16(data,p)
            p+=2
            while 1:
                typeid,cnt=unpack("<HH",data,p)
                if typeid==0: break
                p+=8
                for j in range(cnt):
                    roff,rlen=unpack("<HH",data,p)
                    size=max(size,(roff<<rshift)+(rlen<<rshift))
                    p+=12
        except struct.error:
            r["errors"].append("NE resource table truncated")
    r["size"]=size
    r["imports"]=mods
    return r


#####################################################################
#   LE / LX (DOS extender, OS/2, VxD)
#####################################################################

LE_OS={0:"unknown",1:"os2",2:"windows",3:"dos4",4:"win386"}

# DOS extenderek a stubban (a sorrend szamit: a DOS/32A stub a DOS/4G szoveget is tartalmazza)
DOS_EXTENDERS=((b"DOS/32A","DOS/32A"),(b"STUB/32A","DOS/32A"),(b"STUB/32C","DOS/32A"),(b"DOS32A.EXE","DOS/32A"),
    (b"PMODE/W","PMODE/W"),(b"CauseWay","CauseWay"),(b"WDOSX","WDOSX"),
    (b"DOS4GPATH","DOS/4GW"),(b"DOS/4G","DOS/4GW"),(b"dos4gw.exe","DOS/4GW"))

def dos_extender(stub):
    for sig,name in DOS_EXTENDERS:
        if sig in stub: return name
    return None

def dump_lx(data,h,kind):
    r={"type":kind,"bits":32,"errors":[]}
    g=lambda o: u32(data,h+o)
    r["os"]=r["os_header"]=LE_OS.get(u16(data,h+0x0A),str(u16(data,h+0x0A)))
    # a DOS extenderes programok fejleceben tipikusan OS/2 all (Watcom), valojaban DOS alatt futnak
    r["extender"]=dos_extender(data[:h])
    if r["extender"]: r["os"]="dos"
    npages,psize,last_or_shift=g(0x14),g(0x28),g(0x2C)
    datapages=g(0x80)
    size=h+0xB0
    # loader + fixup szekcio (a fejlec utan)
    size=max(size,h+g(0x40)+g(0x38),h+g(0x68)+g(0x30) if g(0x68) else 0)
    if kind=="LE":
        if npages:
            size=max(size,datapages+(npages-1)*psize+last_or_shift)
    else:
        pagetab=h+g(0x48)
        iterpages=g(0x4C)
        for i in range(npages):
            try:
                poff,plen,pflags=unpack("<IHH",data,pagetab+8*i)
            except struct.error:
                r["errors"].append("LX page table truncated")
                break
            if pflags in (0,1,5) and plen:   # fizikai, iteralt, tomoritett lap
                base=iterpages if pflags==1 else datapages
                pend=base+(poff<<last_or_shift)+plen
                # a Watcom linker a lap hosszat a lapeltolas igazitasara kerekiti: az utolso lap
                # legfeljebb egy igazitasi egyseggel tulnyulhat a file vegen (a loader nullakkal tolti)
                if len(data)<pend<len(data)+(1<<last_or_shift) and base+(poff<<last_or_shift)<len(data):
                    pend=len(data)
                size=max(size,pend)
    if g(0x88) and g(0x8C):   # non-resident names
        size=max(size,g(0x88)+g(0x8C))
    if g(0x98) and g(0x9C):   # debug info
        size=max(size,g(0x98)+g(0x9C))
    try:
        r["module"]=pstr(data,h+g(0x58))
    except IndexError:
        r["module"]=None
    mods=[]
    p=h+g(0x70)
    for i in range(g(0x74)):
        try:
            name=pstr(data,p)
        except IndexError:
            r["errors"].append("%s import module table truncated"%(kind))
            break
        mods.append([name])
        p+=1+len(name)
    r["imports"]=mods
    r["size"]=size
    return r


#####################################################################
#   LC (DOS/32A "Linear Compressed", SUNSYS Compress Utility / sc.exe)
#   forras: DOS/32A src/sc/scomp.asm (iro) es src/dos32a/loadlc.asm (loader)
#
#   LC fejlec (16 byte):
#     0000 DD "LC\0\0"
#     0004 DB objektumok szama
#     0005 DB flagek: bit0..3 = LC verzio (a loader csak 4-et fogad el), bit7 = OEM info a vegen
#     0006 DB EIP objektum, 0007 DB ESP objektum, 0008 DD EIP, 000C DD ESP
#   minden objektum: 16 byte fejlec + tomoritett adat
#     0000 DD virtualis meret (bit31: 1=nem tomoritett), 0004 DD tomoritett meret,
#     0008 DW flagek, 000A DW ext. flagek, 000C DW page table index, 000E DW page table bejegyzesek
#   fixupok: 12 byte fejlec + tomoritett adat
#     0000 DD kicsomagolt meret (bit31: 1=nem tomoritett), 0004 DD tomoritett meret,
#     0008 DD fixup record tabla offset
#   ha flagek&0x80: OEM szoveg (max. 512 byte) + lezaro 0
#####################################################################

LC_SPECVER=4

def dump_lc(data,h):
    r={"type":"LC","bits":32,"os":"dos","extender":"DOS/32A","packer":"DOS/32A SC","imports":None,"errors":[]}
    nobj,flags,eipobj,espobj,eip,esp=unpack("<BBBBII",data,h+4)
    if flags&0x0F!=LC_SPECVER:
        r["errors"].append("unsupported LC version: %d"%(flags&0x0F))
    p=h+16
    for i in range(nobj):
        vsize,csize,oflags,xflags,pti,npte=unpack("<IIHHHH",data,p)
        log(0,"LC OBJ %d: 0x%X+0x%X vsize=0x%X%s flags=0x%X"%(i+1,p,csize,vsize&0x7FFFFFFF,
            "" if vsize&0x80000000 else " (compressed)",oflags))
        p+=16+csize
    usize,csize,frtoff=unpack("<III",data,p)
    log(0,"LC FIXUPS: 0x%X+0x%X size=0x%X"%(p,csize,usize&0x7FFFFFFF))
    p+=12+csize
    if flags&0x80 and p>=len(data):
        r["errors"].append("LC OEM info missing (file truncated)")
    elif flags&0x80:
        end=data.find(b"\0",p,p+513)
        if end<0:
            r["errors"].append("LC OEM info not terminated")
            end=min(len(data),p+513)-1
        r["oem"]=data[p:end].decode("latin-1")
        p=end+1
    r["objects"]=nobj
    r["size"]=p
    return r


#####################################################################
#   DOS/16M "BW" (Rational Systems / Tenberry; a DOS/4GW kernel is ilyen)
#   Open Watcom exe16m.h: dos16m_exe_header: "BW", last_page_bytes, pages_in_file (mint az MZ),
#   ... 0x1C next_header_pos (a kovetkezo hozzafuzott .EXP image file pozicioja),
#   0x20 cv_info_offset (debug info az image elejetol), 0x30+4 exp_flags (0x8000: DOS/4G)
#####################################################################

def dump_bw(data,pos):
    r={"type":"BW","bits":16,"os":"dos","imports":None,"errors":[]}
    r["extender"]=dos_extender(data[:pos]) or "DOS/16M"
    p=pos; images=0; end=pos; seen=set()
    while p is not None and p not in seen and images<256:
        seen.add(p)
        if data[p:p+2]!=b"BW":
            if data[p:p+2] in (b"LE",b"LX"):
                # a lanc egy (4GWBIND-dal kotott) LE/LX alkalmazasba torkollik
                app=dump_lx(data,p,data[p:p+2].decode())
                r["bound_app"]=app["type"]
                for k in ("module","imports"): r[k]=app.get(k)
                r["errors"]+=app["errors"]
                end=max(end,app["size"])
            break
        last,pages=unpack("<HH",data,p+2)
        nxt,cv=unpack("<II",data,p+0x1C)
        flags=u16(data,p+0x34)
        if flags&0x8000: r["extender"]="DOS/4GW"
        isize=pages*512-((512-last) if last else 0)
        images+=1
        end=max(end,p+isize,p+cv if cv else 0)
        if not nxt or nxt<=p or nxt>=len(data): 
            if nxt>p: end=max(end,min(nxt,len(data)))
            break
        end=max(end,nxt)
        p=nxt
    r["images"]=images
    r["size"]=end
    return r


#####################################################################
#   DJGPP COFF (go32 stub + COFF image)
#####################################################################

# 4C 01 03 00 │ 00 00 00 00 │ 00 00 00 00 │ 00 00 00 00 │ 1C 00 0F 01 │ 0B 01 00 00 │ 58 BB 02 00 │ 00 30 00 00 │ 00 CE 00 00  L.......................X....0......
def dump_coff(data,pos):
    """COFF image merete (a COFF fejlectol szamolva), 0 ha hibas."""
    magic,nscns,timdat,symptr,nsyms,opthdr,flags=unpack("<HHIIIHH",data,pos)
    if pos+20+opthdr>len(data): return 0 # bad
    coffsize=20+opthdr+40*nscns
    for i in range(nscns):
        sect=data[pos+20+opthdr+40*i:pos+20+opthdr+40*i+40]
        if len(sect)<40: return 0
        name,paddr,vaddr,ssize,scnptr=struct.unpack_from("<8sIIII",sect)
        if scnptr and scnptr+ssize>coffsize: coffsize=scnptr+ssize
    if symptr and nsyms:
        strtab=symptr+18*nsyms
        try:
            coffsize=max(coffsize,strtab+max(4,u32(data,pos+strtab)))
        except struct.error:
            coffsize=max(coffsize,strtab)
    return coffsize


#####################################################################
#   ELF (Linux, BSD, Solaris, ...)
#####################################################################

ELF_MACHINES={0:"none",2:"SPARC",3:"i386",4:"m68k",8:"MIPS",10:"MIPS-RS3-LE",15:"PA-RISC",18:"SPARC32PLUS",
    20:"PowerPC",21:"PowerPC64",22:"S390",40:"ARM",42:"SuperH",43:"SPARCV9",50:"IA64",62:"AMD64",
    183:"AArch64",243:"RISCV",247:"BPF",258:"LoongArch"}
ELF_OSABI={0:"sysv",1:"hpux",2:"netbsd",3:"linux",6:"solaris",7:"aix",8:"irix",9:"freebsd",
    12:"openbsd",97:"arm",255:"standalone"}
ELF_TYPES={0:"NONE",1:"REL",2:"EXEC",3:"DYN",4:"CORE"}

DT_NEEDED,DT_HASH,DT_STRTAB,DT_SYMTAB,DT_STRSZ,DT_SYMENT,DT_SONAME=1,4,5,6,10,11,14
DT_GNU_HASH,DT_VERSYM,DT_VERNEED,DT_VERNEEDNUM=0x6ffffef5,0x6ffffff0,0x6ffffffe,0x6fffffff
MAX_ELF_SYMS=1000000

def dump_elf(data):
    if len(data)<52: return None
    cls,enc,ver,osabi=data[4],data[5],data[6],data[7]
    if cls not in (1,2) or enc not in (1,2): return None
    E="<" if enc==1 else ">"
    is64=cls==2
    r={"type":"ELF","bits":64 if is64 else 32,"errors":[]}
    errors=r["errors"]
    if is64:
        (etype,machine,version,entry,phoff,shoff,flags,ehsize,phentsize,phnum,
         shentsize,shnum,shstrndx)=unpack(E+"HHIQQQIHHHHHH",data,16)
    else:
        (etype,machine,version,entry,phoff,shoff,flags,ehsize,phentsize,phnum,
         shentsize,shnum,shstrndx)=unpack(E+"HHIIIIIHHHHHH",data,16)
    r["elf_type"]=ELF_TYPES.get(etype,"0x%X"%(etype))
    r["machine"]=ELF_MACHINES.get(machine,"0x%X"%(machine))
    r["os"]=ELF_OSABI.get(osabi,str(osabi))
    r["endian"]="little" if enc==1 else "big"
    size=max(ehsize,52 if not is64 else 64)

    # program headerek (szegmensek)
    segs=[]
    phfmt=E+("IIQQQQQQ" if is64 else "IIIIIIII")
    if phoff and phnum:
        if phentsize<struct.calcsize(phfmt):
            errors.append("bad e_phentsize: %d"%(phentsize))
        else:
            size=max(size,phoff+phnum*phentsize)
            for i in range(phnum):
                try:
                    v=unpack(phfmt,data,phoff+i*phentsize)
                except struct.error:
                    errors.append("program header table truncated")
                    break
                if is64: ptype,pflags,poff,pvaddr,ppaddr,pfilesz,pmemsz,palign=v
                else: ptype,poff,pvaddr,ppaddr,pfilesz,pmemsz,pflags,palign=v
                segs.append((ptype,poff,pvaddr,pfilesz,pmemsz))
                if pfilesz: size=max(size,poff+pfilesz)

    # section headerek
    sects=[]
    shfmt=E+("IIQQQQIIQQ" if is64 else "IIIIIIIIII")
    if shoff:
        try:
            if shnum==0 or shstrndx==0xFFFF:
                # sok szekcio: a valodi szam/strndx a 0. szekcio fejleceben
                v=unpack(shfmt,data,shoff)
                if shnum==0: shnum=v[5]
                if shstrndx==0xFFFF: shstrndx=v[6]
            if shentsize<struct.calcsize(shfmt):
                errors.append("bad e_shentsize: %d"%(shentsize))
            else:
                shnum=min(shnum,65536)
                size=max(size,shoff+shnum*shentsize)
                for i in range(shnum):
                    try:
                        v=unpack(shfmt,data,shoff+i*shentsize)
                    except struct.error:
                        errors.append("section header table truncated")
                        break
                    sname,stype,sflags,saddr,soff,ssize,slink,sinfo,salign,sentsize=v
                    sects.append((sname,stype,saddr,soff,ssize,slink,sentsize))
                    if stype not in (0,8) and ssize:     # SHT_NULL, SHT_NOBITS (.bss) nincs a fileban
                        size=max(size,soff+ssize)
        except struct.error:
            errors.append("section header table out of file")
    r["size"]=size

    def va2off(va):
        for ptype,poff,pvaddr,pfilesz,pmemsz in segs:
            if ptype==1 and pvaddr<=va<pvaddr+pfilesz:
                return poff+va-pvaddr
        for sname,stype,saddr,soff,ssize,slink,sentsize in sects:  # pl. REL (.o) file-oknal
            if saddr and stype!=8 and saddr<=va<saddr+ssize:
                return soff+va-saddr
        return None

    for ptype,poff,pvaddr,pfilesz,pmemsz in segs:
        if ptype==3:                                   # PT_INTERP
            r["interpreter"]=cstr(data,poff,min(pfilesz,4096) or 1).rstrip("\0")
    r.setdefault("interpreter",None)

    # dinamikus szekcio
    dyn=None
    for ptype,poff,pvaddr,pfilesz,pmemsz in segs:
        if ptype==2: dyn=(poff,pfilesz)
    if dyn is None:
        for sname,stype,saddr,soff,ssize,slink,sentsize in sects:
            if stype==6: dyn=(soff,ssize)              # SHT_DYNAMIC
    r["imports"]=None
    r["soname"]=None
    r["packer"]="UPX" if b"UPX!" in data[:0x1000] else None
    r["dll"]=etype==3 and r["interpreter"] is None
    if dyn is None:
        return r

    dfmt=E+("qQ" if is64 else "iI")
    dsz=struct.calcsize(dfmt)
    tags={}
    needed=[]
    for i in range(min(dyn[1]//dsz,100000)):
        try:
            tag,val=unpack(dfmt,data,dyn[0]+i*dsz)
        except struct.error:
            errors.append("dynamic section truncated")
            break
        if tag==0: break
        if tag==DT_NEEDED: needed.append(val)
        elif tag==DT_SONAME: tags["soname"]=val
        else: tags.setdefault(tag,val)
    stroff=va2off(tags.get(DT_STRTAB,0)) if DT_STRTAB in tags else None
    if stroff is None:
        errors.append("DT_STRTAB not in file")
        r["imports"]=[]
        return r
    def dstr(o):
        try: return cstr(data,stroff+o,4096)
        except struct.error: return "?"
    libs=[dstr(o) for o in needed]
    if "soname" in tags: r["soname"]=dstr(tags["soname"])

    # importalt szimbolumok: .dynsym-bol az undefined globalis/weak szimbolumok
    symfmt=E+("IBBHQQ" if is64 else "IIIBBH")
    symsz=struct.calcsize(symfmt)
    symoff=va2off(tags[DT_SYMTAB]) if DT_SYMTAB in tags else None
    nsyms=None
    for sname,stype,saddr,soff,ssize,slink,sentsize in sects:
        if stype==11 and sentsize:                     # SHT_DYNSYM
            nsyms=ssize//sentsize
            if symoff is None: symoff=soff
    if nsyms is None and symoff is not None:
        nsyms=_elf_nsyms(data,E,is64,tags,va2off)
    syms=[]
    if symoff is not None and nsyms:
        for i in range(min(nsyms,MAX_ELF_SYMS)):
            try:
                v=unpack(symfmt,data,symoff+i*symsz)
            except struct.error:
                errors.append("dynamic symbol table truncated")
                break
            if is64: name,info,other,shndx,value,ssize=v
            else: name,value,ssize,info,other,shndx=v
            syms.append((name,info>>4,shndx))
    # symbol versioning: melyik szimbolum melyik konyvtarbol jon
    verlib={}
    if DT_VERNEED in tags:
        p=va2off(tags[DT_VERNEED])
        for i in range(min(tags.get(DT_VERNEEDNUM,0),1000)):
            if p is None: break
            try:
                vn_ver,vn_cnt,vn_file,vn_aux,vn_next=unpack(E+"HHIII",data,p)
                a=p+vn_aux
                for j in range(min(vn_cnt,1000)):
                    vna_hash,vna_flags,vna_other,vna_name,vna_next=unpack(E+"IHHII",data,a)
                    verlib[vna_other]=dstr(vn_file)
                    if not vna_next: break
                    a+=vna_next
            except struct.error:
                errors.append("version needed table truncated")
                break
            if not vn_next: break
            p+=vn_next
    versym=va2off(tags[DT_VERSYM]) if DT_VERSYM in tags else None
    groups={lib:[] for lib in libs}
    other=[]
    for i,(name,bind,shndx) in enumerate(syms):
        if shndx!=0 or bind not in (1,2) or not name: continue    # csak az importalt (undefined) szimbolumok
        n=dstr(name)
        lib=None
        if versym is not None:
            try:
                vi=unpack(E+"H",data,versym+2*i)[0]&0x7FFF
                lib=verlib.get(vi)
            except struct.error:
                pass
        if lib is None: other.append(n)
        else: groups.setdefault(lib,[]).append(n)
    imports=[[lib]+groups[lib] for lib in groups]
    if other: imports.append(["*"]+other)     # verzio nelkuli szimbolumok: barmelyik konyvtarbol johetnek
    r["imports"]=imports
    return r

def _elf_nsyms(data,E,is64,tags,va2off):
    """A dinamikus szimbolumok szama section headerek nelkul: DT_HASH vagy DT_GNU_HASH alapjan."""
    if DT_HASH in tags:
        o=va2off(tags[DT_HASH])
        if o is not None:
            return unpack(E+"II",data,o)[1]           # nchain
    if DT_GNU_HASH in tags:
        o=va2off(tags[DT_GNU_HASH])
        if o is None: return None
        nbuckets,symoffset,bloomsize,bloomshift=unpack(E+"IIII",data,o)
        buckets=o+16+bloomsize*(8 if is64 else 4)
        last=0
        for i in range(min(nbuckets,1000000)):
            last=max(last,unpack(E+"I",data,buckets+4*i)[0])
        if last<symoffset: return symoffset
        chains=buckets+4*nbuckets
        while last-symoffset<MAX_ELF_SYMS:
            if unpack(E+"I",data,chains+4*(last-symoffset))[0]&1: break
            last+=1
        return last+1
    return None


#####################################################################
#   MZ (DOS)
#####################################################################

def dos_packer(data):
    hdr=data[:0x200]
    if b"PKLITE" in hdr: return "PKLITE"
    if data[0x1C:0x20] in (b"LZ09",b"LZ91"): return "LZEXE"
    if b"diet" in hdr[0x1C:0x40]: return "DIET"
    if b"UPX!" in data[:0x400]: return "UPX"
    return None

def dump_exe(data):
    """data: a teljes file tartalma (bytes). Visszaad: None vagy dict (lasd a modul leirasat)"""
    if data[:4]==b"\x7fELF":
        try:
            r=dump_elf(data)
        except Exception as e:
            log(0,"exc:elf: %r"%(e))
            r={"type":"ELF","size":min(len(data),64),"imports":None,"errors":["ELF parse error: %s"%(e)]}
        if r is None: return None
        return finish_result(data,r)
    if len(data)<0x1C or data[:2] not in (b"MZ",b"ZM"):
        return None
# 4D 5A 26 01   1E 00 01 00   06 00 88 0C   FF FF 00 00   40 5E 00 00   00 01 F0 FF   52 00 00 00
# M  Z  size_l size_h relocs hdrsize allmin/max   SS      SP    CRC     IP    CS     reloff  ovl
    size_l,size_h,relocs,hdrsize,allocmin,allocmax,SS,SP,CRC,IP,CS,relocoff,ovl = unpack("<13H",data,2)
    mz_valid=size_l<=512 and size_h>0
    mzsize=size_h*512
    if size_l:
        mzsize+=size_l-512
    ne_off=u32(data,0x3C) if len(data)>=0x40 else 0
    sig=data[ne_off:ne_off+4] if 4<=ne_off<len(data) else b""
    log(0,"MZ size=0x%X  new header at 0x%X: %r"%(mzsize,ne_off,sig[:2]))

    r=None
    if sig==b"PE\0\0":
        # a Windows loader nem nezi a DOS fejlec tobbi mezojet
        try:
            r=PEParser(data,ne_off).parse()
        except Exception as e:
            log(0,"exc:pe: %r"%(e))
            r={"type":"PE","size":max(mzsize,ne_off+24),"imports":None,"errors":["PE parse error: %s"%(e)]}
    elif not mz_valid:
        log(1,"invalid MZ file, probably text? (size=%d,%d)"%(size_l,size_h))
        return None
    else:
        coff=data[mzsize:mzsize+20]
        if len(coff)==20 and coff[0]==0x4C and coff[1]==1 and coff[2]>0 and coff[3]==0:
            coffsize=dump_coff(data,mzsize)
            if coffsize:
                r={"type":"COFF","size":mzsize+coffsize,"imports":None,"errors":[]}
        if r is None and data[mzsize:mzsize+2]==b"BW":
            try:
                r=dump_bw(data,mzsize)
            except Exception as e:
                log(0,"exc:bw: %r"%(e))
                r={"type":"BW","size":mzsize,"imports":None,"errors":["BW parse error: %s"%(e)]}
        if r is None and ne_off>=0x40 and sig[:2] in (b"NE",b"LE",b"LX",b"LC"):
            kind=sig[:2].decode()
            try:
                if kind=="NE": r=dump_ne(data,ne_off)
                elif kind in ("LE","LX"): r=dump_lx(data,ne_off,kind)
                else: r=dump_lc(data,ne_off)
            except Exception as e:
                log(0,"exc:ne_le_lc %s: %r"%(kind,e))
                r={"type":kind,"size":max(mzsize,ne_off),"imports":None,"errors":["%s parse error: %s"%(kind,e)]}
        if r is None:
            r={"type":"MZ","size":mzsize,"imports":None,"errors":[],"packer":dos_packer(data)}
            # maga a DOS program egy extender (kotetlen stub vagy runtime, pl. DOS32A.EXE, PMODE/W stub)
            ext=dos_extender(data[:mzsize])
            if ext: r["extender"]=ext
    return finish_result(data,r)

def appended_debug(data,size):
    """A file vegere fuzott debug info (Watcom/DOS linkerek): (formatum, kezdete) vagy None.
    TIS (Tool Interface Standard) trailer: "TIS\0" ... u32 meret a file vegen (DWARF: ELF konteiner);
    regi Watcom: 0x8386 szignaturaju master header a file vegen, u32 debug_size;
    CodeView: "NB0x"/"NB1x" + u32 offset a file vegen."""
    n=len(data)
    if n-size<16: return None
    t=data[-16:]
    if t[:4]==b"TIS\0":
        start=n-u32(data,n-4)
        if start>=0:
            return ("DWARF" if data[start:start+4]==b"\x7fELF" else "TIS"),start
    if u16(data,n-14)==0x8386:
        start=n-u32(data,n-4)
        if start>=0: return "Watcom",start
    if data[n-8:n-6]==b"NB" and data[n-6:n-4].isdigit():
        start=n-u32(data,n-4)
        if start>=0 and data[start:start+4]==data[n-8:n-4]: return "CodeView "+data[n-8:n-4].decode(),start
    return None

def finish_result(data,r):
    """Kozos resz: csonkolas, overlay, archivum keresese."""
    dbg=appended_debug(data,r["size"])
    if dbg and 0<=dbg[1]-r["size"]<16:   # kozvetlenul (igazitassal) az exe utan: az exe resze
        r["debug"]=dbg[0]
        r["size"]=len(data)
    r["truncated"]=r["size"]>len(data)
    r["overlay"]=detect_overlay(data,r["size"])
    try:
        r.update(find_archive(data,r))
    except Exception as e:
        log(0,"exc:find_archive: %r"%(e))
        r.update({"archive":None,"archive_start":None,"archive_size":None})
        r["errors"].append("archive search error: %s"%(e))
    return r


#####################################################################
#   teszteles
#####################################################################

def iter_files(paths):
    """A megadott fileokat es konyvtarakat (rekurzivan) sorban bejarja."""
    import os
    for path in paths:
        if os.path.isdir(path):
            for root,dirs,files in os.walk(path):
                dirs.sort()
                for name in sorted(files):
                    yield os.path.join(root,name)
        else:
            yield path

def run_one(path):
    """Egy file vizsgalata. Visszaadja: (eredmeny, log szoveg)."""
    import io, contextlib
    out=io.StringIO()
    with open(path,"rb") as f:
        data=f.read()
    with contextlib.redirect_stdout(out):
        ret=dump_exe(data)
    return ret,out.getvalue()

def to_json(ret):
    # tuple -> list, hogy a JSON-bol visszaolvasott ertekkel osszevetheto legyen
    import json
    return json.loads(json.dumps(ret))

def log_summary(text):
    # a behuzott (tobbsoros reszlet) sorok nelkul, hogy atiras utan is osszevetheto legyen
    return [l for l in text.splitlines() if not l.startswith("  ")]

def short(ret):
    if ret is None: return "None"
    s="%s size=0x%X"%(ret["type"],ret["size"])
    if ret.get("bits"): s+=" %dbit"%(ret["bits"])
    if ret.get("dll"): s+=" DLL"
    if ret.get("os"): s+=" os=%s"%(ret["os"])
    if ret.get("extender"): s+=" extender=%s"%(ret["extender"])
    if ret.get("images"): s+=" images=%d"%(ret["images"])
    if ret.get("debug"): s+=" debug=%s"%(ret["debug"])
    if ret.get("packer"): s+=" packer=%s"%(ret["packer"])
    if ret.get("overlay"): s+=" overlay=%s"%(ret["overlay"])
    if ret.get("archive"):
        s+=" archive=%s@0x%X+0x%X"%(ret["archive"],ret["archive_start"],ret["archive_size"])
        if ret.get("sfx_script"): s+=" sfx_script=[%s]"%(", ".join(ret["sfx_script"]))
    if ret.get("truncated"): s+=" TRUNCATED"
    dlls=ret.get("imports")
    if dlls: s+=" imports=[%s]"%(", ".join(d[0] for d in dlls))
    if ret.get("delay_imports"): s+=" delay=[%s]"%(", ".join(d[0] for d in ret["delay_imports"]))
    net=ret.get("dotnet")
    if net:
        s+=" .NET %s"%(net.get("version"))
        if net.get("assembly_refs"): s+=" refs=[%s]"%(", ".join(a for a,v in net["assembly_refs"]))
        if net.get("pinvoke"): s+=" pinvoke=[%s]"%(", ".join(d[0] for d in net["pinvoke"]))
    if ret.get("errors"): s+=" ERRORS=%d"%(len(ret["errors"]))
    return s


if __name__ == '__main__':
  import sys, json, argparse
  ap=argparse.ArgumentParser(description="DOS/Windows EXE elemzo es tesztelo")
  ap.add_argument("paths",nargs="+",help="vizsgalando fileok/konyvtarak")
  ap.add_argument("-v","--verbose",action="store_true",help="debug log")
  ap.add_argument("-e","--errors",action="store_true",help="elemzesi hibak kiirasa")
  ap.add_argument("-s","--save",metavar="JSON",help="eredmenyek mentese")
  ap.add_argument("-c","--compare",metavar="JSON",help="osszevetes korabbi eredmennyel")
  ap.add_argument("-x","--extract",action="store_true",help="exe utani adat kiirasa <file>.dump-ba")
  args=ap.parse_args()
  debug=args.verbose

  results={}
  ref=json.load(open(args.compare)) if args.compare else None
  nfail=nlogdiff=nmissing=0
  for path in iter_files(args.paths):
    try:
      ret,logtext=run_one(path)
    except Exception as e:
      ret,logtext="CRASH","exc:run_one: %r"%(e)
    if debug and logtext: sys.stdout.write(logtext)
    r={"result":to_json(ret),"log":log_summary(logtext)}
    results[path]=r
    status=""
    if ref is not None:
      if path not in ref:
        status="NEW "; nmissing+=1
      elif ref[path]["result"]!=r["result"]:
        status="FAIL "; nfail+=1
      elif ref[path]["log"]!=r["log"]:
        status="LOGDIFF "; nlogdiff+=1
      else:
        status="OK "
    print("%s%s: %s"%(status,path,short(ret) if ret!="CRASH" else "CRASH\n"+logtext))
    if args.errors and ret and ret!="CRASH":
      for e in ret.get("errors") or []: print("   ! "+e)
    if status=="FAIL ":
      print("   expected: %s"%(ref[path]["result"],))
      print("   got:      %s"%(r["result"],))
    if status=="LOGDIFF ":
      print("   expected log: %s"%(ref[path]["log"],))
      print("   got log:      %s"%(r["log"],))
    if args.extract and ret and ret!="CRASH":
      with open(path,"rb") as f:
        data=f.read()[ret["size"]:]
      if data:
        open(path+".dump","wb").write(data)

  if args.save:
    with open(args.save,"w") as f:
      json.dump(results,f,indent=1,ensure_ascii=False,sort_keys=True)
  if ref is not None:
    gone=[p for p in ref if p not in results and any(p.startswith(a.rstrip("/")) for a in args.paths)]
    print("\n%d file: %d OK, %d FAIL, %d LOGDIFF, %d NEW, %d MISSING"%(len(results),len(results)-nfail-nlogdiff-nmissing,nfail,nlogdiff,nmissing,len(gone)))
    sys.exit(1 if nfail or gone else 0)
