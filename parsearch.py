#!/usr/bin/env python3
"""
Archivumok (ZIP, RAR 1.5-4.x, RAR5, 7z, CAB, NSIS, Inno Setup) felismerese, meretenek
meghatarozasa es tartalomjegyzekenek listazasa. Fuggetlen a parseexe.py-tol: onallo
archiv fileokra es SFX exe-kbol kivagott archivumokra is hasznalhato, pl.:

    r=parseexe.dump_exe(data)
    if r and r["archive"]:
        a=parsearch.dump_archive(data[r["archive_start"]:r["archive_start"]+r["archive_size"]])

dump_archive(data) -- data: az archivum (bytes), a 0. offseten kezdodik
  None, ha a data elejen nincs (ervenyes) archivum, kulonben dict:
    type       "ZIP" | "RAR" (1.5-4.x) | "RAR5" | "RAR14" (1.3/1.4) | "7z" | "CAB" | "NSIS" | "Inno Setup"
    size       az archivum merete (ami utana van, az nem resze, pl. digitalis alairas)
    files      tartalomjegyzek: [[nev, meret, tomoritett meret, titkositott, modszer, offset], ...]
               (ZIP, RAR, RAR5, 7z, CAB, NSIS; a meretek None-ok lehetnek), None ha nem olvashato.
               NSIS: a telepito szkript fajljai (File / WriteUninstaller), $INSTDIR elotag nelkul,
               a pluginok $PLUGINSDIR/... alakban; nem solid tomoritett filenal a meret None (csak a
               tomoritett meret ismert), solid telepitonel a tomoritett meret es az offset None.
               Inno Setup-nal nincs tartalomjegyzek.
               A tomoritett meret tarolt (store) filenal = meret (titkositva a padding/fejlec miatt
               nagyobb); 7z solid folderben es CAB-ban None, mert ott nincs file szintu tomoritett meret.
               modszer: "store" = tomoritetlen; ZIP: "deflate","bzip2","lzma",... (AES eseten a valodi
               modszer), RAR: "m1".."m5", 7z: a coder lanc pl. "BCJ2+LZMA" / "LZMA2+AES", CAB: "MSZIP",
               "LZX","Quantum". Ures filenal (7z) None.
               offset: a file (tomoritett/titkositott) adatanak kezdete az archivum elejetol, vagy None
               (7z: csak tarolt, titkositatlan folderben; CAB: None). Tarolt ("store") es titkositatlan
               filenal data[offset:offset+meret] maga a file, igy rekurzivan vizsgalhato (csonka
               archivumnal tulnyulhat a data vegen).
               Konyvtarak nincsenek a listaban; symlink/hardlink bejegyzesek filekent szerepelnek,
               modszer "link" (ZIP, 7z, RAR4: a tartalmuk a cel utvonala, az offset erre mutat;
               RAR5: offset None, nincs sajat adata).
    encrypted  False, True (van jelszavas file), "headers" (a tartalomjegyzek is titkositott)
    comment    az archivum kommentje (RAR/ZIP; WinRAR SFX eseten itt vannak az SFX parancsok)
    sfx_script a kommentbol kiolvasott WinRAR SFX parancsok: {parancs: [ertekek]} vagy None;
               NSIS eseten a telepito szkript: {"Exec": [parancssorok], "ShellExec": ["verb file params"],
               "Plugin": ["dll::fuggveny"]}
    errors     elemzes kozben talalt hibak/anomaliak
    truncated  True, ha a data rovidebb, mint az archivum a fejlec szerint

find_archive(data,lo,hi) -- a [lo,hi) tartomanyban legelol kezdodo ervenyes archivum:
  (tipus, start, end) vagy None. A ZIP-et a vegerol (End of Central Directory) keresi.
parse_7z_config(cfg), parse_winrar_script(comment) -- SFX szkriptek ertelmezese
"""

import struct
import zlib

debug=False

def log(level,text):
    if level>0 or debug: print(level,text)

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

#####################################################################
#   Archivum (SFX / installer adat) keresese es meretenek meghatarozasa
#
#   Az archivum nem feltetlenul kozvetlenul az exe utan kezdodik (pl. 7-Zip
#   SFX konfig szoveg, igazitas), lehet az exe-be agyazva (pl. WinZip SFX,
#   resource), es utana johet digitalis alairas. Ezert szerkezet alapjan
#   keressuk: a ZIP-et a vegerol (End of Central Directory), a tobbit
#   szignatura + fejlec ellenorzes (CRC) alapjan.
#####################################################################

MAX_CANDIDATES=64   # ennyi hamis talalatot probalunk tipusonkent

def _zip_at_eocd(data,eocd,lo,hi):
    """ZIP ellenorzese az EOCD rekord alapjan. Visszaad: (start,end) vagy None"""
    if eocd+22>hi: return None
    sig,disk,cddisk,nent_disk,nent,cdsize,cdoff,clen=unpack("<IHHHHIIH",data,eocd)
    end=min(eocd+22+clen,hi)
    cdend=eocd
    if nent==0xFFFF or cdsize==0xFFFFFFFF or cdoff==0xFFFFFFFF:
        # ZIP64: EOCD64 locator (20 byte) + EOCD64 rekord (56 byte) kozvetlenul elotte
        loc=eocd-20
        if loc<lo or data[loc:loc+4]!=b"PK\6\7": return None
        e64=loc-56
        if e64<lo or data[e64:e64+4]!=b"PK\6\6": return None
        nent,cdsize,cdoff=unpack("<QQQ",data,e64+32)
        cdend=e64
    cd=cdend-cdsize            # a central directory tenyleges helye
    delta=cd-cdoff             # >0: a ZIP offsetjei az archivum elejetol szamitanak
                               # <0: egy nagyobb file elejetol (zip -A), es ebbol kivagott resz
    if cd<lo: return None
    if nent==0:
        return (cd,end) if cdsize==0 else None
    if data[cd:cd+4]!=b"PK\1\2": return None
    # a legkisebb local header offset = az archivum eleje
    minoff=None
    p=cd
    for i in range(min(nent,65536)):
        if p+46>cdend or data[p:p+4]!=b"PK\1\2": break
        fnlen,xlen,cmlen=unpack("<HHH",data,p+28)
        lhoff=u32(data,p+42)
        if lhoff!=0xFFFFFFFF and (minoff is None or lhoff<minoff): minoff=lhoff
        p+=46+fnlen+xlen+cmlen
    if minoff is None: minoff=0
    start=delta+minoff
    if start<lo or data[start:start+4]!=b"PK\3\4":
        if delta<lo or data[delta:delta+4]!=b"PK\3\4": return None
        start=delta
    return start,end

def find_zip(data,lo,hi):
    """Az utolso ervenyes ZIP a [lo,hi) tartomanyban. Visszaad: (start,end) vagy None"""
    pos=hi
    for i in range(MAX_CANDIDATES):
        pos=data.rfind(b"PK\5\6",lo,pos)
        if pos<0: return None
        try:
            r=_zip_at_eocd(data,pos,lo,hi)
            if r and r[0]>=lo: return r
        except struct.error:
            pass

def _vint(data,pos):
    """RAR5 valtozo hosszu egesz. Visszaad: (ertek, uj pozicio)"""
    v=shift=0
    for i in range(10):
        b=data[pos+i]
        v|=(b&0x7F)<<shift
        shift+=7
        if not b&0x80: return v,pos+i+1
    raise struct.error("bad vint")

def _rar4_end(data,start,hi):
    """RAR 1.5-4.x: blokkok bejarasa. Visszaad: archivum vege, None ha nem ervenyes"""
    p=start+7                  # marker block
    first=True
    while p+7<=hi:
        hcrc,htype,flags,hsize=unpack("<HBHH",data,p)
        if hsize<7 or htype<0x72 or htype>0x7B: break
        if zlib.crc32(data[p+2:p+hsize])&0xFFFF!=hcrc:
            # RAR 1.5-2.x: a main headerbe agyazott kommentnel a CRC csak a fix 13 byte-ra vonatkozik
            if not (htype==0x73 and flags&0x02 and hsize>=13 and zlib.crc32(data[p+2:p+13])&0xFFFF==hcrc):
                if first: return None      # a main header CRC-je nem stimmel: nem RAR
                break
        if first and htype!=0x73: return None
        if first and flags&0x80: return hi   # MHD_PASSWORD: titkositott fejlecek, nem jarhato be
        first=False
        add=0
        if flags&0x8000 or htype in (0x74,0x7A):   # LONG_BLOCK: adat a fejlec utan
            add=u32(data,p+7)
            if htype in (0x74,0x7A) and flags&0x100:   # LHD_LARGE: 64 bites meret
                add|=u32(data,p+32)<<32
        p+=hsize+add
        if htype==0x7B: break          # end of archive
    return None if first else min(p,hi)

def _rar5_end(data,start,hi):
    """RAR 5.x: blokkok bejarasa. Visszaad: archivum vege, None ha nem ervenyes"""
    p=start+8
    first=True
    while p+7<=hi:
        hcrc=u32(data,p)
        hsize,q=_vint(data,p+4)
        if hsize==0 or q+hsize>hi: break
        if zlib.crc32(data[p+4:q+hsize])!=hcrc:
            if first: return None
            break
        htype,r=_vint(data,q)
        hflags,r=_vint(data,r)
        if first and htype not in (1,4): return None   # main vagy encryption header
        if htype==4: return hi         # titkositott fejlecek: a tobbi blokk nem jarhato be
        first=False
        if hflags&1: xsize,r=_vint(data,r)
        dsize=0
        if hflags&2: dsize,r=_vint(data,r)
        p=q+hsize+dsize
        if htype==5: break             # end of archive
    return None if first else min(p,hi)

def _rar14_headers(data,start,hi):
    """RAR 1.3/1.4 ("RE~^"): (main header meret, flags, [(pos,hsize,psize,usize,attr,flags,method,name)], vege)
    vagy None ha nem ervenyes. A fajlfejlec: PackSize u32, UnpSize u32, CRC u16, HeadSize u16, FileTime u32,
    Attr u8, Flags u8, UnpVer u8, NameSize u8, Method u8, nev."""
    if start+7>hi: return None
    mhs,mflags=unpack("<HB",data,start+4)
    if mhs<7: return None
    p=start+mhs
    entries=[]
    while p+21<=hi and len(entries)<MAX_FILES:
        psize,usize,crc,hsize,ftime,attr,fflags,uver,nsize,method=unpack("<IIHHIBBBBB",data,p)
        if hsize<21+nsize or method>5 or uver not in (1,2): break
        entries.append((p,hsize,psize,usize,attr,fflags,method,data[p+21:p+21+nsize]))
        p+=hsize+psize
    if not entries and p!=hi: return None     # se fajl, se pontos vege: valoszinuleg nem RAR 1.x
    return mhs,mflags,entries,p

def _rar14_end(data,start,hi):
    h=_rar14_headers(data,start,hi)
    return None if h is None else h[3]

def _7z_end(data,start,hi):
    if start+32>hi: return None
    vmaj,vmin,crc,nextoff,nextsize,nextcrc=unpack("<BBIQQI",data,start+6)
    if zlib.crc32(data[start+12:start+32])!=crc or vmaj!=0: return None
    return start+32+nextoff+nextsize

def _cab_end(data,start,hi):
    if start+36>hi: return None
    sig,res1,cbcab,res2,cofffiles,res3,vmin,vmaj,nfolders,nfiles=unpack("<IIIIIIBBHH",data,start)
    if res1 or res3 or (vmaj,vmin)!=(1,3) or cbcab<36 or not cofffiles<cbcab: return None
    if start+cbcab>hi or not nfolders or not nfiles: return None   # bele kell ferjen
    return start+cbcab

def _nsis_end(data,start,hi):
    # az NSIS stub csak 512 byte-os hataron keresi a firstheader-t, es az adatnak bele kell ferjen
    if start<0 or start%512 or start+28>hi: return None
    flags,magic=unpack("<II",data,start)
    hdrlen,arclen=unpack("<II",data,start+20)
    if flags&~0xF or arclen<28 or not 0<hdrlen or start+arclen>hi: return None
    return start+arclen

# tipus, szignatura, szignatura helye a kezdethez kepest, vege-fuggveny
ARCHIVE_SIGS=(
    ("RAR5",b"Rar!\x1a\x07\x01\x00",0,_rar5_end),
    ("RAR",b"Rar!\x1a\x07\x00",0,_rar4_end),
    ("RAR14",b"RE~^",0,_rar14_end),
    ("7z",b"7z\xbc\xaf\x27\x1c",0,_7z_end),
    ("CAB",b"MSCF\0\0\0\0",0,_cab_end),
    ("NSIS",b"\xef\xbe\xad\xdeNullsoftInst",4,_nsis_end),
)

def find_archive(data,lo=0,hi=None,inno=False):
    """A [lo,hi) tartomanyban legelol kezdodo ervenyes archivum: (tipus,start,end) vagy None.
    inno=True: Inno Setup adatot is elfogad, de csak pontosan a lo offseten (gyenge szignatura)."""
    if hi is None: hi=len(data)
    found=[]
    z=find_zip(data,lo,hi)
    if z: found.append(("ZIP",z[0],z[1]))
    for name,sig,sigoff,endfunc in ARCHIVE_SIGS:
        pos=lo+sigoff
        for i in range(MAX_CANDIDATES):
            pos=data.find(sig,pos,hi)
            if pos<0: break
            start=pos-sigoff
            try:
                end=endfunc(data,start,hi)
            except (struct.error,IndexError):
                end=None
            if end is not None and start>=lo:
                found.append((name,start,min(end,hi)))
                break
            pos+=1
    if inno and (data.startswith(b"zlb\x1a",lo) or data.startswith(b"idska32\x1a",lo)):
        # Inno Setup: gyenge szignatura, csak pontosan az overlay elejen fogadjuk el
        found.append(("Inno Setup",lo,hi))
    if not found: return None
    return min(found,key=lambda x:x[1])

#####################################################################
#   SFX szkriptek
#####################################################################

# WinRAR SFX parancsok (az archivum kommentjeben, RAR es WinRAR ZIP SFX eseten)
WINRAR_SFX_COMMANDS=("delete","license","overwrite","path","presetup","savepath","setup","setupcode",
    "shortcut","silent","tempmode","text","title","update")

def parse_winrar_script(comment):
    """WinRAR SFX parancsok a kommentbol: {parancs: [ertekek]} vagy None ha nincs benne parancs"""
    cmds={}
    in_block=None
    last=None
    for line in comment.splitlines():
        s=line.strip()
        if in_block is not None:      # License/Text { ... } blokk
            if s=="}": in_block=None
            else: cmds[in_block][-1]+=line+"\n"
            continue
        if s=="{" and last is not None:   # a blokk a parancs utani sorban nyilik
            in_block=last
            continue
        last=None
        if not s or s.startswith(";"): continue
        key,sep,val=s.partition("=")
        k=key.strip()
        if k.lower() not in WINRAR_SFX_COMMANDS: continue
        val=val.strip()
        if val=="{":
            in_block=k
            val=""
        cmds.setdefault(k,[]).append(val)
        last=k if not val else None
    return cmds or None

def parse_7z_config(cfg):
    """7-Zip SFX konfig (Kulcs="Ertek" sorok): {kulcs: [ertekek]}"""
    cmds={}
    for line in cfg.splitlines():
        s=line.strip().lstrip("﻿")
        if not s or s.startswith(";"): continue
        key,sep,val=s.partition("=")
        if not sep: continue
        val=val.strip()
        if len(val)>=2 and val[0]==val[-1]=='"': val=_unescape_7z(val[1:-1])
        cmds.setdefault(key.strip(),[]).append(val)
    return cmds or None

def _unescape_7z(v):
    """7-Zip SFX konfig escape-ek: \\" \\\\ \\n \\t"""
    out=[]
    i=0
    while i<len(v):
        c=v[i]
        if c=="\\" and i+1<len(v) and v[i+1] in '"\\nt':
            out.append({'"':'"',"\\":"\\","n":"\n","t":"\t"}[v[i+1]])
            i+=2
        else:
            out.append(c)
            i+=1
    return "".join(out)


#####################################################################
#   Archivum tartalomjegyzek: (files, encrypted, comment)
#     files      [[nev, meret, tomoritett meret, titkositott], ...] vagy None ha nem olvashato
#     encrypted  False / True (van jelszavas file) / "headers" (a tartalomjegyzek is titkositott)
#     comment    az archivum kommentje vagy None
#####################################################################

MAX_FILES=100000

MAX_MISMATCH_ERRORS=10

def zip_details(data,start,end,errors):
    eocd=data.rfind(b"PK\5\6",start,end)
    sig,disk,cddisk,nent_disk,nent,cdsize,cdoff,clen=unpack("<IHHHHIIH",data,eocd)
    comment=data[eocd+22:eocd+22+clen]
    cdend=eocd
    if nent==0xFFFF or cdsize==0xFFFFFFFF or cdoff==0xFFFFFFFF:
        e64=eocd-20-56
        nent,cdsize,cdoff=unpack("<QQQ",data,e64+32)
        cdend=e64
    files=[]
    enc=False
    p=cdend-cdsize
    delta=p-cdoff            # a ZIP offsetek -> file offset (zip -A / kivagott resz eseten is)
    mismatch=0
    for i in range(min(nent,MAX_FILES)):
        if data[p:p+4]!=b"PK\1\2": break
        madeby,=unpack("<H",data,p+4)
        flags,method=unpack("<HH",data,p+8)
        csize,usize,fnlen,xlen,cmlen=unpack("<IIHHH",data,p+20)
        extattr=u32(data,p+38)
        lhoff=u32(data,p+42)
        # symlink: Unix (3) vagy macOS (19) "made by" eseten a kulso attributum felso 16 bitje a mode
        link=(madeby>>8) in (3,19) and is_unix_symlink(extattr>>16)
        rawname=data[p+46:p+46+fnlen]
        name=rawname.decode("utf-8","replace") if flags&0x800 else _decode_name(rawname)
        realmethod=method
        x=p+46+fnlen
        while x+4<=p+46+fnlen+xlen:     # extra mezok: ZIP64 meretek/offset, AES (a valodi modszer)
            xid,xsz=unpack("<HH",data,x)
            if xid==1:
                vals=list(unpack("<%dQ"%(min(xsz,24)//8),data,x+4))
                if usize==0xFFFFFFFF and vals: usize=vals.pop(0)
                if csize==0xFFFFFFFF and vals: csize=vals.pop(0)
                if lhoff==0xFFFFFFFF and vals: lhoff=vals.pop(0)
            elif xid==0x9901 and xsz>=7:
                realmethod=u16(data,x+4+5)
            x+=4+xsz
        e=bool(flags&1) or method==99
        enc|=e
        # local header: az adat helye + osszevetes a central directory-val
        # (az elteres ismert kijatszasi trukk: a viruskereso mast lat, mint a kicsomagolo)
        off=None
        lh=lhoff+delta
        if data[lh:lh+4]==b"PK\3\4":
            lver,lflags,lmethod,lt,ld,lcrc,lcsize,lusize,lfnlen,lxlen=unpack("<HHHHHIIIHH",data,lh+4)
            off=lh+30+lfnlen+lxlen-start
            diff=[]
            if data[lh+30:lh+30+lfnlen]!=rawname: diff.append("name %r"%(data[lh+30:lh+30+lfnlen].decode("cp437","replace")))
            if lmethod!=method: diff.append("method %d/%d"%(lmethod,method))
            if not lflags&8 and 0xFFFFFFFF not in (lcsize,lusize) and (lcsize,lusize)!=(csize,usize):
                diff.append("size %d/%d vs %d/%d"%(lusize,lcsize,usize,csize))
            if diff:
                mismatch+=1
                if mismatch<=MAX_MISMATCH_ERRORS:
                    errors.append("ZIP local header differs from central directory for %r: %s"%(name,", ".join(diff)))
        else:
            mismatch+=1
            if mismatch<=MAX_MISMATCH_ERRORS:
                errors.append("ZIP local header missing for %r"%(name))
        if not name.endswith("/"):      # konyvtar nem kell
            files.append([name,usize,csize,e,"link" if link else zip_method_name(realmethod),off])
        p+=46+fnlen+xlen+cmlen
    if mismatch>MAX_MISMATCH_ERRORS:
        errors.append("ZIP local/central header mismatches: %d"%(mismatch))
    return files,enc,_decode_comment(comment)

def zip_local_headers(data):
    """ZIP tartalomjegyzek a local headerekbol (ha nincs central directory). Visszaad: (files, encrypted)"""
    files=[]
    enc=False
    p=0
    while data.startswith(b"PK\3\4",p) and len(files)<MAX_FILES:
        try:
            ver,flags,method,mtime,mdate,crc,csize,usize,fnlen,xlen=unpack("<HHHHHIIIHH",data,p+4)
        except struct.error:
            break
        name=data[p+30:p+30+fnlen].decode("utf-8","replace") if flags&0x800 else _decode_name(data[p+30:p+30+fnlen])
        e=bool(flags&1) or method==99
        enc|=e
        if not name.endswith("/"):
            files.append([name,None if flags&8 else usize,None if flags&8 else csize,e,zip_method_name(method),p+30+fnlen+xlen])
        if flags&8: break               # data descriptor: a tomoritett meret nem ismert, nem lephetunk tovabb
        p+=30+fnlen+xlen+csize
    return files,enc

ZIP_METHODS={0:"store",1:"shrink",2:"reduce1",3:"reduce2",4:"reduce3",5:"reduce4",6:"implode",8:"deflate",
    9:"deflate64",10:"pkware-dcl",12:"bzip2",14:"lzma",18:"terse",19:"lz77",93:"zstd",94:"mp3",95:"xz",
    96:"jpeg",97:"wavpack",98:"ppmd",99:"aes"}

def zip_method_name(m):
    return ZIP_METHODS.get(m,"m%d"%(m))

S_IFMT,S_IFLNK=0o170000,0o120000

def is_unix_symlink(mode):
    return mode&S_IFMT==S_IFLNK

def _decode_name(b):
    """Kodolas jelzes nelkuli fajlnev: UTF-8, ha ervenyes (pl. Unix alatt keszult archivum), kulonben cp437."""
    try:
        return b.decode("utf-8")
    except UnicodeDecodeError:
        return b.decode("cp437","replace")

def rar4_filename(raw,flags):
    """RAR 1.5-4.x fajlnev. LHD_UNICODE (0x200) eseten: ha nincs benne 0 byte, UTF-8; kulonben
    ASCII/OEM nev + 0 + tomoritett unicode valtozat (az unrar EncodeFileName::Decode algoritmusa)."""
    if not flags&0x200:
        return _decode_name(raw.split(b"\0")[0])
    z=raw.find(b"\0")
    if z<0:
        return raw.decode("utf-8","replace")
    name=raw[:z]; enc=raw[z+1:]
    out=[]
    try:
        encpos=0
        highbyte=enc[encpos]; encpos+=1
        flagbyte=0; flagbits=0
        while encpos<len(enc) and len(out)<1024:
            if flagbits==0:
                flagbyte=enc[encpos]; encpos+=1; flagbits=8
            t=flagbyte>>6
            if t==0:
                out.append(enc[encpos]); encpos+=1
            elif t==1:
                out.append(enc[encpos]+(highbyte<<8)); encpos+=1
            elif t==2:
                out.append(enc[encpos]+(enc[encpos+1]<<8)); encpos+=2
            else:
                length=enc[encpos]; encpos+=1
                if length&0x80:
                    correction=enc[encpos]; encpos+=1
                    for k in range((length&0x7F)+2):
                        if len(out)>=len(name): break
                        out.append(((name[len(out)]+correction)&0xFF)+(highbyte<<8))
                else:
                    for k in range(length+2):
                        if len(out)>=len(name): break
                        out.append(name[len(out)])
            flagbyte=(flagbyte<<2)&0xFF; flagbits-=2
    except IndexError:
        pass
    if not out:
        return _decode_name(name)
    return "".join(chr(c) if c<0xD800 or c>0xDFFF else "\ufffd" for c in out)

def rar_method_name(m):
    """RAR tomoritesi szint: 0=store, 1..5 (fastest..best)"""
    return "store" if m==0 else "m%d"%(m)

def _decode_comment(b):
    if not b: return None
    try: return b.decode("utf-8")
    except UnicodeDecodeError: return b.decode("cp437","replace")

def rar4_details(data,start,end,errors):
    files=[]
    enc=False
    comment=None
    p=start+7
    while p+7<=end and len(files)<MAX_FILES:
        hcrc,htype,flags,hsize=unpack("<HBHH",data,p)
        if hsize<7 or htype<0x72 or htype>0x7B: break
        add=0
        if htype==0x73:
            if flags&0x80:       # MHD_PASSWORD: a fejlecek titkositottak
                return None,"headers",None
            if flags&0x02 and hsize>=13+15:
                # RAR 1.5-2.x: komment alblokk (0x75) a main headerben: UnpSize u16, UnpVer, Method, CRC, adat
                chcrc,chtype,chflags,chsize,cusize,cver,cmethod,ccrc=unpack("<HBHHHBBH",data,p+13)
                if chtype==0x75 and cmethod==0x30:
                    comment=_decode_comment(data[p+13+15:p+13+chsize])
                else:
                    errors.append("RAR old style comment is compressed, not decoded")
        elif htype in (0x74,0x7A):
            psize,usize,hostos,fcrc,ftime,uver,method,nsize,attr=unpack("<IIBIIBBHI",data,p+7)
            q=p+32
            if flags&0x100:
                hp,hu=unpack("<II",data,q); psize|=hp<<32; usize|=hu<<32; q+=8
            raw=data[q:q+nsize]
            add=psize
            if htype==0x74:
                name=rar4_filename(raw,flags).replace("\\","/")
                e=bool(flags&0x04)
                enc|=e
                if flags&0xE0!=0xE0:     # konyvtar nem kell
                    link=hostos==3 and is_unix_symlink(attr)   # Unix symlink: az adat a cel utvonala
                    files.append([name,usize,psize,e,"link" if link else rar_method_name(method-0x30),p+hsize-start])
            elif raw==b"CMT":
                if method==0x30:         # tarolt (nem tomoritett) komment
                    comment=_decode_comment(data[p+hsize:p+hsize+psize])
                else:
                    errors.append("RAR4 comment is compressed, not decoded")
        elif flags&0x8000:
            add=u32(data,p+7)
        p+=hsize+add
        if htype==0x7B: break
    return files,enc,comment

def rar14_details(data,start,end,errors):
    mhs,mflags,entries,p=_rar14_headers(data,start,end)
    comment=None
    if mflags&0x02 and mhs>=9:                 # komment a main headerben
        clen=u16(data,start+7)
        if mflags&0x10:
            errors.append("RAR 1.x comment is compressed, not decoded")
        else:
            comment=_decode_comment(data[start+9:start+9+min(clen,mhs-9)])
    files=[]
    enc=False
    for pos,hsize,psize,usize,attr,fflags,method,rawname in entries:
        e=bool(fflags&0x04)
        enc|=e
        if attr&0x10: continue                 # konyvtar
        files.append([_decode_name(rawname).replace("\\","/"),usize,psize,e,rar_method_name(method),pos+hsize-start])
    return files,enc,comment

def rar5_details(data,start,end,errors):
    files=[]
    enc=False
    comment=None
    p=start+8
    while p+7<=end and len(files)<MAX_FILES:
        hsize,q=_vint(data,p+4)
        hend=q+hsize
        htype,x=_vint(data,q)
        hflags,x=_vint(data,x)
        xsize=0
        if hflags&1: xsize,x=_vint(data,x)
        dsize=0
        if hflags&2: dsize,x=_vint(data,x)
        if htype==4:                     # encryption header: minden tovabbi fejlec titkositott
            return None,"headers",None
        if htype in (2,3):               # file / service header
            fflags,x=_vint(data,x)
            usize,x=_vint(data,x)
            attr,x=_vint(data,x)
            if fflags&2: x+=4            # mtime
            if fflags&4: x+=4            # data crc
            cinfo,x=_vint(data,x)
            hostos,x=_vint(data,x)
            nlen,x=_vint(data,x)
            name=data[x:x+nlen].decode("utf-8","replace")
            # extra terulet: 1 = file encryption, 5 = redirection (symlink/junction/hardlink: nincs sajat adat)
            e=False
            link=False
            xp=hend-xsize
            while xp<hend:
                rsize,rp=_vint(data,xp)
                rtype,rp2=_vint(data,rp)
                if rtype==1: e=True
                if rtype==5: link=True
                xp=rp+rsize
            if htype==2:
                enc|=e
                if not fflags&1:         # konyvtar nem kell
                    if link: files.append([name,None if fflags&8 else usize,dsize,e,"link",None])
                    else: files.append([name,None if fflags&8 else usize,dsize,e,rar_method_name((cinfo>>7)&7),hend-start])
            elif name=="CMT":
                if (cinfo>>7)&7==0 and not e:
                    comment=_decode_comment(data[hend:hend+dsize])
                else:
                    errors.append("RAR5 comment is compressed/encrypted, not decoded")
        p=hend+dsize
        if htype==5: break
    return files,enc,comment

CAB_METHODS={0:"store",1:"MSZIP",2:"Quantum",3:"LZX"}

def cab_details(data,start,end,errors):
    sig,res1,cbcab,res2,cofffiles,res3,vmin,vmaj,nfolders,nfiles,flags=unpack("<IIIIIIBBHHH",data,start)
    # CFFOLDER-ek (a tomorites tipusa folderenkent); opcionalis reserve teruletek (flags&4)
    p=start+36
    cbfolder=0
    if flags&4:
        cbheader,cbfolder,cbdata=unpack("<HBB",data,p)
        p+=4+cbheader
    if flags&1: p=data.find(b"\0",p)+1; p=data.find(b"\0",p)+1    # elozo cabinet neve, lemez neve
    if flags&2: p=data.find(b"\0",p)+1; p=data.find(b"\0",p)+1    # kovetkezo cabinet neve, lemez neve
    folder_methods=[]
    for i in range(min(nfolders,65535)):
        cfstart,ndata,ctype=unpack("<IHH",data,p)
        folder_methods.append(CAB_METHODS.get(ctype&0x0F,"m%d"%(ctype&0x0F)))
        p+=8+cbfolder
    files=[]
    p=start+cofffiles
    for i in range(min(nfiles,MAX_FILES)):
        fsize,foff,ifolder,fdate,ftime,fattr=unpack("<IIHHHH",data,p)
        raw=cstr(data,p+16,256,"utf-8" if fattr&0x80 else "cp437")
        name=raw.replace("\\","/")
        if ifolder>=0xFFFD:          # elozo/kovetkezo cabinetbe atnyulo file: az elso/utolso folder
            ifolder=0 if ifolder in (0xFFFD,0xFFFF) else len(folder_methods)-1
        files.append([name,fsize,None,False,folder_methods[ifolder] if ifolder<len(folder_methods) else None,None])
        p+=16+len(raw.encode("utf-8" if fattr&0x80 else "cp437","replace"))+1
    return files,False,None


#####################################################################
#   7z tartalomjegyzek (a fejlec altalaban LZMA-val tomoritett: kEncodedHeader)
#####################################################################

SZ_AES=b"\x06\xf1\x07\x01"
SZ_CODERS={b"\x00":"store",b"\x21":"LZMA2",b"\x03\x01\x01":"LZMA",b"\x03\x04\x01":"PPMD",
    b"\x04\x01\x08":"Deflate",b"\x04\x01\x09":"Deflate64",b"\x04\x02\x02":"BZip2",
    b"\x03":"Delta",b"\x03\x03\x01\x03":"BCJ",b"\x03\x03\x01\x1b":"BCJ2",b"\x03\x03\x02\x05":"PPC",
    b"\x03\x03\x04\x01":"IA64",b"\x03\x03\x05\x01":"ARM",b"\x03\x03\x07\x01":"ARMT",
    b"\x03\x03\x08\x05":"SPARC",b"\x0a":"ARM64",b"\x0b":"RISCV",b"\x04\xf7\x11\x01":"ZSTD",
    SZ_AES:"AES"}

def sz_method_name(folder):
    """7z folder coder lanc -> nev a kicsomagolas sorrendjeben (a 7-Zip is igy irja ki):
    a fo kimenettol a bind pair-ek menten, pl. "BCJ2+LZMA2+LZMA", "LZMA2+AES", "store+AES"."""
    coders=folder["coders"]
    instart=[]; outstart=[]; i=o=0
    for cid,props,nin,nout in coders:
        instart.append(i); outstart.append(o); i+=nin; o+=nout
    def coder_of_out(out):
        for ci,(cid,props,nin,nout) in enumerate(coders):
            if outstart[ci]<=out<outstart[ci]+nout: return ci
        return None
    binds=dict(folder.get("binds",[]))             # bemenet index -> kimenet index
    mains=[x for x in range(sum(c[3] for c in coders)) if x not in folder.get("bound_out",())]
    order=[]
    def visit(ci,depth=0):
        if ci is None or ci in order or depth>32: return
        order.append(ci)
        for k in range(coders[ci][2]):
            out=binds.get(instart[ci]+k)
            if out is not None: visit(coder_of_out(out),depth+1)
    visit(coder_of_out(mains[0]) if mains else 0)
    for ci in range(len(coders)):                  # biztonsag kedveert: ami kimaradt
        if ci not in order: order.append(ci)
    names=[]
    for ci in order:
        n=SZ_CODERS.get(coders[ci][0],"0x"+coders[ci][0].hex())
        if n not in names: names.append(n)
    return "+".join(names)
MAX_7Z_HEADER=64*1024*1024

class _SzReader:
    def __init__(self,data,pos=0):
        self.d=data; self.p=pos
    def byte(self):
        b=self.d[self.p]; self.p+=1
        return b
    def num(self):
        first=self.byte()
        mask=0x80
        v=0
        for i in range(8):
            if not first&mask:
                return v|((first&(mask-1))<<(8*i))
            v|=self.byte()<<(8*i)
            mask>>=1
        return v
    def bytes(self,n):
        b=self.d[self.p:self.p+n]; self.p+=n
        return b
    def bits(self,n):
        if n>MAX_FILES: raise ValueError("7z: too many items: %d"%(n))
        out=[]
        b=mask=0
        for i in range(n):
            if not mask: b=self.byte(); mask=0x80
            out.append(bool(b&mask)); mask>>=1
        return out
    def defined(self,n):
        if n>MAX_FILES: raise ValueError("7z: too many items: %d"%(n))
        allset=self.byte()
        return [True]*n if allset else self.bits(n)

def _sz_digests(rd,n):
    d=rd.defined(n)
    for x in d:
        if x: rd.bytes(4)
    return d

def _sz_streams_info(rd):
    """StreamsInfo: {"packpos","packsizes","folders":[{"coders","unpack","main"}],"substreams":[[meretek]]}"""
    si={"packpos":0,"packsizes":[],"folders":[],"substreams":None,"folder_crc":None}
    while True:
        t=rd.num()
        if t==0: break
        if t==0x06:                          # PackInfo
            si["packpos"]=rd.num()
            n=rd.num()
            while True:
                t2=rd.num()
                if t2==0: break
                if t2==0x09: si["packsizes"]=[rd.num() for i in range(n)]
                elif t2==0x0A: _sz_digests(rd,n)
                else: raise ValueError("7z: bad PackInfo property %d"%(t2))
        elif t==0x07:                        # UnPackInfo (folderek)
            if rd.num()!=0x0B: raise ValueError("7z: kFolder expected")
            nf=rd.num()
            if rd.byte()!=0: raise ValueError("7z: external folders not supported")
            for i in range(nf):
                coders=[]
                tin=tout=0
                for j in range(rd.num()):
                    fl=rd.byte()
                    cid=rd.bytes(fl&0x0F)
                    nin,nout=(rd.num(),rd.num()) if fl&0x10 else (1,1)
                    props=rd.bytes(rd.num()) if fl&0x20 else b""
                    coders.append((cid,props,nin,nout))
                    tin+=nin; tout+=nout
                bound_out=set()
                binds=[]
                for j in range(tout-1):
                    bin_=rd.num(); bout=rd.num()
                    binds.append((bin_,bout)); bound_out.add(bout)
                npacked=tin-(tout-1)
                if npacked>1:
                    for j in range(npacked): rd.num()
                si["folders"].append({"coders":coders,"nout":tout,"bound_out":bound_out,"npacked":npacked,"binds":binds})
            while True:
                t2=rd.num()
                if t2==0: break
                if t2==0x0C:
                    for f in si["folders"]:
                        f["unpack"]=[rd.num() for i in range(f["nout"])]
                        main=[i for i in range(f["nout"]) if i not in f["bound_out"]]
                        f["main"]=f["unpack"][main[0]] if main else f["unpack"][-1]
                elif t2==0x0A: si["folder_crc"]=_sz_digests(rd,len(si["folders"]))
                else: raise ValueError("7z: bad UnPackInfo property %d"%(t2))
        elif t==0x08:                        # SubStreamsInfo
            nums=[1]*len(si["folders"])
            sizes=None
            while True:
                t2=rd.num()
                if t2==0: break
                if t2==0x0D: nums=[rd.num() for f in si["folders"]]
                elif t2==0x09:
                    sizes=[]
                    for f,n in zip(si["folders"],nums):
                        if n==0: sizes.append([]); continue
                        s=[rd.num() for i in range(n-1)]
                        sizes.append(s+[f["main"]-sum(s)])
                elif t2==0x0A:
                    # CRC-k: minden stream, kiveve az egy-streames foldereket, amiknek mar van folder CRC-je
                    fcrc=si["folder_crc"] or [False]*len(nums)
                    _sz_digests(rd,sum(n for n,c in zip(nums,fcrc) if not (n==1 and c)))
                else: raise ValueError("7z: bad SubStreamsInfo property %d"%(t2))
            if sizes is None:
                sizes=[[f["main"]] if n==1 else ([] if n==0 else [f["main"]]) for f,n in zip(si["folders"],nums)]
            si["substreams"]=sizes
        else:
            raise ValueError("7z: bad StreamsInfo property %d"%(t))
    if si["substreams"] is None:
        si["substreams"]=[[f.get("main",0)] for f in si["folders"]]
    return si

def _sz_decode_folder(data,base,si,fi):
    """Egy folder kicsomagolasa (csak LZMA/LZMA2/copy, egy coder)."""
    import lzma
    f=si["folders"][fi]
    if len(f["coders"])!=1: raise ValueError("7z: multi-coder header not supported")
    cid,props,nin,nout=f["coders"][0]
    pos=base+si["packpos"]+sum(si["packsizes"][:fi])
    packed=data[pos:pos+si["packsizes"][fi]]
    size=f["main"]
    if size>MAX_7Z_HEADER: raise ValueError("7z: header too big")
    if cid==b"\x00": return packed[:size]
    if cid==b"\x03\x01\x01":
        d=props[0]; lc=d%9; d//=9; lp=d%5; pb=d//5
        filt={"id":lzma.FILTER_LZMA1,"dict_size":struct.unpack("<I",props[1:5])[0],"lc":lc,"lp":lp,"pb":pb}
    elif cid==b"\x21":
        p=props[0]
        filt={"id":lzma.FILTER_LZMA2,"dict_size":(2|(p&1))<<(p//2+11) if p<40 else 0xFFFFFFFF}
    else:
        raise ValueError("7z: header coder %s not supported"%(cid.hex()))
    dec=lzma.LZMADecompressor(format=lzma.FORMAT_RAW,filters=[filt])
    return dec.decompress(packed,max_length=size)

def sevenzip_details(data,start,end,errors):
    vmaj,vmin,crc,nextoff,nextsize,nextcrc=unpack("<BBIQQI",data,start+6)
    base=start+32
    if base+nextoff+nextsize>end:
        errors.append("7z header beyond end of data (truncated)")
        return None,None,None
    hdr=data[base+nextoff:base+nextoff+nextsize]
    if not hdr: return [],False,None
    rd=_SzReader(hdr)
    t=rd.num()
    for i in range(4):
        if t!=0x17: break                    # kEncodedHeader
        si=_sz_streams_info(rd)
        if any(c[0]==SZ_AES for f in si["folders"] for c in f["coders"]):
            return None,"headers",None
        hdr=_sz_decode_folder(data,base,si,0)
        rd=_SzReader(hdr)
        t=rd.num()
    if t!=0x01: raise ValueError("7z: kHeader expected (%d)"%(t))
    si=None
    names=[]; empty=[]; emptyfile=[]; anti=[]; attrs=[]
    nfiles=0
    while True:
        t=rd.num()
        if t==0: break
        if t==0x02:                          # archive properties
            while rd.num()!=0: rd.bytes(rd.num())
        elif t==0x03:                        # additional streams
            _sz_streams_info(rd)
        elif t==0x04:
            si=_sz_streams_info(rd)
        elif t==0x05:                        # FilesInfo
            nfiles=rd.num()
            if nfiles>MAX_FILES: raise ValueError("7z: too many files: %d"%(nfiles))
            while True:
                pt=rd.num()
                if pt==0: break
                psize=rd.num()
                pend=rd.p+psize
                if pt==0x0E: empty=rd.bits(nfiles)
                elif pt==0x0F: emptyfile=rd.bits(sum(empty))
                elif pt==0x11:
                    if rd.byte()!=0: raise ValueError("7z: external names not supported")
                    raw=rd.bytes(psize-1)
                    names=_sz_names(raw)
                elif pt==0x15:                   # kAttributes
                    defined=rd.defined(nfiles)
                    if rd.byte()!=0: raise ValueError("7z: external attributes not supported")
                    attrs=[]
                    for dfn in defined:
                        if dfn:
                            attrs.append(unpack("<I",rd.d,rd.p)[0]); rd.p+=4
                        else:
                            attrs.append(None)
                rd.p=pend
        else:
            raise ValueError("7z: bad Header property %d"%(t))
    # meretek: a nem ures stream-u fileok sorban kapjak a substream mereteket
    # tomoritett meret: csak az egy-fileos foldereknel ertelmezheto (a folder osszes pack streamje);
    # solid folderben a fileoknak nincs kulon tomoritett merete (None)
    sizes=[]; folders_of=[]; packed=[]; methods=[]; offsets=[]
    enc=False
    if si:
        pi=0
        for fi,(f,ss) in enumerate(zip(si["folders"],si["substreams"])):
            fenc=any(c[0]==SZ_AES for c in f["coders"])
            enc|=fenc
            fpack=sum(si["packsizes"][pi:pi+f["npacked"]]) if pi+f["npacked"]<=len(si["packsizes"]) else None
            pi+=f["npacked"]
            fmethod=sz_method_name(f)
            # tarolt (Copy, titkositatlan) folderben az adatok folytonosan, sorban vannak
            fpos=base+si["packpos"]+sum(si["packsizes"][:pi-f["npacked"]])-start if fmethod=="store" else None
            for s in ss:
                sizes.append(s); folders_of.append(fenc); packed.append(fpack if len(ss)==1 else None)
                methods.append(fmethod)
                offsets.append(fpos)
                if fpos is not None: fpos+=s
    files=[]
    k=0
    ei=0
    for i in range(nfiles):
        name=names[i] if i<len(names) else "?"
        if empty and empty[i]:
            isdir=not (emptyfile[ei] if ei<len(emptyfile) else False)
            ei+=1
            if not isdir: files.append([name,0,0,False,None,None])      # ures file: nincs adata, nincs modszer
        else:
            s=sizes[k] if k<len(sizes) else None
            e=folders_of[k] if k<len(folders_of) else False
            pk=packed[k] if k<len(packed) else None
            m=methods[k] if k<len(methods) else None
            of=offsets[k] if k<len(offsets) else None
            k+=1
            a=attrs[i] if i<len(attrs) else None
            # symlink: Unix kiterjesztes (0x8000, felso 16 bit = mode) vagy Windows reparse point (0x400)
            if a is not None and ((a&0x8000 and is_unix_symlink(a>>16)) or a&0x400): m="link"
            files.append([name,s,pk,e,m,of])
    return files,enc,None

def _sz_names(raw):
    names=[]
    cur=bytearray()
    for i in range(0,len(raw)-1,2):
        ch=raw[i:i+2]
        if ch==b"\0\0":
            names.append(cur.decode("utf-16-le","replace")); cur=bytearray()
        else:
            cur+=ch
    return names

#####################################################################
#   NSIS (Nullsoft Scriptable Install System) telepito adat
#
#   firstheader (28 byte): flags, 0xDEADBEEF, "NullsoftInst", header hossz (kicsomagolva),
#   az osszes adat hossza. Utana:
#     nem solid: [u32 meret (bit31: tomoritett)][header] majd fileonkent [u32 meret][adat]
#     solid:     egyetlen tomoritett stream: [u32 header hossz][header][u32 meret][adat]...
#   tomorites: raw deflate (zlib), NSIS-bzip2 (stream fejlec nelkul) vagy LZMA (opcionalis x86 BCJ).
#   A fajlnevek a telepito szkriptben vannak: EW_EXTRACTFILE utasitasok + string tabla,
#   a konyvtarat a SetOutPath (EW_CREATEDIR) adja.
#####################################################################

NSIS_EW_CREATEDIR=11
NSIS_EW_EXTRACTFILE=20
NSIS_EW_WRITEUNINSTALLER=62
NSIS_EW_SHELLEXEC=40      # ExecShell: parm0 verb, parm1 file, parm2 parameters
NSIS_EW_EXECUTE=41        # Exec/ExecWait: parm0 parancssor
NSIS_EW_REGISTERDLL=44    # plugin hivas / RegDLL: parm0 dll, parm1 fuggveny
NSIS_MAX_SCRIPT=1000      # parancsonkent legfeljebb ennyi elem
NSIS_MAX_SOLID=256*1024*1024     # solid streambol legfeljebb ennyit bontunk ki a fajlmeretek miatt
NSIS_MAX_SOLID_BZIP2=16*1024*1024   # a tiszta Python bzip2 lassu (~1 MB/s), ott kisebb a korlat
NSIS_MAX_HEADER=64*1024*1024
# beepitett valtozok (a $0..$9, $R0..$R9 utan)
NSIS_VARS=["CMDLINE","INSTDIR","OUTDIR","EXEDIR","LANGUAGE","TEMP","PLUGINSDIR","EXEPATH","EXEFILE",
    "HWNDPARENT","_CLICK","_OUTDIR"]
# shell mappak (CSIDL) -> NSIS nev
NSIS_SHELL={0x00:"DESKTOP",0x02:"SMPROGRAMS",0x05:"DOCUMENTS",0x06:"FAVORITES",0x07:"SMSTARTUP",
    0x08:"RECENT",0x09:"SENDTO",0x0B:"STARTMENU",0x0D:"MUSIC",0x0E:"VIDEOS",0x10:"DESKTOP",
    0x13:"NETHOOD",0x14:"FONTS",0x15:"TEMPLATES",0x1A:"APPDATA",0x1C:"LOCALAPPDATA",0x1B:"PRINTHOOD",
    0x20:"INTERNET_CACHE",0x21:"COOKIES",0x22:"HISTORY",0x23:"APPDATA",0x24:"WINDIR",0x25:"SYSDIR",
    0x26:"PROGRAMFILES",0x27:"PICTURES",0x2B:"COMMONFILES",0x2D:"TEMPLATES",0x30:"ADMINTOOLS",
    0x3B:"CDBURN_AREA"}

def _nsis_bzip2():
    """Az NSIS bzip2 dekoder a kulon bzip2dec.py-bol (tiszta Python)."""
    import bzip2dec
    return bzip2dec.NsisBzip2Decompressor()

def _nsis_lzma_props(data,q):
    """LZMA stream kezdete: (props offset, x86 szuro) vagy None"""
    # LZMA fejlec: 5D (lc=3,lp=0,pb=2), szotarmeret u32 (also 16 bit 0), utana az elso byte felso bitje 0
    def ok(i): return data[i:i+3]==b"\x5d\x00\x00" and len(data)>i+6 and data[i+5]==0 and not data[i+6]&0x80
    if ok(q): return q,False
    if data[q:q+1] in (b"\x00",b"\x01") and ok(q+1): return q+1,data[q]==1   # opcionalis x86 BCJ szuro
    return None

class _StreamReader:
    """Tomoritett stream sorban olvasasa (lzma/bz2/zlib decompressor objektummal), a tartalom eldobasaval."""
    def __init__(self,dec,src,kind):
        self.dec=dec; self.src=src; self.kind=kind
        self.limit=NSIS_MAX_SOLID_BZIP2 if kind=="bz2" else NSIS_MAX_SOLID
        self.pos=0; self.buf=b""; self.fed=False; self.eof=False
    def _more(self,n):
        if self.kind=="zlib":
            src=self.src if not self.fed else self.dec.unconsumed_tail
            self.fed=True
            out=self.dec.decompress(src,n)
            if not out and not self.dec.unconsumed_tail: self.eof=True
        else:
            if self.dec.eof: self.eof=True; return b""
            out=self.dec.decompress(b"" if self.fed else self.src,max_length=n)
            self.fed=True
            if not out and self.dec.needs_input: self.eof=True
        return out
    def read_at(self,target,n):
        """n byte a kibontott stream target poziciojan (target >= az elozo keres vege)"""
        while self.pos+len(self.buf)<target+n and not self.eof:
            if self.pos+len(self.buf)>self.limit: raise ValueError("NSIS solid stream too big for listing (>%d MB)"%(self.limit>>20))
            chunk=self._more(1<<20)
            self.buf+=chunk
            if target>self.pos+len(self.buf):       # a celpozicio elotti reszt eldobjuk
                self.pos+=len(self.buf); self.buf=b""
            else:
                self.buf=self.buf[target-self.pos:]; self.pos=target
        if target<self.pos or self.pos+len(self.buf)<target+n: return None
        return self.buf[target-self.pos:target-self.pos+n]

def _nsis_decoder(data,q,end,method):
    """Uj decompressor a q-n kezdodo streamhez (a mar megallapitott modszerrel)"""
    import lzma
    if "lzma" in method:
        pq,x86=_nsis_lzma_props(data,q)
        d=data[pq]; lc=d%9; d//=9; lpp=d%5; pb=d//5
        filters=[{"id":lzma.FILTER_LZMA1,"dict_size":max(4096,u32(data,pq+1)),"lc":lc,"lp":lpp,"pb":pb}]
        if x86: filters.insert(0,{"id":lzma.FILTER_X86})
        return _StreamReader(lzma.LZMADecompressor(format=lzma.FORMAT_RAW,filters=filters),data[pq+5:end],"lzma")
    if method=="bzip2":
        return _StreamReader(_nsis_bzip2(),data[q:end],"bz2")
    return _StreamReader(zlib.decompressobj(-15),data[q:end],"zlib")

def _nsis_decompress(data,q,end,maxlen):
    """Egy NSIS tomoritett stream kibontasa (legfeljebb maxlen byte). Visszaad: (modszer, adat) vagy None"""
    import lzma
    buf=data[q:end]
    lp=_nsis_lzma_props(data,q)
    if lp:
        pq,x86=lp
        d=data[pq]; lc=d%9; d//=9; lpp=d%5; pb=d//5
        filters=[{"id":lzma.FILTER_LZMA1,"dict_size":max(4096,u32(data,pq+1)),"lc":lc,"lp":lpp,"pb":pb}]
        if x86: filters.insert(0,{"id":lzma.FILTER_X86})
        try:
            out=lzma.LZMADecompressor(format=lzma.FORMAT_RAW,filters=filters).decompress(data[pq+5:end],max_length=maxlen)
            return ("BCJ+lzma" if x86 else "lzma"),out
        except lzma.LZMAError:
            pass
    if buf[:1]==b"1" and len(buf)>1 and buf[1]<14:
        try:
            return "bzip2",_nsis_bzip2().decompress(buf,max_length=maxlen)
        except (ValueError,IndexError,ImportError):
            pass
    try:
        return "deflate",zlib.decompressobj(-15).decompress(buf,maxlen)
    except zlib.error:
        return None

def _nsis_header(data,start,end,hdrlen,errors):
    """A header kibontasa. Visszaad: (header, solid, modszer, adatblokkok kezdete) vagy None"""
    p=start+28
    if hdrlen>NSIS_MAX_HEADER:
        errors.append("NSIS header too big: %d"%(hdrlen))
        return None
    v=u32(data,p)
    if v==hdrlen and p+4+hdrlen<=end:                  # nem solid, tarolt header
        return data[p+4:p+4+hdrlen],False,"store",p+4+hdrlen
    if v&0x80000000:                                   # nem solid, tomoritett header blokk
        csize=v&0x7FFFFFFF
        if p+4+csize<=end:
            r=_nsis_decompress(data,p+4,p+4+csize,hdrlen)
            if r and len(r[1])==hdrlen:
                return r[1],False,r[0],p+4+csize
    r=_nsis_decompress(data,p,end,hdrlen+4)             # solid
    if r and len(r[1])==hdrlen+4 and struct.unpack_from("<I",r[1])[0]==hdrlen:
        return r[1][4:],True,r[0],None
    errors.append("NSIS header could not be decompressed")
    return None

class _NsisStrings:
    def __init__(self,tab):
        self.tab=tab
        # Unicode (NSIS 3): a tabla ures stringgel kezdodik: 00 00
        self.unicode=len(tab)>=2 and tab[0]==0 and tab[1]==0
        if self.unicode:
            self.codes={1:"lang",2:"shell",3:"var",4:"skip"}
        else:
            # ANSI: NSIS 2 kodok 252..255, NSIS 3 kodok 1..4 (a gyakoribb szamit)
            n3=sum(tab.count(bytes([c])) for c in (1,2,3,4))
            n2=sum(tab.count(bytes([c])) for c in (252,253,254,255))
            self.codes={1:"lang",2:"shell",3:"var",4:"skip"} if n3>n2 else {255:"lang",254:"shell",253:"var",252:"skip"}

    def var(self,n):
        if n<10: return "$%d"%(n)
        if n<20: return "$R%d"%(n-10)
        if n-20<len(NSIS_VARS): return "$"+NSIS_VARS[n-20]
        return "$_%d_"%(n-20-len(NSIS_VARS))

    def get(self,off):
        out=[]
        tab=self.tab
        if self.unicode:
            i=off*2
            while i+1<len(tab) and len(out)<4096:
                c=tab[i]|(tab[i+1]<<8); i+=2
                if c==0: break
                kind=self.codes.get(c)
                if kind and i+1<len(tab):
                    n=(tab[i]|(tab[i+1]<<8))&0x7FFF; i+=2
                    out.append(self._code(kind,n,n&0xFF,n>>8))
                else:
                    out.append(chr(c) if not 0xD800<=c<=0xDFFF else "\ufffd")
        else:
            i=off
            while i<len(tab) and len(out)<4096:
                c=tab[i]; i+=1
                if c==0: break
                kind=self.codes.get(c)
                if kind and i+1<len(tab):
                    b1,b2=tab[i],tab[i+1]; i+=2
                    out.append(self._code(kind,(b1&0x7F)|((b2&0x7F)<<7),b1,b2))
                else:
                    out.append(bytes([c]).decode("cp1252","replace"))
        return "".join(out)

    def _code(self,kind,n,b1,b2):
        if kind=="var": return self.var(n)
        if kind=="lang": return "$(LSTR_%d)"%(n)
        if kind=="shell":
            name=NSIS_SHELL.get(b1&0x7F) or NSIS_SHELL.get(b2&0x7F)
            return "$"+name if name else "$SHELL_%d"%(b1)
        return chr(b1) if kind=="skip" else ""

def nsis_details(data,start,end,errors):
    flags,sig=unpack("<II",data,start)
    hdrlen,arclen=unpack("<II",data,start+20)
    h=_nsis_header(data,start,end,hdrlen,errors)
    if h is None:
        return None,False,None
    hdr,solid,method,datastart=h
    # header: flags + 8 blokk (offset,darab): pages, sections, entries, strings, langtables, ...
    blocks=[struct.unpack_from("<II",hdr,4+8*i) for i in range(8)]
    eoff,ecount=blocks[2]
    soff=blocks[3][0]
    if eoff+ecount*28>len(hdr) or soff>len(hdr):
        errors.append("NSIS header block table invalid")
        return None,False,None
    strings=_NsisStrings(hdr[soff:])
    files=[]
    seen=set()
    script={}
    def cmd(k,v):
        l=script.setdefault(k,[])
        if v not in l and len(l)<NSIS_MAX_SCRIPT: l.append(v)
    outdir="$INSTDIR"
    for i in range(min(ecount,1000000)):
        which,p0,p1,p2,p3,p4,p5=struct.unpack_from("<Iiiiiii",hdr,eoff+28*i)
        if which==NSIS_EW_EXECUTE:
            cmd("Exec",strings.get(p0))
        elif which==NSIS_EW_SHELLEXEC:
            cmd("ShellExec"," ".join(x for x in (strings.get(p0),strings.get(p1),strings.get(p2)) if x))
        elif which==NSIS_EW_REGISTERDLL:
            cmd("Plugin","%s::%s"%(strings.get(p0),strings.get(p1)))
        if which==NSIS_EW_CREATEDIR and p1:            # SetOutPath
            outdir=strings.get(p0)
        elif which in (NSIS_EW_EXTRACTFILE,NSIS_EW_WRITEUNINSTALLER):
            if which==NSIS_EW_WRITEUNINSTALLER:
                # az uninstaller: a telepito exe resze + ez az adatblokk (parm0: nev, parm1: adat offset)
                name=strings.get(p0); p2=p1
            else:
                name=strings.get(p1)
            full=name if (name.startswith("$") or ":" in name[:3] or name.startswith("\\")) else outdir+"\\"+name
            if full.startswith("$INSTDIR\\"): full=full[len("$INSTDIR\\"):]
            full=full.replace("\\","/")
            if (full,p2) in seen: continue            # a pluginokat minden hivas elott ujra kibontja: egyszer listazzuk
            seen.add((full,p2))
            size=packed=off=None; m=method
            if not solid and datastart is not None:
                b=datastart+p2
                try:
                    v=u32(data,b)
                    if v&0x80000000:
                        packed=v&0x7FFFFFFF
                    else:
                        size=packed=v; m="store"
                    off=b+4-start
                except struct.error:
                    errors.append("NSIS data block of %r out of range"%(full))
            files.append([full,size,packed,False,m,off,p2])
            if len(files)>=MAX_FILES: break
    if solid:
        # solid: a kibontott streamben minden file elott u32 meret all; sorban olvasva kiolvashato
        try:
            rd=_nsis_decoder(data,start+28,end,method)
            base=4+hdrlen
            for e in sorted(files,key=lambda e:e[6]):
                b=rd.read_at(base+e[6],4)
                if b is None:
                    errors.append("NSIS solid stream ends before %r"%(e[0])); break
                e[1]=struct.unpack("<I",b)[0]
        except Exception as ex:
            errors.append("NSIS solid stream: %s"%(ex))
    return [e[:6] for e in files],False,None,script or None

ARCHIVE_DETAILS={"ZIP":zip_details,"RAR":rar4_details,"RAR14":rar14_details,"RAR5":rar5_details,"CAB":cab_details,"7z":sevenzip_details,
                 "NSIS":nsis_details}


#####################################################################
#   Fo fuggvenyek
#####################################################################

def detect_archive(data,pos=0):
    """(tipus, vege) ha a pos offseten ervenyes archivum kezdodik, kulonben None.
    A vege nagyobb lehet mint len(data), ha a file csonka."""
    hi=len(data)
    if data.startswith(b"PK",pos):
        z=find_zip(data,pos,hi)
        if z and z[0]==pos: return "ZIP",z[1]
    for name,sig,sigoff,endfunc in ARCHIVE_SIGS:
        if data.startswith(sig,pos+sigoff):
            try:
                end=endfunc(data,pos,hi)
            except (struct.error,IndexError):
                end=None
            if end is not None: return name,end
    if data.startswith(b"zlb\x1a",pos) or data.startswith(b"idska32\x1a",pos):
        return "Inno Setup",hi
    return None

def dump_archive(data):
    """data: az archivum (bytes), a 0. offseten kezdodik. Visszaad: None vagy dict (lasd a modul leirasat)"""
    d=detect_archive(data)
    if d is None:
        if data.startswith(b"PK\3\4"):
            # ZIP local header, de nincs (ervenyes) central directory: csonka vagy serult,
            # a tartalomjegyzeket a local headerekbol probaljuk helyreallitani
            files,enc=zip_local_headers(data)
            return {"type":"ZIP","size":len(data),"files":files,"encrypted":enc,"comment":None,"sfx_script":None,
                    "errors":["ZIP central directory not found, listing recovered from local headers"],"truncated":True}
        return None
    name,end=d
    r={"type":name,"size":end,"files":None,"encrypted":None,"comment":None,"sfx_script":None,
       "errors":[],"truncated":end>len(data)}
    func=ARCHIVE_DETAILS.get(name)
    if func:
        try:
            res=func(data,0,min(end,len(data)),r["errors"])
            files,enc,comment=res[:3]
            r.update({"files":files,"encrypted":enc,"comment":comment})
            if len(res)>3: r["sfx_script"]=res[3]         # NSIS: a telepito szkript parancsai
        except Exception as e:
            log(0,"exc:archive_listing %s: %r"%(name,e))
            r["errors"].append("%s listing error: %s"%(name,e))
    if r["comment"] and not r["sfx_script"]:
        r["sfx_script"]=parse_winrar_script(r["comment"])
    return r


#####################################################################
#   teszteles: archivumok es (ha a parseexe elerheto) exe-kbe agyazott archivumok
#####################################################################

def dump_file(data):
    """Egy file: archivum a 0. offseten, vagy exe-be agyazott archivum. Visszaad: (dict, honnan) vagy (None,None)"""
    a=dump_archive(data)
    if a is not None: return a,None
    try:
        import parseexe
    except ImportError:
        return None,None
    r=parseexe.dump_exe(data)
    if r and r.get("archive"):
        s,n=r["archive_start"],r["archive_size"]
        return dump_archive(data[s:s+n]),"%s@0x%X"%(r["type"],s)
    return None,None

def short(a,where):
    if a is None: return "None"
    s="%s size=0x%X"%(a["type"],a["size"])
    if where: s+=" (in %s)"%(where)
    if a["files"] is not None: s+=" files=%d"%(len(a["files"]))
    if a["encrypted"]: s+=" ENCRYPTED%s"%("(headers)" if a["encrypted"]=="headers" else "")
    if a["comment"]: s+=" comment=%d chars"%(len(a["comment"]))
    if a["sfx_script"]: s+=" sfx_script=[%s]"%(", ".join(a["sfx_script"]))
    if a["truncated"]: s+=" TRUNCATED"
    if a["errors"]: s+=" ERRORS=%d"%(len(a["errors"]))
    return s


if __name__ == '__main__':
  import os, sys, json, argparse
  ap=argparse.ArgumentParser(description="Archivum elemzo es tesztelo")
  ap.add_argument("paths",nargs="+",help="vizsgalando fileok/konyvtarak")
  ap.add_argument("-v","--verbose",action="store_true",help="debug log")
  ap.add_argument("-l","--list",action="store_true",help="tartalomjegyzek kiirasa")
  ap.add_argument("-s","--save",metavar="JSON",help="eredmenyek mentese")
  ap.add_argument("-c","--compare",metavar="JSON",help="osszevetes korabbi eredmennyel")
  args=ap.parse_args()
  debug=args.verbose

  def iter_files(paths):
    for path in paths:
      if os.path.isdir(path):
        for root,dirs,files in os.walk(path):
          dirs.sort()
          for name in sorted(files): yield os.path.join(root,name)
      else:
        yield path

  results={}
  ref=json.load(open(args.compare)) if args.compare else None
  nfail=nnew=0
  for path in iter_files(args.paths):
    try:
      with open(path,"rb") as f: data=f.read()
      a,where=dump_file(data)
    except Exception as e:
      a,where={"type":"CRASH","size":0,"files":None,"encrypted":None,"comment":None,
               "sfx_script":None,"truncated":False,"errors":["exc:main: %r"%(e)]},None
    res=json.loads(json.dumps({"result":a,"in":where}))
    results[path]=res
    status=""
    if ref is not None:
      if path not in ref: status="NEW "; nnew+=1
      elif ref[path]!=res: status="FAIL "; nfail+=1
      else: status="OK "
    print("%s%s: %s"%(status,path,short(a,where)))
    if args.list and a and a["files"]:
      for f in a["files"]: print("   %-50s %10s %10s %-12s %s"%(f[0],f[1],f[2],f[4],"*" if f[3] else ""))
    if status=="FAIL ":
      print("   expected: %s"%(ref[path],))
      print("   got:      %s"%(res,))
  if args.save:
    with open(args.save,"w") as f:
      json.dump(results,f,indent=1,ensure_ascii=False,sort_keys=True)
  if ref is not None:
    print("\n%d file: %d OK, %d FAIL, %d NEW"%(len(results),len(results)-nfail-nnew,nfail,nnew))
    sys.exit(1 if nfail else 0)
