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
    type       "ZIP" | "RAR" | "RAR5" | "7z" | "CAB" | "NSIS" | "Inno Setup"
    size       az archivum merete (ami utana van, az nem resze, pl. digitalis alairas)
    files      tartalomjegyzek: [[nev, meret, tomoritett meret, titkositott, modszer], ...]
               (ZIP, RAR, RAR5, 7z, CAB; a meretek None-ok lehetnek), None ha nem olvashato.
               A tomoritett meret tarolt (store) filenal = meret (titkositva a padding/fejlec miatt
               nagyobb); 7z solid folderben es CAB-ban None, mert ott nincs file szintu tomoritett meret.
               modszer: "store" = tomoritetlen; ZIP: "deflate","bzip2","lzma",... (AES eseten a valodi
               modszer), RAR: "m1".."m5", 7z: a coder lanc pl. "BCJ2+LZMA" / "LZMA2+AES", CAB: "MSZIP",
               "LZX","Quantum". Ures filenal (7z) None. Konyvtarak nincsenek a listaban; symlink/hardlink
               bejegyzesek fileként szerepelnek.
    encrypted  False, True (van jelszavas file), "headers" (a tartalomjegyzek is titkositott)
    comment    az archivum kommentje (RAR/ZIP; WinRAR SFX eseten itt vannak az SFX parancsok)
    sfx_script a kommentbol kiolvasott WinRAR SFX parancsok: {parancs: [ertekek]} vagy None
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
    for i in range(min(nent,MAX_FILES)):
        if data[p:p+4]!=b"PK\1\2": break
        flags,method=unpack("<HH",data,p+8)
        csize,usize,fnlen,xlen,cmlen=unpack("<IIHHH",data,p+20)
        name=data[p+46:p+46+fnlen].decode("utf-8" if flags&0x800 else "cp437","replace")
        realmethod=method
        x=p+46+fnlen
        while x+4<=p+46+fnlen+xlen:     # extra mezok: ZIP64 meretek, AES (a valodi modszer)
            xid,xsz=unpack("<HH",data,x)
            if xid==1 and (usize==0xFFFFFFFF or csize==0xFFFFFFFF):
                vals=list(unpack("<%dQ"%(min(xsz,16)//8),data,x+4))
                if usize==0xFFFFFFFF and vals: usize=vals.pop(0)
                if csize==0xFFFFFFFF and vals: csize=vals.pop(0)
            elif xid==0x9901 and xsz>=7:
                realmethod=u16(data,x+4+5)
            x+=4+xsz
        e=bool(flags&1) or method==99
        enc|=e
        if not name.endswith("/"):      # konyvtar nem kell
            files.append([name,usize,csize,e,zip_method_name(realmethod)])
        p+=46+fnlen+xlen+cmlen
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
        name=data[p+30:p+30+fnlen].decode("utf-8" if flags&0x800 else "cp437","replace")
        e=bool(flags&1) or method==99
        enc|=e
        if not name.endswith("/"):
            files.append([name,None if flags&8 else usize,None if flags&8 else csize,e,zip_method_name(method)])
        if flags&8: break               # data descriptor: a tomoritett meret nem ismert, nem lephetunk tovabb
        p+=30+fnlen+xlen+csize
    return files,enc

ZIP_METHODS={0:"store",1:"shrink",2:"reduce1",3:"reduce2",4:"reduce3",5:"reduce4",6:"implode",8:"deflate",
    9:"deflate64",10:"pkware-dcl",12:"bzip2",14:"lzma",18:"terse",19:"lz77",93:"zstd",94:"mp3",95:"xz",
    96:"jpeg",97:"wavpack",98:"ppmd",99:"aes"}

def zip_method_name(m):
    return ZIP_METHODS.get(m,"m%d"%(m))

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
            if flags&0x02:
                errors.append("RAR4 old style (compressed) comment not decoded")
        elif htype in (0x74,0x7A):
            psize,usize,hostos,fcrc,ftime,uver,method,nsize,attr=unpack("<IIBIIBBHI",data,p+7)
            q=p+32
            if flags&0x100:
                hp,hu=unpack("<II",data,q); psize|=hp<<32; usize|=hu<<32; q+=8
            raw=data[q:q+nsize]
            add=psize
            if htype==0x74:
                name=raw.split(b"\0")[0].decode("utf-8" if flags&0x200 else "cp437","replace").replace("\\","/")
                e=bool(flags&0x04)
                enc|=e
                if flags&0xE0!=0xE0:     # konyvtar nem kell
                    files.append([name,usize,psize,e,rar_method_name(method-0x30)])
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
            # extra terulet: 1 = file encryption rekord
            e=False
            xp=hend-xsize
            while xp<hend:
                rsize,rp=_vint(data,xp)
                rtype,rp2=_vint(data,rp)
                if rtype==1: e=True
                xp=rp+rsize
            if htype==2:
                enc|=e
                if not fflags&1:         # konyvtar nem kell
                    files.append([name,None if fflags&8 else usize,dsize,e,rar_method_name((cinfo>>7)&7)])
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
        files.append([name,fsize,None,False,folder_methods[ifolder] if ifolder<len(folder_methods) else None])
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
    names=[]; empty=[]; emptyfile=[]; anti=[]
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
                rd.p=pend
        else:
            raise ValueError("7z: bad Header property %d"%(t))
    # meretek: a nem ures stream-u fileok sorban kapjak a substream mereteket
    # tomoritett meret: csak az egy-fileos foldereknel ertelmezheto (a folder osszes pack streamje);
    # solid folderben a fileoknak nincs kulon tomoritett merete (None)
    sizes=[]; folders_of=[]; packed=[]; methods=[]
    enc=False
    if si:
        pi=0
        for fi,(f,ss) in enumerate(zip(si["folders"],si["substreams"])):
            fenc=any(c[0]==SZ_AES for c in f["coders"])
            enc|=fenc
            fpack=sum(si["packsizes"][pi:pi+f["npacked"]]) if pi+f["npacked"]<=len(si["packsizes"]) else None
            pi+=f["npacked"]
            fmethod=sz_method_name(f)
            for s in ss:
                sizes.append(s); folders_of.append(fenc); packed.append(fpack if len(ss)==1 else None)
                methods.append(fmethod)
    files=[]
    k=0
    ei=0
    for i in range(nfiles):
        name=names[i] if i<len(names) else "?"
        if empty and empty[i]:
            isdir=not (emptyfile[ei] if ei<len(emptyfile) else False)
            ei+=1
            if not isdir: files.append([name,0,0,False,None])      # ures file: nincs adata, nincs modszer
        else:
            s=sizes[k] if k<len(sizes) else None
            e=folders_of[k] if k<len(folders_of) else False
            pk=packed[k] if k<len(packed) else None
            m=methods[k] if k<len(methods) else None
            k+=1
            files.append([name,s,pk,e,m])
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

ARCHIVE_DETAILS={"ZIP":zip_details,"RAR":rar4_details,"RAR5":rar5_details,"CAB":cab_details,"7z":sevenzip_details}


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
            files,enc,comment=func(data,0,min(end,len(data)),r["errors"])
            r.update({"files":files,"encrypted":enc,"comment":comment})
        except Exception as e:
            log(0,"exc:archive_listing %s: %r"%(name,e))
            r["errors"].append("%s listing error: %s"%(name,e))
    if r["comment"]:
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
