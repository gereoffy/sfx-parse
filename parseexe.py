#!/usr/bin/env python3

import struct
import traceback

debug=False

def log(level,text):
    if level>0 or debug: print(level,text)

def unpack(fmt,data,pos):
    """struct.unpack a data[pos:] helyen; a kicsomagolt ertekek utan az uj poziciot is visszaadja."""
    if pos<0:
        raise struct.error("negative offset: %d"%(pos))
    return struct.unpack_from(fmt,data,pos)+(pos+struct.calcsize(fmt),)

def unp_cstr(data,pos):
    """0-val lezart string olvasasa (vagy a data vegeig). Visszaad: (string, uj pozicio a 0 utan)"""
    if pos<0:
        raise ValueError("negative offset: %d"%(pos))
    end=data.find(b"\0",pos)
    if end<0:
        end=max(pos,len(data))
        return data[pos:end].decode("latin-1"),end
    return data[pos:end].decode("latin-1"),end+1

def printable(b,minc=32,maxc=None):
    return "".join(chr(c) for c in b if c>=minc and (maxc is None or c<maxc))



dotnet_tab={0:"Module",1:"TypeRef",2:"TypeDef",4:"Field",6:"MethodDef",8:"Param",9:"InterfaceImpl",10:"MemberRef",11:"Constant",
    12:"CustomAttribute",13:"FieldMarshal",14:"DeclSecurity", 15:"ClassLayout",16:"FieldLayout",17:"StandAloneSig",
    18:"EventMap",20:"Event",21:"PropertyMap", 23:"Property",24:"MethodSemantics",25:"MethodImpl",
    26:"ModuleRef",27:"TypeSpec",28:"ImplMap",  29:"FieldRVA",
    32:"Assembly",33:"AssemblyProcessor",34:"AssemblyOS",35:"AssemblyRef",36:"AssemblyRefProcessor",37:"AssemblyRefOS",
    38:"File",39:"ExportedType",40:"ManifestResource",41:"NestedClass",42:"GenericParam",44:"GenericParamConstraint"}

def dotnet_parsemeta(data,pos,metalen):
  metapos=pos
  marker,version,reserved,verlen,pos = unpack("<IIII",data,pos)
  if marker!=0x424A5342:
    return
  version=printable(data[pos:pos+verlen],32,128)
  pos=min(pos+verlen,max(pos,len(data)))

  flags,streams,pos = unpack("<HH",data,pos)
  log(1,".NET Metadata %s flags=%d streams=%d len=%d"%(version,flags,streams,metalen))
  sections={}
  while streams>0:
    s=pos
    if s+12>metapos+metalen:
        return
    s_off,s_size,pos = unpack("<II",data,pos)
    s_name,pos=unp_cstr(data,pos)
    l=pos-s
    log(0,".NET SECT: %08X %5d '%s' %d"%(s_off,s_size,s_name,l))
    if l&3:
      pos+=4-(l&3) # padding
    streams-=1
    sections[s_name]=(s_off,s_size)
  strpos=metapos+sections['#Strings'][0]
  strings=data[strpos:strpos+sections['#Strings'][1]]
  pos=metapos+sections['#~'][0]
  # metadata tables!
  reserved,version,sizemask,onebyte,pos = unpack("<IHBB",data,pos)
  # sizemask:  &1=stringDWORD  &2=guidDQORD  &4=blobDWORD
  validmask,sortedmask,pos=unpack("<QQ",data,pos)
  tables={}
  for bit in range(64):
    if validmask&(1<<bit):
      n,pos=unpack("<I",data,pos)
      tables[bit]=n
      if bit in dotnet_tab:
        log(0,"Table %d [%s]: %d"%(bit,dotnet_tab[bit],n))
      else:
        log(0,"Table %d: %d"%(bit,n))
    else:
      tables[bit]=0

  if not debug:
    return

  def rd(fmt):
    nonlocal pos
    *vals,pos=unpack(fmt,data,pos)
    return vals

  def skip(n):
    nonlocal pos
    pos+=n

  def read_str():
    i=rd("<Q" if sizemask&1 else "<H")[0]
    end=strings.find(b"\0",i)
    return printable(strings[i:] if end<0 else strings[i:end],32,128)

  guidsize=4 if sizemask&2 else 2
  blobsize=4 if sizemask&4 else 2
  ref_tables={}

  # Table 0: Module
  for i in range(tables[0]):
    rd("<H")
    name=read_str()
    skip(3*guidsize)

  # Table 1: TypeRef
  ref_tables[1]=[]
  for i in range(tables[1]):
    rd("<H")
    name=read_str()
    namespace=read_str()
    ref_tables[1].append(namespace+"::"+name)

  # Table 2: TypeDef
  ref_tables[0]=[]
  for i in range(tables[2]):
    rd("<I") # flags
    name=read_str()
    namespace=read_str()
    ref_tables[0].append(namespace+"::"+name)
    rd("<HHH") # 3 index

  # Table 4: Field
  for i in range(tables[4]):
    rd("<H") # flags
    name=read_str()
    skip(blobsize) # blob index

  # Table 6: MethodDef
  ref_tables[3]=[]
  for i in range(tables[6]):
    rd("<I") # RVA
    rd("<HH") # implflags,flags
    name=read_str()
    ref_tables[3].append(name)
    skip(blobsize) # blob index
    rd("<H") # index

  # Table 8: Param
  for i in range(tables[8]):
    rd("<HH") # flags,seq
    name=read_str()

  # Table 9: InterfaceImpl
  for i in range(tables[9]):
    rd("<HH") # flags,seq

  # Table 10: MemberRef
  MemberRefParent=["TypeDef","TypeRef","ModuleRef","MethodDef","TypeSpec","???","???","???"]
  for i in range(tables[10]):
    x=rd("<H")[0] # class
    name=read_str()
    try:
      log(0,"%s[%d] = %s.%s"%(MemberRefParent[x&7],x>>3,ref_tables[x&7][x>>3],name))
    except (KeyError,IndexError):
      log(0,"%s[%d] = %s"%(MemberRefParent[x&7],x>>3,name))
    skip(blobsize) # blob index






def dump_pe(data,pos,exesize):
  dlllist=None
  dotnet=0
  try:
    # IMAGE_FILE_HEADER 0xD8
    zero,arch,numsects, timedate,debug1,debug2, ophdrsize,charflags,pos = unpack("<HHHLLLHH",data,pos)
    start_oh=pos
    # IMAGE_OPTIONAL_HEADER 0xF0
    magic,lnkvers, size_code,size_data,size_bss,  rva1,rva2,  rva3,loadaddr,pos=unpack("<HHLLLLLLL",data,pos)
    if magic!=0x20B and magic!=0x10B:
        log(0,"Bad PE OH MAGIC number: 0x%02X"%(magic))
    sect_align,file_align,os_ver,bin_ver,subsys_ver,win32_ver,pos=unpack("<LLLLLL",data,pos)
    image_size,header_size,CRC, subsys,dllchr,pos=unpack("<LLLHH",data,pos)
    if arch==0x14c:
        log(0,"32-bit PE-EXE detected!")
        if magic!=0x10B:
            log(0,"Bad PE OH magic: 0x%02X"%(magic))
        if ophdrsize!=224:
            log(0,"Bad PE OH size: %d"%(ophdrsize))
        stack_rvd,stack_com,heap_rvd,heap_com,pos=unpack("<LLLL",data,pos)
    elif arch==0x8664:
        log(0,"64-bit PE-EXE detected!")
        if magic!=0x20B:
            log(0,"Bad PE OH magic: 0x%02X"%(magic))
        if ophdrsize!=240:
            log(0,"Bad PE OH size: %d"%(ophdrsize))
        stack_rvd,stack_com,heap_rvd,heap_com,pos=unpack("<QQQQ",data,pos)
    else:
        log(0,"Unknown format PE-EXE detected! arch=0x%02X ohmagic=%02X ohlen=%d"%(arch,magic,ophdrsize))
    loader_flags,num_dirent,pos=unpack("<LL",data,pos)
    # IMAGE_DATA_DIRECTORYs
    img_dir_entries=[]
    for i in range(0,16):
        *tmp,pos=unpack("<2L",data,pos)
        img_dir_entries.append(tuple(tmp))
    # SECTIONS:
    sections=[]
    for sno in range(numsects):
        sect_name,tmp,rva,rawsize,fileoff,ptr_reloc,ptr_lno,num_reloc,num_lno,flags,pos=unpack("<8sLLLLLLHHL",data,pos)
        name=printable(sect_name)
        #     0      1       2     3    4
        tmp=(name,rawsize,fileoff,rva,flags)
        sections.append(tmp)
        log(0,"SECT: '%s' %d 0x%08X<-0x%08X" % (name,rawsize,fileoff,rva))
        if name=="_winzip_":
            exesize=fileoff+0x2f
            log(0,"WinZip SFX detected, ZIP file at 0x%08X" % (exesize))
        elif fileoff+rawsize>exesize:
            exesize=fileoff+rawsize

    def rva_to_file(rva,sections):
        for sect in sections:
            if rva>=sect[3] and rva<sect[3]+sect[1]:
                return sect[2]+(rva-sect[3])
        return rva  #&0x7fffffffffffffff

    tmp=img_dir_entries[14]
    if tmp[0] and tmp[1]>=16:
        dotnet=1
        nethdr_pos=rva_to_file(tmp[0],sections)
        log(0,"MS .NET binary detected! header pos=0x%X len=%d" % (nethdr_pos,tmp[1]))
        try:
          hdrlen,ver1,ver2,metadata_rva,metadata_len,_=unpack("<IHHII",data,nethdr_pos) # 16 bytes
          metadata_pos=rva_to_file(metadata_rva,sections)
          log(0,".NET header: v%d.%d  MetaData: fpos=0x%X len=%d"%(ver1,ver2,metadata_pos,metadata_len))
          dotnet_parsemeta(data,metadata_pos,metadata_len)
        except Exception:
          log(3,"Exception!!! while .NET parsing: %s" % (traceback.format_exc()))

    tmp=img_dir_entries[1]
    if tmp[1]:
        fpos=rva_to_file(tmp[0],sections)
        if fpos:
            # we have imports! load 'em all!
            imps=[]
            while 1:
                *imp,fpos=unpack("<LLLLL",data,fpos)
                if (imp[0]==0 or imp[3]==0) and imp[4]==0:
                    break
                imps.append(imp)
            dlllist=[]
            for imp in imps:
                dllentry=[""]
                # read DLL name:
                fpos=rva_to_file(imp[3],sections)
                if fpos:
                    dllentry[0],_=unp_cstr(data,fpos)
                # dump symbols:
                if imp[0]:
                    fpos=rva_to_file(imp[0],sections)
                else:
                    fpos=rva_to_file(imp[4],sections)
                if fpos:
                  try:
                    symfmt="<Q" if arch==0x8664 else "<L"  # 64/32 bit
                    syms=[]
                    while 1:
                        sym,fpos=unpack(symfmt,data,fpos)
                        if sym==0:
                            break
                        syms.append(sym)
                    for sym in syms:
                        if sym<0x80000000:
                            fpos=rva_to_file(sym,sections)
                            if fpos:
                                hint,fpos=unpack("<H",data,fpos)
                                dllentry.append(unp_cstr(data,fpos)[0])
                        else:
                            dllentry.append("0x%X"%(sym&0x7FFFFFFF))
                  except Exception:
                    log(3,"error parsing DLL info at 0x%08X" % (fpos))
                dlllist.append(dllentry)
  except Exception:
    log(3,"Exception!!! while PE-EXE parsing: %s" % (traceback.format_exc()))
  return ("PE",exesize,dlllist,dotnet)


# 4C 01 03 00 │ 00 00 00 00 │ 00 00 00 00 │ 00 00 00 00 │ 1C 00 0F 01 │ 0B 01 00 00 │ 58 BB 02 00 │ 00 30 00 00 │ 00 CE 00 00  L.......................X....0......
def dump_coff(data,pos,hdr):
    hdr2len=hdr[16]+hdr[17]*256
    if len(data[pos:pos+hdr2len])!=hdr2len: return 0 # bad
    pos+=hdr2len
    coffsize=20+hdr2len
    # read sections!
    for sn in range(hdr[2]):
        sect=data[pos:pos+40]
        pos+=40
        size=sect[16]+(sect[17]<<8)+(sect[18]<<16)+(sect[19]<<24)
        fpos=sect[20]+(sect[21]<<8)+(sect[22]<<16)+(sect[23]<<24)
        if fpos and fpos+size>coffsize: coffsize=fpos+size
    return coffsize

def dump_exe(data):
    """data: a teljes file tartalma (bytes). Visszaad: None vagy (tipus, exe_meret[, dlllist, dotnet])"""
    try:
        MZ,_=unpack("<H",data,0)
        if not MZ in (0x5A4D,0x4D5A):
            return None
# 4D 5A 26 01   1E 00 01 00   06 00 88 0C   FF FF 00 00   40 5E 00 00   00 01 F0 FF   52 00 00 00 
# M  Z  size_l size_h relocs hdrsize allmin/max   SS      SP    CRC     IP    CS     reloff  ovl
        size_l,size_h,relocs,hdrsize,allocmin,allocmax,SS,SP,CRC,IP,CS,relocoff,ovl,_ = unpack("<13H",data,2)
        if size_l>512 or size_h==0:
            log(1,"invalid MZ file, probably text? (size=%d,%d)"%(size_l,size_h))
            return None
    except Exception:
        log(3,"Exception!!! while MZ-EXE parsing: %s" % (traceback.format_exc()))
        return None
    size=size_h*512
    if size_l:
        size+=size_l-512
    try:
        # coff:
        if size<32768:
            coff=data[size:size+20]
            if len(coff)==20 and coff[0]==0x4C and coff[1]==1 and coff[2]>0 and coff[3]==0:
                coffsize=dump_coff(data,size+20,coff)
                if coffsize: return "COFF",size+coffsize
        # new-exe:
        ne_off,_=unpack("<L",data,0x3c)
        log(0,"NE start pos: %d+%d"%(0,ne_off))
        NE,pos=unpack("<H",data,ne_off)
        if NE==0x4550:
            return dump_pe(data,pos,size)
        if NE==0x454E:
            # win 3.1 (16-bit) EXE (FIXME: parse out size!)
            return ("NE",size)
        if NE==0x434C:
            # DOS/32A: (FIXME: parse out size!)
            return ("LC",size)
        if NE==0x454C:
            # dos4gw/watcom: (FIXME: parse out size!)
            return ("LE",size)
    except Exception:
        log(3,"Exception!!! while NE-EXE parsing: %s" % (traceback.format_exc()))
    return ("MZ",size)


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
    if isinstance(ret,(tuple,list)):
        return [to_json(x) for x in ret]
    return ret

def log_summary(text):
    # traceback sorszamok/kodsorok nelkul, hogy atiras utan is osszevetheto legyen
    return [l for l in text.splitlines() if not l.startswith("  ")]

def short(ret):
    if ret is None: return "None"
    s="%s size=0x%X"%(ret[0],ret[1])
    if len(ret)>2:
        dlls=ret[2]
        s+=" dotnet=%d dlls=%s"%(ret[3],"None" if dlls is None else len(dlls))
        if dlls: s+=" [%s]"%(", ".join(d[0] for d in dlls))
    return s


if __name__ == '__main__':
  import sys, json, argparse
  ap=argparse.ArgumentParser(description="DOS/Windows EXE elemzo es tesztelo")
  ap.add_argument("paths",nargs="+",help="vizsgalando fileok/konyvtarak")
  ap.add_argument("-v","--verbose",action="store_true",help="debug log")
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
    except Exception:
      ret,logtext="CRASH",traceback.format_exc()
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
    print("%s%s: %s"%(status,path,short(ret) if ret!="CRASH" else "CRASH"))
    if status=="FAIL ":
      print("   expected: %s"%(ref[path]["result"],))
      print("   got:      %s"%(r["result"],))
    if status=="LOGDIFF ":
      print("   expected log: %s"%(ref[path]["log"],))
      print("   got log:      %s"%(r["log"],))
    if args.extract and ret and ret!="CRASH":
      with open(path,"rb") as f:
        data=f.read()[ret[1]:]
      if data:
        open(path+".dump","wb").write(data)

  if args.save:
    with open(args.save,"w") as f:
      json.dump(results,f,indent=1,ensure_ascii=False,sort_keys=True)
  if ref is not None:
    gone=[p for p in ref if p not in results and any(p.startswith(a.rstrip("/")) for a in args.paths)]
    print("\n%d file: %d OK, %d FAIL, %d LOGDIFF, %d NEW, %d MISSING"%(len(results),len(results)-nfail-nlogdiff-nmissing,nfail,nlogdiff,nmissing,len(gone)))
    sys.exit(1 if nfail or gone else 0)
