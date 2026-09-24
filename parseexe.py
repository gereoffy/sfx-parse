#!/usr/bin/env python3

import struct
import traceback

debug=False

def log(level,text):
    if level>0 or debug: print(level,text)

def unpack(fmt,f):
#    l=struct.calcsize(fmt)
#    data=f.read(l)
#    print("l=%d  len(data)=%d"%(l,len(data)))
#    return struct.unpack(fmt,data)
    return struct.unpack(fmt,f.read(struct.calcsize(fmt)))

def unp_cstr(f):
    s=""
    while 1:
        #c,=unpack("c",f)
        c=f.read(1)
        try:
            # python2
            if len(c)!=1 or ord(c[0])==0:
                return s
            s+=c
        except TypeError:
            # python3
            if len(c)!=1 or c[0]==0:
                return s
            s+=chr(c[0])



dotnet_tab={0:"Module",1:"TypeRef",2:"TypeDef",4:"Field",6:"MethodDef",8:"Param",9:"InterfaceImpl",10:"MemberRef",11:"Constant",
    12:"CustomAttribute",13:"FieldMarshal",14:"DeclSecurity", 15:"ClassLayout",16:"FieldLayout",17:"StandAloneSig",
    18:"EventMap",20:"Event",21:"PropertyMap", 23:"Property",24:"MethodSemantics",25:"MethodImpl",
    26:"ModuleRef",27:"TypeSpec",28:"ImplMap",  29:"FieldRVA",
    32:"Assembly",33:"AssemblyProcessor",34:"AssemblyOS",35:"AssemblyRef",36:"AssemblyRefProcessor",37:"AssemblyRefOS",
    38:"File",39:"ExportedType",40:"ManifestResource",41:"NestedClass",42:"GenericParam",44:"GenericParamConstraint"}

def dotnet_parsemeta(zf,metalen):
  metapos=zf.tell()
  marker,version,reserved,verlen = unpack("<IIII",zf)
  if marker!=0x424A5342:
    return
  versionstr=zf.read(verlen).decode("us-ascii","ignore")

  version=""
  for c in versionstr:
            try:
                if ord(c)>=32 and ord(c)<128:
                    version+=c
            except TypeError:
                if c>=32 and c<128:
                    version+=chr(c)  # python3

  flags,streams = unpack("<HH",zf)
  log(1,".NET Metadata %s flags=%d streams=%d len=%d"%(version,flags,streams,metalen))
  sections={}
  while streams>0:
    s=zf.tell()
    if s+12>metapos+metalen:
        return
    s_off,s_size = unpack("<II",zf)
    s_name=unp_cstr(zf)
    l=zf.tell()-s
    log(0,".NET SECT: %08X %5d '%s' %d"%(s_off,s_size,s_name,l))
    if l&3:
      zf.read(4-(l&3)) # padding
    streams-=1
    sections[s_name]=(s_off,s_size)
#  zf.read(metapos+sections['#~'][0]-f.tell())
  zf.seek(metapos+sections['#Strings'][0])
  strings=zf.read(sections['#Strings'][1])
#  print(len(strings))
  zf.seek(metapos+sections['#~'][0])
#  print("%08X"%(zf.tell()))
  # metadata tables!
  reserved,version,sizemask,onebyte = unpack("<IHBB",zf)
  # sizemask:  &1=stringDWORD  &2=guidDQORD  &4=blobDWORD
  validmask,sortedmask=unpack("<QQ",zf)
  bit=0
  mask=1
  tables={}
  while bit<64:
    if validmask&mask:
      n=unpack("<I",zf)[0]
      tables[bit]=n
      try:
        log(0,"Table %d [%s]: %d"%(bit,dotnet_tab[bit],n))
#        tables[dotnet_tab[bit]]=n
      except:
        log(0,"Table %d: %d"%(bit,n))
    else:
      tables[bit]=0
    bit+=1
    mask+=mask

  if not debug:
    return

  tablerows=zf.tell()

  def read_str():
    if sizemask&1:
      i=unpack("<Q",zf)[0]
    else:
      i=unpack("<H",zf)[0]
#    if i>=len(strings): print("Str index: %d"%(i))
    s=""
    while i<len(strings):
      c=strings[i]
#      print(c)
      try:
        if ord(c)==0: break
        if ord(c)>=32 and ord(c)<128: s+=c
      except TypeError:
        if c==0: break
        if c>=32 and c<128: s+=chr(c)
      i+=1
#    print('"%s"'%s)
    return s

  guidsize=4 if sizemask&2 else 2
  blobsize=4 if sizemask&4 else 2
  ref_tables={}

#  print("%08X reading Table 0: Module Table (%d)"%(zf.tell(),tables[0]))
  for i in range(tables[0]):
    x=unpack("<H",zf)
    name=read_str()
    zf.read(3*guidsize)

#  print("%08X reading Table 1: TypeRef Table (%d)"%(zf.tell(),tables[1]))
  ref_tables[1]=[]
  for i in range(tables[1]):
    x=unpack("<H",zf)
    name=read_str()
    namespace=read_str()
    ref_tables[1].append(namespace+"::"+name)

#  print("%08X reading Table 2: TypeDef Table (%d)"%(zf.tell(),tables[2]))
  ref_tables[0]=[]
  for i in range(tables[2]):
    x=unpack("<I",zf) # flags
    name=read_str()
    namespace=read_str()
    ref_tables[0].append(namespace+"::"+name)
    unpack("<HHH",zf) # 3 index

#  print("%08X reading Table 4: Field Table (%d)"%(zf.tell(),tables[4]))
  for i in range(tables[4]):
    x=unpack("<H",zf) # flags
    name=read_str()
    zf.read(blobsize) # blob index

#  print("%08X reading Table 6: MethodDef Table (%d)"%(zf.tell(),tables[6]))
  ref_tables[3]=[]
  for i in range(tables[6]):
    x=unpack("<I",zf) # RVA
    x=unpack("<HH",zf) # implflags,flags
    name=read_str()
    ref_tables[3].append(name)
    zf.read(blobsize) # blob index
    unpack("<H",zf) # index

#  print("%08X reading Table 8: Param Table (%d)"%(zf.tell(),tables[8]))
  for i in range(tables[8]):
    x=unpack("<HH",zf) # flags,seq
    name=read_str()

#  print("%08X reading Table 9: InterfaceImpl Table (%d)"%(zf.tell(),tables[9]))
  for i in range(tables[9]):
    x=unpack("<HH",zf) # flags,seq

#  print("%08X reading Table 10: MemberRef Table (%d)"%(zf.tell(),tables[10]))
  for i in range(tables[10]):
    x=unpack("<H",zf)[0] # class
    MemberRefParent=["TypeDef","TypeRef","ModuleRef","MethodDef","TypeSpec","???","???","???"]
#    print("%s[%d] = %s"%(MemberRefParent[x&7],x>>3,typeref_table[x>>3]))
    name=read_str()
    try:
      log(0,"%s[%d] = %s.%s"%(MemberRefParent[x&7],x>>3,ref_tables[x&7][x>>3],name))
    except:
      log(0,"%s[%d] = %s"%(MemberRefParent[x&7],x>>3,name))
    zf.read(blobsize) # blob index






def dump_pe(f,startoff,exesize):
  dlllist=None
  dotnet=0
  try:
    # IMAGE_FILE_HEADER 0xD8
    zero,arch,numsects, timedate,debug1,debug2, ophdrsize,charflags = unpack("<HHHLLLHH",f)
#    print("PE arch=0x%04X  numsects=%d"%(arch,numsects))
    start_oh=f.tell()
    # IMAGE_OPTIONAL_HEADER 0xF0
    magic,lnkvers, size_code,size_data,size_bss,  rva1,rva2,  rva3,loadaddr=unpack("<HHLLLLLLL",f)
    #print("magic=0x%X  opt_hdr_len=%d   size=%d+%d+%d"%(magic,ophdrsize,  size_code,size_data,size_bss))
    if magic!=0x20B and magic!=0x10B:
        log(0,"Bad PE OH MAGIC number: 0x%02X"%(magic))
    sect_align,file_align,os_ver,bin_ver,subsys_ver,win32_ver=unpack("<LLLLLL",f)
    image_size,header_size,CRC, subsys,dllchr=unpack("<LLLHH",f)
    if arch==0x14c:
        log(0,"32-bit PE-EXE detected!")
        if magic!=0x10B:
            log(0,"Bad PE OH magic: 0x%02X"%(magic))
        if ophdrsize!=224:
            log(0,"Bad PE OH size: %d"%(ophdrsize))
        stack_rvd,stack_com,heap_rvd,heap_com=unpack("<LLLL",f)
    elif arch==0x8664:
        log(0,"64-bit PE-EXE detected!")
        if magic!=0x20B:
            log(0,"Bad PE OH magic: 0x%02X"%(magic))
        if ophdrsize!=240:
            log(0,"Bad PE OH size: %d"%(ophdrsize))
        stack_rvd,stack_com,heap_rvd,heap_com=unpack("<QQQQ",f)
    else:
        log(0,"Unknown format PE-EXE detected! arch=0x%02X ohmagic=%02X ohlen=%d"%(arch,magic,ophdrsize))
    loader_flags,num_dirent=unpack("<LL",f)
    # IMAGE_DATA_DIRECTORYs
    img_dir_entries=[]
    for i in range(0,16):
        tmp=unpack("<2L",f)
        img_dir_entries.append(tmp)
    #print("OH size: %d / %d"%(f.tell()-start_oh,ophdrsize))
    # SECTIONS:
    sections=[]
    for sno in range(numsects):
        sect_name,tmp,rva,rawsize,fileoff,ptr_reloc,ptr_lno,num_reloc,num_lno,flags=unpack("<8sLLLLLLHHL",f)
#        print(sect_name)
        name=""
        for c in sect_name:
            try:
                if ord(c)>=32:
                    name+=c
            except TypeError:
                if c>=32:
                    name+=chr(c)  # python3
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
#        print("0x%X"%(rva))
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
          f.seek(startoff+nethdr_pos,0)
          hdrlen,ver1,ver2,metadata_rva,metadata_len=unpack("<IHHII",f) # 16 bytes
          metadata_pos=rva_to_file(metadata_rva,sections)
          log(0,".NET header: v%d.%d  MetaData: fpos=0x%X len=%d"%(ver1,ver2,metadata_pos,metadata_len))
          f.seek(startoff+metadata_pos,0)
          dotnet_parsemeta(f,metadata_len)
        except:
          log(3,"Exception!!! while .NET parsing: %s" % (traceback.format_exc()))

    tmp=img_dir_entries[1]
    if tmp[1]:
        fpos=rva_to_file(tmp[0],sections)
        if fpos:
            # we have imports! load 'em all!
            f.seek(startoff+fpos,0)
            imps=[]
            while 1:
                imp=unpack("<LLLLL",f)
                if (imp[0]==0 or imp[3]==0) and imp[4]==0:
                    break
                imps.append(imp)
#                print(imp)
            dlllist=[]
            for imp in imps:
                dllentry=[""]
                # read DLL name:
                fpos=rva_to_file(imp[3],sections)
#                print(fpos)
                if fpos:
                    f.seek(startoff+fpos,0)
                    dllentry[0]=unp_cstr(f)
#                    print "DLL: "+dllentry[0]
                # dump symbols:
                if imp[0]:
                    fpos=rva_to_file(imp[0],sections)
                else:
                    fpos=rva_to_file(imp[4],sections)
                if fpos:
                  try:
#                    print fpos
                    f.seek(startoff+fpos,0)
#                    print("fpos=0x%X  dll=%s"%(startoff+fpos,dllentry[0]))
                    syms=[]
                    while 1:
                        if arch==0x8664:
                            tmp,=unpack("<Q",f) # 64 bit
                        else:
                            tmp,=unpack("<L",f) # 32 bit
                        if tmp==0:
                            break
                        syms.append(tmp)
#                    print syms
                    for sym in syms:
                        if sym<0x80000000:
                            fpos=rva_to_file(sym,sections)
                            if fpos:
                                f.seek(startoff+fpos,0)
                                tmp=unpack("<H",f)
                                dllentry.append(unp_cstr(f))
                        else:
                            dllentry.append("0x%X"%(sym&0x7FFFFFFF))
                  except:
                    log(3,"error parsing DLL info at 0x%08X" % (fpos))
                dlllist.append(dllentry)
  except:
    log(3,"Exception!!! while PE-EXE parsing: %s" % (traceback.format_exc()))
#    traceback.print_exc()
  return ("PE",exesize,dlllist,dotnet)


# 4C 01 03 00 │ 00 00 00 00 │ 00 00 00 00 │ 00 00 00 00 │ 1C 00 0F 01 │ 0B 01 00 00 │ 58 BB 02 00 │ 00 30 00 00 │ 00 CE 00 00  L.......................X....0......
def dump_coff(f,hdr):
    hdr2len=hdr[16]+hdr[17]*256
    hdr2=f.read(hdr2len)
    if len(hdr2)!=hdr2len: return 0 # bad
    sn=0
    coffsize=20+hdr2len
    # read sections!
    while sn<hdr[2]:
        sn+=1
        sect=f.read(40)
        size=sect[16]+(sect[17]<<8)+(sect[18]<<16)+(sect[19]<<24)
        fpos=sect[20]+(sect[21]<<8)+(sect[22]<<16)+(sect[23]<<24)
        if fpos and fpos+size>coffsize: coffsize=fpos+size
#        print(sn,fpos,size,sect[:8])
    return coffsize

def dump_exe(f):
    startoff=f.tell()
    try:
        MZ,=unpack("<H",f)
        if not MZ in (0x5A4D,0x4D5A):
            return None
# 4D 5A 26 01   1E 00 01 00   06 00 88 0C   FF FF 00 00   40 5E 00 00   00 01 F0 FF   52 00 00 00 
# M  Z  size_l size_h relocs hdrsize allmin/max   SS      SP    CRC     IP    CS     reloff  ovl
        size_l,size_h,relocs,hdrsize,allocmin,allocmax,SS,SP,CRC,IP,CS,relocoff,ovl = unpack("<13H",f)
        if size_l>512 or size_h==0:
            log(1,"invalid MZ file, probably text? (size=%d,%d)"%(size_l,size_h))
            return None
    except:
        log(3,"Exception!!! while MZ-EXE parsing: %s" % (traceback.format_exc()))
        return None
    size=size_h*512
    if size_l:
        size+=size_l-512
#    if relocoff>=0x40:
    try:
        # coff:
        if size<32768:
            f.seek(startoff+size)
            coff=f.read(20)
            if len(coff)==20 and coff[0]==0x4C and coff[1]==1 and coff[2]>0 and coff[3]==0:
                coffsize=dump_coff(f,coff)
#                print(hex(startoff),hex(size),hex(coffsize))
                if coffsize: return "COFF",startoff+size+coffsize
        # new-exe:
        f.seek(startoff+0x3c)
        ne_off,=unpack("<L",f)
        log(0,"NE start pos: %d+%d"%(startoff,ne_off))
        f.seek(startoff+ne_off)
        NE,=unpack("<H",f)
#        print("NE=%X"%(NE))
        if NE==0x4550:
            return dump_pe(f,startoff,size)
        if NE==0x454E:
            # win 3.1 (16-bit) EXE (FIXME: parse out size!)
            return ("NE",size)
        if NE==0x434C:
            # DOS/32A: (FIXME: parse out size!)
            return ("LC",size)
        if NE==0x454C:
            # dos4gw/watcom: (FIXME: parse out size!)
            return ("LE",size)
    except:
        log(3,"Exception!!! while NE-EXE parsing: %s" % (traceback.format_exc()))
        NE=0
    return ("MZ",size)


if __name__ == '__main__':
  import sys
  path=sys.argv[1]
  debug=True
  f=open(path,"rb")
  ret=dump_exe(f)
  print(ret, hex(ret[1]))
  f.seek(ret[1])
  data=f.read()
  print(data[:32])
  open(path+".dump","wb").write(data)

