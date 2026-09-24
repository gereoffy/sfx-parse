#!/usr/bin/env python3
"""
Tiszta Python bzip2 kibonto: a szabvanyos bzip2 es az NSIS telepitokben hasznalt valtozat.

Szabvanyos bzip2 (a Python bz2 moduljaval azonos kimenet):
    decompress(data, check_crc=True)          -> bytes   (tobb egymas utani stream is)
    Bzip2Decompressor(check_crc=True)          -> .decompress(data, max_length=-1), .eof, .needs_input

NSIS bzip2 (nincs "BZh" fejlec es CRC; a blokk egyetlen 0x31 byte-tal kezdodik, utana kozvetlenul a
24 bites origPtr, "randomised" bit nelkul; a stream vege egyetlen 0x17 byte):
    decompress_nsis(data, max_length=-1)       -> bytes
    NsisBzip2Decompressor()                    -> .decompress(data, max_length=-1), .eof, .needs_input

A blokk tartalma (szimbolum terkep, Huffman tablak, MTF, inverz BWT, RLE) mindkettoben azonos.
A regi "randomised" blokkokat (bzip2 0.9.0 elotti) nem tamogatja: ValueError.
Hibas adatnal ValueError, csonka adatnal EOFError (a decompressor objektumok ilyenkor eof-ot jeleznek).
"""

import zlib

MAX_BLOCK=900000
_BITREV=bytes(int("{:08b}".format(i)[::-1],2) for i in range(256))


def bzip2_crc(data):
    """A bzip2 CRC-je (CRC-32/BZIP2, nem tukrozott) a gyors zlib.crc32-bol, bitforditassal."""
    c=zlib.crc32(bytes(data).translate(_BITREV))
    return int("{:032b}".format(c)[::-1],2)


class _BitReader:
    def __init__(self,data):
        self.src=data; self.bit=0

    def bits(self,n):
        p=self.bit; b=p>>3; need=((p&7)+n+7)>>3
        chunk=self.src[b:b+need]
        if len(chunk)<need: raise EOFError("bzip2: unexpected end of data")
        self.bit=p+n
        return (int.from_bytes(chunk,"big")>>(need*8-(p&7)-n))&((1<<n)-1)

    def align(self):
        self.bit=(self.bit+7)&~7


def _decode_block(br,origptr,maxblock):
    """Egy blokk torzse az origPtr utan (szimbolum terkeptol a kimenetig). Visszaad: bytes"""
    bits=br.bits
    used16=[bits(1) for i in range(16)]
    seq=[i*16+j for i in range(16) if used16[i] for j in range(16) if bits(1)]
    if not seq: raise ValueError("bzip2: empty symbol map")
    alpha=len(seq)+2
    ngroups=bits(3); nsel=bits(15)
    if not 2<=ngroups<=6 or nsel<1: raise ValueError("bzip2: bad selectors")
    pos=list(range(ngroups)); selectors=[]
    for i in range(nsel):
        j=0
        while bits(1):
            j+=1
            if j>=ngroups: raise ValueError("bzip2: bad selector")
        v=pos.pop(j); pos.insert(0,v); selectors.append(v)
    tables=[]
    for t in range(ngroups):
        curr=bits(5); lens=[]
        for i in range(alpha):
            while True:
                if not 1<=curr<=20: raise ValueError("bzip2: bad code length")
                if not bits(1): break
                curr+=-1 if bits(1) else 1
            lens.append(curr)
        # kanonikus Huffman dekodolo tabla (BZ2_hbCreateDecodeTables)
        minl,maxl=min(lens),max(lens)
        perm=[j for i in range(minl,maxl+1) for j in range(alpha) if lens[j]==i]
        base=[0]*25
        for l in lens: base[l+1]+=1
        for i in range(1,25): base[i]+=base[i-1]
        limit=[0]*25; vec=0
        for i in range(minl,maxl+1):
            vec+=base[i+1]-base[i]; limit[i]=vec-1; vec<<=1
        for i in range(minl+1,maxl+1):
            base[i]=((limit[i-1]+1)<<1)-base[i]
        tables.append((minl,maxl,limit,base,perm))

    eob=alpha-1
    mtf=list(range(256)); tt=[]
    gi=-1; gleft=0
    run=-1; n=1
    # gyors bitolvasas: helyi akkumulator (acc, nacc), szimbolumonkent egy "elore nezes"
    src=br.src; bpos=br.bit>>3; nacc=8-(br.bit&7)
    acc=src[bpos]&((1<<nacc)-1) if bpos<len(src) else 0
    bpos+=1; srclen=len(src); over=0
    minl=maxl=0; limit=base=perm=None
    while True:
        if gleft==0:
            gi+=1
            if gi>=len(selectors): raise ValueError("bzip2: selectors exhausted")
            minl,maxl,limit,base,perm=tables[selectors[gi]]; gleft=50
        gleft-=1
        while nacc<maxl:
            if bpos<srclen: acc=(acc<<8)|src[bpos]
            else: acc<<=8; over+=8
            bpos+=1; nacc+=8
        zn=minl; zvec=acc>>(nacc-zn)
        while zvec>limit[zn]:
            zn+=1
            if zn>maxl: raise ValueError("bzip2: bad Huffman code")
            zvec=acc>>(nacc-zn)
        nacc-=zn; acc&=(1<<nacc)-1
        if over>nacc: raise EOFError("bzip2: unexpected end of data")
        sym=perm[zvec-base[zn]]
        if sym<=1:                              # RUNA / RUNB
            if run<0: run=0; n=1
            run+=n if sym==0 else 2*n
            n<<=1
            if n>2*1024*1024: raise ValueError("bzip2: run too long")
            continue
        if run>=0:
            tt.extend([seq[mtf[0]]]*run); run=-1
            if len(tt)>maxblock: raise ValueError("bzip2: block too big")
        if sym==eob: break
        v=mtf.pop(sym-1); mtf.insert(0,v); tt.append(seq[v])
        if len(tt)>maxblock: raise ValueError("bzip2: block too big")
    br.bit=bpos*8-nacc

    nb=len(tt)
    if not 0<=origptr<nb: raise ValueError("bzip2: bad origPtr")
    # inverz BWT
    cnt=[0]*256
    for c in tt: cnt[c]+=1
    cf=[0]*256; s=0
    for c in range(256): cf[c]=s; s+=cnt[c]
    T=[0]*nb
    for i,c in enumerate(tt):
        T[cf[c]]=i; cf[c]+=1
    p=T[origptr]; blk=bytearray(nb)
    for i in range(nb):
        blk[i]=tt[p]; p=T[p]
    # RLE1: 4 azonos byte utan egy ismetlesszam
    out=bytearray(); i=0; last=-1; same=0
    while i<nb:
        c=blk[i]; i+=1
        if same==4:
            out.extend(bytes([last])*c); same=0; last=-1
            continue
        out.append(c)
        if c==last: same+=1
        else: last=c; same=1
    return bytes(out)


class _Decompressor:
    """Kozos resz: blokkonkent kibontva pufferel, max_length-ig ad vissza."""
    def __init__(self):
        self.br=None; self.out=bytearray(); self.eof=False; self.needs_input=True

    def decompress(self,data,max_length=-1):
        if self.br is None: self.br=_BitReader(bytes(data))
        self.needs_input=False
        while (max_length<0 or len(self.out)<max_length) and not self.eof:
            try:
                blk=self._next_block()
            except EOFError:
                blk=None
            if blk is None: self.eof=True
            else: self.out+=blk
        if max_length<0: max_length=len(self.out)
        r=bytes(self.out[:max_length]); del self.out[:max_length]
        if self.eof and not self.out: self.needs_input=True
        return r


class NsisBzip2Decompressor(_Decompressor):
    def _next_block(self):
        b=self.br.bits(8)
        if b==0x17: return None
        if b!=0x31: raise ValueError("NSIS bzip2: bad block header 0x%02X"%(b))
        return _decode_block(self.br,self.br.bits(24),MAX_BLOCK)


class Bzip2Decompressor(_Decompressor):
    """Szabvanyos bzip2 (tobb egymas utani stream is, mint a bunzip2)."""
    BLOCK_MAGIC=0x314159265359
    END_MAGIC=0x177245385090

    def __init__(self,check_crc=True):
        _Decompressor.__init__(self)
        self.check_crc=check_crc; self.maxblock=None; self.combined=0

    def _stream_header(self):
        br=self.br
        if br.bit//8+4>len(br.src): return False
        hdr=br.src[br.bit//8:br.bit//8+4]
        if hdr[:3]!=b"BZh" or not 0x31<=hdr[3]<=0x39:
            raise ValueError("bzip2: bad stream header")
        br.bit+=32
        self.maxblock=(hdr[3]-0x30)*100000; self.combined=0
        return True

    def _next_block(self):
        br=self.br
        while True:
            if self.maxblock is None:
                if not self._stream_header(): return None
            magic=br.bits(48)
            if magic==self.END_MAGIC:
                crc=br.bits(32)
                if self.check_crc and crc!=self.combined:
                    raise ValueError("bzip2: stream CRC mismatch")
                br.align(); self.maxblock=None
                continue                        # kovetkezo stream (ha van)
            if magic!=self.BLOCK_MAGIC: raise ValueError("bzip2: bad block magic")
            crc=br.bits(32)
            if br.bits(1): raise ValueError("bzip2: randomised blocks are not supported")
            blk=_decode_block(br,br.bits(24),self.maxblock)
            if self.check_crc:
                if bzip2_crc(blk)!=crc: raise ValueError("bzip2: block CRC mismatch")
                self.combined=(((self.combined<<1)|(self.combined>>31))&0xFFFFFFFF)^crc
            return blk


def decompress(data,check_crc=True):
    """Szabvanyos bzip2 kibontasa (a bz2.decompress megfeleloje)."""
    d=Bzip2Decompressor(check_crc)
    out=d.decompress(data)
    if not d.eof or d.maxblock is not None:
        raise EOFError("bzip2: compressed data ended before the end-of-stream marker")
    return out

def decompress_nsis(data,max_length=-1):
    """NSIS bzip2 kibontasa (legfeljebb max_length byte)."""
    return NsisBzip2Decompressor().decompress(data,max_length)


if __name__=="__main__":
    import sys
    for path in sys.argv[1:]:
        with open(path,"rb") as f: data=f.read()
        out=decompress(data) if data[:3]==b"BZh" else decompress_nsis(data)
        sys.stdout.buffer.write(out)
