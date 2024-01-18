#!/usr/bin/python3
import os, sys, zlib
class zfile:
  def __init__(self, fname, zipver, fver, flag, method, mtime, mdate, crc32, csize, osize, diskid, proint, proext, offset, fextn, fcomm, buf):
    self.fname = fname
    self.zipver = zipver
    self.fver = fver
    self.flag = flag
    self.method = method
    self.mtime = mtime
    self.mdate = mdate
    self.crc32 = crc32
    self.csize = csize
    self.osize = osize
    self.diskid = diskid
    self.proint = proint
    self.proext = proext
    self.offset = offset
    self.fextn = fextn
    self.fcomm = fcomm
    self.buf = buf
  def __len__(self):
    if 0x08 & self.flag:
      raise
    else:
      return 30 + len(self.fname.encode()) + len(self.fextn) + len(self.buf)
  def cntrlen(self):
      return 46 + len(self.fname.encode()) + len(self.fextn) + len(self.fcomm)

def fdgetint(fd, size):
  buf = os.read(fd, size)
  assert size == len(buf)
  return int.from_bytes(buf, sys.byteorder)

fd = os.open(sys.argv[1], os.O_RDONLY)
files = {}
filedict = {}
localist = []
cntrlist = []
status = 0
while True:
  header = fdgetint(fd, 4)
  if 0 == status:
    if 0x04034b50 == header: # local file header
      fver = fdgetint(fd, 2)
      flag = fdgetint(fd, 2)
      method = fdgetint(fd, 2)
      mtime = fdgetint(fd, 2)
      mdate = fdgetint(fd, 2)
      crc32 = fdgetint(fd, 4)
      csize = fdgetint(fd, 4)
      osize = fdgetint(fd, 4)
      lname = fdgetint(fd, 2)
      lextn = fdgetint(fd, 2)
      assert not 0xffffffff == csize # ZIP64
      assert not 0xffffffff == osize # ZIP64
      fname = os.read(fd, lname)
      fextn = os.read(fd, lextn)
      assert lname == len(fname)
      assert lextn == len(fextn)
      fname = fname.decode()
      buf = b''
      if csize > 0:
        buf = os.read(fd, csize)
        assert csize == len(buf)
        assert zlib.DEFLATED == method
        dobj = zlib.decompressobj(-15)
        raw = dobj.decompress(buf) + dobj.flush()
        del dobj
        assert crc32 == zlib.crc32(raw)
        cobj = zlib.compressobj(9, zlib.DEFLATED, -15)
        enc = cobj.compress(raw) + cobj.flush()
        del cobj
        dobj = zlib.decompressobj(-15)
        dec = dobj.decompress(enc) + dobj.flush()
        assert enc == buf
        assert raw == dec
      if 0x08 & flag: # data descriptor
        raise
        header = fdgetint(fd, 4)
        crc32 = fdgetint(fd, 4)
        csize = fdgetint(fd, 4)
        osize = fdgetint(fd, 4)
        assert 0x08074b50 == header
      assert None == filedict.get(fname)
      filedict[fname] = zfile(fname, None, fver, flag, method, mtime, mdate, crc32, csize, osize, 0, 0, 0, 0, fextn, None, buf)
      localist.append(fname)
    elif 0x02014b50 == header:
      status = 1
    else:
      raise
  if 1 == status:
    if 0x02014b50 == header: # central directory file header
      zipver = fdgetint(fd, 2)
      fver = fdgetint(fd, 2)
      flag = fdgetint(fd, 2)
      method = fdgetint(fd, 2)
      mtime = fdgetint(fd, 2)
      mdate = fdgetint(fd, 2)
      crc32 = fdgetint(fd, 4)
      csize = fdgetint(fd, 4)
      osize = fdgetint(fd, 4)
      lname = fdgetint(fd, 2)
      lextn = fdgetint(fd, 2)
      lcomm = fdgetint(fd, 2)
      diskid = fdgetint(fd, 2)
      proint = fdgetint(fd, 2)
      proext = fdgetint(fd, 4)
      offset = os.read(fd, 4)
      assert 4 == len(offset)
      fname = os.read(fd, lname)
      fextn = os.read(fd, lextn)
      fcomm = os.read(fd, lcomm)
      assert lname == len(fname)
      assert lextn == len(fextn)
      assert lcomm == len(fcomm)
      fname = fname.decode()
      zfobj = filedict.get(fname)
      assert not None == zfobj
      assert None == zfobj.zipver
      zfobj.zipver = zipver
      assert fver == zfobj.fver
      assert flag == zfobj.flag
      assert method == zfobj.method
      assert mtime == zfobj.mtime
      assert mdate == zfobj.mdate
      assert crc32 == zfobj.crc32
      assert csize == zfobj.csize
      assert osize == zfobj.osize
      assert fextn == zfobj.fextn
      zfobj.diskid = diskid
      zfobj.proint = proint
      zfobj.proext = proext
      zfobj.offset = offset
      zfobj.fcomm = fcomm
      cntrlist.append(fname)
    elif 0x06054b50 == header:
      status = 2
    else:
      raise
  if 2 == status: # end of central directory record
    if 0x06054b50 == header:
      disknumber = fdgetint(fd, 2)
      diskcenter = fdgetint(fd, 2)
      assert 0 == disknumber
      assert 0 == diskcenter
      diskrecord = fdgetint(fd, 2)
      recordnum = fdgetint(fd, 2)
      assert diskrecord == recordnum
      assert diskrecord == len(filedict)
      assert len(cntrlist) == len(filedict)
      recordsiz = fdgetint(fd, 4)
      recordptr = fdgetint(fd, 4)
      offset = 0
      for i in localist:
        offset += len(filedict[i])
      assert offset == recordptr
      offset = 0
      for i in cntrlist:
        offset += filedict[i].cntrlen()
      assert offset == recordsiz
      lcomm = fdgetint(fd, 2)
      comment = os.read(fd, lcomm)
      assert lcomm == len(comment)
      assert 0 == len(os.read(fd, 1))
      os.close(fd)
      break

hack = 'libLicenseManagerJNI.so'
hack = 'LicenseJNI-windows-64.dll'
hack = 'libLicenseJNI-linux-x86-64.so'
zfobj = filedict[hack]
fd = os.open(hack, os.O_RDONLY)
raw = os.read(fd, os.fstat(fd).st_size)
os.close(fd)
cobj = zlib.compressobj(9, zlib.DEFLATED, -15)
zfobj.buf = cobj.compress(raw) + cobj.flush()
del cobj
zfobj.crc32 = zlib.crc32(raw)
zfobj.csize = len(zfobj.buf)
zfobj.osize = len(raw)

def int2bytes(i, size):
  return i.to_bytes(size, sys.byteorder)

offset = 0
for fname in localist:
  zfobj = filedict.get(fname)
  assert not None == zfobj
  os.write(1, int2bytes(0x04034b50, 4))
  os.write(1, int2bytes(zfobj.fver, 2))
  os.write(1, int2bytes(zfobj.flag, 2))
  os.write(1, int2bytes(zfobj.method, 2))
  os.write(1, int2bytes(zfobj.mtime, 2))
  os.write(1, int2bytes(zfobj.mdate, 2))
  os.write(1, int2bytes(zfobj.crc32, 4))
  os.write(1, int2bytes(zfobj.csize, 4))
  os.write(1, int2bytes(zfobj.osize, 4))
  os.write(1, int2bytes(len(zfobj.fname.encode()), 2))
  os.write(1, int2bytes(len(zfobj.fextn), 2))
  os.write(1, zfobj.fname.encode())
  os.write(1, zfobj.fextn)
  os.write(1, zfobj.buf)
  zfobj.offset = offset
  offset += len(zfobj)
  if 0x08 & zfobj.flag: # data descriptor
    raise

recordptr = offset
recordsiz = 0
for fname in cntrlist:
  zfobj = filedict.get(fname)
  assert not None == zfobj
  os.write(1, int2bytes(0x02014b50, 4))
  os.write(1, int2bytes(zfobj.zipver, 2))
  os.write(1, int2bytes(zfobj.fver, 2))
  os.write(1, int2bytes(zfobj.flag, 2))
  os.write(1, int2bytes(zfobj.method, 2))
  os.write(1, int2bytes(zfobj.mtime, 2))
  os.write(1, int2bytes(zfobj.mdate, 2))
  os.write(1, int2bytes(zfobj.crc32, 4))
  os.write(1, int2bytes(zfobj.csize, 4))
  os.write(1, int2bytes(zfobj.osize, 4))
  os.write(1, int2bytes(len(zfobj.fname.encode()), 2))
  os.write(1, int2bytes(len(zfobj.fextn), 2))
  os.write(1, int2bytes(len(zfobj.fcomm), 2))
  os.write(1, int2bytes(zfobj.diskid, 2))
  os.write(1, int2bytes(zfobj.proint, 2))
  os.write(1, int2bytes(zfobj.proext, 4))
  os.write(1, int2bytes(zfobj.offset, 4))
  os.write(1, zfobj.fname.encode())
  os.write(1, zfobj.fextn)
  os.write(1, zfobj.fcomm)
  recordsiz += zfobj.cntrlen()

os.write(1, int2bytes(0x06054b50, 4))
os.write(1, int2bytes(0, 2))
os.write(1, int2bytes(0, 2))
os.write(1, int2bytes(len(cntrlist), 2))
os.write(1, int2bytes(len(cntrlist), 2))
os.write(1, int2bytes(recordsiz, 4))
os.write(1, int2bytes(recordptr, 4))
os.write(1, int2bytes(len(comment), 2))
os.write(1, comment)
