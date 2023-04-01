#!/usr/bin/env python3
import ctypes, fcntl, os, sys, zlib
fcntl.LOOP_SET_FD = 0x4C00
fcntl.LOOP_CLR_FD = 0x4C01
fcntl.LOOP_SET_STATUS = 0x4C02
fcntl.LOOP_GET_STATUS = 0x4C03
fcntl.LOOP_SET_STATUS64 = 0x4C04
fcntl.LOOP_GET_STATUS64 = 0x4C05
fcntl.LOOP_CHANGE_FD = 0x4C06
fcntl.LOOP_SET_CAPACITY = 0x4C07
fcntl.LOOP_SET_DIRECT_IO = 0x4C08
fcntl.LOOP_SET_BLOCK_SIZE = 0x4C09
fcntl.LOOP_CONFIGURE = 0x4C0A
fcntl.LOOP_CTL_ADD = 0x4C80
fcntl.LOOP_CTL_REMOVE = 0x4C81
fcntl.LOOP_CTL_GET_FREE = 0x4C82
fcntl.LO_NAME_SIZE = 64
fcntl.LO_KEY_SIZE = 32
fcntl.LO_FLAGS_READ_ONLY = 1
fcntl.LO_FLAGS_AUTOCLEAR = 4
fcntl.LO_FLAGS_PARTSCAN = 8
fcntl.LO_FLAGS_DIRECT_IO = 16
class loop_info64(ctypes.Structure):
  _fields_ = [
    ('lo_device', ctypes.c_ulonglong),
    ('lo_inode', ctypes.c_ulonglong),
    ('lo_rdevice', ctypes.c_ulonglong),
    ('lo_offset', ctypes.c_ulonglong),
    ('lo_sizelimit', ctypes.c_ulonglong),
    ('lo_number', ctypes.c_uint),
    ('lo_encrypt_type', ctypes.c_uint),
    ('lo_encrypt_key_size', ctypes.c_uint),
    ('lo_flags', ctypes.c_uint),
    ('lo_file_name', ctypes.c_ubyte * fcntl.LO_NAME_SIZE),
    ('lo_crypt_name', ctypes.c_ubyte * fcntl.LO_NAME_SIZE),
    ('lo_encrypt_key', ctypes.c_ubyte * fcntl.LO_KEY_SIZE),
    ('lo_init', ctypes.c_ulonglong * 2)
  ]

if len(sys.argv) < 3:
  raise
elif 3 == len(sys.argv):
  boot = 'both'
else:
  boot = sys.argv[3]
  assert boot in ['bios', 'uefi', 'both']

size = int(sys.argv[2])
fd = os.open(sys.argv[1], os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o0644)
size <<= 30
assert size <= (2 << 40)
os.ftruncate(fd, size)
if 'bios' == boot:
  # 0 + 512 = 512 mbr header
  # 1MiB ~ -0 Linux 0x83 ext4
  os.lseek(fd, 440, os.SEEK_SET)
  os.write(fd, os.getrandom(4))
  os.lseek(fd, 2, os.SEEK_CUR)
  start = 2048
  end = size // 512
  os.write(fd, b'\x80\xfe\xff\xff\x83\xfe\xff\xff' + start.to_bytes(4, 'little') + (end - start).to_bytes(4, 'little'))
  os.lseek(fd, 510, os.SEEK_SET)
  os.write(fd, b'\x55\xaa')
elif 'uefi' == boot:
  # 0 + 512 = 512 mbr header
  # 512 + 512 = 1024 gpt header
  # 1024 + 128 * 128 = 1KiB + 16KiB = 17KiB gpt entries
  # 1MiB + 127MiB = 128MiB EFI System C12A7328-F81F-11D2-BA4B-00A0C93EC93B vfat 32(FAT size)
  # 128MiB ~ -16.5KiB Linux filesystem 0FC63DAF-8483-4772-8E79-3D69D8477DE4 ext4
  # -512 - 128 * 128 = -512 - 16KiB = -16.5KiB gpt entries
  # -0 - 512 = -512 gpt header
  efisector = (128 << 20) // 512
  start = 2048
  end = size // 512
  os.lseek(fd, 446, os.SEEK_SET)
  os.write(fd, b'\x00\xfe\xff\xff\xee\xfe\xff\xff\x01\x00\x00\x00\xff\xff\xff\xff')
  # os.write(fd, b'\x00\xfe\xff\xff\xee\xfe\xff\xff\x01\x00\x00\x00' + (end - 1).to_bytes(4, 'little'))
  os.lseek(fd, 510, os.SEEK_SET)
  os.write(fd, b'\x55\xaa')
  os.lseek(fd, 1024, os.SEEK_SET)
  os.write(fd, b'\x28\x73\x2a\xc1\x1f\xf8\xd2\x11\xba\x4b\x00\xa0\xc9\x3e\xc9\x3b')
  #               C12A7328        F81F    11D2    BA4B    00A0C93EC93B # EFI System
  os.write(fd, os.getrandom(16)) # GUID
  os.write(fd, start.to_bytes(8, 'little'))
  os.write(fd, (efisector - 1).to_bytes(8, 'little'))
  os.lseek(fd, 80, os.SEEK_CUR)
  os.write(fd, b'\xaf\x3d\xc6\x0f\x83\x84\x72\x47\x8e\x79\x3d\x69\xd8\x47\x7d\xe4')
  #               0FC63DAF        8483    4772    8E79    3D69D8477DE4 # Linux filesystem
  os.write(fd, os.getrandom(16)) # GUID
  os.write(fd, efisector.to_bytes(8, 'little'))
  os.write(fd, (end - 33 - 1).to_bytes(8, 'little')) # partition end sector
  os.lseek(fd, 1024, os.SEEK_SET)
  crc32entry = zlib.crc32(os.read(fd, 32 * 512)).to_bytes(4, 'little')
  os.lseek(fd, 512, os.SEEK_SET)
  os.write(fd, b'EFI PART')
  os.write(fd, b'\x00\x00\x01\x00')
  os.write(fd, (92).to_bytes(4, 'little'))
  os.lseek(fd, 8, os.SEEK_CUR)
  os.write(fd, (1).to_bytes(8, 'little')) # current LBA
  os.write(fd, (end - 1).to_bytes(8, 'little')) # backup LBA
  os.write(fd, start.to_bytes(8, 'little')) # partition first sector
  os.write(fd, (end - 33 - 1).to_bytes(8, 'little')) # partition end sector
  gptuid = os.getrandom(16)
  os.write(fd, gptuid) # GUID
  os.write(fd, (2).to_bytes(8, 'little')) # first table sector
  os.write(fd, (128).to_bytes(4, 'little')) # table numbers
  os.write(fd, (128).to_bytes(4, 'little')) # table size
  os.write(fd, crc32entry)
  os.lseek(fd, 512, os.SEEK_SET)
  crc32 = zlib.crc32(os.read(fd, 92)).to_bytes(4, 'little')
  os.lseek(fd, 512 + 16, os.SEEK_SET)
  os.write(fd, crc32)
  for i in range(2):
    os.lseek(fd, 1024 + 128 * i, os.SEEK_SET)
    buf = os.read(fd, 48)
    os.lseek(fd, 128 * i - 512 * 33, os.SEEK_END)
    os.write(fd, buf)
  os.lseek(fd, -512, os.SEEK_END)
  os.write(fd, b'EFI PART')
  os.write(fd, b'\x00\x00\x01\x00')
  os.write(fd, (92).to_bytes(4, 'little'))
  os.lseek(fd, 8, os.SEEK_CUR)
  os.write(fd, (end - 1).to_bytes(8, 'little')) # current LBA
  os.write(fd, (1).to_bytes(8, 'little')) # backup LBA
  os.write(fd, start.to_bytes(8, 'little')) # partition first sector
  os.write(fd, (end - 33 - 1).to_bytes(8, 'little')) # partition end sector
  os.write(fd, gptuid) # GUID
  os.write(fd, (end - 1 - 32).to_bytes(8, 'little')) # first table sector
  os.write(fd, (128).to_bytes(4, 'little')) # table numbers
  os.write(fd, (128).to_bytes(4, 'little')) # table size
  os.write(fd, crc32entry)
  os.lseek(fd, -512, os.SEEK_END)
  crc32 = zlib.crc32(os.read(fd, 92)).to_bytes(4, 'little')
  os.lseek(fd, -512, os.SEEK_END)
  os.lseek(fd, 16, os.SEEK_CUR)
  os.write(fd, crc32)
elif 'both' == boot:
  # 0 + 512 = 512 mbr header
  # 512 + 512 = 1024 gpt header
  # 1024 + 128 * 128 = 1KiB + 16KiB = 17KiB gpt entries
  # 1MiB + 15MiB = 16MiB BIOS boot 21686148-6449-6E6F-744E-656564454649
  # 16MiB + 112MiB = 128MiB EFI System C12A7328-F81F-11D2-BA4B-00A0C93EC93B vfat 32(FAT size)
  # 128MiB ~ -16.5KiB Linux filesystem 0FC63DAF-8483-4772-8E79-3D69D8477DE4 ext4
  # -512 - 128 * 128 = -512 - 16KiB = -16.5KiB gpt entries
  # -0 - 512 = -512 gpt header
  efisector = (128 << 20) // 512
  bootsector = (16 << 20) // 512
  start = 2048
  end = size // 512
  os.lseek(fd, 446, os.SEEK_SET)
  os.write(fd, b'\x00\xfe\xff\xff\xee\xfe\xff\xff\x01\x00\x00\x00\xff\xff\xff\xff')
  # os.write(fd, b'\x00\xfe\xff\xff\xee\xfe\xff\xff\x01\x00\x00\x00' + (end - 1).to_bytes(4, 'little'))
  os.lseek(fd, 510, os.SEEK_SET)
  os.write(fd, b'\x55\xaa')
  os.lseek(fd, 1024, os.SEEK_SET)
  os.write(fd, b'Hah!IdontNeedEFI') # BIOS boot
  os.write(fd, os.getrandom(16)) # GUID
  os.write(fd, start.to_bytes(8, 'little'))
  os.write(fd, (bootsector - 1).to_bytes(8, 'little'))
  os.lseek(fd, 80, os.SEEK_CUR)
  os.write(fd, b'\x28\x73\x2a\xc1\x1f\xf8\xd2\x11\xba\x4b\x00\xa0\xc9\x3e\xc9\x3b')
  #               C12A7328        F81F    11D2    BA4B    00A0C93EC93B # EFI System
  os.write(fd, os.getrandom(16)) # GUID
  os.write(fd, bootsector.to_bytes(8, 'little'))
  os.write(fd, (efisector - 1).to_bytes(8, 'little'))
  os.lseek(fd, 80, os.SEEK_CUR)
  os.write(fd, b'\xaf\x3d\xc6\x0f\x83\x84\x72\x47\x8e\x79\x3d\x69\xd8\x47\x7d\xe4')
  #               0FC63DAF        8483    4772    8E79    3D69D8477DE4 # Linux filesystem
  os.write(fd, os.getrandom(16)) # GUID
  os.write(fd, efisector.to_bytes(8, 'little'))
  os.write(fd, (end - 33 - 1).to_bytes(8, 'little')) # partition end sector
  os.lseek(fd, 1024, os.SEEK_SET)
  crc32entry = zlib.crc32(os.read(fd, 32 * 512)).to_bytes(4, 'little')
  os.lseek(fd, 512, os.SEEK_SET)
  os.write(fd, b'EFI PART')
  os.write(fd, b'\x00\x00\x01\x00')
  os.write(fd, (92).to_bytes(4, 'little'))
  os.lseek(fd, 8, os.SEEK_CUR)
  os.write(fd, (1).to_bytes(8, 'little')) # current LBA
  os.write(fd, (end - 1).to_bytes(8, 'little')) # backup LBA
  os.write(fd, start.to_bytes(8, 'little')) # partition first sector
  os.write(fd, (end - 33 - 1).to_bytes(8, 'little')) # partition end sector
  gptuid = os.getrandom(16)
  os.write(fd, gptuid) # GUID
  os.write(fd, (2).to_bytes(8, 'little')) # first table sector
  os.write(fd, (128).to_bytes(4, 'little')) # table numbers
  os.write(fd, (128).to_bytes(4, 'little')) # table size
  os.write(fd, crc32entry)
  os.lseek(fd, 512, os.SEEK_SET)
  crc32 = zlib.crc32(os.read(fd, 92)).to_bytes(4, 'little')
  os.lseek(fd, 512 + 16, os.SEEK_SET)
  os.write(fd, crc32)
  for i in range(3):
    os.lseek(fd, 1024 + 128 * i, os.SEEK_SET)
    buf = os.read(fd, 48)
    os.lseek(fd, 128 * i - 512 * 33, os.SEEK_END)
    os.write(fd, buf)
  os.lseek(fd, -512, os.SEEK_END)
  os.write(fd, b'EFI PART')
  os.write(fd, b'\x00\x00\x01\x00')
  os.write(fd, (92).to_bytes(4, 'little'))
  os.lseek(fd, 8, os.SEEK_CUR)
  os.write(fd, (end - 1).to_bytes(8, 'little')) # current LBA
  os.write(fd, (1).to_bytes(8, 'little')) # backup LBA
  os.write(fd, start.to_bytes(8, 'little')) # partition first sector
  os.write(fd, (end - 33 - 1).to_bytes(8, 'little')) # partition end sector
  os.write(fd, gptuid) # GUID
  os.write(fd, (end - 1 - 32).to_bytes(8, 'little')) # first table sector
  os.write(fd, (128).to_bytes(4, 'little')) # table numbers
  os.write(fd, (128).to_bytes(4, 'little')) # table size
  os.write(fd, crc32entry)
  os.lseek(fd, -512, os.SEEK_END)
  crc32 = zlib.crc32(os.read(fd, 92)).to_bytes(4, 'little')
  os.lseek(fd, -512, os.SEEK_END)
  os.lseek(fd, 16, os.SEEK_CUR)
  os.write(fd, crc32)
os.close(fd)
fdcntl = os.open('/dev/loop-control', os.O_RDWR | os.O_CLOEXEC)
loopid = fcntl.ioctl(fdcntl, fcntl.LOOP_CTL_GET_FREE)
os.close(fdcntl)

fdfile = os.open(sys.argv[1], os.O_RDWR | os.O_CLOEXEC)
fdloop = os.open('/dev/loop' + str(loopid), os.O_RDWR | os.O_CLOEXEC)
fcntl.ioctl(fdloop, fcntl.LOOP_SET_FD, fdfile)
lpinfo = loop_info64()
lpinfo.lo_flags = fcntl.LO_FLAGS_PARTSCAN
fcntl.ioctl(fdloop, fcntl.LOOP_SET_STATUS64, bytes(lpinfo))
os.close(fdfile)
os.close(fdloop)

if 'bios' == boot:
  if 0 == os.fork():
    fdin, fdout = os.open('/dev/null', os.O_WRONLY), os.open('/dev/null', os.O_RDONLY)
    assert fdin > -1 and fdout > -1
    os.dup2(fdin, 0)
    os.dup2(fdout, 1)
    os.dup2(fdout, 2)
    os.close(fdin)
    os.close(fdout)
    os.execv('/usr/bin/env', ['env', 'mkfs.ext4', '/dev/loop' + str(loopid) + 'p1'])
    exit(-1)
  assert 0 == os.wait()[1]
elif 'uefi' == boot:
  if 0 == os.fork():
    fdin, fdout = os.open('/dev/null', os.O_WRONLY), os.open('/dev/null', os.O_RDONLY)
    assert fdin > -1 and fdout > -1
    os.dup2(fdin, 0)
    os.dup2(fdout, 1)
    os.dup2(fdout, 2)
    os.close(fdin)
    os.close(fdout)
    os.execv('/usr/bin/env', ['env', 'mkfs.vfat', '-F', '32', '/dev/loop' + str(loopid) + 'p1'])
    exit(-1)
  assert 0 == os.wait()[1]
  if 0 == os.fork():
    fdin, fdout = os.open('/dev/null', os.O_WRONLY), os.open('/dev/null', os.O_RDONLY)
    assert fdin > -1 and fdout > -1
    os.dup2(fdin, 0)
    os.dup2(fdout, 1)
    os.dup2(fdout, 2)
    os.close(fdin)
    os.close(fdout)
    os.execv('/usr/bin/env', ['env', 'mkfs.ext4', '/dev/loop' + str(loopid) + 'p2'])
    exit(-1)
  assert 0 == os.wait()[1]
elif 'both' == boot:
  if 0 == os.fork():
    fdin, fdout = os.open('/dev/null', os.O_WRONLY), os.open('/dev/null', os.O_RDONLY)
    assert fdin > -1 and fdout > -1
    os.dup2(fdin, 0)
    os.dup2(fdout, 1)
    os.dup2(fdout, 2)
    os.close(fdin)
    os.close(fdout)
    os.execv('/usr/bin/env', ['env', 'mkfs.vfat', '-F', '32', '/dev/loop' + str(loopid) + 'p2'])
    exit(-1)
  assert 0 == os.wait()[1]
  if 0 == os.fork():
    fdin, fdout = os.open('/dev/null', os.O_WRONLY), os.open('/dev/null', os.O_RDONLY)
    assert fdin > -1 and fdout > -1
    os.dup2(fdin, 0)
    os.dup2(fdout, 1)
    os.dup2(fdout, 2)
    os.close(fdin)
    os.close(fdout)
    os.execv('/usr/bin/env', ['env', 'mkfs.ext4', '/dev/loop' + str(loopid) + 'p3'])
    exit(-1)
  assert 0 == os.wait()[1]

print('/dev/loop' + str(loopid))
