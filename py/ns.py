#!/bin/python3
import os, ctypes, errno
libc = ctypes.CDLL(None, use_errno = True)
exec('from ctypes import byref, ' + ', '.join([] + [i for i in dir(ctypes) if i.startswith('c')]))
libc.mount.argtypes, libc.mount.restype = [c_void_p, c_void_p, c_void_p, c_ulong, c_void_p], c_int
libc.umount.argtypes, libc.umount.restype = [c_void_p, c_int], c_int
MS_REC = 1 << 14
MS_PRIVATE = 1 << 18
uid, gid = os.getuid(), os.getgid()
os.unshare(os.CLONE_NEWNS | os.CLONE_NEWUSER)
fd = os.open('/proc/self/setgroups', os.O_WRONLY)
os.write(fd, b'deny')
os.close(fd)
fd = os.open('/proc/self/uid_map', os.O_WRONLY)
os.write(fd, b' '.join([b'0', str(uid).encode(), b'1']))
os.close(fd)
fd = os.open('/proc/self/gid_map', os.O_WRONLY)
os.write(fd, b' '.join([b'0', str(gid).encode(), b'1']))
os.close(fd)
r = libc.mount(0, b'/', 0, MS_REC | MS_PRIVATE, 0)
if 0 != r:
  e = ctypes.get_errno()
  raise OSError(e, os.strerror(e))

os.execvp('csh', ['csh'])
# mount -t overlay overlay -o rw,lowerdir=lower,upperdir=rw,workdir=wk tagert
# unshare --mount --user --map-root-user bash
# unshare --mount --user --map-root-user --propagation private bash
# --propagation slave|shared|private
