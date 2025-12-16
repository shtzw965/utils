#!/bin/python3
import os, ctypes, errno
exec('from ctypes import byref, ' + ', '.join([] + [i for i in dir(ctypes) if i.startswith('c')]))
libc = ctypes.CDLL(None, use_errno = True)
libc.mount.argtypes, libc.mount.restype = [c_void_p, c_void_p, c_void_p, c_ulong, c_void_p], c_int
libc.umount.argtypes, libc.umount.restype = [c_void_p, c_int], c_int
MS_REC = 1 << 14
MS_PRIVATE = 1 << 18
MS_SLAVE = 1 << 19
MS_SHARED = 1 << 20
uid, gid = os.getuid(), os.getgid()
os.unshare(os.CLONE_NEWNS | os.CLONE_NEWUSER)
fd = os.open('/proc/self/setgroups', os.O_WRONLY)
os.write(fd, b'deny')
os.close(fd)
fd = os.open('/proc/self/uid_map', os.O_WRONLY)
os.write(fd, b'0 %i 1' % uid)
os.close(fd)
fd = os.open('/proc/self/gid_map', os.O_WRONLY)
os.write(fd, b'0 %i 1' % gid)
os.close(fd)
assert libc.mount(0, b'/', 0, MS_REC | MS_SLAVE, 0) == 0

os.execvp('csh', ['csh'])
# unshare --mount --user --map-root-user --propagation slave csh
# mkdir rd rw wk merge
# mount -t overlay overlay -o rw,lowerdir=rd,upperdir=rw,workdir=wk merge
# rm -rf rd rw wk merge
