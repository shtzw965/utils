#!/usr/bin/python3
import os, ctypes, fcntl, select, sys, termios
exec('from ctypes import byref, ' + ', '.join([i for i in dir(ctypes) if i.startswith('c_')]))
termios.TIOCGPTN = 0x80045430
termios.TIOCSPTLCK = 0x40045431
termios.TIOCGPTPEER = 0x5441
class Structure(ctypes.Structure):
  _pack_ = 1
  def strdict(self):
    ret = {}
    for i, _ in self._fields_:
      value = getattr(self, i)
      if type(value) in [int, bytes, str]:
        ret[i] = value
      else:
        ret[i] = str(value)
    return ret
  def __str__(self):
    return str(self.strdict())

class ktermios(Structure):
  _fields_ = [
    ('c_iflag', c_uint),
    ('c_oflag', c_uint),
    ('c_cflag', c_uint),
    ('c_lflag', c_uint),
    ('c_line', c_ubyte),
    ('c_cc', c_ubyte * 32),
    ('c_ispeed', c_uint),
    ('c_ospeed', c_uint)
  ]

assert os.path.ismount('/proc')
pids = []
for pid in os.listdir('/proc'):
  if pid.isdigit():
    try:
      linkname = os.readlink('/proc/' + pid + '/exe')
    except FileNotFoundError:
      pass 
    else:
      if os.path.basename(linkname) in ['lmgrd']:
        pids.append(pid)
assert len(pids) > 0
pid = pids[0]

for ns, nstype in [
  ('cgroup', os.CLONE_NEWCGROUP),
  ('ipc', os.CLONE_NEWIPC),
  ('uts', os.CLONE_NEWUTS),
  ('net', os.CLONE_NEWNET),
  ('pid', os.CLONE_NEWPID),
  ('time', os.CLONE_NEWTIME),
  ('mnt', os.CLONE_NEWNS)
]:
  fd = os.open('/proc/' + str(pid) + '/ns/' + ns, os.O_RDONLY)
  os.setns(fd, nstype)
  os.close(fd)

os.chroot('/usr/lib/x86_64-linux-gnu/lxc/rootfs/')
os.chdir('/')
ptmxfd = os.open('/dev/pts/ptmx', os.O_RDWR | os.O_NOCTTY)
fcntl.ioctl(ptmxfd, termios.TIOCSPTLCK, int(0).to_bytes(4, sys.byteorder))
termios_old = ktermios()
termios_new = ktermios()
ret = fcntl.ioctl(0, termios.TCGETS, bytes(termios_old))
ctypes.memmove(ctypes.addressof(termios_old), ret, ctypes.sizeof(ktermios))
ctypes.memmove(ctypes.addressof(termios_new), ret, ctypes.sizeof(ktermios))
termios_new.c_iflag |= termios.IGNPAR
termios_new.c_iflag &= (1 << (ktermios.c_iflag.size * 8)) - 1 - (
  termios.ISTRIP |
  termios.INLCR |
  termios.IGNCR |
  termios.ICRNL |
  termios.IXON |
  termios.IXANY |
  termios.IXOFF |
  termios.IUCLC
)
termios_new.c_lflag &= (1 << (ktermios.c_lflag.size * 8)) - 1 - (
  termios.ISIG | # make ptmx driver of father proccess of this script proccess not send signals when control characters about signals are written to the stdin
  termios.ICANON | # make ptmx driver of father proccess of this script proccess not cache characters, which will make tab work as expected, like completing commands
  termios.ECHO | # make ptmx driver of father proccess of this script proccess not echo characters, because the slave tty will echo, too
  termios.ECHOE |
  termios.ECHOK |
  termios.ECHONL |
  termios.IEXTEN
)
termios_new.c_oflag &= (1 << (ktermios.c_oflag.size * 8)) - 1 - termios.OPOST
termios_new.c_cc[termios.VMIN] = 1
termios_new.c_cc[termios.VTIME] = 0
fcntl.ioctl(0, termios.TCSETSW, bytes(termios_new))
if 0 == os.fork():
  fdstdio = fcntl.ioctl(ptmxfd, termios.TIOCGPTPEER, 0x80002)
  os.close(ptmxfd)
  os.dup2(fdstdio, 0)
  os.dup2(fdstdio, 1)
  os.dup2(fdstdio, 2)
  os.close(fdstdio)
  os.setsid()
  fcntl.ioctl(0, termios.TIOCSCTTY, 0)
  #os.setgid(1000)
  os.setgroups([])
  #os.setuid(1000)
  os.chdir('/root')
  os.execve('/usr/bin/bash', ['bash'], {
    'LANG': 'C',
    'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
    'PWD': '/root',
    'HOME': '/root',
    'USER': 'root',
    'USERNAME': 'root'
  })
else:
  bufsiz = 128 * 1024
  os.read(ptmxfd, 4)
  os.write(ptmxfd, b"alias ls='ls --color=auto'\n")
  os.write(ptmxfd, b"alias ll='ls -lA'\n")
  os.write(ptmxfd, b"ip addr\n")
  epoll = select.epoll()
  epoll.register(0, select.EPOLLIN)
  epoll.register(ptmxfd, select.EPOLLIN)
  while True:
    events = epoll.poll(None, 1)
    if len(events) == 1:
      fd, event = events[0]
    else:
      break
    if event == select.EPOLLIN:
      buf = os.read(fd, bufsiz)
    else:
      break
    if 0 == len(buf):
      break
    fdout = ptmxfd if 0 == fd else 1
    try:
      os.write(fdout, buf)
    except:
      break
  os.wait()
  epoll.close()
  os.close(ptmxfd)
  fcntl.ioctl(0, termios.TCSETSW, bytes(termios_old))
os._exit(0)
