#!/usr/bin/env python3
import atexit, ctypes, datetime, hashlib, http.client, gzip, os, stat, sys

libc = ctypes.CDLL(None, 0, None, True)
# int mount(const char *source, const char *target, const char *filesystemtype, unsigned long mountflags, const void *data);
# int umount(const char *target);
# int umount2(const char *target, int flags);
libc.mount.argtypes, libc.mount.restype = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulong, ctypes.c_void_p], ctypes.c_int
libc.umount.argtypes, libc.umount.restype = [ctypes.c_void_p], ctypes.c_int
libc.umount2.argtypes, libc.umount2.restype = [ctypes.c_void_p, ctypes.c_int], ctypes.c_int

# url actually in use
srcurl = 'http://ftp.cn.debian.org/debian/'
# srcurl = 'http://deb.debian.org/debian/'

# url shown in etc/apt/sources.list and var/lib/apt/lists/
apturl = None
# apturl = 'http://deb.debian.org/debian/'

dist = 'bullseye'
arch = 'amd64'

class InRelease:
  def __init__(self, path):
    assert self.parse(path) and self.check()
  def parse(self, path):
    self.pool = {}
    self.days = None
    self.day = None
    self.time = None
    fobj = open(path, 'r')
    status = 0
    ret = False
    while True:
      line = fobj.readline()
      if 0 == len(line):
        break
      line = line.replace('\r', '').replace('\n', '')
      if 0 == status:
        if 'MD5Sum:' == line:
          status = 1
        elif None == self.day and None == self.time and line.startswith('Date: '):
          date = line.split()
          try:
            day, month, year, time = date[2], date[3], date[4], date[5]
            i = 1
            for j in ['January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December']:
              if j.startswith(month):
                break
              i += 1
            else:
              raise
            month = i
            day = int(day)
            assert day > 0
            if 2 == month:
              if 0 == year % 100:
                if 0 == year % 400:
                  assert day < 30
                else:
                  assert day < 29
              elif 0 == year % 4:
                assert day < 30
              else:
                assert day < 29
            elif month < 8:
              assert day < 31 + (month & 1)
            else:
              assert day < 31 + ((month + 1) & 1)
            year = int(year)
            assert year > 0
            time = time.split(':')
            hour, minute, second = time[0], time[1], time[2]
            hour = int(hour)
            minute = int(minute)
            second = int(second)
            assert hour >= 0
            assert hour < 24
            assert minute >= 0
            assert minute < 60
            assert second >= 0
            assert second < 60
            self.days = (datetime.datetime(year, month, day) - datetime.datetime(1970, 1, 1)).days
            self.day = '%04d-%02d-%02d' % (year, month, day)
            self.time = '%02d:%02d:%02d' % (hour, minute, second)
          except:
            pass
      elif 1 == status:
        if line.startswith(' '):
          md5sum, size, name = line.split()
          self.pool[name] = [size, md5sum, None]
        elif 'SHA256:' == line:
          status = 3
        else:
          status = 2
      elif 2 == status:
        if 'SHA256:' == line:
          status = 3
      else:
        if line.startswith(' '):
          sha256, size, name = line.split()
          i = self.pool.get(name)
          if None == i:
            self.pool[name] = [size, None, sha256]
          elif size == i[0]:
            i[2] = sha256
          else:
            return False
        else:
          ret = True
          break
    fobj.close()
    return ret
  def check(self):
    for i in self.pool:
      if None == i[1] or None == i[2]:
        return False
    return True

class Packages:
  class Package:
    def __init__(self, name):
      self.name = name
      self.Filename = None
      self.MD5sum = None
      self.SHA256 = None
      self.Homepage = None
      self.Size = 0
      self.Installed_Size = 0
      self.Version = None
      self.Priority = None
      self.Important = False
      self.Protected = False
      self.Depends = None
      self.Pre_Depends = None
      self.Section = None
      self.Maintainer = None
      self.Architecture = None
      self.Multi_Arch = None
      self.dpkgname = None
      self.lines = []
  def __init__(self, path):
    self.pool = {}
    self.path = path
    self.required = []
    self.important = []
    self.system = []
    self.first = []
    self.after = []
  def parse(self):
    fobj = open(self.path, 'r')
    current = None
    while True:
      line = fobj.readline()
      if 0 == len(line):
        fobj.close()
        break
      line = line.replace('\r', '').replace('\n', '')
      if 0 == len(line):
        if not None == current:
           dpkgname = current.Filename.split('/')[-1].split('_')
           current.dpkgname = dpkgname[0] + '_' + current.Version.replace(':', '%3a') + '_' + dpkgname[2]
        current = None
        continue
      elif None == current:
        field, name = line.split()
        if 'Package' in field:
          current = Packages.Package(name)
          self.pool[name] = current
        else:
          exit(-1)
      elif line.startswith('Filename: '):
        current.Filename = line.split()[1]
      elif line.startswith('MD5sum: '):
        current.MD5sum = line.split()[1]
      elif line.startswith('SHA256: '):
        current.SHA256 = line.split()[1]
      elif line.startswith('Homepage: '):
        current.Homepage = line[len('Homepage: '):]
      elif line.startswith('Size: '):
        current.Size = int(line[len('Size: '):])
      elif line.startswith('Installed-Size: '):
        current.Installed_Size = int(line[len('Installed-Size: '):])
      elif line.startswith('Version: '):
        current.Version = line.split()[1]
      elif line.startswith('Priority: '):
        current.Priority = line.split()[1]
        if 'required' == current.Priority:
          self.required.append(current.name)
        elif 'important' == current.Priority:
          self.important.append(current.name)
      elif line.startswith('Important: '):
        current.Important = (not 'no' == line[len('Important: '):])
      elif line.startswith('Protected: '):
        current.Protected = (not 'no' == line[len('Protected: '):])
      elif line.startswith('Depends: '):
        current.Depends = line[len('Depends: '):]
      elif line.startswith('Pre-Depends: '):
        current.Pre_Depends = line[len('Pre-Depends: '):]
      elif line.startswith('Section: '):
        current.Section = line[len('Section: '):]
      elif line.startswith('Maintainer: '):
        current.Maintainer = line[len('Maintainer: '):]
      elif line.startswith('Architecture: '):
        current.Architecture = line[len('Architecture: '):]
      elif line.startswith('Multi-Arch: '):
        current.Multi_Arch = line[len('Multi-Arch: '):]
      current.lines.append(line)
    return self
  def getreal(self, pkgs):
    ret = []
    for name in pkgs:
      if not None == self.pool.get(name):
        ret.append(name)
    return ret
  def getdeps(self, pkgs):
    ret = []
    for name in pkgs:
      for depends in self.pool[name].Depends, self.pool[name].Pre_Depends:
        if not None == depends:
          for pack in depends.split(','):
            ret.append(pack.split()[0])
    return ret
  def resolve(self, pkgs):
    ret = pkgs.copy()
    while len(pkgs) > 0:
      pkgs += self.getdeps(pkgs)
      pkgs = list(set(pkgs))
      pkgs = self.getreal(pkgs)
      allpkgs = pkgs + ret
      allpkgs = list(set(allpkgs))
      pkgs = list(set(allpkgs) - set(ret))
      ret = allpkgs
    ret.sort()
    return ret
  def build(self, other = []):
    # both required and important package lists are collected from file Packages
    # requied packages are more basically than important packages, which means requied packages must be ready first
    # in this function, other packages can be added to important package list by parament other
    # this function will find depend packages, and will detect and handle repeat packages, and get list self.first and self.after
    required = self.resolve(self.required)
    important = list(set(self.resolve(self.important + other)) - set(required))
    for name in self.pool.keys():
      if name in required:
        self.system.append(name)
        self.first.append(name)
      elif name in important:
        self.system.append(name)
        self.after.append(name)
    return self
  def getdebs(self, pkgs, aptcache):
    ret = []
    for name, obj in self.pool.items():
      if name in pkgs:
        ret.append(aptcache + obj.dpkgname)
    return ret

def parseurl(srcurl, apturl):
  dlurl = srcurl
  con = None
  if dlurl.startswith('http://'):
    field = dlurl[len('http://'):].split('/')
    host = field[0]
    if ':' in host:
      host, port = host.split(':')
      port = int(port)
    else:
      port = 80
    con = http.client.HTTPConnection(host, port)
  elif dlurl.startswith('https://'):
    field = dlurl[len('http://'):].split('/')
    host = field[0]
    if ':' in host:
      host, port = host.split(':')
      port = int(port)
    else:
      port = 443
    con = http.client.HTTPSConnection(host, port)
  else:
    exit(-1)
  if not None == con:
    con.putrequest('GET', '/' + '/'.join(field[1:]), False, True)
    con.putheader('Accpet', '*/*')
    con.endheaders()
    res = con.getresponse()
    con.close()
    location = res.headers.get('Location')
    if not None == location:
      dlurl = location
      if not '/' == dlurl[-1]:
        dlurl += '/'
  if apturl.startswith('http://'):
    field = apturl[len('http://'):].split('/')
  elif apturl.startswith('https://'):
    field = apturl[len('http://'):].split('/')
  return '_'.join(field), dlurl

def mkdir(path, mode = 0o0755):
  if os.path.lexists(path):
    if not os.path.isdir(path):
      print('Error:', 'exists:', path, 'exiting')
      exit(-1)
  else:
    os.makedirs(path, mode, True)

def getsha256(name):
  fobj = open(name, 'rb')
  if sys.version_info.minor < 11:
    hobj = hashlib.sha256()
    while True:
      buf = fobj.read(512)
      if len(buf) == 0:
        break
      hobj.update(buf)
  else: # only works in very new python3 version (Python 3.11)
    hobj = hashlib.file_digest(fobj, 'sha256')
  fobj.close()
  return hobj.hexdigest()

def download(path, url, counter = ''):
  if 0 == os.fork():
    print()
    print(counter + 'downloading', url)
    os.execv('/usr/bin/env', ['env', 'curl', '--location', '--output', path, url])
    exit(-1)
  return 0 == os.wait()[1]

def gpgv(*files):
  if 0 == os.fork():
    fdin, fdout = os.open('/dev/null', os.O_WRONLY), os.open('/dev/null', os.O_RDONLY)
    assert fdin > -1 and fdout > -1
    os.dup2(fdin, 0)
    os.dup2(fdout, 1)
    os.dup2(fdout, 2)
    os.close(fdin)
    os.close(fdout)
    os.execv('/usr/bin/env', ['env', 'gpgv', '--keyring'] + list(files))
    exit(-1)
  return 0 == os.wait()[1]

def mknod(name, major, minor):
  path = 'dev/' + name
  if not os.path.lexists(path):
    try:
      os.mknod(path, stat.S_IFCHR | 0o0666, os.makedev(major, minor))
    except:
      return False
  return True

def umount(pid):
  global aptcache
  if os.getpid() == pid:
    for path in [aptcache, 'sys', 'proc']:
      if os.path.ismount(path):
        assert 0 == libc.umount2(path.encode(), 0)

def dpkgaddinfo(pkgs):
  global packobj, aptcache
  for name in pkgs:
    obj = packobj.pool.get(name)
    if None == obj:
      raise
    fd = os.open('var/lib/dpkg/status', os.O_WRONLY | os.O_APPEND)
    buffer = ['Package: ' + name, 'Status: install ok installed']
    for line in obj.lines[1:]:
      for field in ['Build-Essential', 'Description-md5', 'Tag', 'Filename', 'Size', 'MD5sum', 'SHA256']:
        if line.startswith(field + ': '):
          break
      else:
        buffer.append(line)
    buffer.append('')
    os.write(fd, '\n'.join(buffer).encode())
    os.close(fd)
    os.close(os.open('var/lib/dpkg/info/' + name + '.list', os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o0644))

def dpkginstall(pkgs):
  global packobj, aptcache
  if 0 == os.fork():
    os.chroot('.')
    os.chdir('/')
    os.environ['PATH'] = '/sbin:/usr/sbin:/bin:/usr/bin'
    for name in pkgs:
      obj = packobj.pool.get(name)
      if None == obj:
        exit(-1)
      if 0 == os.fork():
        os.execv('/usr/bin/env', ['env', 'dpkg', '--force-depends', '--install', aptcache + obj.dpkgname])
        exit(-1)
      e = os.wait()[1]
      if not 0 == e:
        print('Warning:', 'dpkg:', 'extract:', name, ' return ', e)
        #exit(-1)
    exit(0)
  return os.wait()[1]
  #assert 0 == os.wait()[1]

os.umask(0o0022)
os.setuid(0)
os.setgid(0)

if not '/' == srcurl[-1]:
  srcurl += '/'
if None == apturl:
  apturl = srcurl
elif not '/' == apturl[-1]:
  apturl += '/'

dirs = os.listdir()
if 0 == len(dirs):
  pass
elif 1 == len(dirs) and 'lost+found' == dirs[0]:
  pass
else:
  raise

prefix, dlurl = parseurl(srcurl, apturl)

# prepare apt dirs
# mount a tmpfs to var/cache/apt/archives/ to storage deb files in memory instead of disk to avoid expanding virtual machine images
aptlists = 'var/lib/apt/lists/'
aptcache = 'var/cache/apt/archives/'
aptlistspart = aptlists + 'partial'
aptcachepart = aptcache + 'partial'
mkdir(aptlistspart, 0o0755)
mkdir(aptcachepart, 0o0755)
assert 0 == libc.mount(b'tmpfs', aptcache.encode(), b'tmpfs', 0, 0)
mkdir(aptcachepart, 0o0755)
aptlistspart += '/'
aptcachepart += '/'
atexit.register(umount, os.getpid())

# download and verify InRelease and Packages.gz
path = aptlistspart + prefix + 'dists_' + dist + '_InRelease'
download(path, dlurl + 'dists/' + dist + '/InRelease')
os.rename(path, aptlists + prefix + 'dists_' + dist + '_InRelease')
gpgpath = '/usr/share/keyrings/debian-archive-keyring.gpg'
if os.path.exists(gpgpath):
  assert gpgv(gpgpath, aptlists + prefix + 'dists_' + dist + '_InRelease')
path = aptlistspart + prefix + 'dists_' + dist + '_main_binary-' + arch + '_Packages.gz'
packpath = aptlists + prefix + 'dists_' + dist + '_main_binary-' + arch + '_Packages'
download(path, dlurl + 'dists/' + dist + '/main/binary-' + arch + '/Packages.gz')
os.rename(path, packpath + '.gz')

robj = InRelease(aptlists + prefix + 'dists_' + dist + '_InRelease')
finfo = robj.pool.get('main/binary-' + arch + '/Packages.gz')
assert not None == finfo
assert finfo[2] == getsha256(packpath + '.gz')

# decompress Packages.gz and verify
gobj = gzip.open(packpath + '.gz', 'rb')
fobj = open(packpath, 'wb')
while True:
  buf = gobj.read(512)
  if len(buf) == 0:
    break
  fobj.write(buf)
gobj.close()
fobj.close()
os.unlink(packpath + '.gz')
finfo = robj.pool.get('main/binary-' + arch + '/Packages')
assert not None == finfo
assert finfo[2] == getsha256(packpath)

for i in ['bin', 'sbin', 'lib', 'lib32', 'lib64', 'libx32']:
  os.symlink('usr/' + i, i, False)
  mkdir('usr/' + i, 0o0755)

# if '.' is a mount point, then add packages to install linux kernel vmlinuz and grub files requied by bios boot and uefi boot
# the install progess will make initrd.img, which used by boot
packobj = Packages(packpath).parse()
if os.path.ismount('.'):
  packobj.build(['linux-image-amd64', 'grub-pc-bin', 'grub-efi-amd64-bin'])
else:
  packobj.build()

# download deb files
number = str(len(packobj.system))
ready = 0
for name in packobj.system:
  ready += 1
  pobj = packobj.pool.get(name)
  assert not None == pobj
  path, dpkgname, sha256 = pobj.Filename, pobj.dpkgname, pobj.SHA256
  download(aptcachepart + dpkgname, dlurl + path, ('[%' + str(len(number)) + 'd/' + number + '] ') % ready)
  os.rename(aptcachepart + dpkgname, aptcache + dpkgname)
  assert sha256 == getsha256(aptcache + dpkgname)

# decompress deb files (first list)
for name in packobj.first:
  fdr, fdw = os.pipe()
  if 0 == os.fork():
    os.dup2(fdw, 1)
    os.close(fdr)
    os.close(fdw)
    os.execv('/usr/bin/env', ['env', 'dpkg-deb', '--fsys-tarfile', aptcache + packobj.pool[name].dpkgname])
    exit(-1)
  if 0 == os.fork():
    os.dup2(fdr, 0)
    os.close(fdr)
    os.close(fdw)
    os.execv('/usr/bin/env', ['env', 'tar', '-k', '-xf', '-'])
    exit(-1)
  os.close(fdr)
  os.close(fdw)
  assert 0 == os.wait()[1]
  assert 0 == os.wait()[1]

mkdir('var/lib/dpkg', 0o0755)
os.close(os.open('var/lib/dpkg/status', os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o0644))
os.close(os.open('var/lib/dpkg/available', os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o0644))
path = 'etc/fstab'

mkdir('etc', 0o0755)

path = 'etc/resolv.conf'
if not os.path.lexists(path):
  fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o0644)
  os.close(fd)

path = 'etc/hostname'
if not os.path.lexists(path):
  fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o0644)
  os.write(fd, b'localhost\n')
  os.close(fd)

# if '.' is a mount point, then read UUID to etc/fstab, else just like debootstrap
path = 'etc/fstab'
if not os.path.lexists(path):
  fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o0644)
  try:
    assert os.path.ismount('.')
    assert os.path.ismount('/dev')
    assert os.path.isdir('/dev/block/')
    assert os.path.isdir('/dev/disk/by-uuid/')
  except:
    os.write(fd, b'# UNCONFIGURED FSTAB FOR BASE SYSTEM\n')
  else:
    st_dev = os.stat('.').st_dev
    path = '../' + os.readlink('/dev/block/' + str(st_dev >> 8) + ':' + str(st_dev & 255))
    for uuid in os.listdir('/dev/disk/by-uuid/'):
      if path == os.readlink('/dev/disk/by-uuid/' + uuid):
        os.write(fd, b'UUID=' + uuid.encode() + b' / auto defaults 0 1\ntmpfs /tmp tmpfs nosuid,nodev 0 0\n')
        break
    else:
      os.write(fd, b'# UNCONFIGURED FSTAB FOR BASE SYSTEM\n')
  os.close(fd)

# initialize dev dir
mknod('null', 1, 3)
mknod('zero', 1, 5)
mknod('full', 1, 7)
mknod('random', 1, 8)
mknod('urandom', 1, 9)
mknod('tty', 5, 0)
mknod('console', 5, 1)
for i in ['pts', 'shm']:
  path = 'dev/' + i
  mkdir(path, 0o0755)
if not mknod('ptmx', 5, 2):
  if os.path.lexists('dev/ptmx'):
    os.unlink('dev/ptmx')
  os.symlink('pts/ptmx', 'dev/ptmx', False)
for src, dst in [
  ('/proc/self/fd', 'dev/fd'),
  ('/proc/self/fd/0', 'dev/stdin'),
  ('/proc/self/fd/1', 'dev/stdout'),
  ('/proc/self/fd/2', 'dev/stderr')
]:
  if os.path.lexists(dst):
    os.unlink(dst)
  os.symlink(src, dst)

mkdir('etc/apt', 0o0755)
fd = os.open('etc/apt/sources.list', os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o0644)
os.write(fd, (' '.join(['deb', apturl[:-1], dist, 'main']) + '\n').encode())
os.close(fd)

mkdir('var/lib/dpkg/info', 0o0755)

dpkgaddinfo(['dpkg'])

# mount /sys /proc
if 0 == os.fork():
  os.chroot('.')
  os.chdir('/')
  os.environ['PATH'] = '/sbin:/usr/sbin:/bin:/usr/bin'
  assert 0 == libc.mount(b'proc', b'/proc', b'proc', 0, 0)
  assert 0 == libc.mount(b'sysfs', b'/sys', b'sysfs', 0, 0)
  os.execv('/sbin/ldconfig', ['/sbin/ldconfig'])
  exit(-1)
assert 0 == os.wait()[1]
mkdir('run/mount', 0o0755)

path = 'usr/bin/awk'
if os.path.lexists(path):
  os.unlink(path)
os.symlink('mawk', path, False)

dpkginstall(['base-passwd', 'base-files', 'dpkg'])

if not os.path.exists('etc/localtime'):
  if os.path.islink('etc/localtime'):
    os.unlink('etc/localtime')
  os.symlink('/usr/share/zoneinfo/UTC', 'etc/localtime', False)

dpkginstall(['libc6', 'perl-base'])
os.unlink('usr/bin/awk')
dpkginstall(['mawk', 'debconf'])

def chroot(argv):
  os.chroot('.')
  os.chdir('/')
  os.environ['PATH'] = '/sbin:/usr/sbin:/bin:/usr/bin'
  os.execv('/usr/bin/env', ['env'] + argv)
  exit(-1)

# unpack deb files (first list)
if 0 == os.fork():
  chroot(['dpkg', '--force-depends', '--unpack'] + packobj.getdebs(packobj.first, aptcache))
e = os.wait()[1]
if not 0 == e:
  print('Warning:', 'dpkg:', 'unpack:', 'return', e)

fd = os.open('usr/sbin/policy-rc.d', os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o0755)
os.write(fd, b'#!/bin/sh\nexit 101\n')
os.close(fd)
os.rename('usr/sbin/start-stop-daemon', 'usr/sbin/start-stop-daemon.REAL')
fd = os.open('usr/sbin/start-stop-daemon', os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o0755)
os.write(fd, b'#!/bin/sh\necho\necho "Warning: Fake start-stop-daemon called, doing nothing"\n')
os.close(fd)
fd = os.open('var/lib/dpkg/cmethopt', os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o0644)
os.write(fd, b'apt apt\n')
os.close(fd)

# config packages (first list)
if 0 == os.fork():
  fdr, fdw = os.pipe()
  if 0 == os.fork():
    os.dup2(fdr, 0)
    os.close(fdr)
    os.close(fdw)
    chroot(['dpkg', '--configure', '--pending', '--force-configure-any', '--force-depends'])
  os.close(fdr)
  while True:
    try:
      os.write(fdw, b'yes\n')
    except:
      exit(os.wait()[1])
e = os.wait()[1]
if not 0 == e:
  print('Warning:', 'dpkg:', 'configure:', 'return', e)

fd = os.open('var/lib/dpkg/available', os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o0644)
fobj = open(packpath, 'r')
status = 0
while True:
  line = fobj.readline()
  if 0 == len(line):
    os.close(fd)
    fobj.close()
    break
  info = line.replace('\r', '').replace('\n', '')
  if 0 == len(info):
    if 1 == status:
      os.write(fd, line.encode())
    status = 0
  elif 0 == status:
    field, name = info.split()
    if 'Package' in field:
      if name in packobj.system:
        os.write(fd, line.encode())
        status = 1
      else:
        status = 2
    else:
      print('Error:', 'Package file format:', packpath)
      exit(-1)
  elif 1 == status:
    os.write(fd, line.encode())

fdr, fdw = os.pipe()
if 0 == os.fork():
  os.dup2(fdr, 0)
  os.close(fdr)
  os.close(fdw)
  chroot(['dpkg', '--set-selections'])
os.close(fdr)
for name in packobj.first + packobj.after:
  os.write(fdw, name.encode() + b' install\n')
os.close(fdw)
e = os.wait()[-1]

def getpredep():
  ret = []
  fdr, fdw = os.pipe()
  if 0 == os.fork():
    os.dup2(fdw, 1)
    os.close(fdr)
    os.close(fdw)
    chroot(['dpkg', '--predep-package'])
  os.close(fdw)
  fobj = os.fdopen(fdr)
  while True:
    line = fobj.readline()
    if 0 == len(line):
      fobj.close()
      e = os.wait()[1]
      return ret
    elif line.startswith('Package:'):
      ret.append(line.split()[1])

def listminus(left, rght):
  ret = []
  for i in left:
    if i not in rght:
      ret.append(i)
  return ret

# handle predep
done = []
after = packobj.after.copy()
while True:
  predep = getpredep()
  if 0 == len(predep):
    break
  predep = listminus(listminus(packobj.resolve(predep), packobj.first), done)
  if 0 == os.fork():
    chroot(['dpkg', '--force-overwrite', '--force-confold', '--skip-same-version', '--install'] + packobj.getdebs(predep, aptcache))
  e = os.wait()[1]
  after = listminus(after, predep)
  done += predep

# unpack deb files (after list)
if 0 == os.fork():
  chroot(['dpkg', '--force-overwrite', '--force-confold', '--skip-same-version', '--unpack'] + packobj.getdebs(after, aptcache))
e = os.wait()[1]

# config packages (after list)
if 0 == os.fork():
  chroot(['dpkg', '--force-confold', '--skip-same-version', '--configure', '-a'])
e = os.wait()[1]

os.rename('sbin/start-stop-daemon.REAL', 'sbin/start-stop-daemon')
os.unlink('usr/sbin/policy-rc.d')

def getpackpath(path):
  i = 1
  while True:
    if not os.path.lexists(path + '.' + str(i)):
      break
    i += 1
  return path + '.' + str(i)

# set the time info in files blow, according to time info in file InRelease to hide install time info
if not None == robj.day and not None == robj.time and not None == robj.days:
  days = ':' + str(robj.days) + ':'
  for path, split, start, end, prefix in [
    ('var/log/dpkg.log', ' ', 0, 2, robj.day + ' ' + robj.time + ' '),
    ('var/log/alternatives.log', ' ', 1, 3, ' ' + robj.day + ' ' + robj.time + ': '),
    ('etc/shadow', ':', 2, 3, days),
    ('etc/shadow-', ':', 2, 3, days)
  ]:
    if os.path.isfile(path):
      stat = os.stat(path)
      os.setgid(stat.st_gid)
      mode = stat.st_mode & 0o7777
      pathback = getpackpath(path)
      os.rename(path, pathback)
      try:
        fdw = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
        try:
          fobjw = os.fdopen(fdw, 'w')
          try:
            fdr = os.open(pathback, os.O_RDONLY)
            try:
              fobjr = os.fdopen(fdr, 'r')
            except:
              os.close(fdr)
              raise
          except:
            raise
        except OSError:
          os.close(fdw)
          raise
        except:
          fobjw.close()
          raise
      except:
        os.rename(pathback, path)
      else:
        while True:
          line = fobjr.readline()
          if 0 == len(line):
            break
          else:
            line = line.split(split, end)
            fobjw.write(split.join(line[:start]) + prefix + line[end])
        fobjw.close()
        fobjr.close()
        os.unlink(pathback)
      os.setgid(0)

# choose whether to delete these files according to the situation
os.unlink('etc/machine-id')
os.unlink('var/cache/ldconfig/aux-cache')
# os.unlink('var/log/dpkg.log')
# os.unlink('var/log/alternatives.log')

exit(0)
