#!/usr/bin/python3
import ctypes, dpkt, fcntl, os, socket, sys
from ctypes import c_int, c_void_p, c_size_t, c_ulong, c_uint32, c_uint64, c_ushort, c_byte
socket.IP_MTU_DISCOVER = 10
namespace = None
interface = None

MS_REC = 16384
MS_SLAVE = 1 << 19
MNT_DETACH = 2

def route(buf):
  prefix, mask = buf.split('/', 1)
  return int(mask).to_bytes() + socket.inet_aton(prefix)[:(int(mask) + 7) // 8]

opts = []
for arg in sys.argv[1:]:
  if arg.startswith('-ns='):
    namespace = arg[len('-ns='):].encode()
  elif arg.startswith('-eth='):
    interface = arg[len('-eth='):].encode()
  elif arg.startswith('-net='):
    prefix, mask = arg[len('-net='):].split('/', 1)
    prefix = int.from_bytes(socket.inet_aton(prefix))
    mask = 32 - int(mask)
    assert mask <= 32 and mask >= 0
  elif arg.startswith('-opt='):
    arg = arg[len('-opt='):]
    arg = arg.split(',', 1)
    assert 2 == len(arg)
    opt, value = arg
    if '3' == opt:
      opts.insert(0, (3, socket.inet_aton(value)))
    elif '6' == opt:
      opts.insert(0, (6, socket.inet_aton(value)))
    elif '121' == opt:
      subnet, gate = value.split(',', 1)
      opts.insert(0, (121, route(subnet) + socket.inet_aton(gate)))

assert interface is not None
libc = ctypes.CDLL(None, 0, None, True)
libc.mount.argtypes, libc.mount.restype = [c_void_p, c_void_p, c_void_p, c_ulong, c_void_p], c_int
libc.umount2.argtypes, libc.umount2.restype = [c_void_p, c_int], c_int

if namespace is not None:
  fd = os.open(b'/run/netns/' + namespace, os.O_RDONLY)
  os.setns(fd, os.CLONE_NEWNET)
  os.close(fd)
  os.unshare(os.CLONE_NEWNS)
  assert 0 == libc.mount(b'', b'/', b'none', MS_REC | MS_SLAVE, 0)
  assert 0 == libc.umount2(b'/sys', MNT_DETACH)
  assert 0 == libc.mount(namespace, b'/sys', b'sysfs', 0, 0)

if not 0 == os.fork():
  os._exit(0)

fd = os.open('/dev/null', os.O_RDONLY)
os.dup2(fd, 0)
os.close(fd)
fd = os.open('/dev/null', os.O_WRONLY | os.O_TRUNC)
os.dup2(fd, 1)
os.dup2(fd, 2)
os.close(fd)
os.setsid()
sock = socket.socket(socket.AF_INET.value, socket.SOCK_DGRAM.value,  socket.IPPROTO_UDP)
sock.setsockopt(socket.SOL_IP, socket.IP_MTU_DISCOVER, 0)
sock.setsockopt(socket.SOL_IP, socket.IP_TOS, 192)
sock.setsockopt(socket.SOL_IP, socket.IP_PKTINFO, 1)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, interface)
sock.bind(('0.0.0.0', 67))

class sockaddr(ctypes.Structure):
  _fields_ = [
    ('sa_family', c_ushort),
    ('sa_data', c_byte * 14)
  ]
  def __str__(self):
    ret = {}
    ret['sa_family'] = socket.AddressFamily(self.sa_family).name
    ret['sa_data'] = bytes(self.sa_data).decode()
    return str(ret)

class sockaddr_in(ctypes.Structure):
  _fields_ = [
    ('sa_family', c_ushort),
    ('sin_port', c_ushort),
    ('sin_addr', c_byte * 4),
    ('__pad', c_byte * 8)
  ]
  def __str__(self):
    ret = {}
    ret['sa_family'] = socket.AddressFamily(self.sa_family).name
    ret['sin_port'] = socket.ntohs(self.sin_port)
    ret['sin_addr'] = socket.inet_ntoa(self.sin_addr)
    return str(ret)

IFNAMSIZ = 16
class arpreq(ctypes.Structure):
  _fields_ = [
    ('arp_pa', sockaddr_in),
    ('arp_ha', sockaddr),
    ('arp_flags', c_int),
    ('arp_netmask', sockaddr),
    ('arp_dev', c_byte * IFNAMSIZ)
  ]
  def __str__(self):
    ret = {}
    ret['arp_pa'] = str(self.arp_pa)
    ret['arp_ha'] = str(self.arp_ha)
    ret['arp_flags'] = str(self.arp_flags)
    ret['arp_netmask'] = str(self.arp_netmask)
    ret['arp_dev'] = bytes(self.arp_dev).decode()
    return str(ret)

SIOCSARP = 0x8955
ATF_COM = 0x02
arp_req = arpreq()
arp_req.arp_flags = ATF_COM
arp_req.arp_pa.sa_family = socket.AF_INET.value
arp_req.arp_ha.sa_family = 1
ctypes.memmove(arp_req.arp_dev, interface, ctypes.sizeof(arp_req.arp_dev))
while True:
  data, anc, flags, addr = sock.recvmsg(2048, 2048, 0)
  obj = dpkt.dhcp.DHCP(data)
  msgtype = -1
  for i in obj.opts:
    if not 2 == len(i):
      msgtype = -1
      break
    elif 53 == i[0]:
      msgtype = i[1][0]
  msgtype = 2 if (1 == msgtype) else 5 if (3 == msgtype) else -1
  if msgtype < 0:
    continue
  yiaddr = (prefix | int.from_bytes(obj.chaddr) & ((1 << mask) - 1)).to_bytes(4) # 192.168.122.128
  arp_req.arp_pa.sa_port = socket.htons(addr[1])
  ctypes.memmove(arp_req.arp_pa.sin_addr, yiaddr, sockaddr_in.sin_addr.size)
  ctypes.memmove(arp_req.arp_ha.sa_data, obj.chaddr, 6)
  fcntl.ioctl(sock.fileno(), SIOCSARP, bytes(arp_req))
  broadcast = prefix | ((1 << mask) - 1) # 192.168.122.255
  siaddr = broadcast & ((1 << 32) - 2) # 192.168.122.254
  msg = dpkt.dhcp.DHCP(
    op = 2,
    hrd = 1,
    hln = 6,
    hops = 0,
    xid = obj.xid,
    ciaddr = 0,
    yiaddr = int.from_bytes(yiaddr),
    siaddr = siaddr,
    giaddr = 0,
    chaddr = obj.chaddr,
    magic = obj.magic,
    opts = [
      (53, int(msgtype).to_bytes()),
      (54, siaddr.to_bytes(4)),
      (51, int(3600).to_bytes(4)),
      (58, int(1800).to_bytes(4)),
      (59, int(3150).to_bytes(4)),
      (1, (((1 << (32 - mask)) - 1) << mask).to_bytes(4)), # 255.255.255.0
      (28, broadcast.to_bytes(4))
    ] + opts
  )
  sock.sendmsg([msg.pack()], [(
    socket.SOL_IP,
    socket.IP_PKTINFO,
    socket.if_nametoindex(interface).to_bytes(4, 'little') + socket.inet_aton('0.0.0.0') + socket.inet_aton('255.255.255.255')
  )], 0, (socket.inet_ntoa(yiaddr), 68))
