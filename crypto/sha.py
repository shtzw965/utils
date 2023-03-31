#!/usr/bin/env python3
'''
https://nvlpubs.nist.gov/nistpubs/Legacy/FIPS/NIST.FIPS.180.pdf
https://csrc.nist.gov/csrc/media/publications/fips/180/2/archive/2002-08-01/documents/fips180-2.pdf
https://csrc.nist.gov/csrc/media/publications/fips/180/2/archive/2002-08-01/documents/fips180-2withchangenotice.pdf
https://csrc.nist.gov/csrc/media/publications/fips/180/3/archive/2008-10-31/documents/fips180-3_final.pdf
https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA512_224.pdf
https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA512_256.pdf
https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA_All.pdf
https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines/example-values
https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
https://keccak.team/files/Keccak-reference-3.0.pdf
'''
import time
t = time.time()
class Keccak:
  def __init__(self, l = 6):
    if l < 3 or l > 6:
      raise
    self.l = l
    self.w = 1 << (self.l - 3)
    self.b = self.w * 25
    self.nr = 12 + 2 * self.l
    self.A = [[0 for j in range(5)] for i in range(5)]
    self.B = [[0 for j in range(5)] for i in range(5)]
  def __str__(self):
    return '' if self.A == None else '[\n  ' + ',\n  '.join(['[' + ', '.join(['0x%016x' % j for j in i]) + ']' for i in self.A]) + '\n]'
  def absorb(self, msg):
    if len(msg) > self.b or not 0 == len(msg) % self.w:
      raise
    offset = 0
    for y in range(5):
      for x in range(5):
        self.A[x][y] ^= int.from_bytes(msg[offset:offset + self.w], 'little')
        offset += self.w
        if offset == len(msg):
          self.f()
          return self
  def squeeze(self, length = 0):
    if length < 0 or length > self.b:
      raise
    msg = b''
    for y in range(5):
      for x in range(5):
        if length > 8:
          msg += self.A[x][y].to_bytes(self.w, 'little')
          length -= 8
        else:
          msg += self.A[x][y].to_bytes(self.w, 'little')[:length]
          self.f()
          return msg
  def reset(self):
    for x in range(5):
      for y in range(5):
        self.A[x][y] = 0
    return self
  def setstate(self, A):
    for x in range(5):
      for y in range(5):
        self.A[x][y] = A[x][y]
    return self
  def getstate(self):
    return [[j for j in i] for i in self.A]
  def setstring(self, msg):
    if not self.b == len(msg):
      raise
    offset = 0
    for y in range(5):
      for x in range(5):
        self.A[x][y] = int.from_bytes(msg[offset:offset + self.w], 'little')
        offset += self.w
    return self
  def getstring(self):
    msg = b''
    for y in range(5):
      for x in range(5):
        msg += self.A[x][y].to_bytes(self.w, 'little')
    return msg
  def ROTL(i, o, b):
    return (i << o) % (1 << b) | (i >> b - o)
  def ROTR(i, o, b):
    return (i << b - o) % (1 << b) | (i >> o)
  def rc(t):
    if 0 == (t % 255):
      return 1
    else:
      R = 1 << 7
      for i in range(1, t % 255 + 1):
        R &= 0xff
        R ^= (R & 1) * 0b100011100
        R >>= 1
      return R >> 7
  def iota(self, ir): # ι
    RC = 0
    for j in range(self.l + 1):
      RC |= Keccak.rc(j + 7 * ir) << ((1 << j) - 1)
    self.A[0][0] ^= RC
    return self
  def chi(self): # χ
    for x in range(5):
      for y in range(5):
        self.B[x][y] = self.A[x][y]
    for x in range(5):
      for y in range(5):
        self.A[x][y] = self.B[x][y] ^ (~self.B[(x + 1) % 5][y] & self.B[(x + 2) % 5][y])
    return self
  def pi(self): # π
    for x in range(5):
      for y in range(5):
        self.B[x][y] = self.A[x][y]
    for x in range(5):
      for y in range(5):
        self.A[x][y] = self.B[(x + 3 * y) % 5][x]
    return self
  def rho(self): # ρ
    x, y, b = 1, 0, self.w << 3
    for t in range(24):
      self.A[x][y] = Keccak.ROTL(self.A[x][y], ((t + 1) * (t + 2) // 2) % b, b)
      x, y = y, (2 * x + 3 * y) % 5
    return self
  def theta(self): # θ
    C, D, b = [0, 0, 0, 0, 0], [0, 0, 0, 0, 0], self.w << 3
    for x in range(5):
      C[x] = self.A[x][0] ^ self.A[x][1] ^ self.A[x][2] ^ self.A[x][3] ^ self.A[x][4]
    for x in range(5):
      D[x] = C[(x + 4) % 5] ^ Keccak.ROTL(C[(x + 1) % 5], 1, b)
    for x in range(5):
      for y in range(5):
        self.A[x][y] ^= D[x]
    return self
  def Rnd(self, ir):
    return self.theta().rho().pi().chi().iota(ir)
    self.theta()
    for x in range(5):
      for y in range(5):
        self.B[y][(2 * x + 3 * y) % 5] = Keccak.ROTL(self.A[x][y], [
          [0x00, 0x24, 0x03, 0x29, 0x12],
          [0x01, 0x2c, 0x0a, 0x2d, 0x02],
          [0x3e, 0x06, 0x2b, 0x0f, 0x3d],
          [0x1c, 0x37, 0x19, 0x15, 0x38],
          [0x1b, 0x14, 0x27, 0x08, 0x0e]
        ][x][y], self.w << 3)
    for x in range(5):
      for y in range(5):
        self.A[x][y] = ((~self.B[(x + 1) % 5][y]) & self.B[(x + 2) % 5][y]) ^ self.B[x][y]
    self.A[0][0] ^= [
      0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
      0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
      0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
      0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
      0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
      0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008
    ][ir] % (1 << (self.w << 3))
    return self
  def p(self, nr):
    for ir in range(nr):
      self.Rnd(ir)
    return self
  def f(self):
    return self.p(self.nr)
  def test():
    k = Keccak(6).f()
    print(k)
    assert [
      [0xf1258f7940e1dde7, 0xff97a42d7f8e6fd4, 0xeb5aa93f2317d635, 0x05e5635a21d9ae61, 0x940c7922ae3a2614],
      [0x84d5ccf933c0478a, 0x90fee5a0a44647c4, 0xa9a6e6260d712103, 0x64befef28cc970f2, 0x1841f924a2c509e4],
      [0xd598261ea65aa9ee, 0x8c5bda0cd6192e76, 0x81a57c16dbcf555f, 0x613670957bc46611, 0x16f53526e70465c2],
      [0xbd1547306f80494d, 0xad30a6f71b19059c, 0x43b831cd0347c826, 0xb87c5a554fd00ecb, 0x75f644e97f30a13b],
      [0x8b284e056253d057, 0x30935ab7d08ffc64, 0x01f22f1a11a5569f, 0x8c3ee88a1ccf32c8, 0xeaf1ff7b5ceca249]
    ] == k.A
    assert b''.join([
      b'\xe7\xdd\xe1\x40\x79\x8f\x25\xf1\x8a\x47\xc0\x33\xf9\xcc\xd5\x84\xee\xa9\x5a\xa6\x1e\x26\x98\xd5\x4d\x49\x80\x6f\x30\x47\x15\xbd\x57\xd0\x53\x62\x05\x4e\x28\x8b',
      b'\xd4\x6f\x8e\x7f\x2d\xa4\x97\xff\xc4\x47\x46\xa4\xa0\xe5\xfe\x90\x76\x2e\x19\xd6\x0c\xda\x5b\x8c\x9c\x05\x19\x1b\xf7\xa6\x30\xad\x64\xfc\x8f\xd0\xb7\x5a\x93\x30',
      b'\x35\xd6\x17\x23\x3f\xa9\x5a\xeb\x03\x21\x71\x0d\x26\xe6\xa6\xa9\x5f\x55\xcf\xdb\x16\x7c\xa5\x81\x26\xc8\x47\x03\xcd\x31\xb8\x43\x9f\x56\xa5\x11\x1a\x2f\xf2\x01',
      b'\x61\xae\xd9\x21\x5a\x63\xe5\x05\xf2\x70\xc9\x8c\xf2\xfe\xbe\x64\x11\x66\xc4\x7b\x95\x70\x36\x61\xcb\x0e\xd0\x4f\x55\x5a\x7c\xb8\xc8\x32\xcf\x1c\x8a\xe8\x3e\x8c',
      b'\x14\x26\x3a\xae\x22\x79\x0c\x94\xe4\x09\xc5\xa2\x24\xf9\x41\x18\xc2\x65\x04\xe7\x26\x35\xf5\x16\x3b\xa1\x30\x7f\xe9\x44\xf6\x75\x49\xa2\xec\x5c\x7b\xff\xf1\xea'
    ]) == k.setstring(bytes(200)).f().getstring()
    return True

class SHA:
  constants, hashs = [[ # sha0 sha1
    0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6
  ], [[ # sha2 256
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  ], [ # sha2 512
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
  ]]], [[ # sha0 sha1
    0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0
  ], [[ # sha2 sha256
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
  ], [ # sha2 sha224
    0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4
  ], [ # sha2 sha512
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
    0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
  ], [ # sha2 sha384
    0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17, 0x152fecd8f70e5939,
    0x67332667ffc00b31, 0x8eb44a8768581511, 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4
  ], [ # sha2 sha512/224
    0x8c3d37c819544da2, 0x73e1996689dcd4d6, 0x1dfab7ae32ff9c82, 0x679dd514582f9fcf,
    0x0f6d2b697bd44da8, 0x77e36f7304c48942, 0x3f9d85a86a1d36c8, 0x1112e6ad91d692a1
  ], [ # sha2 sha512/256
    0x22312194fc2bf72c, 0x9f555fa3c84c64c2, 0x2393b86b6f53b151, 0x963877195940eabd,
    0x96283ee2a88effe3, 0xbe5e1e2553863992, 0x2b0199fc2c85b8aa, 0x0eb72ddc81c52ca2
  ]]]
  def __init__(self, version = 2, length = 256, size = 0):
    self.version = version
    self.length = length
    self.size = size
    self.msg = b''
    self.msglen = 0
    if 0 == self.version or 1 == self.version: # sha0 sha1
      self.size = self.length = 160
      self.unit = 64
      self.padlen = 8
      self.msgmax = self.getmax()
      self.func = self._SHA_0 if 0 == self.version else self._SHA_1
      self.constant = self.constants[0]
      self.hash = self.hashs[0]
    elif 2 == self.version:
      if 0 == self.size:
        self.size = 256 if 224 == self.length else (512 if 384 == self.length else self.length)
      if 256 == self.size:
        self.unit = 64
        self.padlen = 8
        self.msgmax = self.getmax()
        self.func = self._SHA_2_256
        self.constant = self.constants[1][0]
        if 256 == self.length: # sha256
          self.hash = self.hashs[1][0]
        elif 224 == self.length: # sha224
          self.hash = self.hashs[1][1]
        else:
          raise
      elif 512 == self.size:
        self.unit = 128
        self.padlen = 16
        self.msgmax = self.getmax()
        self.func = self._SHA_2_512
        self.constant = self.constants[1][1]
        if 512 == self.length: # sha512
          self.hash = self.hashs[1][2]
        elif 384 == self.length: # sha384
          self.hash = self.hashs[1][3]
        elif 224 == self.length: # sha512/224
          self.hash = self.hashs[1][4]
        elif 256 == self.length: # sha512/256
          self.hash = self.hashs[1][5]
        else:
          raise
      else:
        raise
    elif 3 == self.version:
      if 0 == self.size: # sha3-224 sha3-256 sha3-384 sha3-512
        self.shake = False
        if not self.length in [224, 256, 384, 512]:
          raise
        self.unit = 200 - (self.length >> 2)
      else: # shake-128 shake-256
        self.shake = True
        if not self.size in [128, 256]:
          raise
        self.unit = 200 - (self.size >> 2)
      self.keccak = Keccak(6)
    else:
      raise
  def getmax(self):
    return (1 << (self.padlen * 8)) // 8 - 1
    '''
0x1fffffffffffffff >= 2EiB (2 * 1024 * 1024 TiB)
sha0 sha1 sha2(sha224 sha256)
0x1fffffffffffffffffffffffffffffff
sha2 (sha384 sha512 sha512/224 sha512/256)
    '''
  def getpad(self, length):
    return b'\x80' + (b'\x00' * ((self.unit - ((length + self.padlen + 1) % self.unit)) % self.unit)) + (length << 3).to_bytes(self.padlen, 'big')
  def ROTL(i, o, b):
    return (i << o) % (1 << b) | (i >> b - o)
  def ROTR(i, o, b):
    return (i << b - o) % (1 << b) | (i >> o)
  def update(self, msg):
    length = len(msg)
    if 3 == self.version:
      if len(self.msg) + length < self.unit:
        self.msg += msg
      else:
        offset = self.unit - len(self.msg)
        self.keccak.absorb(self.msg + msg[:offset])
        while True:
          if offset + self.unit > length:
            self.msg = msg[offset:]
            break
          else:
            self.keccak.absorb(msg[offset:offset + self.unit])
            offset += self.unit
    else:
      self.msglen += length
      if self.msglen > self.msgmax:
        raise
      if len(self.msg) + length < self.unit:
        self.msg += msg
      else:
        self.func(self.msg + msg[:self.unit - len(self.msg)])
        msg = msg[self.unit - len(self.msg):]
        length = len(msg) // self.unit * self.unit
        self.func(msg[:length])
        self.msg = msg[length:]
    return self
  def result(self):
    if 3 == self.version:
      if len(self.msg) == self.unit - 1:
        self.keccak.absorb(self.msg + (b'\x9f' if self.shake else b'\x86'))
      elif len(self.msg) == self.unit - 2:
        self.keccak.absorb(self.msg + (b'\x1f\x80' if self.shake else b'\x06\x80'))
      else:
        self.keccak.absorb(self.msg + (b'\x1f' if self.shake else b'\x06') + b'\x00' * (self.unit - 2 - len(self.msg)) + b'\x80')
      msg = b''
      while len(msg) < (self.length >> 3):
        msg += self.keccak.squeeze(self.unit)
      return msg[:self.length >> 3]
    else:
      self.func(self.msg + self.getpad(self.msglen))
      return b''.join([i.to_bytes(self.size // len(self.hash) >> 3, 'big') for i in self.hash])[:self.length >> 3]
  def _SHA_0(self, msg):
    for i in range(0, len(msg), 64):
      W = [int.from_bytes(msg[i + j:i + j + 4], 'big') for j in range(0, 64, 4)] + ([0] * 64)
      A, B, C, D, E = self.hash
      for j in range(80):
        s = j & 0xf
        if j > 0xf:
          W[s] = W[(s + 13) & 0xf] ^ W[(s + 8) & 0xf] ^ W[(s + 2) & 0xf] ^ W[s]
        k = j // 20
        F = (B & C) ^ (~B & D) if 0 == k else (B & C) ^ (B & D) ^ (C & D) if 2 == k else B ^ C ^ D
        T = (SHA.ROTL(A, 5, 32) + F + E + self.constant[k] + W[s]) & 0xffffffff
        A, B, C, D, E = T, A, SHA.ROTL(B, 30, 32), C, D
      self.hash = [(i + j) & 0xffffffff for i, j in zip(self.hash, [A, B, C, D, E])]
      # print(['%08x' % i for i in [A, B, C, D, E]], j)
  def _SHA_1(self, msg):
    for i in range(0, len(msg), 64):
      W = [int.from_bytes(msg[i + j:i + j + 4], 'big') for j in range(0, 64, 4)] + ([0] * 64)
      A, B, C, D, E = self.hash
      for j in range(80):
        if j > 0xf:
          W[j] = SHA.ROTL(W[j - 3] ^ W[j - 8] ^ W[j - 14] ^ W[j - 16], 1, 32)
        k = j // 20
        F = (B & C) ^ (~B & D) if 0 == k else (B & C) ^ (B & D) ^ (C & D) if 2 == k else B ^ C ^ D
        T = (SHA.ROTL(A, 5, 32) + F + E + self.constant[k] + W[j]) & 0xffffffff
        A, B, C, D, E = T, A, SHA.ROTL(B, 30, 32), C, D
      self.hash = [(i + j) & 0xffffffff for i, j in zip(self.hash, [A, B, C, D, E])]
  def _SHA_2_256(self, msg):
    for i in range(0, len(msg), 64):
      W = [int.from_bytes(msg[i + j:i + j + 4], 'big') for j in range(0, 64, 4)] + ([0] * 48)
      for j in range(16, 64):
        S0 = SHA.ROTR(W[j - 15], 7, 32) ^ SHA.ROTR(W[j - 15], 18, 32) ^ (W[j - 15] >> 3)
        S1 = SHA.ROTR(W[j - 2], 17, 32) ^ SHA.ROTR(W[j - 2], 19, 32) ^ (W[j - 2] >> 10)
        W[j] = (S1 + W[j - 7] + S0 + W[j - 16]) & 0xffffffff
      A, B, C, D, E, F, G, H = self.hash
      for j in range(64):
        T1 = H + (SHA.ROTR(E, 6, 32) ^ SHA.ROTR(E, 11, 32) ^ SHA.ROTR(E, 25, 32)) + ((E & F) ^ (~E & G)) + self.constant[j] + W[j]
        T2 = (SHA.ROTR(A, 2, 32) ^ SHA.ROTR(A, 13, 32) ^ SHA.ROTR(A, 22, 32)) + ((A & B) ^ (A & C) ^ (B & C))
        A, B, C, D, E, F, G, H = (T1 + T2) & 0xffffffff, A, B, C, (D + T1) & 0xffffffff, E, F, G
      self.hash = [(i + j) & 0xffffffff for i, j in zip(self.hash, [A, B, C, D, E, F, G, H])]
  def _SHA_2_512(self, msg):
    for i in range(0, len(msg), 128):
      W = [int.from_bytes(msg[i + j:i + j + 8], 'big') for j in range(0, 128, 8)] + ([0] * 64)
      for j in range(16, 80):
        S0 = SHA.ROTR(W[j - 15], 1, 64) ^ SHA.ROTR(W[j - 15], 8, 64) ^ (W[j - 15] >> 7)
        S1 = SHA.ROTR(W[j - 2], 19, 64) ^ SHA.ROTR(W[j - 2], 61, 64) ^ (W[j - 2] >> 6)
        W[j] = (S1 + W[j - 7] + S0 + W[j - 16]) & 0xffffffffffffffff
      A, B, C, D, E, F, G, H = self.hash
      for j in range(80):
        T1 = H + (SHA.ROTR(E, 14, 64) ^ SHA.ROTR(E, 18, 64) ^ SHA.ROTR(E, 41, 64)) + ((E & F) ^ (~E & G)) + self.constant[j] + W[j]
        T2 = (SHA.ROTR(A, 28, 64) ^ SHA.ROTR(A, 34, 64) ^ SHA.ROTR(A, 39, 64)) + ((A & B) ^ (A & C) ^ (B & C))
        A, B, C, D, E, F, G, H = (T1 + T2) & 0xffffffffffffffff, A, B, C, (D + T1) & 0xffffffffffffffff, E, F, G
      self.hash = [(i + j) & 0xffffffffffffffff for i, j in zip(self.hash, [A, B, C, D, E, F, G, H])]
  def test():
    print('SHA test:')
    print()
    msg = b'abc'
    print('msg:', msg)
    assert           SHA(0).update(msg).result().hex() == '0164b8a914cd2a5e74c4f7ff082c4d97f1edf880'
    print('sha0:', True)
    assert           SHA(1).update(msg).result().hex() == 'a9993e364706816aba3e25717850c26c9cd0d89d'
    print('sha1:', True)
    assert      SHA(2, 224).update(msg).result().hex() == '23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7'
    print('sha224:', True)
    assert SHA(2, 224, 512).update(msg).result().hex() == '4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa'
    print('sha512/224:', True)
    assert      SHA(2, 256).update(msg).result().hex() == 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
    print('sha256:', True)
    assert SHA(2, 256, 512).update(msg).result().hex() == '53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23'
    print('sha512/256:', True)
    assert      SHA(2, 384).update(msg).result().hex() == 'cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7'
    print('sha384:', True)
    assert      SHA(2, 512).update(msg).result().hex() == 'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f'
    print('sha512:', True)
    print()
    msg = b'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq'
    print('msg:', msg)
    assert           SHA(0).update(msg).result().hex() == 'd2516ee1acfa5baf33dfc1c471e438449ef134c8'
    print('sha0:', True)
    assert           SHA(1).update(msg).result().hex() == '84983e441c3bd26ebaae4aa1f95129e5e54670f1'
    print('sha1:', True)
    assert      SHA(2, 224).update(msg).result().hex() == '75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525'
    print('sha224:', True)
    assert SHA(2, 224, 512).update(msg).result().hex() == 'e5302d6d54bb242275d1e7622d68df6eb02dedd13f564c13dbda2174'
    print('sha512/224:', True)
    assert      SHA(2, 256).update(msg).result().hex() == '248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1'
    print('sha256:', True)
    assert SHA(2, 256, 512).update(msg).result().hex() == 'bde8e1f9f19bb9fd3406c90ec6bc47bd36d8ada9f11880dbc8a22a7078b6a461'
    print('sha512/256:', True)
    assert      SHA(2, 384).update(msg).result().hex() == '3391fdddfc8dc7393707a65b1b4709397cf8b1d162af05abfe8f450de5f36bc6b0455a8520bc4e6f5fe95b1fe3c8452b'
    print('sha384:', True)
    assert      SHA(2, 512).update(msg).result().hex() == '204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c33596fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445'
    print()
    msg0 = b'abcdbcdecdefdefgefghfghi'
    msg1 = b'ghijhijkijkljklmklmnlmnomnopnopq'
    print('msg:', msg0 + msg1)
    assert           SHA(0).update(msg0).update(msg1).result().hex() == 'd2516ee1acfa5baf33dfc1c471e438449ef134c8'
    print('sha0:', True)
    assert           SHA(1).update(msg0).update(msg1).result().hex() == '84983e441c3bd26ebaae4aa1f95129e5e54670f1'
    print('sha1:', True)
    assert      SHA(2, 224).update(msg0).update(msg1).result().hex() == '75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525'
    print('sha224:', True)
    assert SHA(2, 224, 512).update(msg0).update(msg1).result().hex() == 'e5302d6d54bb242275d1e7622d68df6eb02dedd13f564c13dbda2174'
    print('sha512/224:', True)
    assert      SHA(2, 256).update(msg0).update(msg1).result().hex() == '248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1'
    print('sha256:', True)
    assert SHA(2, 256, 512).update(msg0).update(msg1).result().hex() == 'bde8e1f9f19bb9fd3406c90ec6bc47bd36d8ada9f11880dbc8a22a7078b6a461'
    print('sha512/256:', True)
    assert      SHA(2, 384).update(msg0).update(msg1).result().hex() == '3391fdddfc8dc7393707a65b1b4709397cf8b1d162af05abfe8f450de5f36bc6b0455a8520bc4e6f5fe95b1fe3c8452b'
    print('sha384:', True)
    assert      SHA(2, 512).update(msg0).update(msg1).result().hex() == '204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c33596fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445'
    print()
    msg = b'\xa3' * 200
    print('msg:', "b'\\xa3' * 200")
    assert SHA(3, 224).update(msg).result().hex() == '9376816aba503f72f96ce7eb65ac095deee3be4bf9bbc2a1cb7e11e0'
    assert SHA(3, 224).update(b'\xa3' * 100).update(b'\xa3' * 100).result().hex() == '9376816aba503f72f96ce7eb65ac095deee3be4bf9bbc2a1cb7e11e0'
    assert SHA(3, 224).update(b'\xa3' * 144).result().hex() == '5cf2d36273844ce16ededcc9afb6a7a393a6c72c41731aea144b7a00'
    assert SHA(3, 224).update(b'\xa3' * 142).result().hex() == 'c733dc5736e2b8c1a25fd8ca933659f49fe6f79a6b5af218e2ebeb9e'
    assert SHA(3, 224).update(b'\xa3' * 143).result().hex() == '1e66e6c67ca1affecd0bb4c38b1a930933cb7e34e498e132f1c6661b'
    assert SHA(3, 224).update(b'').result().hex() == '6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7'
    print('sha3-224:', True)
    assert SHA(3, 256).update(msg).result().hex() == '79f38adec5c20307a98ef76e8324afbfd46cfd81b22e3973c65fa1bd9de31787'
    assert SHA(3, 256).update(b'').result().hex() == 'a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a'
    print('sha3-256:', True)
    assert SHA(3, 384).update(msg).result().hex() == '1881de2ca7e41ef95dc4732b8f5f002b189cc1e42b74168ed1732649ce1dbcdd76197a31fd55ee989f2d7050dd473e8f'
    assert SHA(3, 384).update(b'').result().hex() == '0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004'
    print('sha3-384:', True)
    assert SHA(3, 512).update(msg).result().hex() == 'e76dfad22084a8b1467fcf2ffa58361bec7628edf5f3fdc0e4805dc48caeeca81b7c13c30adf52a3659584739a2df46be589c51ca1a4a8416df6545a1ce8ba00'
    assert SHA(3, 512).update(b'').result().hex() == 'a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26'
    print('sha3-512:', True)
    assert SHA(3, 128, 128).update(msg).result().hex() == '131ab8d2b594946b9c81333f9bb6e0ce'
    assert SHA(3, 128, 128).update(b'').result().hex() == '7f9c2ba4e88f827d616045507605853e'
    print('shake128:', True)
    assert SHA(3, 256, 256).update(msg).result().hex() == 'cd8a920ed141aa0407a22d59288652e9d9f1a7ee0c1e7c1ca699424da84a904d'
    assert SHA(3, 256, 256).update(b'').result().hex() == '46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f'
    print('shake256:', True)
    print()
    print('SHA test:', True)
    print()
    return True

print(Keccak.test())
print(SHA.test())
print()
print(time.time() - t)
