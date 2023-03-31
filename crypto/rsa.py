#!/usr/bin/env python3
import os, sys
sys.path[0] = '/'
import Cryptodome.Random, Cryptodome.Cipher.AES, Cryptodome.Cipher.PKCS1_v1_5, Cryptodome.Util.Counter, OpenSSL, pyasn1.codec.ber.decoder, pyasn1.codec.der.encoder, pyasn1.type.univ, rsa
from Cryptodome.PublicKey import RSA

def stream(length = 16):
  stream.i += 1
  return Cryptodome.Cipher.AES.new(stream.i.to_bytes(32, 'big'), mode=Cryptodome.Cipher.AES.MODE_CTR, counter=Cryptodome.Util.Counter.new(16 * 8, initial_value=int((bytes(16)).hex(), 0x10))).encrypt(bytes(length))

stream.i = 0

# PKCS1-v1_5
# msg = b''
# msg = b'\x00\x02' + os.getrandom(256 - 3 - len(msg)) + b'\x00' + msg

# i ** p % m
def powermod(i:int, p:int, m:int):
  if 0 == m:
    return i ** p
  elif not i > 1:
    return i ** p % m
  else:
    r = 1
    while 0 < p:
      n = i
      t = 1
      while n < m:
        n *= i
        t += 1
      r = i ** (p % t) * r % m
      i = n % m
      p = p // t
    return r % m

def rand_odd_int(nbits):
  return int(stream(nbits // 8 + (0 if 0 == nbits % 8 else 1)).hex(), 0x10) & (2 ** nbits - 1)

rsa.randnum.read_random_odd_int = rand_odd_int

class asn1RSAprivate(pyasn1.type.univ.Sequence):
  componentType = pyasn1.type.namedtype.NamedTypes(
    pyasn1.type.namedtype.NamedType('version', pyasn1.type.univ.Integer()),
    pyasn1.type.namedtype.NamedType('modulus', pyasn1.type.univ.Integer()),
    pyasn1.type.namedtype.NamedType('publicExponent', pyasn1.type.univ.Integer()),
    pyasn1.type.namedtype.NamedType('privateExponent', pyasn1.type.univ.Integer()),
    pyasn1.type.namedtype.NamedType('prime1', pyasn1.type.univ.Integer()),
    pyasn1.type.namedtype.NamedType('prime2', pyasn1.type.univ.Integer()),
    pyasn1.type.namedtype.NamedType('exponent1', pyasn1.type.univ.Integer()),
    pyasn1.type.namedtype.NamedType('exponent2', pyasn1.type.univ.Integer()),
    pyasn1.type.namedtype.NamedType('coefficient', pyasn1.type.univ.Integer())
  )

def gcd(a, b):
  while 0 != a:
    a, b = b % a, a
  return b

def modinverse(a, m):
  v1, v2, v3, u1, u2, u3 = 0, 1, m, 1, 0, a
  while 0 != v3:
    q = u3 // v3
    v1, v2, v3, u1, u2, u3 = (u1 - q * v1), (u2 - q * v2), (u3 - q * v3), v1, v2, v3
  return u1 if 0 == m else u1 % m

def RSAencrypt(pub, plain):
  return Cryptodome.Cipher.PKCS1_v1_5.new(pub, stream).encrypt(plain)

def RSAdecrypt(rsa, encrypt):
  return Cryptodome.Cipher.PKCS1_v1_5.new(rsa).decrypt(encrypt, 0)

plain = b'0' * 245

stream.i = 0
rsa = RSA.generate(2048, stream)
print(rsa.e == rsa.publickey().e)
print(rsa.n == rsa.publickey().n)
print(0x10001 == rsa.e)
print(rsa.n == rsa.p * rsa.q)
print(1 == rsa.d * rsa.e % ((rsa.p - 1) * (rsa.q - 1) // gcd(rsa.p - 1, rsa.q - 1)))
print(1 == rsa.u * rsa.p % rsa.q)
print(rsa.d == modinverse(rsa.e, (rsa.p - 1) * (rsa.q - 1) // gcd(rsa.p - 1, rsa.q - 1)))
print(rsa.u == modinverse(rsa.p, rsa.q))
print(rsa == RSA.importKey(rsa.exportKey()))
print(rsa.publickey() == RSA.importKey(rsa.publickey().exportKey()))
encrypt = RSAencrypt(rsa.publickey(), plain)
print(plain == RSAdecrypt(rsa, encrypt))
print(powermod(int.from_bytes(encrypt, 'big'), rsa.d, rsa.n).to_bytes(256, 'big').hex())

asn1rsa = asn1RSAprivate()
asn1rsa['version'] = version = 0
asn1rsa['modulus'] = modulus = rsa.p * rsa.q
asn1rsa['publicExponent'] = publicExponent = rsa.e
asn1rsa['privateExponent'] = privateExponent = modinverse(rsa.e, (rsa.p - 1) * (rsa.q - 1) // gcd(rsa.p - 1, rsa.q - 1))
asn1rsa['prime1'] = prime1 = rsa.p
asn1rsa['prime2'] = prime2 = rsa.q
asn1rsa['exponent1'] = exponent1 = asn1rsa['privateExponent'] % (rsa.p - 1)
asn1rsa['exponent2'] = exponent2 = asn1rsa['privateExponent'] % (rsa.q - 1)
asn1rsa['coefficient'] = coefficient = modinverse(rsa.p, rsa.q)
der = pyasn1.codec.der.encoder.encode(asn1rsa)
rsader = RSA.importKey(pyasn1.codec.der.encoder.encode(asn1rsa))
print(rsader == rsa)
print(rsader.n == rsa.n)
print(rsader.e == rsa.e)
print(rsader.d == rsa.d)
print(rsader.p == rsa.p)
print(rsader.q == rsa.q)
print(rsader.u == rsa.u)
print(rsader.publickey() == rsa.publickey())
dersa = pyasn1.codec.ber.decoder.decode(der, asn1Spec=asn1RSAprivate())[0]
print(asn1rsa == dersa)
print(version == int(dersa['version']))
print(modulus == int(dersa['modulus']))
print(publicExponent == int(dersa['publicExponent']))
print(privateExponent == int(dersa['privateExponent']))
print(prime1 == int(dersa['prime1']))
print(prime2 == int(dersa['prime2']))
print(exponent1 == int(dersa['exponent1']))
print(exponent2 == int(dersa['exponent2']))
print(coefficient == int(dersa['coefficient']))


pkey = OpenSSL.crypto.PKey()
pkey.generate_key(OpenSSL.crypto.TYPE_RSA, 2048)
print(RSA.importKey(OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_ASN1, pkey)) == RSA.importKey(OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, pkey)))
print(RSA.importKey(OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_ASN1, pkey)).publickey() == RSA.importKey(OpenSSL.crypto.dump_publickey(OpenSSL.crypto.FILETYPE_ASN1, pkey)))
print(RSA.importKey(OpenSSL.crypto.dump_publickey(OpenSSL.crypto.FILETYPE_ASN1, pkey)) == RSA.importKey(OpenSSL.crypto.dump_publickey(OpenSSL.crypto.FILETYPE_PEM, pkey)))
asn1rsa = pyasn1.codec.ber.decoder.decode(OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_ASN1, pkey), asn1Spec=asn1RSAprivate())[0]
print(0 == int(asn1rsa['version']))
print(0x10001 == int(asn1rsa['publicExponent']))
prime1 = int(asn1rsa['prime1'])
prime2 = int(asn1rsa['prime2'])
gcd(prime1 - 1, prime2 - 1)
print(prime1 * prime2 == int(asn1rsa['modulus']))
print(modinverse(prime2, prime1) == int(asn1rsa['coefficient']))
print(int(asn1rsa['privateExponent']) == modinverse(int(asn1rsa['publicExponent']), (prime1 - 1) * (prime2 - 1)))
print(asn1rsa['exponent1'] == int(asn1rsa['privateExponent']) % (prime1 - 1))
print(asn1rsa['exponent2'] == int(asn1rsa['privateExponent']) % (prime2 - 1))
rsa = RSA.importKey(OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_ASN1, pkey))
encrypt = RSAencrypt(rsa.publickey(), plain)
print(plain == RSAdecrypt(rsa, encrypt))
