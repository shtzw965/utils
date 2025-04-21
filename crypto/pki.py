#!/bin/python3
import os
from cryptography import x509

class pkibox:
  flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_EXCL
  @classmethod
  def rsa(cls, bits = 3072):
    self = cls()
    self.key = x509.base.rsa.generate_private_key(65537, bits)
    self.pub = self.key.public_key()
    self.algorithm = x509.base.hashes.SHA256
    return self
  @classmethod
  def dsa(cls, bits = 3072):
    self = cls()
    self.key = x509.base.dsa.generate_private_key(bits)
    self.pub = self.key.public_key()
    self.algorithm = x509.base.hashes.SHA256
    return self
  @classmethod
  def ec(cls, curve = 'secp256r1'):
    self = cls()
    if isinstance(curve, str):
      curve = x509.base.ec._CURVE_TYPES[curve]
    elif not issubclass(curve, x509.base.ec.EllipticCurve):
      raise
    self.key = x509.base.ec.generate_private_key(curve)
    self.pub = self.key.public_key()
    self.algorithm = x509.base.hashes.SHA256
    return self
  @classmethod
  def ed25519(cls):
    self = cls()
    self.key = x509.base.ed25519.Ed25519PrivateKey.generate()
    self.pub = self.key.public_key()
    self.algorithm = lambda: None
    return self
  @classmethod
  def ed448(cls):
    self = cls()
    self.key = x509.base.ed448.Ed448PrivateKey.generate()
    self.pub = self.key.public_key()
    self.algorithm = lambda: None
    return self
  @classmethod
  def ed(cls, i = 25519):
    if 448 == i:
      return cls.ed448()
    elif 25519 == i:
      return cls.ed25519()
    else:
      raise
  @classmethod
  def private(cls, alg = 'rsa', param = None):
    assert alg in ['rsa', 'dsa', 'ec', 'ed25519', 'ed448', 'ed']
    method = getattr(cls, alg)
    if param is None:
      return method()
    else:
      return method(param)
  def generate(self, subject, exts):
    self.csr = x509.CertificateSigningRequestBuilder(
      subject_name = x509.Name(subject),
      extensions = exts
    ).sign(self.key, self.algorithm())
    return self
  def create(self, cn = None, ca = False, server = False, client = False):
    if cn is None:
      subject = []
    else:
      subject = [x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, cn)]
    exts = [
      x509.Extension(x509.BasicConstraints.oid, True, x509.BasicConstraints(ca, None)),
      x509.Extension(x509.KeyUsage.oid, False, x509.KeyUsage(
        digital_signature = server or client,
        content_commitment = False,
        key_encipherment = server or client,
        data_encipherment = False,
        key_agreement = False,
        key_cert_sign = ca,
        crl_sign = ca,
        encipher_only = False,
        decipher_only = False
      ))
    ]
    usage = []
    if server:
      usage.append(x509.oid.ExtendedKeyUsageOID.SERVER_AUTH)
    if client:
      usage.append(x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH)
    if len(usage) > 0:
      exts.append(x509.Extension(x509.ExtendedKeyUsage.oid, False, x509.ExtendedKeyUsage(usage)))
    self.generate(subject, exts)
    if ca:
      self.serials = []
      self.sign(self.csr)
      self.revokes = []
      self.crl = self.gencrl()
    return self
  def genca(self, cn = None):
    return self.create(cn = cn, ca = True)
  def genserver(self, cn = None):
    return self.create(cn = cn, server = True)
  def genclient(self, cn = None):
    return self.create(cn = cn, client = True)
  @property
  def pub(self):
    return self._pub
  @pub.setter
  def pub(self, pub):
    self._pub = pub
    self.digest = x509.SubjectKeyIdentifier.from_public_key(pub).digest
    self.hex = self.digest.hex().upper()
  @property
  def crt(self):
    return self._crt
  @crt.setter
  def crt(self, crt):
    if hasattr(self, '_pub'):
      assert crt.public_key() == self._pub
    else:
      self.pub = crt.public_key()
    for ext in crt.extensions:
      if ext.oid == x509.OID_SUBJECT_KEY_IDENTIFIER:
        assert ext.value.digest == self.digest
      elif ext.oid == x509.OID_AUTHORITY_KEY_IDENTIFIER:
        if ext.value.key_identifier == self.digest:
          crt.verify_directly_issued_by(crt)
    self._crt = crt
    self.serial = crt.serial_number
    self.finger = crt.fingerprint(x509.base.hashes.SHA256()).hex().upper()
    return self._crt
  def verifycrt(self, crt):
    try:
      crt.verify_directly_issued_by(self._crt)
    except:
      return False
    else:
      return True
  def verifycsr(self, csr = None):
    if csr is None:
      csr = self.csr
    if hasattr(self, '_pub'):
      assert csr.public_key() == self._pub
    try:
      assert csr.is_signature_valid
    except:
      return False
    else:
      return True
  def verifycrl(self, crl):
    try:
      crl.is_signature_valid(self._pub)
    except:
      return False
    else:
      return True
  def verify(self, obj):
    if isinstance(obj, x509.Certificate):
      return self.verifycrt(obj)
    elif isinstance(obj, x509.CertificateSigningRequest):
      return self.verifycsr(obj)
    elif isinstance(obj, x509.CertificateRevocationList):
      return self.verifycrl(obj)
    else:
      raise TypeError('Unsupported object type: {type(obj)}')
  def sign(self, csr):
    assert csr.is_signature_valid
    now = x509.base.datetime.datetime.now(x509.base.datetime.UTC)
    pub = csr.public_key()
    keyid = x509.SubjectKeyIdentifier.from_public_key(pub)
    issuerid = x509.AuthorityKeyIdentifier.from_issuer_public_key(self._pub)
    serial = int(keyid.digest.hex(), 16)
    subject = csr.subject
    if hasattr(self, '_crt'):
      issuer = self._crt.subject
    elif self._pub == pub:
      issuer = subject
    else:
      raise
    exts = []
    for ext in csr.extensions:
      if ext.oid not in [keyid.oid, issuerid.oid]:
        exts.append(ext)
    exts.extend([
      x509.Extension(keyid.oid, False, keyid),
      x509.Extension(issuerid.oid, False, issuerid)
    ])
    crt = x509.CertificateBuilder(
      issuer_name = issuer,
      subject_name = subject,
      public_key = pub,
      serial_number = serial,
      not_valid_before = now,
      not_valid_after = now + x509.base.datetime.timedelta(days = 5 * 365),
      extensions = exts
    ).sign(self.key, self.algorithm())
    if issuer is subject:
      self.crt = crt
    assert self.verifycrt(crt)
    self.serials.append(x509.RevokedCertificateBuilder(
      serial_number = serial,
      revocation_date = now
    ).build())
    self.lst = self.gencrl(self.serials)
    return crt
  def gencrl(self, revokes = None):
    if revokes is None:
      revokes = self.revokes
    now = x509.base.datetime.datetime.now(x509.base.datetime.UTC)
    crl = x509.CertificateRevocationListBuilder(
      issuer_name = self._crt.subject,
      last_update = now,
      next_update = now + x509.base.datetime.timedelta(days=30),
      extensions = [
        x509.Extension(x509.CRLNumber.oid, False, x509.CRLNumber(len(revokes))),
        x509.Extension(
          x509.AuthorityKeyIdentifier.oid,
          False,
          x509.AuthorityKeyIdentifier.from_issuer_public_key(self._pub)
        )
      ],
      revoked_certificates = revokes
    ).sign(self.key, self.algorithm())
    assert self.verifycrl(crl)
    return crl
  def revoke(self, serial):
    if not isinstance(serial, int):
      serial = int(serial, 16)
    self.revokes.append(x509.RevokedCertificateBuilder(
      serial_number = serial,
      revocation_date = x509.base.datetime.datetime.now(x509.base.datetime.UTC)
    ).build())
    self.crl = self.gencrl()
    return self.crl
  def dump(self, name):
    if 'crt' == name:
      name = '_crt'
    if 'key' == name:
      return self.key.private_bytes(
        x509.base.serialization.Encoding.PEM,
        x509.base.serialization.PrivateFormat.PKCS8,
        x509.base.serialization.NoEncryption()
      )
    elif 'pub' == name:
      return self._pub.public_bytes(
        x509.base.serialization.Encoding.PEM,
        x509.base.serialization.PublicFormat.SubjectPublicKeyInfo
      )
    elif name in ['csr', '_crt', 'crl', 'lst']:
      return getattr(self, name).public_bytes(x509.base.serialization.Encoding.PEM)
    else:
      raise
  def pathdump(self, path):
    fd = os.open(path + '/pub.pem', self.flags, 0o0644)
    os.write(fd, self.dump('pub'))
    os.close(fd)
    if hasattr(self, 'key'):
      fd = os.open(path + '/key.pem', self.flags, 0o0600)
      os.write(fd, self.dump('key'))
      os.close(fd)
    if hasattr(self, '_crt'):
      fd = os.open(path + '/crt.pem', self.flags, 0o0644)
      os.write(fd, self.dump('crt'))
      os.close(fd)
    for i in ['csr', 'crl', 'lst']:
      if hasattr(self, i):
        fd = os.open(path + '/' + i + '.pem', self.flags, 0o0644)
        os.write(fd, self.dump(i))
        os.close(fd)
    return self
  def load(self, name, buf):
    if 'pub' == name:
      self.pub = x509.base.serialization.load_pem_public_key(buf)
    elif 'key' == name:
      self.key = x509.base.serialization.load_pem_private_key(buf, None)
      if hasattr(self, '_pub'):
        assert self.key.public_key() == self._pub
      else:
        self.pub = self.key.public_key()
    elif 'crt' == name:
      self.crt = x509.load_pem_x509_certificate(buf)
    elif 'csr' == name:
      self.csr = x509.load_pem_x509_csr(buf)
      assert self.verifycsr(self.csr)
      if hasattr(self, '_pub'):
        assert self.csr.public_key() == self._pub
      else:
        self.pub = self.csr.public_key()
    elif 'crl' == name:
      self.crl = x509.load_pem_x509_crl(buf)
      assert self.verifycrl(self.crl)
      for i in self.crl:
        self.revokes.append(i)
    elif 'lst' == name:
      self.lst = x509.load_pem_x509_crl(buf)
      assert self.verifycrl(self.lst)
      for i in self.lst:
        self.serials.append(i)
    else:
      raise
    return self
  @classmethod
  def pathload(cls, path):
    self = cls()
    for i in ['pub', 'key', 'crt', 'csr']:
      if os.path.lexists(path + '/' + i + '.pem'):
        with open(path + '/' + i + '.pem', 'rb') as fobj:
          buf = fobj.read()
        self.load(i, buf)
    return self
  @classmethod
  def pathloadca(cls, path):
    self = cls.pathload(path)
    assert self.verifycrt(self._crt)
    self.revokes, self.serials = [], []
    if os.path.lexists(path + '/crl.pem'):
      with open(path + '/crl.pem', 'rb') as fobj:
        buf = fobj.read()
      self.load('crl', buf)
    else:
      self.crl = self.gencrl()
    if os.path.lexists(path + '/lst.pem'):
      with open(path + '/lst.pem', 'rb') as fobj:
        buf = fobj.read()
      self.load('lst', buf)
    else:
      self.lst = self.gencrl([])
    return self
  def list(self):
    for i in self.serials:
      print(i.serial_number.to_bytes(20).hex().upper(), i.revocation_date)
    return self
  @property
  def sshkey(self):
    key_type = x509.base.serialization.ssh._get_ssh_key_type(self.key)
    kformat = x509.base.serialization.ssh._lookup_kformat(key_type)
    f_kdfoptions = x509.base.serialization.ssh._FragList()
    ciphername = kdfname = x509.base.serialization.ssh._NONE
    blklen, ciph, nkeys, checkval, comment = 8, None, 1, os.urandom(4), b''
    if hasattr(self, 'comment') and self.comment is not None:
      if isinstance(self.comment, str):
        comment = self.comment.encode()
      elif isinstance(self.comment, bytes):
        comment = self.comment
      else:
        raise
    if hasattr(self, 'checkval') and self.checkval is not None:
      checkval = self.checkval.to_bytes(4, 'big')
    f_public_key = x509.base.serialization.ssh._FragList()
    f_public_key.put_sshstr(key_type)
    kformat.encode_public(self.key.public_key(), f_public_key)
    f_secrets = x509.base.serialization.ssh._FragList([checkval, checkval])
    f_secrets.put_sshstr(key_type)
    kformat.encode_private(self.key, f_secrets)
    f_secrets.put_sshstr(comment)
    f_secrets.put_raw(x509.base.serialization.ssh._PADDING[:blklen - (f_secrets.size() % blklen)])
    f_main = x509.base.serialization.ssh._FragList()
    f_main.put_raw(x509.base.serialization.ssh._SK_MAGIC)
    f_main.put_sshstr(ciphername)
    f_main.put_sshstr(kdfname)
    f_main.put_sshstr(f_kdfoptions)
    f_main.put_u32(nkeys)
    f_main.put_sshstr(f_public_key)
    f_main.put_sshstr(f_secrets)
    slen = f_secrets.size()
    mlen = f_main.size()
    buf = memoryview(bytearray(mlen + blklen))
    f_main.render(buf)
    ofs = mlen - slen
    return x509.base.serialization.ssh._ssh_pem_encode(buf[:mlen])
    return x509.base.serialization.ssh._serialize_ssh_private_key(
      self.key,
      b'',
      x509.base.serialization.NoEncryption()
    )
    return self.key.private_bytes(
      x509.base.serialization.Encoding.PEM,
      x509.base.serialization.PrivateFormat.OpenSSH,
      x509.base.serialization.NoEncryption()
    )
  @property
  def sshmd5(self):
    if not hasattr(self, '_sshmd5'):
      self.sshpub
    return self._sshmd5
  @property
  def sshsha256(self):
    if not hasattr(self, '_sshsha256'):
      self.sshpub
    return self._sshsha256
  @property
  def sshpub(self):
    key_type = x509.base.serialization.ssh._get_ssh_key_type(self._pub)
    kformat = x509.base.serialization.ssh._lookup_kformat(key_type)
    f_pub = x509.base.serialization.ssh._FragList()
    f_pub.put_sshstr(key_type)
    kformat.encode_public(self._pub, f_pub)
    f_pub = f_pub.tobytes()
    self._sshmd5 = ':'.join(['%02x' % i for i in list(x509.extensions.hashlib.md5(f_pub).digest())])
    self._sshsha256 = x509.name.binascii.b2a_base64(
      x509.extensions.hashlib.sha256(f_pub).digest()
    ).strip().decode().rstrip('=')
    pub = x509.name.binascii.b2a_base64(f_pub).strip()
    r = [key_type, pub]
    if hasattr(self, 'comment') and self.comment is not None:
      if isinstance(self.comment, str):
        r.append(self.comment.encode())
      elif isinstance(self.comment, bytes):
        r.append(self.comment)
      else:
        raise
    return b' '.join(r) + b'\n'
    return self._pub.public_bytes(
      x509.base.serialization.Encoding.OpenSSH,
      x509.base.serialization.PublicFormat.OpenSSH
    )
  def load_ssh_private_key(self, data):
    m = x509.base.serialization.ssh._PEM_RC.search(data)
    data = x509.name.binascii.a2b_base64(memoryview(data)[m.start(1):m.end(1)])
    assert data.startswith(x509.base.serialization.ssh._SK_MAGIC)
    data = memoryview(data)[len(x509.base.serialization.ssh._SK_MAGIC):]
    ciphername, data = x509.base.serialization.ssh._get_sshstr(data)
    kdfname, data = x509.base.serialization.ssh._get_sshstr(data)
    kdfoptions, data = x509.base.serialization.ssh._get_sshstr(data)
    nkeys, data = x509.base.serialization.ssh._get_u32(data)
    assert 1 == nkeys
    pubdata, data = x509.base.serialization.ssh._get_sshstr(data)
    pub_key_type, pubdata = x509.base.serialization.ssh._get_sshstr(pubdata)
    kformat = x509.base.serialization.ssh._lookup_kformat(pub_key_type)
    pubfields, pubdata = kformat.get_public(pubdata)
    x509.base.serialization.ssh._check_empty(pubdata)
    assert b'none' == ciphername.tobytes() and b'none' == kdfname.tobytes()
    edata, data = x509.base.serialization.ssh._get_sshstr(data)
    x509.base.serialization.ssh._check_empty(data)
    x509.base.serialization.ssh._check_block_size(edata, 8)
    ck1, edata = x509.base.serialization.ssh._get_u32(edata)
    ck2, edata = x509.base.serialization.ssh._get_u32(edata)
    assert ck1 == ck2
    self.checkval = ck1
    key_type, edata = x509.base.serialization.ssh._get_sshstr(edata)
    assert key_type == pub_key_type
    self.key_type = key_type.tobytes().decode()
    self.key, edata = kformat.load_private(edata, pubfields)
    comment, edata = x509.base.serialization.ssh._get_sshstr(edata)
    assert edata == x509.base.serialization.ssh._PADDING[:len(edata)]
    self.comment = comment.tobytes().decode()
    if hasattr(self, '_pub'):
      assert self.key.public_key() == self._pub
    else:
      self.pub = self.key.public_key()
    return self
  def load_ssh_public_identity(self, data):
    m = x509.base.serialization.ssh._SSH_PUBKEY_RC.match(data)
    self.key_type = m.group(1).decode()
    self.comment = data[m.end():].strip().decode()
    ret = x509.base.serialization.ssh._load_ssh_public_identity(data, True)
    if isinstance(ret, x509.base.serialization.ssh.SSHCertificate):
      self.crt = ret
    else:
      self.pub = ret
    if hasattr(self, 'key'):
      assert self.key.public_key() == self._pub
    return self
  def load_ssh_public_key(self, data):
    return self.load_ssh_public_identity(data)
  @classmethod
  def makepki(cls, path = '', srv = None, cli = None, alg = None, param = None):
    if alg is None:
      alg = ['ed25519', 'ed25519', 'ed25519']
    if isinstance(alg, str):
      algca, algsrv, algcli = alg, alg, alg
    elif isinstance(alg, list):
      assert len(alg) == 3
      algca, algsrv, algcli = alg
    else:
      raise
    if param is None:
      pca, psrv, pcli = None, None, None
    else:
      pca, psrv, pcli = param
    if len(path) == 0:
      path = '.'
    else:
      path = os.path.relpath(path) + '/'
    for i in ['', '/ca', '/server', '/client']:
      os.mkdir(path + '/pki' + i, 0o0755)
    ca = cls.private(algca, pca).genca()
    if srv is None:
      srv = [None] * 4
    elif isinstance(srv, int):
      srv = [None] * srv
    for cn in srv:
      n = cls.private(algsrv, psrv).genserver(cn)
      n.crt = ca.sign(n.csr)
      os.mkdir(path + '/pki/server/' + n.hex, 0o0755)
      n.pathdump(path + '/pki/server/' + n.hex)
      if os.path.lexists(path + '/pki/server/current'):
        os.unlink(path + '/pki/server/current')
      os.symlink(n.hex, path + '/pki/server/current')
      if cn is not None:
        os.symlink(n.hex, path + '/pki/server/' + cn)
    if cli is None:
      cli = [None] * 4
    elif isinstance(cli, int):
      cli = [None] * cli
    for cn in cli:
      n = cls.private(algcli, pcli).genclient(cn)
      n.crt = ca.sign(n.csr)
      os.mkdir(path + '/pki/client/' + n.hex, 0o0755)
      n.pathdump(path + '/pki/client/' + n.hex)
      if os.path.lexists(path + '/pki/client/current'):
        os.unlink(path + '/pki/client/current')
      os.symlink(n.hex, path + '/pki/client/current')
    ca.pathdump(path + '/pki/ca')
  @classmethod
  def test(cls):
    import shutil
    if os.path.lexists('pki'):
      shutil.rmtree('pki')
    cls.makepki(
      srv = ['google.com', 'facebook.com', None, None],
      alg = ['rsa', 'ec', 'dsa'],
      param = [512, 'secp256k1', 1024]
    )
    shutil.rmtree('pki')
    cls.makepki()
    for name, curve in x509.base.ec._CURVE_TYPES.items():
      serverkey = x509.base.ec.generate_private_key(curve())
      serverpub = serverkey.public_key()
      clientkey = x509.base.ec.generate_private_key(curve())
      clientpub = clientkey.public_key()
      assert serverkey.exchange(x509.base.ec.ECDH(), clientpub) == clientkey.exchange(x509.base.ec.ECDH(), serverpub)
    serverkey = x509.base.x25519.X25519PrivateKey.generate()
    serverpub = serverkey.public_key()
    clientkey = x509.base.x25519.X25519PrivateKey.generate()
    clientpub = clientkey.public_key()
    assert serverkey.exchange(clientpub) == clientkey.exchange(serverpub)
    serverkey = x509.base.x448.X448PrivateKey.generate()
    serverpub = serverkey.public_key()
    clientkey = x509.base.x448.X448PrivateKey.generate()
    clientpub = clientkey.public_key()
    assert serverkey.exchange(clientpub) == clientkey.exchange(serverpub)
    # generator 2 or 5
    dhparam = x509.base.dsa.rust_openssl.dh.generate_parameters(generator=2, key_size=512)
    clientkey = dhparam.generate_private_key()
    clientpub = clientkey.public_key()
    serverkey = dhparam.generate_private_key()
    serverpub = serverkey.public_key()
    assert clientkey.exchange(serverpub) == serverkey.exchange(clientpub)
  @classmethod
  def testssh(cls):
    # dsa 1024 only, dsa ssh deprecated
    # ed448 ssh not supported
    notkey, notpub, okcurve = [], [], []
    for name, curve in x509.base.ec._CURVE_TYPES.items():
      n = cls.ec(name)
      try:
        sshkey = n.sshkey
      except:
        notkey.append(name)
      else:
        sshkey.decode()
      try:
        sshpub = n.sshpub
      except:
        notpub.append(name)
      else:
        sshpub.decode()
      if name not in notkey and name not in notpub:
        okcurve.append(name)
    assert notkey == notpub
    okcurve.sort()
    print(okcurve) # prime256v1, secp256r1, secp384r1, secp521r1
    okcurve = [i.name for i in set(x509.base.ec._CURVE_TYPES[i] for i in okcurve)]
    okcurve.sort()
    print(okcurve) # secp256r1, secp384r1, secp521r1
    for i in ['rsa', 'ecdsa', 'ed25519', 'dsa']:
      path = '/etc/ssh/ssh_host_' + i + '_key'
      if not os.path.lexists(path):
        continue
      with open(path, 'rb') as fobj:
        key = cls().load_ssh_private_key(fobj.read())
      with open(path + '.pub', 'rb') as fobj:
        assert key.sshpub ==  fobj.read()
      pub = cls().load_ssh_public_key(key.sshpub)
      assert key.pub == pub.pub
      assert key.comment == pub.comment
      print(path + '.pub', hex(key.checkval), key.comment, key.sshmd5, key.sshsha256, sep = '\n')
      for alg, res in [('md5', key.sshmd5), ('sha256', key.sshsha256)]:
        fdrd, fdwr = os.pipe()
        pid = os.fork()
        if 0 == pid:
          os.close(fdrd)
          os.dup2(fdwr, 1)
          os.dup2(fdwr, 2)
          os.close(fdwr)
          os.execvp('ssh-keygen', ['ssh-keygen', '-l', '-f', path + '.pub', '-E', alg])
          os._exit(-1)
        os.close(fdwr)
        with os.fdopen(fdrd, 'r') as fobj:
          assert res in fobj.read()
        os.waitpid(pid, 0)

if '__main__' == __name__:
    pkibox.makepki()
