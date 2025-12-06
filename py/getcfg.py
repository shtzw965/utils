#!/bin/python3
def resolve(src):
  import requests, base64, json, re
  from urllib.parse import unquote
  session = requests.Session()
  session.headers['User-Agent'] = 'curl'
  resp = session.get(src)
  assert resp.status_code == 200
  v2ray, hysteria, trojan = {'inbounds': [], 'outbounds': [], 'routing': {'domainStrategy': 'IPOnDemand', 'rules': []}}, [], []
  v2ray['inbounds'].append({'listen': '127.0.0.1', 'port': 9080, 'protocol': 'socks', 'settings': {'udp': False}, 'streamSettings': {'sockopt': {'bindToDevice': 'lo'}}})
  v2ray['inbounds'].append({'listen': '127.0.0.1', 'port': 8080, 'protocol': 'http', 'streamSettings': {'sockopt': {'bindToDevice': 'lo'}}})
  for url in base64.decodebytes(resp.content).splitlines():
    url = url.decode('utf-8')
    if url.startswith('vmess://'):
      jobj = json.loads(base64.b64decode(url[len('vmess://'):]))
      #print('vmess', jobj)
      user = {'id': jobj['id']}
      aid = int(jobj.get('aid'))
      if aid is not None:
        user['alterId'] = aid
      scy = jobj.get('scy')
      if scy is not None:
        user['security'] = scy
      streamSetting = {}
      streamSetting['network'] = jobj['net']
      if jobj.get('tls') == 'tls':
        streamSetting['security'] = 'tls'
        sni = jobj.get('sni')
        tlsSetting = {}
        tlsSetting['allowInsecure'] = True
        tlsSetting['allowInsecureCiphers'] = True
        if sni is not None:
          tlsSetting['serverName'] = sni
        if len(tlsSetting) > 0:
          streamSetting['tlsSettings'] = tlsSetting
      if 'ws' == jobj['net']:
        wsSetting = {}
        path = jobj.get('path')
        if path is not None:
          wsSetting['path'] = path
        #add = jobj.get('add')
        #if add is not None:
        #  wsSetting['headers'] = {'Host': add}
        if len(wsSetting) > 0:
          streamSetting['wsSettings'] = wsSetting
      outbound = {'name': jobj['ps'], 'protocol': 'vmess', 'settings': {'vnext': [{'address': jobj['host'], 'port': int(jobj['port']), 'users': [user]}]}, 'streamSettings': streamSetting}
      v2ray['outbounds'].append(outbound)
    elif url.startswith('ss://'):
      match = re.match(r'ss://(?P<method>[^@]+)@(?P<host>[^:#]+)(:(?P<port>[\d]+))?(#(?P<name>.*))?', url)
      method, host, port, name = match.group('method'), match.group('host'), int(match.group('port')), unquote(match.group('name'))
      method, password = base64.b64decode(method).decode('utf-8').split(':', 1)
      #print('ss', method, password, host, port, name)
      v2ray['outbounds'].append({'name': name, 'protocol': 'shadowsocks', 'settings': {'servers': [{'address': host, 'port': port, 'method': method, 'password': password}]}})
    elif url.startswith('trojan://'):
      match = re.match(r'trojan://(?P<password>[^@]+)@(?P<host>[^:?#]+)(:(?P<port>[\d]+))?(\?(?P<args>[^#]+))?(#(?P<name>.*))?', url)
      password, host, port, args, name = match.group('password'), match.group('host'), int(match.group('port')), {i.split('=', 1)[0]: i.split('=', 1)[1] for i in match.group('args').split('&')}, unquote(match.group('name'))
      allowInsecure = args.get('allowInsecure')
      if allowInsecure is not None:
        allowInsecure = int(allowInsecure)
        args['allowInsecure'] = allowInsecure
      #print('trojan', password, host, port, args, name)
      if args.get('type') is not None:
        assert 'tcp' == args['type']
        argtype = args['type']
      else:
        argtype = 'tcp'
      if argtype == 'tcp':
        security = 'tls'
      tlsSetting = {}
      server = {'name': name, 'run_type': 'client', 'local_addr': '127.0.0.1', 'local_port': 9080, 'remote_addr': host, 'remote_port': port, 'password': [password]}
      if security == 'tls':
        peer, sni = args.get('peer'), args.get('sni')
        if peer is None:
          peer = sni
        elif sni is None:
          pass
        else:
          assert peer == sni
        ssl = {}
        if peer is not None:
          tlsSetting['serverName'] = peer
          ssl['sni'] = peer
        if allowInsecure == 0:
          tlsSetting['allowInsecure'] = False
          tlsSetting['allowInsecureCiphers'] = False
          ssl['verify'] = True
          ssl['verify_hostname'] = True
        if len(ssl) > 0:
          server['ssl'] = ssl
      v2ray['outbounds'].append({'name': name, 'protocol': 'trojan', 'settings': {'servers': [{'address': host, 'port': port, 'password': password}]}, 'streamSettings': {'network': argtype, 'security': security, 'tlsSettings': tlsSetting}})
      trojan.append(server)
    elif url.startswith('hysteria2://'):
      match = re.match(r'hysteria2://(?P<auth>[^@]+)@(?P<host>[^:?#]+)(:(?P<port>[\d]+))?/(\?(?P<args>[^#]+))?(#(?P<name>.*))?', url)
      auth, host, port, args, name = match.group('auth'), match.group('host'), int(match.group('port')), {i.split('=', 1)[0]: i.split('=', 1)[1] for i in match.group('args').split('&')}, unquote(match.group('name'))
      insecure = args.get('insecure')
      if insecure is not None:
        insecure = int(insecure)
        args['insecure'] = insecure
      #print('hysteria2', auth, host, port, args, name)
      mport = args.get('mport')
      server = {'server': ':'.join([host, port if mport is None else mport]), 'auth': auth}
      sni, obfs = args.get('sni'), args.get('obfs')
      if sni is not None:
        server['tls'] = {'sni': sni}
        if insecure is not None:
          if insecure == 0:
            server['tls']['insecure'] = False
          else:
            server['tls']['insecure'] = True
      if obfs is not None:
        server['obfs'] = {'type': obfs}
        if args.get('obfs-password') is not None:
          server['obfs'][obfs] = {'password': args['obfs-password']}
      server['socks5'] = {'listen': '127.0.0.1:9080'}
      server['http'] = {'listen': '127.0.0.1:8080'}
      hysteria.append(server)
    else:
      print('unsupported:', url)
  return v2ray, trojan, hysteria

import sys, json, yaml
v2ray, trojan, hysteria = resolve(sys.argv[1])
for server in hysteria:
  print(yaml.dump(server, sort_keys=False))
for server in trojan:
  print(json.dumps(server, indent=2, ensure_ascii=False))
print(json.dumps(v2ray, indent=2, ensure_ascii=False))
