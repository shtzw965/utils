#!/usr/bin/env python3

class rbtree:
  class rbnode:
    RBNUL = 0
    RBLFT = 1 << 0
    RBRGT = 1 << 1
    RBPST = RBLFT | RBRGT
    RBRED = 1 << 2
    RBBLK = 1 << 3
    RBCLR = RBRED | RBBLK
    RBXXP = 1 << 2
    RBXPX = 1 << 3
    RBPXX = 1 << 4
    RBLRP = RBLFT | RBXXP
    RBLPR = RBLFT | RBXPX
    RBPLR = RBLFT | RBPXX
    RBRLP = RBRGT | RBXXP
    RBRPL = RBRGT | RBXPX
    RBPRL = RBRGT | RBPXX
    RBSML = RBLPR
    RBBIG = RBRPL
    def __init__(self, key = None):
      self.key = key
      self.value = None
      self.flag = 0
      self.ptrs = [None, None, None]
      self.prev, self.next = None, None
    @property
    def prnt(self):
      return self.ptrs[self.RBNUL]
    @prnt.setter
    def prnt(self, v):
      self.ptrs[self.RBNUL] = v
    @property
    def left(self):
      return self.ptrs[self.RBLFT]
    @left.setter
    def left(self, v):
      self.ptrs[self.RBLFT] = v
    @property
    def rght(self):
      return self.ptrs[self.RBRGT]
    @rght.setter
    def rght(self, v):
      self.ptrs[self.RBRGT] = v
  def __init__(self, comp = None):
    self.comp = (lambda x, y: 0 if x == y else x > y) if None == comp else comp
    self.root, self.head, self.node = None, None, None
  def rotate(self, node):
    prnt = node.prnt
    flag = prnt.flag
    node.prnt = prnt.prnt
    prnt.prnt = node
    pstn = node.flag & rbtree.rbnode.RBPST
    prnt.ptrs[pstn] = node.ptrs[rbtree.rbnode.RBPST - pstn]
    node.ptrs[rbtree.rbnode.RBPST - pstn] = prnt
    if not None == prnt.ptrs[pstn]:
      prnt.ptrs[pstn].prnt = prnt
      prnt.ptrs[pstn].flag = prnt.ptrs[pstn].flag & rbtree.rbnode.RBCLR | pstn
    prnt.flag = prnt.flag & rbtree.rbnode.RBCLR | (rbtree.rbnode.RBPST - pstn)
    if None == node.prnt and prnt == self.root:
      self.root = node
      node.flag = rbtree.rbnode.RBBLK
    elif None == node.prnt or prnt == self.root:
      raise
    else:
      pstn = flag & rbtree.rbnode.RBPST
      node.prnt.ptrs[pstn] = node
      node.flag = node.flag & rbtree.rbnode.RBCLR | pstn
  def insert(self, node, prnt, pstn):
    if not None == self.node:
      raise
    pstn = pstn & rbtree.rbnode.RBPST
    if None == prnt and None == self.root:
      node.next = node.prev = node
      node.prnt, node.left, node.rght = None, None, None
      node.flag = rbtree.rbnode.RBBLK
      self.head = self.root = node
      return node
    elif None == prnt or None == self.root or rbtree.rbnode.RBNUL == pstn or not None == prnt.ptrs[pstn]:
      raise
    node.prev = self.head.prev
    node.next = self.head
    node.prev.next = node
    self.head.prev = node
    prnt.ptrs[pstn] = node
    node.flag = rbtree.rbnode.RBRED | pstn
    node.prnt = prnt
    node.rght, node.left = None, None
    rtrn = node
    while not None == prnt:
      if prnt.flag & rbtree.rbnode.RBRED and not None == prnt.prnt:
        gpoc = prnt.prnt.ptrs[rbtree.rbnode.RBPST - (prnt.flag & rbtree.rbnode.RBPST)]
        if not None == gpoc and gpoc.flag & rbtree.rbnode.RBRED:
          prnt.flag = prnt.flag & rbtree.rbnode.RBPST | rbtree.rbnode.RBBLK
          gpoc.flag = gpoc.flag & rbtree.rbnode.RBPST | rbtree.rbnode.RBBLK
          node = prnt.prnt
          prnt = node.prnt
          node.flag = node.flag & rbtree.rbnode.RBPST | rbtree.rbnode.RBRED
        else:
          prnt.prnt.flag = prnt.prnt.flag & rbtree.rbnode.RBPST | rbtree.rbnode.RBRED
          if (node.flag & rbtree.rbnode.RBPST) == (prnt.flag & rbtree.rbnode.RBPST):
            prnt.flag = prnt.flag & rbtree.rbnode.RBPST | rbtree.rbnode.RBBLK
            self.rotate(prnt)
          else:
            node.flag = node.flag & rbtree.rbnode.RBPST | rbtree.rbnode.RBBLK
            self.rotate(node)
            self.rotate(node)
          break
      elif prnt.flag & rbtree.rbnode.RBBLK:
        break
      else:
        raise
    self.root.flag = self.root.flag & rbtree.rbnode.RBPST | rbtree.rbnode.RBBLK
    return rtrn
  def remove(self, node):
    if not None == self.node:
      raise
    if node == self.root and None == node.prnt and None == node.left and None == node.rght:
      self.root, self.head, node.prnt, node.left, node.rght, node.next, node.prev = None, None, None, None, None, None, None
      return node
    elif None == node.prnt and None == node.left and None == node.rght:
      raise
    elif node == self.head:
      self.head = node.next
    node.next.prev = node.prev
    node.prev.next = node.next
    node.prev, node.next = None, None
    if not None == node.left and not None == node.rght:
      move = node.rght
      if None == move.left:
        move.prnt = node.prnt
        move.left = node.left
        node.rght = move.rght
        node.prnt = move
        move.rght = node
      else:
        rght = move
        while not None == move.left:
          move = move.left
        prnt = move.prnt
        move.prnt = node.prnt
        move.left = node.left
        node.rght = move.rght
        node.prnt = prnt
        rght.prnt = move
        prnt.left = node
        move.rght = rght
      flag = node.flag
      node.flag = move.flag
      move.flag = flag
      node.left = None
      move.left.prnt = move
      if not None == node.rght:
        node.rght.prnt = node
      if None == move.prnt and node == self.root:
        self.root = move
      elif None == move.prnt or node == self.root:
        raise
      else:
        move.prnt.ptrs[move.flag & rbtree.rbnode.RBPST] = move
    if node.flag & rbtree.rbnode.RBRED:
      node.prnt.ptrs[node.flag & rbtree.rbnode.RBPST], node.prnt, node.left, node.rght = None, None, None, None
    elif None == node.left and None == node.rght:
      prnt = node.prnt
      flag = node.flag
      prnt.ptrs[flag & rbtree.rbnode.RBPST], node.prnt, node.left, node.rght = None, None, None, None
      while not None == prnt:
        if None == prnt.ptrs[rbtree.rbnode.RBPST - (flag & rbtree.rbnode.RBPST)]:
          raise
        brth = prnt.ptrs[rbtree.rbnode.RBPST - (flag & rbtree.rbnode.RBPST)]
        dfnp = brth.ptrs[rbtree.rbnode.RBPST - (flag & rbtree.rbnode.RBPST)]
        smnp = brth.ptrs[flag & rbtree.rbnode.RBPST]
        if not None == smnp:
          dgnp = smnp.ptrs[rbtree.rbnode.RBPST - (flag & rbtree.rbnode.RBPST)]
          sgnp = smnp.ptrs[flag & rbtree.rbnode.RBPST]
        if brth.flag & rbtree.rbnode.RBRED and None == smnp:
          raise
        elif brth.flag & rbtree.rbnode.RBRED and not None == dgnp and dgnp.flag & rbtree.rbnode.RBRED:
          dgnp.flag = dgnp.flag & rbtree.rbnode.RBPST | rbtree.rbnode.RBBLK
          self.rotate(smnp)
          self.rotate(smnp)
          return node
        elif brth.flag & rbtree.rbnode.RBRED and not None == sgnp and sgnp.flag & rbtree.rbnode.RBRED:
          sgnp.flag = sgnp.flag & rbtree.rbnode.RBPST | rbtree.rbnode.RBBLK
          self.rotate(sgnp)
          self.rotate(sgnp)
          self.rotate(sgnp)
          return node
        elif brth.flag & rbtree.rbnode.RBRED:
          brth.flag = brth.flag & rbtree.rbnode.RBPST | rbtree.rbnode.RBBLK
          smnp.flag = smnp.flag & rbtree.rbnode.RBPST | rbtree.rbnode.RBRED
          self.rotate(brth)
          return node
        elif prnt.flag & rbtree.rbnode.RBBLK and (None == dfnp or dfnp.flag & rbtree.rbnode.RBBLK) and (None == smnp or smnp.flag & rbtree.rbnode.RBBLK):
          prnt.flag = prnt.flag & rbtree.rbnode.RBPST | rbtree.rbnode.RBRED
          self.rotate(brth)
          prnt = brth.prnt
          flag = brth.flag
        elif not None == dfnp and dfnp.flag & rbtree.rbnode.RBRED:
          brth.flag = brth.flag & rbtree.rbnode.RBPST | (prnt.flag & rbtree.rbnode.RBCLR)
          prnt.flag = prnt.flag & rbtree.rbnode.RBPST | rbtree.rbnode.RBBLK
          dfnp.flag = dfnp.flag & rbtree.rbnode.RBPST | rbtree.rbnode.RBBLK
          self.rotate(brth)
          return node
        elif not None == smnp and smnp.flag & rbtree.rbnode.RBRED:
          smnp.flag = smnp.flag & rbtree.rbnode.RBPST | (prnt.flag & rbtree.rbnode.RBCLR)
          prnt.flag = prnt.flag & rbtree.rbnode.RBPST | rbtree.rbnode.RBBLK
          self.rotate(smnp)
          self.rotate(smnp)
          return node
        else:
          prnt.flag = prnt.flag & rbtree.rbnode.RBPST | rbtree.rbnode.RBBLK
          brth.flag = brth.flag & rbtree.rbnode.RBPST | rbtree.rbnode.RBRED
          return node
    else:
      chld = node.rght if None == node.left else node.left
      chld.prnt = node.prnt
      chld.flag = node.flag
      if None == node.prnt and node == self.root:
        self.root = chld
      elif None == node.prnt or node == self.root:
        raise
      else:
        node.prnt.ptrs[node.flag & rbtree.rbnode.RBPST] = chld
      node.prnt, node.left, node.rght = None, None, None
    return node
  def touch(self, func, order = rbnode.RBLPR):
    node = self.root
    stack = []
    similar = rbtree.rbnode.RBPST & order
    if rbtree.rbnode.RBPST == similar or rbtree.rbnode.RBNUL == similar:
      raise
    oppsite = rbtree.rbnode.RBPST - similar
    if order & rbtree.rbnode.RBXXP:
      prev = None
      while not None == node or len(stack) > 0:
        while not None == node:
          stack.append(node)
          node = node.ptrs[similar]
        node = stack[-1]
        if None == node.ptrs[oppsite] or prev == node.ptrs[oppsite]:
          func(node)
          prev = node
          stack.pop()
          node = None
        else:
          node = node.ptrs[oppsite]
    elif order & rbtree.rbnode.RBPXX:
      while True:
        if None == node:
          if 0 == len(stack):
            break
          else:
            node = stack.pop().ptrs[oppsite]
        else:
          func(node)
          stack.append(node)
          node = node.ptrs[similar]
    elif order & rbtree.rbnode.RBXPX:
      while True:
        if None == node:
          if 0 == len(stack):
            break
          else:
            node = stack.pop()
            func(node)
            node = node.ptrs[oppsite]
        else:
          stack.append(node)
          node = node.ptrs[similar]
    else:
      raise
  def search(self, key):
    node = self.root
    if None == node:
      return None, rbtree.rbnode.RBNUL
    else:
      while True:
        i = self.comp(key, node.key)
        if True == i or i > 0:
          if None == node.rght:
            return node, rbtree.rbnode.RBRGT
          node = node.rght
        elif False == i or i < 0:
          if None == node.left:
            return node, rbtree.rbnode.RBLFT
          node = node.left
        else:
          return node, rbtree.rbnode.RBNUL
  def get(self, key):
    node, pstn = self.search(key)
    return node
  def add(self, key, overwite = True):
    node, pstn = self.search(key)
    if not None == node and rbtree.rbnode.RBNUL == pstn:
      if overwite:
        node.key = key
        return node
      else:
        raise
    else:
      return self.insert(rbtree.rbnode(key), node, pstn)
  def pop(self, key):
    node, pstn = self.search(key)
    if not None == node:
      self.remove(node)
    else:
      raise KeyError
    return node
  def getprev(self, node):
    if None == node or None == self.head:
      raise
    if self.head == node:
      return None
    return node.prev
  def getnext(self, node):
    if None == node or None == self.head:
      raise
    if self.tail == node:
      return None
    return node.next
  def getleft(self, node):
    if None == node or None == self.root:
      raise
    if None == node.left:
      while node.flag & rbtree.rbnode.RBLFT:
        node = node.prnt
      return node.prnt
    else:
      node = node.left
      while not None == node.rght:
        node = node.rght
      return node
  def getrght(self, node):
    if None == node or None == self.root:
      raise
    if None == node.rght:
      while node.flag & rbtree.rbnode.RBRGT:
        node = node.prnt
      return node.prnt
    else:
      node = node.rght
      while not None == node.left:
        node = node.left
      return node
  @property
  def tail(self):
    if None == self.head:
      return None
    return self.head.prev
  @property
  def left(self):
    node = self.root
    if None == node:
      return None
    while not None == node.left:
      node = node.left
    return node
  @property
  def rght(self):
    node = self.root
    if None == node:
      return None
    while not None == node.rght:
      node = node.rght
    return node
  @property
  def depth(self):
    node = self.root
    if None == node:
      return 0
    elif not None == node.prnt or node.flag & rbtree.rbnode.RBRED:
      return -1
    depthleft = [0]
    depthrght = 0
    stack = []
    prev = None
    stack.append(None)
    while not None == node.left:
      stack.append(node)
      node = node.left
    while len(stack) > 0:
      if not None == node.rght and not prev == node.rght:
        stack.append(node)
        node = node.rght
        while not None == node.left:
          stack.append(node)
          node = node.left
        depthleft.append(0)
        continue
      elif None == node.rght:
        depthrght = 0
      if not depthrght == depthleft.pop():
        return -1
      if node.flag & rbtree.rbnode.RBBLK:
        depthrght += 1
      elif node.prnt.flag & rbtree.rbnode.RBRED:
        return -1
      if node.flag & rbtree.rbnode.RBLFT:
        depthleft.append(depthrght)
      prev = node
      node = stack.pop()
    return depthrght
  def __iter__(self):
    self.node = None
    return self
  def __next__(self):
    if None == self.node:
      if None == self.head:
        raise StopIteration
      self.node = self.head
    else:
      self.node = self.node.next
      if self.head == self.node:
        self.node = None
        raise StopIteration
    return self.node
  def clear(self):
    while not None == self.root:
      self.remove(self.root)
  def __del__(self):
    self.clear()









import random
data = list(range(1024000))
random.shuffle(data)

rb = rbtree()

for i in data:
  n = rb.add(i)

def prnode(node):
  print(node.key, ' ', node.flag)

rb.touch(prnode)
print('depth', rb.depth)

for i in rb:
  print(i.key)

l = rb.left
r = rb.rght
n = l
while True:
  print(n.key)
  if n == r:
    break
  n = rb.getrght(n)

n = r
while True:
  print(n.key)
  if n == l:
    break
  n = rb.getleft(n)

