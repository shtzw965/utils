## 记录一次linux服务器上面tty资源耗尽问题的定位
使用terminal时都会使用一种资源，叫做tty。本说明应同事需求，介绍一下tty，所有信息已脱敏。

### ssh如何使用的tty
通过ssh的案例说明tty的原理。ssh提供远程登录的功能，就像本地计算机连接了远程系统的命令行。下面通过说明ssh的原理说明tty的原理。为简化理解，下文不严格区分sshd和sshd的子进程。

服务端运行sshd，监听22端口。ssh客户端连接22端口，与sshd进程进行通信。

网络连接步骤完成后，sshd会使用open系统函数打开/dev/ptmx或/dev/pts/ptmx文件，返回一个fd（是一个int类型的数字），记为fd1。打开/dev/下面某个特殊类型的文件是用户态软件使用linux系统io资源的标准架构。

然后sshd对fd1进行配置，主要使用ioctl函数进行配置，ioctl函数是linux下用户态软件配置io资源映射的fd的标准函数。当软件通过fd1向linux传递创建tty的语义后，操作系统会在/dev/pts/下面创建一个新文件。

该文件的文件名是一个数字。整体路径就是/dev/pts/0 到 /dev/pts/999 之类。数字的大小从0开始分配，逐渐递增。

sshd通过fd1获取/dev/pts/下面新文件的数字的大小，后面以999为例。

sshd然后使用open函数打开/dev/pts/999，获取的fd记为fd2。此时fd1和fd2对应tty设备的两端。写入fd1的字符串可以从fd2读到，写入fd2的字符串可以从fd1读到。

然后sshd执行dup2函数，把fd2放在数字0 1 2的位置上。dup2(fd2, 0); dup2(fd2, 1); dup2(fd2, 2); 然后执行exec(bash, 参数)类似的函数。bash进程的fd中编号为0 1 2的都是之前由fd2的复制的fd。

由于fd1和fd2对应tty设备的两端。写入fd1的字符，可以通过fd2读到，由于bash进程中0 1 2都是fd2复制得到的，可以通过0读到。同样写入1 2的字符串也可以从fd1读到。

fd复制只是复制一个操作接口，不复制内核中对应的真实资源，在内核中共享一个缓存资源，fd1读到的字符串不会区分bash写入到1还是写入2。

ssh从客户端读取的字符串会被发送到sshd，sshd写入fd1，bash就会从0 1 2读到客户端的字符串。bash（及bash的子进程）希望打印到客户端的字符串，就写入1 2，sshd就会从fd1中读到。sshd再把从fd1读到的字符串发给客户端的ssh进程。

### tty原理
上述ssh是使用tty的重要案例。为什么不直接使用类似socketpair来fd对来处理这个问题呢？因为tty功能在操作系统实现，提供了ctl+c杀掉进程，处理换行，处理当前中断行数和列数等等的功能。

命令行中可以使用tty命令查看当前使用的tty。可以通过stty配置一些tty功能。stty -a可以打印当前tty所有配置。

gnome-terminal同样使用tty的功能，每打开一个tab都会使用一个新的tty。

但是上述ssh和gnome-termianl使用的tty都是伪终端。特征是通过/dev/pts/提供服务。

/dev/tty0 - /dev/tty9和/dev/ttyS0 - /dev/ttyS9是物理终端。（编号只是示例，实际可能更少或更多）

linux开机打印信息就是打印在/dev/tty0上面的。linux可以使用某些快捷键进入其他同类中断，终端路径格式是/dev/tty加数字。

/dev/ttyS0可以是那些电脑外接的字符串设备。具体例如，电脑上面USB连接FPGA，FPGA通过USB-UART桥，FPGA中的数字逻辑写字符串，可以在电脑上面读取/dev/ttyS0读到。

虽然叫伪中断，但图形界面的系统中伪终端使用更广泛。因为tty是继承古早计算机的字符串设备而来，伪字表示其非物理终端。

### tty的一些细节
/dev/ptmx /dev/pts/ptmx都是字符设备，但权限等文件属性可能不同。linux设备文件决定对应资源的性质有文件类型（char设备还是block设备），major编号，minor编号。/dev/ptmx /dev/pts/ptmx的major都为5，minor都为2。

/dev/pts是一个特殊挂载点。

```
root@localhost:~# mount | grep /dev/pts
devpts on /dev/pts type devpts (rw,nosuid,noexec,relatime,gid=5,mode=620,ptmxmode=000)
```

下面只有ptmx文件和操作系统生成的数字编号文件：
```
root@localhost:~# ls /dev/pts
0  1  ptmx
```

对一个具体tty，例如/dev/pts/0，可以通过文件的所有者得知该tty被哪个linux创建和使用。

### 追踪占用
之前遇到系统tty资源耗尽的情况，需要追踪到具体linux user

使用python脚本

```
import os
d = {}
for i in os.listdir('/dev/pts/'):
  uid = os.lstat('/dev/pts/' + i).st_uid
  m = d.get(uid)
  if m is None:
    d[uid] = 1
  else:
    d[uid] += 1
print(d)
```

打印d变量是一个字典，key是user的uid，value是该用户使用的tty数量。应该找到使用了大量tty的uid。假如定位到uid为999使用了大量tty。

可以使用ls -la /dev/pts/可以看到/dev/pts/下面每个文件的用户名。ls -lan /dev/pts/可以把用户名换成uid。

```
ls -lan /dev/pts/ | grep 999
crw--w----  1 999 5 136, 1970 Jan  1 00:00 888
```

这样表明uid为999的人使用了/dev/pts/888。然后使用ls -la /dev/pts/888就能获取该大量使用tty的用户名。
