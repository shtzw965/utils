## unshare黑魔法

工作时候很多使用别人的脚本遇到报错，脚本没有编辑权限，找脚本文件写入权限所有者调试很麻烦。本文分享一种使用容器的技术，达到修改别人脚本的效果。

### 原理

#### linux命名空间

linux为了隔离资源使用了命名空间的概念。使用ls /proc/self/ns/命令可以看到linux实现的命名空间。通常有cgroup、ipc、mnt、net、pid、pid_for_children、time、time_for_children、user、uts。具体情形根据内核版本和编译参数而定。

这些命名空间是实现现代容器的核心技术。本文涉及mnt、user两个命名空间。使用unshare、mount工具进行操作。后续介绍具体操作。

#### mount bind

linux的所有路径都是挂载而来。linux支持把两个路径绑定。通常把一个目录绑定到另一个目录，或一个普通文件绑定到另一个普通文件。（bind其他文件类型如symlink ipc device不常使用）

mount --bind file1 file2 或 mount --bind dir1 dir2

执行后对于file2或dir2的访问都会映射到file1或dir1（包括权限） 而不需要删除file1和dir1（此处与symlink不同）

需要解除映射时，执行umount file2或umount dir2

限制：mount --bind被内核视为需要高权限操作，因为这种映射影响所有用户。多数情况需要root权限，本文后续介绍无root权限执行bind的方法。

#### mnt命名空间

前述介绍了bind，但是需要root权限。内核提供了无root权限bind的方法。bind的风险在影响所有用户。内核提供了不影响其他用户的方式进行bind。原理如下。

使用unshare(CLONE_NEWNS)后进入独立的mnt命名空间（后称子mnt空间）。通过mount函数设置原mnt空间和子mnt空间如何传播。常用传播模式有private、shared、slave。private模式下子mnt空间继承原mnt空间的挂载点，但不再接收来自原mnt空间新的挂载点。shared模式下子mnt空间何原mnt空间相互影响。slave模式下原mnt空间的挂载点会传播到子mnt挂载点，但子mnt空间新的挂载点对原mnt空间不可见。

根据上面说明，应该使用slave模式。实际上可以使用private和slave模式，不可使用shared模式（即使设置成功也无效）。
```
unshare --help

Usage:
 unshare [options] [<program> [<argument>...]]

Run a program with some namespaces unshared from the parent.

Options:
 -m, --mount[=<file>]      unshare mounts namespace
 -u, --uts[=<file>]        unshare UTS namespace (hostname etc)
 -i, --ipc[=<file>]        unshare System V IPC namespace
 -n, --net[=<file>]        unshare network namespace
 -p, --pid[=<file>]        unshare pid namespace
 -U, --user[=<file>]       unshare user namespace
 -C, --cgroup[=<file>]     unshare cgroup namespace
 -f, --fork                fork before launching <program>
     --kill-child[=<signame>]  when dying, kill the forked child (implies --fork); defaults to SIGKILL
     --mount-proc[=<dir>]  mount proc filesystem first (implies --mount)
 -r, --map-root-user       map current user to root (implies --user)
     --propagation slave|shared|private|unchanged
                           modify mount propagation in mount namespace
 -s, --setgroups allow|deny  control the setgroups syscall in user namespaces

 -h, --help                display this help
 -V, --version             display version

For more details see unshare(1).
```

根据上述说明应该使用unshare -m --propagation slave csh命令。但内核要求CLONE_NEWNS同时必须CLONE_NEWUSER。也就是至少unshare -m -U --propagation slave csh。执行后uid和gid都是65534。应该map到root。综上所述，最终unshare的命令是unshare -m -U -r --propagation slave csh。

但还有一个限制就是系统的/bin/mount是s权限文件，对bind行为在内核检查之外有额外检查，就是强制要求bind行为必须是uid为0的用户才能执行。使用-r参数后mount程序会认为uid为0。

#### user命名空间

上面说了使用-U和-r参数。这两个参数是对user命名空间的使用和配置。unshare程序会写入/proc/self/setgroups /proc/self/uid_map /proc/self/gid_map对uid gid进行映射到0，也就是root。映射后程序调用getuid会认为自身是root用户，使用id命令可以看到uid和gid都是0。但内核进行权限检查时仍然按照真实uid和gid进行检查，不会违反传统linux权限控制。

### 具体操作

unshare -m -U -r --propagation slave csh进入新的命令行。所有相关操作在这个csh下执行才生效。

cp /path/to/original/script /path/to/local/script

vi /path/to/local/script

mount --bind /path/to/local/script /path/to/original/script

调用脚本执行操作。

结束后退出unshare后面的csh。csh及其所有的后代进程退出后会清理user命名空间，mnt命名空间（及其bind关系）。如需手动清理，可以在这个csh里执行umount /path/to/original/script，然后退出这个csh。

### 注意事项和使用限制

由于所有系统调用都是内核预期的使用方式。改方式不会造成操作系统层面的安全风险，或对同系统下其他用户产生影响，其他用户读取脚本时还是原来的文件。

由于uid和gid被map到0。一些程序无法工作，已知的有bsub p4。解决办法是在正常环境使用p4（脚本中跳过p4）。需要bsub时，先bsub一个csh，再在此csh中执行unshare -m -U -r --propagation slave csh命令。

还有一些脚本和程序根据uid推断用户名进一步推断home目录也无法工作，会出现尝试对/root目录的访问失败。此类脚本可以在报错附近修改home目录（使用bind方法）。此类程序无法继续正常工作。
