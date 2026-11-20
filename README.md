# shellhook

AWD 场景下的「反 pwn」拦截器：不阻止漏洞被利用，只让利用之后的每一种兑现方式落空。

攻击者打进你的服务之后，无论用的是栈溢出、堆溢出还是 ret2shellcode，最后能做的事其实只有三类：拿一个 shell、把 flag 读出来、把数据带出去。shellhook 就守在这三个口子上——`execve`、`openat`、`connect/sendto`。

- 拿 shell → `execve` / `execveat` 直接拒绝，返回 `EACCES`
- 读 flag → 命中保护路径的 `open` / `openat` / `openat2` 重定向到诱饵文件
- 外带数据 → `connect` / `sendto` / `sendmsg` / `sendmmsg` 按白名单拦截

服务本身照常运行，checker 的可用性检查不受影响。

## 它是怎么做到的

shellhook 用 `ptrace` 把目标进程（以及它 fork/clone 出来的所有子进程、子线程）跟住，在 syscall 的**入口停**处改写寄存器：

| 动作 | 入口处做什么 | 出口处做什么 |
| --- | --- | --- |
| 拦截 execve | 把 `orig_rax` 改成 `-1`，内核直接跳过这个系统调用 | 把返回值改成 `-EACCES` |
| 假 flag | 把路径字符串改写成诱饵文件路径，或把路径指针指到栈上写入的诱饵 | — |
| 拦截外联 | 解析 `sockaddr` 判断目的地址，不在白名单就跳过 syscall | 把返回值改成 `-ENETUNREACH` |

两种接入方式：

- **run**：从 `execve` 之前就把目标拉起来，链路最干净，能保证不漏
- **attach**：挂到已经在跑的进程上，用 `PTRACE_SEIZE` + `PTRACE_INTERRUPT`，不发 `SIGSTOP`，不打断服务已有的信号语义；退出时（Ctrl-C）只 detach，服务继续活着

## 特性

- **两种模式**：`run` 自己拉起目标，`attach --pid` 挂已有进程（默认遍历全部线程，`--main-only` 只挂主线程）
- **只记录不拦**：`--log-only`，用于比赛前摸清服务的正常行为
- **假 flag**：`--fake-flag <路径> --decoy <诱饵文件>`，默认关闭；诱饵文件不存在会自动生成
- **出网管控**：`--block-out` + `--allow-cidr`，回环永远放行
- **学习模式**：`--learn-secs N` 先放行 N 秒并记录目的地址，到点自动切换为拦截，学到的地址可通过 `--allow-file` 落盘复用
- **子进程跟随**：`system()`、`sh -c`、fork 出来的孙进程都在网里
- **干净退出**：Ctrl-C / `SIGTERM` 只 detach，不连累被保护的服务
- **开箱自检**：`shellhook check` 报权限、yama 闸门，并真的 fork 一个子进程验证链路

## 快速开始

```bash
# 编译（需要 Go 1.21+）
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o shellhook .

# 先自检这台机器能不能用
./shellhook check

# 自己拉起服务
sudo ./shellhook run -- ./victim

# 先只观察，不拦
sudo ./shellhook run --log-only -- ./victim

# 挂到已经在跑的服务上
sudo ./shellhook attach --pid 1234

# 假 flag + 拦截外联
sudo ./shellhook attach --pid 1234 \
  --fake-flag /flag --decoy /tmp/.d/flag \
  --block-out --allow-cidr 10.0.0.0/8

# 学习模式：先放养 60 秒，把正常外联目标记下来
sudo ./shellhook run --block-out --learn-secs 60 \
  --allow-file /tmp/sh_allow -- ./victim
```

## 权限与 ptrace 闸门

shellhook 靠 ptrace 工作，能不能挂上去只看两件事：权限，和内核的 `yama` 限制。

**权限**：跟踪者要和目标**同 uid**，或者持有 `CAP_SYS_PTRACE`（root 天然有）。所以 root 环境下没有障碍；服务降权到 `www-data` 而你也是 `www-data` 也能挂；比目标权限低就不行。

**yama 的 `ptrace_scope`**：

| 值 | 含义 |
| --- | --- |
| 0 | 不限制，同 uid 可以 attach 任意进程 |
| 1 | 只能 attach 自己的直接子进程（多数发行版默认） |
| 2 | 只允许 root，或显式声明过的父进程 |
| 3 | 完全禁止 attach |

先看当前状态：

```bash
id
cat /proc/sys/kernel/yama/ptrace_scope
```

临时放开（重启失效，需要 root）：

```bash
echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope
# 等价写法
sudo sysctl -w kernel.yama.ptrace_scope=0
```

要永久生效就写进 `/etc/sysctl.d/99-ptrace.conf`：

```
kernel.yama.ptrace_scope = 0
```

然后 `sudo sysctl --system` 应用。

两点经验：

- **`run` 模式不受 scope 影响**。目标是你 fork 出来的子进程，天然满足「直接子进程」，scope=1 也能用；真正会被卡的是 attach 一个已经在跑的、跟你没有父子关系的服务。
- **容器里要先看 capability**。Docker 默认集合里没有 `CAP_SYS_PTRACE`，需要 `--cap-add=SYS_PTRACE`；容器内部同 uid 跟踪一般没问题，跨容器不行。

不想逐条看的话，直接跑 `./shellhook check`：它会把 uid、`CAP_SYS_PTRACE`、yama 档位打出来，然后真 fork 一个 `/bin/true` 跟一次，最后给出 run / attach 两种模式各自能不能用的结论。退出码 0 表示 run 模式可用。

`check` 的典型输出：

```
shellhook check

uid/euid       : 0/0 (root)
CAP_SYS_PTRACE : yes
yama scope     : 0    (unrestricted)
run mode       : OK  (can fork + trace a child)
attach mode    : likely OK  (scope=0，同 uid 的目标可直接挂)
```

## 选项

| 选项 | 说明 |
| --- | --- |
| `--pid <pid>` | attach 的目标进程号（仅 attach） |
| `--log-only` | 只记录不拦截 |
| `--main-only` | attach 时只挂主线程 |
| `--fake-flag <路径>` | 保护路径，可重复 |
| `--decoy <文件>` | 诱饵文件，不存在时自动生成 |
| `--block-out` | 拦截对外 `connect` / `sendto` / `sendmsg` / `sendmmsg` |
| `--allow-cidr <cidr>` | 出网白名单，可重复；回环永远放行 |
| `--allow-file <文件>` | 白名单文件，一行一个 IP 或 CIDR；学习结果也追加到这里 |
| `--learn-secs <N>` | 前 N 秒放行并记录目的地址，之后自动切拦截 |
| `-h`, `--help` | 帮助 |
| `-v`, `--version` | 版本 |

单独一个 `--` 是分隔符，它后面的内容原样交给被启动的程序，避免目标自己的 `-p`、`-b` 之类参数被 shellhook 吃掉。

## 比赛里怎么用

1. 服务先正常起来，`shellhook attach --pid <pid> --log-only` 挂上去
2. 跑一轮真实流量，看日志里服务会不会 exec、会开哪些文件、会连哪些地址
3. 确认基线之后，用 `--learn-secs` 跑一次学习，把正常外联目标记进 `--allow-file`
4. 开正式拦截：execve 全禁、flag 走诱饵、出网走白名单
5. 日志里出现 `BLOCKED` 就是有人在打，把它连同 pid、路径、目的地址一起留档

建议顺序是「先记录、再拦截」——AWD 里误伤自家业务是确定掉分，漏一次还有机会。

## 能力边界

能挡住的：

- 各类拿到 shell 的利用（`system()`、`execve("/bin/sh")`、`execveat`、memfd 无文件执行）
- ROP / ret2shellcode 里直接读 flag、直接反弹 shell 的利用
- 堆溢出、格式化字符串等，只要最终兑现方式是上面那几类 syscall

挡不住的，不要指望：

- **`io_uring`**：`open` / `connect` 的参数由内核从 ring 里读，ptrace 看不到字符串
- **已经在内存里的泄露**：服务自己把 flag 读进内存、利用只是一次 `write` 出去的，拦不到
- **`mprotect` / `mmap` 的 `PROT_EXEC`**：目前不拦 shellcode staging，可以后续加开关
- **控制流劫持本身**：这层只有 CET shadow stack 或编译期 CFI 能做，且要求目标二进制本身开启

几个部署相关的已知限制：

- **跨 namespace attach**：在宿主机上挂容器内的进程时，受保护文件的 `(dev, ino)` 在两边不是同一个文件，按 inode 的判定会失效，只剩路径字符串那一层。推荐在容器内跑。
- **非 root 追踪**：服务如果自己调 `prctl(PR_SET_DUMPABLE, 0)`，非 root 的追踪者读不到 `/proc/<pid>/fd`、`/proc/<pid>/root`、`/proc/<pid>/cwd`，入口和出口两层 inode 判定会一起退化，只剩路径字符串比对。root 部署不受影响。
- **32 位目标**：i386 的 `close` 注入依赖 `int 0x80`，如果目标走 `sysenter`（vDSO 的 `__kernel_vsyscall`）就注入不了。所以 32 位目标的 open 全部在**入口**按 inode 判定并直接拒，不挂出口复核；入口读不到 `/proc` 时 inode 层整体失效，只剩字符串比对。另外入口单点判定存在一个窄 TOCTOU 窗口：tracee 停住时我们 stat 的是当时的链接，恢复后内核才解析，同进程的另一个线程抢在这中间换掉软链就能让入口判成未命中。64 位有出口 fd 复核兜底，32 位没有。
- **回环放行**：`--block-out` 永远放行 127.0.0.0/8。本地 DNS（127.0.0.53）或本机代理可以被当成出网跳板，需要的话把回环也纳入白名单策略。
- **性能**：目前是全量 `PTRACE_SYSCALL`，每个 syscall 停两次。syscall 密集的程序会明显变慢，后续可用 seccomp `RET_TRACE` 只对关心的 syscall 停。

换句话说：它不是杀毒软件，是「利用之后的收益阻断器」。

## 项目结构

| 文件 | 职责 |
| --- | --- |
| `main.go` | 入口、`run` / `attach` 命令、退出时 detach |
| `cli.go` | 常量、全局状态、参数解析、帮助与版本 |
| `ptrace.go` | ptrace 原语、目标内存读写、寄存器、`sockaddr` 解析 |
| `proc.go` | 线程枚举、`/proc/<tid>/syscall` 探测 |
| `policy.go` | 假 flag、出网策略、学习模式、日志 |
| `trace.go` | 主循环：事件分发、相位跟踪、各类 hook、出口复核与 close 注入 |
| `abi.go` | 64 位 / 32 位兼容 ABI 的寄存器解析、`int 0x80` 判别、close 注入 |
| `inode.go` | 受保护文件的 `(dev, ino)` 记录、按 tracee 视图解析路径、fd 归属复核 |

## 32 位与内核 ABI

- 同时支持 64 位 `syscall` 与 32 位兼容 ABI。`int 0x80` 的判别看 `RIP-2` 处的指令字节（`cd 80`），因为 64 位代码里发 `int 0x80` 时 `CS` 仍然是 `0x33`。
- 32 位的 syscall 号与 64 位完全不同（execve=11、open=5、openat=295、openat2=437、execveat=358），兼容表是单独维护的。
- 内核若支持 `PTRACE_GET_SYSCALL_INFO`，入口/出口直接由内核告知；否则用 per-tid 相位交替，并在每个线程前几次停下时用 `rax == -ENOSYS` 校准。`shellhook check` 的 `syscall-info` 一行会告诉你这台机器走的是哪条。
- 路径保护是两层：先比字符串，再按 tracee 的 root/cwd/dirfd 解析后比 inode。64 位目标的 open 在出口还会用 `/proc/<pid>/fd/<fd>` 复核一次兜住软链，命中时注入一次 `close` 把真 fd 关掉；32 位目标只在入口判定。

## 已知的坑（开发备注）

- Go 里做 ptrace 必须 `runtime.LockOSThread()`。ptrace 的「追踪者」身份绑定在具体线程上，goroutine 一换线程，所有 ptrace 调用都会返回 `ESRCH`，现象是目标被挂住不动。
- 本工具在部分内核上发现 `PTRACE_GET_SYSCALL_INFO` 返回 `op=0`（结构体里只有 `arch` 有值）。因此入口/出口判定做了退化：入口停时内核把 `rax` 置为 `-ENOSYS(-38)`，而出口停是返回值；另外「刚跳过的 syscall 的下一个停必然是出口」用标记单独截住，否则被跳过 syscall 的出口（`rax` 也是 `-38`）会被误判成入口，导致回填的 errno 永远不生效。
- `PTRACE_POKEDATA` 的第 4 个参数是**要写的值**，不是指针。
- 开了 `PTRACE_O_TRACESYSGOOD` 之后，syscall 停的信号是 `SIGTRAP|0x80`，其它 `SIGTRAP`（int3、外部投递）必须原样回注，否则会吞掉服务的信号。
- 出口停上改 `Orig_rax` 没有任何效果（内核已经分发完了），要拒绝只能改 `Rax`。

## 许可

MIT，见 [LICENSE](LICENSE)。作者：guaidao2。
