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

## 快速开始

```bash
# 编译（需要 Go 1.21+）
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o shellhook .

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

需要 root 或具备 `ptrace` 权限（`kernel.yama.ptrace_scope` 允许的前提下）。

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

换句话说：它不是杀毒软件，是「利用之后的收益阻断器」。

## 项目结构

| 文件 | 职责 |
| --- | --- |
| `main.go` | 入口、`run` / `attach` 命令、退出时 detach |
| `cli.go` | 常量、全局状态、参数解析、帮助与版本 |
| `ptrace.go` | ptrace 原语、目标内存读写、寄存器、`sockaddr` 解析 |
| `proc.go` | 线程枚举、`/proc/<tid>/syscall` 探测 |
| `policy.go` | 假 flag、出网策略、学习模式、日志 |
| `trace.go` | 主循环：事件分发、syscall 入口/出口判定、各类 hook |

## 已知的坑（开发备注）

- Go 里做 ptrace 必须 `runtime.LockOSThread()`。ptrace 的「追踪者」身份绑定在具体线程上，goroutine 一换线程，所有 ptrace 调用都会返回 `ESRCH`，现象是目标被挂住不动。
- 本工具在部分内核上发现 `PTRACE_GET_SYSCALL_INFO` 返回 `op=0`（结构体里只有 `arch` 有值）。因此入口/出口判定做了退化：入口停时内核把 `rax` 置为 `-ENOSYS(-38)`，而出口停是返回值；另外「刚跳过的 syscall 的下一个停必然是出口」用标记单独截住，否则被跳过 syscall 的出口（`rax` 也是 `-38`）会被误判成入口，导致回填的 errno 永远不生效。
- `PTRACE_POKEDATA` 的第 4 个参数是**要写的值**，不是指针。

## 许可

MIT，见 [LICENSE](LICENSE)。作者：guaidao2。
