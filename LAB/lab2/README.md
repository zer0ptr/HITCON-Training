# 分析
```bash
zhailin@DESKTOP-7U7Q35J:~/HITCON-Training/LAB/lab2$ checksec orw.bin
[*] '/home/zhailin/HITCON-Training/LAB/lab2/orw.bin'
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX unknown - GNU_STACK missing
    PIE:        No PIE (0x8048000)
    Stack:      Executable
    RWX:        Has RWX segments
    Stripped:   No

zhailin@DESKTOP-7U7Q35J:~/HITCON-Training/LAB/lab2$ file orw.bin
orw.bin: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=e60ecccd9d01c8217387e8b77e9261a1f36b5030, not stripped
```

ida F5伪代码
```C
int __cdecl main(int argc, const char **argv, const char **envp)
{
  orw_seccomp();
  printf("Give my your shellcode:");
  read(0, &shellcode, 0xC8u);
  ((void (*)(void))shellcode)();
  return 0;
}
```
大致逻辑：接受用户传入的shellcode并且直接执行。这里需要注意的是在此之前调用了`orw_seccomp()`函数，经过搜索知道`seccomp`大概是一个类似沙箱的东西，禁用掉了一部分的系统调用，可以使用[seccomp-tools](https://github.com/david942j/seccomp-tools)来查看

```bash
zhailin@DESKTOP-7U7Q35J:~/HITCON-Training/LAB/lab2$ seccomp-tools dump ./orw.bin
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x09 0x40000003  if (A != ARCH_I386) goto 0011
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x15 0x07 0x00 0x000000ad  if (A == rt_sigreturn) goto 0011
 0004: 0x15 0x06 0x00 0x00000077  if (A == sigreturn) goto 0011
 0005: 0x15 0x05 0x00 0x000000fc  if (A == exit_group) goto 0011
 0006: 0x15 0x04 0x00 0x00000001  if (A == exit) goto 0011
 0007: 0x15 0x03 0x00 0x00000005  if (A == open) goto 0011
 0008: 0x15 0x02 0x00 0x00000003  if (A == read) goto 0011
 0009: 0x15 0x01 0x00 0x00000004  if (A == write) goto 0011
 0010: 0x06 0x00 0x00 0x00050026  return ERRNO(38)
 0011: 0x06 0x00 0x00 0x7fff0000  return ALLOW
```

是一个白名单，只有跳转到0010的几个系统调用是可以使用的，其余的都被禁用掉了。我们的目标是获取`flag`文件，使用`read`读入文件，再用`write`写入标准输出流即可，不需要得到`shell`

# Exploit
使用pwntools的shellcode生成模块来生成shellcode，对于flag目录直接猜测，用相对路径尝试

然后没打通，菜鸡学艺不精。